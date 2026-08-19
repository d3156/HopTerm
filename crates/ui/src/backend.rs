//! Backend bridge: runs on a tokio runtime, owns the [`SessionManager`], and
//! translates IPC commands from the webview into real SSH operations.
//!
//! Sessions are kept **per profile** in a map and opened lazily: connecting to a
//! profile that already has a live session is a no-op switch, never a reconnect.
//! Every streamed event is tagged with the profile id so the webview can route
//! it to the right terminal tab (multi-session).

use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine;
use hopterm_app::{HostKeyAsk, SessionManager, Services};
use hopterm_domain::*;
use hopterm_security::SecretPrompter;
use serde_json::{json, Value};
use tao::event_loop::EventLoopProxy;
use tokio::sync::{mpsc, oneshot};

use crate::UserEvent;

const DEFAULT_COLS: u16 = 100;
const DEFAULT_ROWS: u16 = 30;

type Sessions = Arc<Mutex<HashMap<String, Active>>>;

#[derive(Clone, Default)]
struct Pending {
    secrets: Arc<Mutex<HashMap<u64, oneshot::Sender<Option<String>>>>>,
    host_keys: Arc<Mutex<HashMap<u64, std::sync::mpsc::Sender<bool>>>>,
    counter: Arc<AtomicU64>,
}
impl Pending {
    fn next_id(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }
}

struct Active {
    id: SessionId,
    input_tx: mpsc::Sender<ShellCmd>,
    read_abort: tokio::task::AbortHandle,
    title: String,
    route: String,
    /// The profile this session was opened from — rsync downloads rebuild the
    /// same hop chain with an external ssh.
    profile: SessionProfile,
}

enum ShellCmd {
    Input(Vec<u8>),
    Resize(PtySize),
}

/// A live port-forward plus the metadata the UI shows for it. Dropping `pf`
/// (or calling `pf.stop()`) tears the tunnel down.
struct ActiveForward {
    pf: Box<dyn PortForward>,
    /// `"local"` (ssh -L) or `"socks"` (ssh -D dynamic SOCKS5 proxy).
    kind: &'static str,
    /// Session key this forward rides on (so it can be stopped on disconnect).
    session_key: String,
    local_port: u16,
    /// Empty for SOCKS forwards.
    remote_host: String,
    /// 0 for SOCKS forwards.
    remote_port: u16,
    /// Human label of the session, for display.
    label: String,
}

type Forwards = Arc<Mutex<HashMap<String, ActiveForward>>>;

fn forwards_json(forwards: &HashMap<String, ActiveForward>) -> Value {
    Value::Array(
        forwards
            .iter()
            .map(|(fid, f)| {
                json!({
                    "fid": fid,
                    "kind": f.kind,
                    "session": f.session_key,
                    "label": f.label,
                    "local_port": f.local_port,
                    "remote_host": f.remote_host,
                    "remote_port": f.remote_port,
                })
            })
            .collect(),
    )
}

/// Stop and forget every forward riding on `session_key`, then push the updated
/// list to the UI. Called whenever a session ends — explicit disconnect OR the
/// shell dying on its own — so a forward never outlives the connection it needs.
fn stop_forwards_for(forwards: &Forwards, session_key: &str, proxy: &EventLoopProxy<UserEvent>) {
    let items = {
        let mut fw = forwards.lock().unwrap();
        let dead: Vec<String> = fw
            .iter()
            .filter(|(_, f)| f.session_key == session_key)
            .map(|(k, _)| k.clone())
            .collect();
        if dead.is_empty() {
            return;
        }
        for k in &dead {
            if let Some(f) = fw.remove(k) {
                f.pf.stop();
            }
        }
        forwards_json(&fw)
    };
    emit(proxy, json!({"ev":"forwards","items":items}));
}

pub(crate) fn emit(proxy: &EventLoopProxy<UserEvent>, value: Value) {
    let _ = proxy.send_event(UserEvent::Js(format!("window.hop && window.hop.onEvent({value})")));
}
fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Local directory downloads land in. Always a dedicated folder — never `$HOME`
/// directly, so a downloaded file can't clobber dotfiles like `~/.bashrc`.
fn download_dir() -> String {
    let base = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let dl = format!("{base}/Downloads");
    if std::fs::create_dir_all(&dl).is_ok() {
        return dl;
    }
    let fallback = format!("{base}/.hopterm/downloads");
    let _ = std::fs::create_dir_all(&fallback);
    fallback
}

/// Expand a leading `~` to `$HOME` in a user-typed local path.
fn expand_home(path: &str) -> String {
    let home = || std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    if path == "~" {
        home()
    } else if let Some(rest) = path.strip_prefix("~/") {
        format!("{}/{rest}", home())
    } else {
        path.to_string()
    }
}

fn save_commands(path: &str, commands: &[Value]) {
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(text) = serde_json::to_string_pretty(commands) {
        let _ = std::fs::write(path, text);
    }
}

/// [`ProgressSink`] that streams throttled transfer progress to the webview.
struct XferProgress {
    proxy: EventLoopProxy<UserEvent>,
    job: String,
    name: String,
    dir: &'static str,
    last: Arc<AtomicU64>,
}
impl ProgressSink for XferProgress {
    fn on_progress(&self, transferred: u64, total: u64) {
        let last = self.last.load(Ordering::Relaxed);
        let step = (total / 100).max(64 * 1024); // ~1% or 64 KiB, whichever larger
        if transferred == total || transferred.saturating_sub(last) >= step {
            self.last.store(transferred, Ordering::Relaxed);
            emit(
                &self.proxy,
                json!({"ev":"xfer","id":self.job,"name":self.name,"dir":self.dir,
                       "t":transferred,"total":total,"status":"running"}),
            );
        }
    }
}

struct JsObserver {
    proxy: EventLoopProxy<UserEvent>,
    id: String,
}
impl ConnectionObserver for JsObserver {
    fn on_state(&self, state: ConnectionState) {
        emit(
            &self.proxy,
            json!({"ev":"state","id":self.id,"text":describe_state(&state),"live":state.is_live()}),
        );
    }
}

struct WebPrompter {
    proxy: EventLoopProxy<UserEvent>,
    pending: Pending,
    /// Stored node passwords (HostId -> password), seeded from saved profiles so
    /// a configured password is used at connect time without a dialog.
    stored_pw: Arc<Mutex<HashMap<String, String>>>,
}
impl WebPrompter {
    async fn ask(&self, prompt: String) -> Option<String> {
        let id = self.pending.next_id();
        let (tx, rx) = oneshot::channel();
        self.pending.secrets.lock().unwrap().insert(id, tx);
        emit(&self.proxy, json!({"ev":"secret","id":id,"prompt":prompt}));
        rx.await.ok().flatten()
    }
}
#[async_trait]
impl SecretPrompter for WebPrompter {
    async fn prompt_password(&self, h: HostId, username: &str) -> Option<String> {
        if let Some(pw) = self.stored_pw.lock().unwrap().get(&h.to_string()).cloned() {
            if !pw.is_empty() {
                return Some(pw);
            }
        }
        self.ask(format!("Пароль для {username}")).await
    }
    async fn prompt_passphrase(&self, key_path: &str) -> Option<String> {
        self.ask(format!("Passphrase для {key_path}")).await
    }
}

fn host_key_asker(proxy: EventLoopProxy<UserEvent>, pending: Pending) -> HostKeyAsk {
    Arc::new(move |key: &HostKey| {
        let id = pending.next_id();
        let (tx, rx) = std::sync::mpsc::channel();
        pending.host_keys.lock().unwrap().insert(id, tx);
        let fp = format!("{}\n{}\n[{}]", key.host_port(), key.fingerprint_sha256, key.algorithm);
        emit(&proxy, json!({"ev":"hostkey","id":id,"fingerprint":fp}));
        rx.recv().unwrap_or(false)
    })
}

pub async fn run(mut cmd_rx: mpsc::UnboundedReceiver<String>, proxy: EventLoopProxy<UserEvent>) {
    let pending = Pending::default();
    let settings = AppSettings::default();
    let stored_pw: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let web_prompter = Arc::new(WebPrompter {
        proxy: proxy.clone(),
        pending: pending.clone(),
        stored_pw: stored_pw.clone(),
    });
    let prompter: Arc<dyn SecretPrompter> = web_prompter.clone();
    let asker = host_key_asker(proxy.clone(), pending.clone());
    let services = Services::production(prompter, Some(asker), &settings);
    let manager = SessionManager::new(services);
    let store = manager.services().store.clone();

    // An encrypted config can't be read until the user enters the PIN, which
    // happens via the webview — so its profiles arrive after "ready".
    let locked = store.config_encryption() == ConfigEncryption::Locked;
    let mut loaded = if locked { Vec::new() } else { store.load_profiles().unwrap_or_default() };
    if !locked && loaded.is_empty() {
        loaded = hopterm_app::demo::demo_profiles();
    }
    seed_stored_passwords(&stored_pw, &loaded);
    let profiles: Arc<Mutex<Vec<SessionProfile>>> = Arc::new(Mutex::new(loaded));
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    // Active transfer jobs → cancel tokens.
    let transfers: Arc<Mutex<HashMap<String, CancelToken>>> = Arc::new(Mutex::new(HashMap::new()));
    // Active local port-forwards, keyed by a generated forward id.
    let forwards: Forwards = Arc::new(Mutex::new(HashMap::new()));
    // Saved quick commands, persisted to ~/.hopterm/commands.json.
    let commands_path = format!(
        "{}/.hopterm/commands.json",
        std::env::var("HOME").unwrap_or_default()
    );
    let mut commands: Vec<Value> = std::fs::read_to_string(&commands_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    // System clipboard, kept alive for the app's lifetime so X11 selection
    // ownership persists for other apps to paste from.
    let mut clipboard = arboard::Clipboard::new().ok();

    while let Some(raw) = cmd_rx.recv().await {
        let Ok(msg): Result<Value, _> = serde_json::from_str(&raw) else {
            continue;
        };
        let cmd = msg.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
        let id = msg.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();

        match cmd {
            "ready" => {
                emit(&proxy, json!({"ev":"hosts","items":host_items(&profiles.lock().unwrap())}));
                emit_config_state(&proxy, &*store);
                if store.config_encryption() == ConfigEncryption::Locked {
                    spawn_config_unlock(
                        web_prompter.clone(),
                        store.clone(),
                        profiles.clone(),
                        stored_pw.clone(),
                        proxy.clone(),
                    );
                }
                if let Ok(v) = std::env::var("HOPTERM_AUTOCONNECT") {
                    let idx: usize = v.parse().unwrap_or(0);
                    let profile = profiles.lock().unwrap().get(idx).cloned();
                    if let Some(profile) = profile {
                        let key = profile.id.to_string();
                        spawn_connect(profile, manager.clone(), proxy.clone(), sessions.clone(), false, key, forwards.clone());
                    }
                }
            }

            "connect" => {
                // Lazy: already-open profile just switches, no reconnect.
                if let Some(active) = sessions.lock().unwrap().get(&id) {
                    emit(
                        &proxy,
                        json!({"ev":"connected","id":id,"title":active.title,"route":active.route}),
                    );
                    continue;
                }
                let sudo = msg.get("sudo").and_then(|v| v.as_bool()).unwrap_or(false);
                // `id` is the session key; for sudo it carries a `#sudo` suffix.
                let profile_id = id.strip_suffix("#sudo").unwrap_or(&id).to_string();
                let profile = {
                    let ps = profiles.lock().unwrap();
                    ps.iter().find(|p| p.id.to_string() == profile_id).map(|p| resolve_profile(p, &ps))
                };
                match profile {
                    Some(Ok(profile)) => {
                        spawn_connect(profile, manager.clone(), proxy.clone(), sessions.clone(), sudo, id.clone(), forwards.clone());
                    }
                    Some(Err(e)) => {
                        emit(&proxy, json!({"ev":"state","id":id,"text":format!("ошибка: {e}"),"live":false}));
                    }
                    None => {}
                }
            }

            // Reproduce the profile's hop chain as a plain `ssh` command and hand
            // it to an external terminal emulator (gnome-terminal / fly-term / …).
            "open_external" => {
                let profile = {
                    let ps = profiles.lock().unwrap();
                    ps.iter().find(|p| p.id.to_string() == id).map(|p| resolve_profile(p, &ps))
                };
                match profile {
                    Some(Ok(profile)) => match open_in_external_terminal(&profile) {
                        Ok(term) => emit(&proxy, json!({"ev":"toast",
                            "text": format!("Открыто во внешнем терминале ({term})")})),
                        Err(e) => emit(&proxy, json!({"ev":"toast", "error": true,
                            "text": format!("Внешний терминал — {e}")})),
                    },
                    Some(Err(e)) => emit(&proxy, json!({"ev":"toast", "error": true,
                        "text": format!("Маршрут: {e}")})),
                    None => emit(&proxy, json!({"ev":"toast", "error": true,
                        "text": "Хост не найден"})),
                }
            }

            "save_host" => {
                if let Some(host) = msg.get("host") {
                    let mut profile = profile_from_json(host);
                    let vault_res = {
                        let ps = profiles.lock().unwrap();
                        let old = ps.iter().find(|p| p.id == profile.id);
                        vault_keys(&mut profile, old)
                    };
                    if let Err(e) = vault_res {
                        emit(&proxy, json!({"ev":"toast","error":true,
                            "text":format!("Хост не сохранён: {e}")}));
                        continue;
                    }
                    // Reject dangling/cyclic hop references at save time, not
                    // at the first connect attempt.
                    let ref_err = {
                        let ps = profiles.lock().unwrap();
                        let mut future: Vec<SessionProfile> =
                            ps.iter().filter(|p| p.id != profile.id).cloned().collect();
                        future.push(profile.clone());
                        resolve_profile(&profile, &future).err()
                    };
                    if let Some(e) = ref_err {
                        emit(&proxy, json!({"ev":"toast","error":true,
                            "text":format!("Хост не сохранён: {e}")}));
                        continue;
                    }
                    if let Err(e) = store.save_profile(&profile) {
                        emit(&proxy, json!({"ev":"toast","error":true,
                            "text":format!("Хост не сохранён: {e}")}));
                        continue;
                    }
                    {
                        let mut ps = profiles.lock().unwrap();
                        match ps.iter_mut().find(|p| p.id == profile.id) {
                            Some(slot) => *slot = profile.clone(),
                            None => ps.push(profile.clone()),
                        }
                        seed_stored_passwords(&stored_pw, &ps);
                    }
                    emit(&proxy, json!({"ev":"hosts","items":host_items(&profiles.lock().unwrap())}));
                }
            }

            "delete_host" => {
                if let Ok(uuid) = uuid::Uuid::parse_str(&id) {
                    let pid = ProfileId::new(uuid);
                    // Referential integrity: a host other targets hop through
                    // must not silently disappear from under them.
                    let dependents: Vec<String> = profiles
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|p| p.route.hops.iter().any(|h| h.hop_ref == Some(pid)))
                        .map(|p| p.display_name.clone())
                        .collect();
                    if !dependents.is_empty() {
                        emit(&proxy, json!({"ev":"toast","error":true,
                            "text":format!("Хост используется как хоп у: {} — сначала уберите ссылки",
                                           dependents.join(", "))}));
                        continue;
                    }
                    match store.delete_profile(pid) {
                        // NotFound is fine: demo profiles never hit the disk.
                        Ok(()) | Err(StorageError::NotFound(_)) => {}
                        Err(e) => {
                            emit(&proxy, json!({"ev":"toast","error":true,
                                "text":format!("Хост не удалён: {e}")}));
                            continue;
                        }
                    }
                    {
                        let mut ps = profiles.lock().unwrap();
                        ps.retain(|p| p.id != pid);
                        seed_stored_passwords(&stored_pw, &ps);
                    }
                    emit(&proxy, json!({"ev":"hosts","items":host_items(&profiles.lock().unwrap())}));
                }
            }

            // Export chosen hosts (plus their reference-hop closure), stored
            // passwords included — the file is always sealed with a PIN in the
            // same envelope as the config, so it also drops in as an encrypted
            // config.json.
            "export_hosts" => {
                let ids: std::collections::HashSet<String> = msg
                    .get("ids")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                let pin = msg.get("pin").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if ids.is_empty() {
                    continue;
                }
                if pin.is_empty() {
                    emit(&proxy, json!({"ev":"toast","error":true,
                        "text":"Экспорт защищается PIN-кодом — укажите его"}));
                    continue;
                }
                let ps = profiles.lock().unwrap().clone();
                let keep = ref_closure(
                    ps.iter().filter(|p| ids.contains(&p.id.to_string())).map(|p| p.id),
                    &ps,
                );
                let picked: Vec<SessionProfile> =
                    ps.iter().filter(|p| keep.contains(&p.id)).cloned().collect();
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let path = format!("{}/hopterm-hosts-{stamp}.json", download_dir());
                let count = picked.len();
                let doc = json!({"profiles": picked});
                match serde_json::to_string(&doc)
                    .map_err(|e| e.to_string())
                    .map(|text| hopterm_storage::seal_with_pin(&text, &pin))
                    .and_then(|sealed| std::fs::write(&path, sealed).map_err(|e| e.to_string()))
                {
                    Ok(()) => emit(&proxy, json!({"ev":"toast",
                        "text":format!("Экспортировано хостов: {count} — {path} (зашифровано PIN-кодом)")})),
                    Err(e) => emit(&proxy, json!({"ev":"toast","error":true,
                        "text":format!("Экспорт не удался: {e}")})),
                }
            }

            // Import a config-shaped file (a sealed export or a plain config)
            // and merge it into the current hosts: same profile id updates the
            // existing entry, a new id is added. Ids survive export, so
            // re-import refreshes rather than duplicates.
            "import_hosts" => {
                let path =
                    expand_home(msg.get("path").and_then(|v| v.as_str()).unwrap_or("").trim());
                let pin = msg.get("pin").and_then(|v| v.as_str()).unwrap_or("");
                if path.is_empty() {
                    continue;
                }
                let parsed = std::fs::read_to_string(&path)
                    .map_err(|e| format!("файл не прочитан: {path}: {e}"))
                    .and_then(|text| {
                        hopterm_storage::open_with_pin(&text, pin).map_err(|e| e.to_string())
                    })
                    .and_then(|json| {
                        serde_json::from_str::<Value>(&json)
                            .ok()
                            .and_then(|v| v.get("profiles").cloned())
                            .map(serde_json::from_value::<Vec<SessionProfile>>)
                            .transpose()
                            .map_err(|e| format!("не конфиг HopTerm: {e}"))?
                            .filter(|ps| !ps.is_empty())
                            .ok_or_else(|| "в файле нет хостов".to_string())
                    });
                let imported = match parsed {
                    Ok(ps) => ps,
                    Err(e) => {
                        emit(&proxy, json!({"ev":"toast","error":true,"text":e}));
                        continue;
                    }
                };
                let (mut added, mut updated) = (0u32, 0u32);
                let mut failed: Option<String> = None;
                for p in &imported {
                    if let Err(e) = store.save_profile(p) {
                        failed = Some(e.to_string());
                        break;
                    }
                    let mut ps = profiles.lock().unwrap();
                    match ps.iter_mut().find(|x| x.id == p.id) {
                        Some(slot) => {
                            *slot = p.clone();
                            updated += 1;
                        }
                        None => {
                            ps.push(p.clone());
                            added += 1;
                        }
                    }
                }
                seed_stored_passwords(&stored_pw, &profiles.lock().unwrap());
                emit(&proxy, json!({"ev":"hosts","items":host_items(&profiles.lock().unwrap())}));
                match failed {
                    Some(e) => emit(&proxy, json!({"ev":"toast","error":true,
                        "text":format!("Импорт прерван: {e} (добавлено {added}, обновлено {updated})")})),
                    None => emit(&proxy, json!({"ev":"toast",
                        "text":format!("Импорт: добавлено {added}, обновлено {updated}")})),
                }
            }

            // Enable (`pin` set) or disable (`pin` null) config encryption.
            // While the store is still locked, the toggle re-asks for the PIN
            // instead — also the recovery path after a cancelled startup prompt.
            "config_pin" => {
                if store.config_encryption() == ConfigEncryption::Locked {
                    spawn_config_unlock(
                        web_prompter.clone(),
                        store.clone(),
                        profiles.clone(),
                        stored_pw.clone(),
                        proxy.clone(),
                    );
                } else {
                    let pin = msg.get("pin").and_then(|v| v.as_str());
                    match store.set_config_pin(pin) {
                        Ok(()) => emit(&proxy, json!({"ev":"toast","text": if pin.is_some() {
                            "Конфиг зашифрован"
                        } else {
                            "Шифрование конфига отключено"
                        }})),
                        Err(e) => emit(&proxy,
                            json!({"ev":"toast","error":true,"text":format!("Конфиг: {e}")})),
                    }
                }
                emit_config_state(&proxy, &*store);
            }

            "input" => {
                if let Some(data) = msg.get("data").and_then(|v| v.as_str()) {
                    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(data) {
                        if let Some(active) = sessions.lock().unwrap().get(&id) {
                            let _ = active.input_tx.try_send(ShellCmd::Input(bytes));
                        }
                    }
                }
            }

            "resize" => {
                let cols = msg.get("cols").and_then(|v| v.as_u64()).unwrap_or(DEFAULT_COLS as u64) as u16;
                let rows = msg.get("rows").and_then(|v| v.as_u64()).unwrap_or(DEFAULT_ROWS as u64) as u16;
                if let Some(active) = sessions.lock().unwrap().get(&id) {
                    let _ = active.input_tx.try_send(ShellCmd::Resize(PtySize::new(cols, rows)));
                }
            }

            "disconnect" => {
                let taken = sessions.lock().unwrap().remove(&id);
                if let Some(active) = taken {
                    active.read_abort.abort();
                    let mgr = manager.clone();
                    tokio::spawn(async move {
                        let _ = mgr.close(active.id).await;
                    });
                }
                // Tear down any port-forwards riding on this session.
                stop_forwards_for(&forwards, &id, &proxy);
            }

            "secret_reply" => {
                let sid = msg.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                let value = msg.get("value").and_then(|v| v.as_str()).map(|s| s.to_string());
                if let Some(tx) = pending.secrets.lock().unwrap().remove(&sid) {
                    let _ = tx.send(value);
                }
            }

            "hostkey_reply" => {
                let sid = msg.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                let accept = msg.get("accept").and_then(|v| v.as_bool()).unwrap_or(false);
                if let Some(tx) = pending.host_keys.lock().unwrap().remove(&sid) {
                    let _ = tx.send(accept);
                }
            }

            "copy" => {
                if let (Some(cb), Some(text)) =
                    (clipboard.as_mut(), msg.get("text").and_then(|v| v.as_str()))
                {
                    let _ = cb.set_text(text.to_string());
                }
            }

            "paste" => {
                if let Some(cb) = clipboard.as_mut() {
                    if let Ok(text) = cb.get_text() {
                        if !text.is_empty() {
                            if let Some(active) = sessions.lock().unwrap().get(&id) {
                                let _ = active.input_tx.try_send(ShellCmd::Input(text.into_bytes()));
                            }
                        }
                    }
                }
            }

            // ---- SFTP / transfers (operate on the session keyed by `id`) ----
            "sftp_list" => {
                let path = msg.get("path").and_then(|v| v.as_str()).unwrap_or(".").to_string();
                let conn = connection_for(&sessions, &manager, &id);
                if let Some(conn) = conn {
                    let (proxy, key) = (proxy.clone(), id.clone());
                    tokio::spawn(async move {
                        let p = if path.is_empty() { ".".into() } else { path };
                        let res = async {
                            let sftp = conn.open_sftp().await.map_err(|e| e.to_string())?;
                            let cwd = sftp.canonicalize(&p).await.unwrap_or_else(|_| p.clone());
                            let entries = sftp.list_dir(&p).await.map_err(|e| e.to_string())?;
                            Ok::<_, String>((cwd, entries))
                        }
                        .await;
                        match res {
                            Ok((cwd, mut entries)) => {
                                entries.sort_by(|a, b| {
                                    b.is_dir
                                        .cmp(&a.is_dir)
                                        .then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                                });
                                let items: Vec<_> = entries
                                    .iter()
                                    .filter(|e| e.name != ".")
                                    .map(|e| json!({"name":e.name,"dir":e.is_dir,"size":e.size}))
                                    .collect();
                                emit(&proxy, json!({"ev":"sftp","key":key,"path":cwd,"entries":items}));
                            }
                            Err(e) => emit(&proxy, json!({"ev":"sftp_err","key":key,"error":e})),
                        }
                    });
                }
            }

            "upload" => {
                let local =
                    expand_home(msg.get("local").and_then(|v| v.as_str()).unwrap_or("").trim());
                let remote = msg.get("remote").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let Some(profile) = sessions.lock().unwrap().get(&id).map(|a| a.profile.clone())
                else {
                    emit(&proxy, json!({"ev":"sftp_err","key":id,"error":"нет активного соединения"}));
                    continue;
                };
                if std::fs::metadata(&local).is_err() {
                    emit(&proxy, json!({"ev":"toast","error":true,
                        "text":format!("нет такого локального файла: {local}")}));
                    continue;
                }
                // Uploads go over a local rsync (directories, resume,
                // auto-retry); SFTP stays the single-file fallback.
                let fallback: Box<dyn FnOnce(String) + Send> = {
                    let (sessions, manager, proxy, transfers) =
                        (sessions.clone(), manager.clone(), proxy.clone(), transfers.clone());
                    let (key, local, remote) = (id.clone(), local.clone(), remote.clone());
                    Box::new(move |reason: String| {
                        if std::fs::metadata(&local).map(|m| m.is_dir()).unwrap_or(false) {
                            emit(&proxy, json!({"ev":"toast","error":true,
                                "text":format!("{reason} — папку можно отправить только по rsync")}));
                            return;
                        }
                        emit(&proxy, json!({"ev":"toast","error":false,
                            "text":format!("{reason} — отправка по SFTP (без докачки)")}));
                        start_transfer(&sessions, &manager, &proxy, &transfers, &key, "up", local, remote);
                    })
                };
                crate::rsync::spawn_upload(proxy.clone(), transfers.clone(), profile, local, remote, fallback);
            }

            "download" => {
                let remote = msg.get("remote").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let name = remote.rsplit('/').next().unwrap_or("file").to_string();
                // A "download" command can pin a destination folder; otherwise ~/Downloads.
                let dir = match msg.get("local_dir").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                    Some(d) => {
                        let expanded = expand_home(d);
                        let _ = std::fs::create_dir_all(&expanded);
                        expanded
                    }
                    None => download_dir(),
                };
                let Some(profile) = sessions.lock().unwrap().get(&id).map(|a| a.profile.clone())
                else {
                    emit(&proxy, json!({"ev":"sftp_err","key":id,"error":"нет активного соединения"}));
                    continue;
                };
                // Downloads go over a local rsync (resume + auto-retry); the
                // SFTP paths below remain the fallback when the rsync road is
                // closed (no rsync, external ssh can't authenticate...).
                // rsync expands globs remotely itself.
                let local = if is_glob(&remote) {
                    dir.clone()
                } else {
                    format!("{}/{name}", dir.trim_end_matches('/'))
                };
                let fallback: Box<dyn FnOnce(String) + Send> = {
                    let (sessions, manager, proxy, transfers) =
                        (sessions.clone(), manager.clone(), proxy.clone(), transfers.clone());
                    let (key, dir, local, remote) = (id.clone(), dir, local.clone(), remote.clone());
                    Box::new(move |reason: String| {
                        emit(&proxy, json!({"ev":"toast","error":false,
                            "text":format!("{reason} — скачивание по SFTP (без докачки)")}));
                        if is_glob(&remote) {
                            start_glob_download(&sessions, &manager, &proxy, &transfers, &key, dir, remote);
                        } else {
                            start_transfer(&sessions, &manager, &proxy, &transfers, &key, "down", local, remote);
                        }
                    })
                };
                crate::rsync::spawn_download(proxy.clone(), transfers.clone(), profile, remote, local, fallback);
            }

            "xfer_cancel" => {
                if let Some(c) = transfers.lock().unwrap().get(&id) {
                    c.cancel();
                }
            }

            // ---- saved quick commands ----
            "cmd_list" => emit(&proxy, json!({"ev":"commands","items":commands})),

            "cmd_save" => {
                if let Some(mut c) = msg.get("command").cloned() {
                    let cid = c
                        .get("id")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                    c["id"] = json!(cid);
                    match commands
                        .iter_mut()
                        .find(|x| x.get("id").and_then(|v| v.as_str()) == Some(cid.as_str()))
                    {
                        Some(slot) => *slot = c,
                        None => commands.push(c),
                    }
                    save_commands(&commands_path, &commands);
                    emit(&proxy, json!({"ev":"commands","items":commands}));
                }
            }

            "cmd_delete" => {
                commands.retain(|x| x.get("id").and_then(|v| v.as_str()) != Some(id.as_str()));
                save_commands(&commands_path, &commands);
                emit(&proxy, json!({"ev":"commands","items":commands}));
            }

            // ---- local port forwarding (`ssh -L`) ----
            "forward_list" => {
                let items = forwards_json(&forwards.lock().unwrap());
                emit(&proxy, json!({"ev":"forwards","items":items}));
            }

            "forward_start" => {
                // `id` is the session key the forward rides on.
                let session_key = id.clone();
                let local_port = msg.get("local_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                let remote_host = msg
                    .get("remote_host")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("127.0.0.1")
                    .to_string();
                let remote_port = msg.get("remote_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;

                if remote_port == 0 {
                    emit(&proxy, json!({"ev":"toast","error":true,"text":"Укажите удалённый порт"}));
                    continue;
                }
                let (conn, label) = {
                    let s = sessions.lock().unwrap();
                    match s.get(&session_key) {
                        Some(a) => (manager.connection(a.id), a.title.clone()),
                        None => (None, String::new()),
                    }
                };
                let Some(conn) = conn else {
                    emit(&proxy, json!({"ev":"toast","error":true,
                        "text":"Нет активного соединения — подключитесь к хосту"}));
                    continue;
                };
                let (proxy2, forwards2, sessions2) = (proxy.clone(), forwards.clone(), sessions.clone());
                tokio::spawn(async move {
                    match conn
                        .forward_local("127.0.0.1", local_port, &remote_host, remote_port)
                        .await
                    {
                        Ok(pf) => {
                            let bound = pf.local_port();
                            let fid = uuid::Uuid::new_v4().to_string();
                            // The session may have been torn down while we were
                            // binding. Check membership *under the forwards lock*
                            // (disconnect removes from `sessions` before it locks
                            // `forwards`), so we never leave an orphaned forward.
                            let items = {
                                let mut fw = forwards2.lock().unwrap();
                                if !sessions2.lock().unwrap().contains_key(&session_key) {
                                    drop(fw);
                                    // `pf` drops here → listener + tunnels torn down.
                                    return;
                                }
                                fw.insert(
                                    fid,
                                    ActiveForward {
                                        pf,
                                        kind: "local",
                                        session_key,
                                        local_port: bound,
                                        remote_host: remote_host.clone(),
                                        remote_port,
                                        label,
                                    },
                                );
                                forwards_json(&fw)
                            };
                            emit(&proxy2, json!({"ev":"forwards","items":items}));
                            emit(&proxy2, json!({"ev":"toast",
                                "text": format!("Проброс запущен: localhost:{bound} → {remote_host}:{remote_port}")}));
                        }
                        Err(e) => emit(&proxy2, json!({"ev":"toast","error":true,
                            "text": format!("Проброс не удался: {e}")})),
                    }
                });
            }

            "socks_start" => {
                // `id` is the session key the SOCKS proxy rides on.
                let session_key = id.clone();
                let local_port = msg.get("local_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                let (conn, label) = {
                    let s = sessions.lock().unwrap();
                    match s.get(&session_key) {
                        Some(a) => (manager.connection(a.id), a.title.clone()),
                        None => (None, String::new()),
                    }
                };
                let Some(conn) = conn else {
                    emit(&proxy, json!({"ev":"toast","error":true,
                        "text":"Нет активного соединения — подключитесь к хосту"}));
                    continue;
                };
                let (proxy2, forwards2, sessions2) = (proxy.clone(), forwards.clone(), sessions.clone());
                tokio::spawn(async move {
                    match conn.forward_socks("127.0.0.1", local_port).await {
                        Ok(pf) => {
                            let bound = pf.local_port();
                            let fid = uuid::Uuid::new_v4().to_string();
                            let items = {
                                let mut fw = forwards2.lock().unwrap();
                                if !sessions2.lock().unwrap().contains_key(&session_key) {
                                    drop(fw);
                                    return;
                                }
                                fw.insert(
                                    fid,
                                    ActiveForward {
                                        pf,
                                        kind: "socks",
                                        session_key,
                                        local_port: bound,
                                        remote_host: String::new(),
                                        remote_port: 0,
                                        label,
                                    },
                                );
                                forwards_json(&fw)
                            };
                            emit(&proxy2, json!({"ev":"forwards","items":items}));
                            emit(&proxy2, json!({"ev":"toast",
                                "text": format!("SOCKS-прокси запущен: socks5://127.0.0.1:{bound}")}));
                        }
                        Err(e) => emit(&proxy2, json!({"ev":"toast","error":true,
                            "text": format!("SOCKS-прокси не удался: {e}")})),
                    }
                });
            }

            "desktop_start" => {
                // `id` is the session key. One remote probe picks the road:
                // X11 -> x11vnc shadow (as before), GNOME on Wayland -> RDP
                // (gnome-remote-desktop), wlroots -> wayvnc. A missing tool is
                // offered for installation instead of a dead-end error.
                let session_key = id.clone();
                // Empty = auto-detect on the remote. Sanitised so it is safe to
                // splice into the shell command below.
                let display: String = msg
                    .get("display")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || ":._-".contains(*c))
                    .collect();
                let (conn, label) = {
                    let s = sessions.lock().unwrap();
                    match s.get(&session_key) {
                        Some(a) => (manager.connection(a.id), a.title.clone()),
                        None => (None, String::new()),
                    }
                };
                let Some(conn) = conn else {
                    emit(&proxy, json!({"ev":"toast","error":true,
                        "text":"Нет активного соединения — подключитесь к хосту"}));
                    continue;
                };
                let (proxy2, forwards2, sessions2) = (proxy.clone(), forwards.clone(), sessions.clone());
                tokio::spawn(async move {
                    let det = exec_collect(&conn, DESKTOP_DETECT_CMD).await.unwrap_or_default();
                    let has = |k: &str| det.lines().any(|l| l.trim() == k);
                    let missing = |tool: &str| {
                        emit(&proxy2, json!({"ev":"desktop_setup","key":session_key,
                            "kind":"missing","tool":tool}));
                    };
                    if has("TYPE=X11") {
                        if !has("X11VNC=OK") {
                            return missing("x11vnc");
                        }
                        vnc_desktop_flow(conn, proxy2, forwards2, sessions2, session_key,
                                         label, remote_x11vnc_cmd(&display)).await;
                    } else if has("TYPE=GNOME_WAYLAND") {
                        // Sharing counts as up only when grd's listener is
                        // found — "enabled" with a dead daemon must go through
                        // the enable dialog (its restart brings the port back).
                        if has("RDP=ON") && det.contains("RDP_PORT=") {
                            let port = rdp_port_of(&det);
                            rdp_connect_flow(conn, proxy2, forwards2, sessions2, session_key, label, port).await;
                        } else {
                            emit(&proxy2, json!({"ev":"desktop_setup","key":session_key,
                                "kind":"gnome_rdp"}));
                        }
                    } else if has("TYPE=WLROOTS") {
                        if !has("WAYVNC=OK") {
                            return missing("wayvnc");
                        }
                        vnc_desktop_flow(conn, proxy2, forwards2, sessions2, session_key,
                                         label, remote_wayvnc_cmd()).await;
                    } else if has("TYPE=WAYLAND_OTHER") {
                        emit(&proxy2, json!({"ev":"toast","error":true,
                            "text":"Wayland-композитор хоста не поддержан (умею GNOME и wlroots)"}));
                    } else {
                        emit(&proxy2, json!({"ev":"toast","error":true,
                            "text":"На хосте не найдено графической сессии (X11/Wayland)"}));
                    }
                });
            }

            // Enable gnome-remote-desktop's RDP on the host (its GNOME/Wayland
            // desktop is shared over RDP, not VNC), then connect to it.
            "desktop_rdp_enable" => {
                let session_key = id.clone();
                let user = msg.get("user").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let pass = msg.get("pass").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if user.is_empty() || pass.is_empty() {
                    emit(&proxy, json!({"ev":"toast","error":true,
                        "text":"Укажите логин и пароль для RDP"}));
                    continue;
                }
                let (conn, label) = {
                    let s = sessions.lock().unwrap();
                    match s.get(&session_key) {
                        Some(a) => (manager.connection(a.id), a.title.clone()),
                        None => (None, String::new()),
                    }
                };
                let Some(conn) = conn else {
                    emit(&proxy, json!({"ev":"toast","error":true,
                        "text":"Нет активного соединения — подключитесь к хосту"}));
                    continue;
                };
                let (proxy2, forwards2, sessions2) = (proxy.clone(), forwards.clone(), sessions.clone());
                tokio::spawn(async move {
                    let q = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
                    let cmd = format!(
                        r#"export XDG_RUNTIME_DIR=${{XDG_RUNTIME_DIR:-/run/user/$(id -u)}}
export DBUS_SESSION_BUS_ADDRESS=${{DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}}
if grdctl status 2>/dev/null | grep -q 'TLS certificate: *$'; then
  D="$HOME/.local/share/gnome-remote-desktop"; mkdir -p "$D"
  openssl req -x509 -newkey rsa:2048 -keyout "$D/tls.key" -out "$D/tls.crt" \
    -days 3650 -nodes -subj /CN=hopterm >/dev/null 2>&1
  grdctl rdp set-tls-cert "$D/tls.crt" && grdctl rdp set-tls-key "$D/tls.key"
fi
grdctl rdp enable && grdctl rdp set-credentials {u} {p} && grdctl rdp disable-view-only \
  && systemctl --user restart gnome-remote-desktop
for i in 1 2 3 4 5 6 7 8; do
  P=$(LC_ALL=C ss -ltnp 2>/dev/null | sed -n 's/.*:\([0-9][0-9]*\) .*gnome-remote.*/\1/p' | head -1)
  [ -n "$P" ] && echo RDP_UP && echo "RDP_PORT=$P" && exit 0
  sleep 1
done
echo RDP_FAIL
journalctl --user -u gnome-remote-desktop -n 5 --no-pager 2>/dev/null"#,
                        u = q(&user),
                        p = q(&pass),
                    );
                    match exec_collect(&conn, &cmd).await {
                        Ok(out) if out.contains("RDP_UP") => {
                            emit(&proxy2, json!({"ev":"toast",
                                "text":"gnome-remote-desktop включён — подключаюсь"}));
                            let port = rdp_port_of(&out);
                            rdp_connect_flow(conn, proxy2, forwards2, sessions2, session_key, label, port).await;
                        }
                        Ok(out) => emit(&proxy2, json!({"ev":"toast","error":true,
                            "text":format!("RDP не поднялся: {}", last_lines(&out, 3))})),
                        Err(e) => emit(&proxy2, json!({"ev":"toast","error":true,
                            "text":format!("grdctl: {e}")})),
                    }
                });
            }

            // Run a single GUI app off the host through waypipe — its window
            // renders on the local Wayland compositor.
            "app_start" => {
                let session_key = id.clone();
                let app = msg.get("command").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
                if app.is_empty() {
                    emit(&proxy, json!({"ev":"toast","error":true,
                        "text":"Укажите команду приложения (напр. gnome-calculator)"}));
                    continue;
                }
                let pc = {
                    let s = sessions.lock().unwrap();
                    s.get(&session_key).map(|a| (a.profile.clone(), manager.connection(a.id)))
                };
                let Some((profile, Some(conn))) = pc else {
                    emit(&proxy, json!({"ev":"toast","error":true,
                        "text":"Нет активного соединения — подключитесь к хосту"}));
                    continue;
                };
                if std::env::var("WAYLAND_DISPLAY").is_err() {
                    emit(&proxy, json!({"ev":"toast","error":true,
                        "text":"Локальная сессия не Wayland — waypipe здесь не работает"}));
                    continue;
                }
                if !local_tool_exists("waypipe") {
                    emit(&proxy, json!({"ev":"toast","error":true,
                        "text":"На этой машине нет waypipe — sudo apt install waypipe"}));
                    continue;
                }
                let proxy2 = proxy.clone();
                tokio::spawn(async move {
                    match exec_collect(&conn, "command -v waypipe >/dev/null 2>&1 && echo WP_OK || echo WP_MISSING").await {
                        Ok(o) if o.contains("WP_OK") => {}
                        Ok(_) => {
                            emit(&proxy2, json!({"ev":"desktop_setup","key":session_key,
                                "kind":"missing","tool":"waypipe"}));
                            return;
                        }
                        Err(e) => {
                            emit(&proxy2, json!({"ev":"toast","error":true,
                                "text":format!("проверка waypipe: {e}")}));
                            return;
                        }
                    }
                    match spawn_waypipe_app(&profile, &app, proxy2.clone()) {
                        Ok(()) => emit(&proxy2, json!({"ev":"toast",
                            "text":format!("Запускаю через waypipe: {app} — окно появится через несколько секунд")})),
                        Err(e) => emit(&proxy2, json!({"ev":"toast","error":true,
                            "text":format!("waypipe: {e}")})),
                    }
                });
            }

            "forward_stop" => {
                // `id` is the forward id.
                let items = {
                    let mut fw = forwards.lock().unwrap();
                    if let Some(f) = fw.remove(&id) {
                        f.pf.stop();
                    }
                    forwards_json(&fw)
                };
                emit(&proxy, json!({"ev":"forwards","items":items}));
            }

            _ => {}
        }
    }
}

/// Resolve the live SSH connection behind a session key.
fn connection_for(
    sessions: &Sessions,
    manager: &SessionManager,
    key: &str,
) -> Option<Arc<dyn SshConnection>> {
    let sid = sessions.lock().unwrap().get(key).map(|a| a.id)?;
    manager.connection(sid)
}

/// Does this remote path carry a shell-style wildcard the SFTP server won't expand?
fn is_glob(s: &str) -> bool {
    s.contains('*') || s.contains('?')
}

/// fnmatch-style match for `*` (any run) and `?` (one char). Enough for the file
/// patterns a download command builds; ranges (`[...]`) are not supported.
fn glob_match(pattern: &str, name: &str) -> bool {
    fn rec(p: &[char], n: &[char]) -> bool {
        match p.first() {
            None => n.is_empty(),
            Some('*') => rec(&p[1..], n) || (!n.is_empty() && rec(p, &n[1..])),
            Some('?') => !n.is_empty() && rec(&p[1..], &n[1..]),
            Some(&c) => !n.is_empty() && n[0] == c && rec(&p[1..], &n[1..]),
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    rec(&p, &n)
}

/// A synchronous `Read` fed by the async exec pump over a bounded channel, so the
/// blocking gzip+tar extractor can pull archive bytes as they stream in.
struct ChanReader {
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}
impl std::io::Read for ChanReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.pos >= self.buf.len() {
            match self.rx.blocking_recv() {
                Some(chunk) => {
                    self.buf = chunk;
                    self.pos = 0;
                }
                None => return Ok(0), // sender dropped → end of archive
            }
        }
        let n = std::cmp::min(out.len(), self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Expand a wildcard remote path, `tar czf -` the matched files on the host, and
/// stream the gzip archive through a single channel that is gunzip+untarred into
/// `local_dir` on the fly — one combined transfer with one progress bar.
#[allow(clippy::too_many_arguments)]
fn start_glob_download(
    sessions: &Sessions,
    manager: &SessionManager,
    proxy: &EventLoopProxy<UserEvent>,
    transfers: &Arc<Mutex<HashMap<String, CancelToken>>>,
    key: &str,
    local_dir: String,
    remote_pattern: String,
) {
    let Some(conn) = connection_for(sessions, manager, key) else {
        emit(proxy, json!({"ev":"sftp_err","key":key,"error":"нет активного соединения"}));
        return;
    };
    let (parent, pat) = match remote_pattern.rsplit_once('/') {
        Some(("", f)) => ("/".to_string(), f.to_string()),
        Some((p, f)) => (p.to_string(), f.to_string()),
        None => (".".to_string(), remote_pattern.clone()),
    };
    let (proxy, transfers, key) = (proxy.clone(), transfers.clone(), key.to_string());
    tokio::spawn(async move {
        // 1) list the directory over SFTP and match the pattern.
        let entries = match conn.open_sftp().await {
            Ok(sftp) => match sftp.list_dir(&parent).await {
                Ok(es) => es,
                Err(e) => { emit(&proxy, json!({"ev":"sftp_err","key":key,"error":format!("{parent}: {e}")})); return; }
            },
            Err(e) => { emit(&proxy, json!({"ev":"sftp_err","key":key,"error":e.to_string()})); return; }
        };
        let matched: Vec<RemoteEntry> = entries
            .into_iter()
            .filter(|e| !e.is_dir && glob_match(&pat, &e.name))
            .collect();
        if matched.is_empty() {
            emit(&proxy, json!({"ev":"sftp_err","key":key,"error":format!("по маске «{pat}» в {parent} ничего не найдено")}));
            return;
        }
        let total: u64 = matched.iter().map(|e| e.size).sum();
        let parent_base = parent.rsplit('/').find(|s| !s.is_empty()).unwrap_or(&parent);
        let job_name = format!("{parent_base}/{pat} — {} файл(ов)", matched.len());

        // 2) build the remote archive command (shell-quoted names).
        let _ = std::fs::create_dir_all(&local_dir);
        let q = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
        let files = matched.iter().map(|e| q(&e.name)).collect::<Vec<_>>().join(" ");
        let cmd = format!("tar czf - -C {} -- {}", q(&parent), files);

        // 3) one combined transfer job.
        let job = uuid::Uuid::new_v4().to_string();
        let cancel = CancelToken::new();
        transfers.lock().unwrap().insert(job.clone(), cancel.clone());
        emit(&proxy, json!({"ev":"xfer","id":job,"name":job_name,"dir":"down","t":0,"total":total,"status":"running"}));

        let mut stream = match conn.exec_stream(&cmd).await {
            Ok(s) => s,
            Err(e) => {
                transfers.lock().unwrap().remove(&job);
                emit(&proxy, json!({"ev":"xfer","id":job,"name":job_name,"dir":"down","status":"error","error":e.to_string()}));
                return;
            }
        };

        // 4) blocking gunzip+untar extractor, pulling archive bytes from a channel.
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        let (dest, p2, job2, name2, cancel2) =
            (local_dir.clone(), proxy.clone(), job.clone(), job_name.clone(), cancel.clone());
        let extract = tokio::task::spawn_blocking(move || -> Result<(), String> {
            let gz = flate2::read::GzDecoder::new(ChanReader { rx, buf: Vec::new(), pos: 0 });
            let mut archive = tar::Archive::new(gz);
            let mut done = 0u64;
            let mut last = 0u64;
            let step = (total / 100).max(64 * 1024);
            for entry in archive.entries().map_err(|e| e.to_string())? {
                if cancel2.is_cancelled() {
                    return Err("отменено".into());
                }
                let mut e = entry.map_err(|e| e.to_string())?;
                let sz = e.header().size().unwrap_or(0);
                e.unpack_in(&dest).map_err(|e| e.to_string())?;
                done += sz;
                if done - last >= step || done >= total {
                    last = done;
                    emit(&p2, json!({"ev":"xfer","id":job2,"name":name2,"dir":"down","t":done,"total":total,"status":"running"}));
                }
            }
            Ok(())
        });

        // 5) pump the archive stream into the extractor (backpressured by the channel).
        let mut pump_err = None;
        loop {
            if cancel.is_cancelled() {
                break;
            }
            match stream.next_chunk().await {
                Ok(Some(chunk)) => {
                    if tx.send(chunk).await.is_err() {
                        break; // extractor ended (likely an error)
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    pump_err = Some(e.to_string());
                    break;
                }
            }
        }
        drop(tx); // signal end-of-archive
        let extract_res = extract.await;
        transfers.lock().unwrap().remove(&job);

        let result = match (pump_err, extract_res) {
            (Some(e), _) => Err(e),
            (None, Ok(Ok(()))) => Ok(()),
            (None, Ok(Err(e))) => Err(e),
            (None, Err(join)) => Err(join.to_string()),
        };
        match result {
            Ok(()) => emit(&proxy, json!({"ev":"xfer","id":job,"name":job_name,"dir":"down","t":total,"total":total,"status":"done","local":local_dir})),
            Err(e) => {
                let msg = if cancel.is_cancelled() { format!("отменено: {e}") } else { e };
                emit(&proxy, json!({"ev":"xfer","id":job,"name":job_name,"dir":"down","status":"error","error":msg}));
            }
        }
    });
}

/// Spawn an SFTP upload/download job, streaming progress to the UI.
#[allow(clippy::too_many_arguments)]
fn start_transfer(
    sessions: &Sessions,
    manager: &SessionManager,
    proxy: &EventLoopProxy<UserEvent>,
    transfers: &Arc<Mutex<HashMap<String, CancelToken>>>,
    key: &str,
    dir: &'static str,
    local: String,
    remote: String,
) {
    let Some(conn) = connection_for(sessions, manager, key) else {
        emit(proxy, json!({"ev":"sftp_err","key":key,"error":"нет активного соединения"}));
        return;
    };
    let job = uuid::Uuid::new_v4().to_string();
    let name = if dir == "up" { &local } else { &remote }
        .rsplit('/')
        .next()
        .unwrap_or("file")
        .to_string();
    let cancel = CancelToken::new();
    transfers.lock().unwrap().insert(job.clone(), cancel.clone());
    let (proxy, transfers) = (proxy.clone(), transfers.clone());
    tokio::spawn(async move {
        emit(&proxy, json!({"ev":"xfer","id":job,"name":name,"dir":dir,"t":0,"total":0,"status":"running"}));
        let progress = XferProgress {
            proxy: proxy.clone(),
            job: job.clone(),
            name: name.clone(),
            dir,
            last: Arc::new(AtomicU64::new(0)),
        };
        let res = async {
            let sftp = conn.open_sftp().await.map_err(|e| e.to_string())?;
            if dir == "up" {
                sftp.upload(&local, &remote, &progress, &cancel).await
            } else {
                sftp.download(&remote, &local, &progress, &cancel).await
            }
            .map_err(|e| e.to_string())
        }
        .await;
        transfers.lock().unwrap().remove(&job);
        match res {
            Ok(()) => emit(&proxy, json!({"ev":"xfer","id":job,"name":name,"dir":dir,"status":"done","local":local})),
            Err(e) => emit(&proxy, json!({"ev":"xfer","id":job,"name":name,"dir":dir,"status":"error","error":e})),
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn spawn_connect(
    profile: SessionProfile,
    manager: SessionManager,
    proxy: EventLoopProxy<UserEvent>,
    sessions: Sessions,
    sudo: bool,
    key: String,
    forwards: Forwards,
) {
    let pid = key; // session key (profile id, or profile id + "#sudo")
    tokio::spawn(async move {
        let observer = JsObserver { proxy: proxy.clone(), id: pid.clone() };
        let id = match manager.connect(&profile, &observer).await {
            Ok(id) => id,
            Err(e) => {
                emit(&proxy, json!({"ev":"state","id":pid,"text":format!("ошибка: {e}"),"live":false}));
                return;
            }
        };
        let shell = match manager.open_shell(id, PtySize::new(DEFAULT_COLS, DEFAULT_ROWS)).await {
            Ok(s) => s,
            Err(e) => {
                emit(&proxy, json!({"ev":"state","id":pid,"text":format!("ошибка shell: {e}"),"live":false}));
                let _ = manager.close(id).await;
                return;
            }
        };

        let (input_tx, input_rx) = mpsc::channel::<ShellCmd>(64);
        let handle = tokio::spawn(shell_pump(
            shell,
            input_rx,
            proxy.clone(),
            pid.clone(),
            sessions.clone(),
            forwards.clone(),
        ));

        // "Подключиться с sudo": after the shell is up, type the escalation
        // command and feed the sudo password to its prompt (if set).
        if sudo {
            if let Some(cmd) = profile.sudo.command.clone() {
                let tx = input_tx.clone();
                let pw = profile.sudo.password.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    let _ = tx.send(ShellCmd::Input(format!("{cmd}\n").into_bytes())).await;
                    if let Some(pw) = pw {
                        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
                        let _ = tx.send(ShellCmd::Input(format!("{pw}\n").into_bytes())).await;
                    }
                });
            }
        }

        let route = profile.route.breadcrumb();
        sessions.lock().unwrap().insert(
            pid.clone(),
            Active {
                id,
                input_tx,
                read_abort: handle.abort_handle(),
                title: profile.display_name.clone(),
                route: route.clone(),
                profile: profile.clone(),
            },
        );
        emit(
            &proxy,
            json!({"ev":"connected","id":pid,"title":profile.display_name,"route":route}),
        );
    });
}

async fn shell_pump(
    mut shell: Box<dyn ShellChannel>,
    mut input_rx: mpsc::Receiver<ShellCmd>,
    proxy: EventLoopProxy<UserEvent>,
    pid: String,
    sessions: Sessions,
    forwards: Forwards,
) {
    loop {
        tokio::select! {
            r = shell.read_output() => match r {
                Ok(Some(bytes)) if !bytes.is_empty() => {
                    emit(&proxy, json!({"ev":"output","id":pid,"data":b64(&bytes)}));
                }
                Ok(Some(_)) => {}
                _ => {
                    sessions.lock().unwrap().remove(&pid);
                    // The connection is gone → any forwards on it are dead too.
                    stop_forwards_for(&forwards, &pid, &proxy);
                    emit(&proxy, json!({"ev":"closed","id":pid}));
                    break;
                }
            },
            cmd = input_rx.recv() => match cmd {
                Some(ShellCmd::Input(b)) => { let _ = shell.write_input(&b).await; }
                Some(ShellCmd::Resize(s)) => { let _ = shell.resize(s).await; }
                None => break,
            }
        }
    }
}

/// Tell the UI whether the config is encrypted (settings toggle state).
fn emit_config_state(proxy: &EventLoopProxy<UserEvent>, store: &dyn ProfileStore) {
    let encrypted = store.config_encryption() != ConfigEncryption::Plain;
    emit(proxy, json!({"ev":"config","encrypted":encrypted}));
}

/// Ask for the config PIN (repeating on a wrong one) until the store unlocks,
/// then publish the real profile list.
fn spawn_config_unlock(
    prompter: Arc<WebPrompter>,
    store: Arc<dyn ProfileStore>,
    profiles: Arc<Mutex<Vec<SessionProfile>>>,
    stored_pw: Arc<Mutex<HashMap<String, String>>>,
    proxy: EventLoopProxy<UserEvent>,
) {
    tokio::spawn(async move {
        let mut prompt = "PIN для расшифровки конфига".to_string();
        loop {
            let Some(pin) = prompter.ask(prompt).await else {
                emit(&proxy, json!({"ev":"toast","error":true,
                    "text":"Конфиг зашифрован — профили не загружены. \
                            Ввести PIN: тумблер шифрования в Настройках"}));
                return;
            };
            match store.unlock_config(&pin) {
                Ok(true) => break,
                Ok(false) => prompt = "Неверный PIN — попробуйте ещё раз".into(),
                Err(e) => {
                    emit(&proxy, json!({"ev":"toast","error":true,"text":format!("Конфиг: {e}")}));
                    return;
                }
            }
        }
        let loaded = store.load_profiles().unwrap_or_default();
        seed_stored_passwords(&stored_pw, &loaded);
        *profiles.lock().unwrap() = loaded;
        emit(&proxy, json!({"ev":"hosts","items":host_items(&profiles.lock().unwrap())}));
    });
}

/// Rebuild the HostId -> password map from the current profiles, so connect-time
/// auth uses the configured password without a prompt. Called on load and after
/// every profile mutation (ids are regenerated on save).
fn seed_stored_passwords(map: &Mutex<HashMap<String, String>>, profiles: &[SessionProfile]) {
    let mut m = map.lock().unwrap();
    m.clear();
    for p in profiles {
        for node in p.route.hops.iter().chain(std::iter::once(p.target())) {
            if matches!(node.auth_method, AuthMethod::Password) {
                if let Some(pw) = node.password.as_ref().filter(|s| !s.is_empty()) {
                    m.insert(node.id.to_string(), pw.clone());
                }
            }
        }
    }
}

/// Fill in requested key copies (`key_data == Some("")` markers from the
/// editor): read the key file, or keep the copy the old profile already had —
/// the file on disk may be long gone, that is the feature's point.
fn vault_keys(profile: &mut SessionProfile, old: Option<&SessionProfile>) -> Result<(), String> {
    let old_nodes: Vec<&HostProfile> =
        old.map(|p| p.route.nodes()).unwrap_or_default();
    let mut nodes: Vec<&mut HostProfile> = profile.route.hops.iter_mut().collect();
    nodes.push(&mut profile.route.target);
    for node in nodes {
        let AuthMethod::PublicKey { key_path, key_data, .. } = &mut node.auth_method else {
            continue;
        };
        if key_data.as_deref() != Some("") {
            continue;
        }
        let path = expand_home(key_path);
        match std::fs::read_to_string(&path) {
            Ok(pem) => *key_data = Some(pem),
            Err(read_err) => {
                let carried = old_nodes.iter().find_map(|o| match &o.auth_method {
                    AuthMethod::PublicKey { key_path: kp, key_data: Some(d), .. }
                        if kp == key_path && !d.is_empty() =>
                    {
                        Some(d.clone())
                    }
                    _ => None,
                });
                match carried {
                    Some(d) => *key_data = Some(d),
                    None => return Err(format!("ключ не прочитан: {path}: {read_err}")),
                }
            }
        }
    }
    Ok(())
}

/// The selected profile ids plus every profile they hop-reference,
/// transitively — an exported subset must carry its dependencies.
fn ref_closure(
    selected: impl Iterator<Item = ProfileId>,
    all: &[SessionProfile],
) -> std::collections::HashSet<ProfileId> {
    let mut keep: std::collections::HashSet<ProfileId> = selected.collect();
    loop {
        let missing: Vec<ProfileId> = all
            .iter()
            .filter(|p| keep.contains(&p.id))
            .flat_map(|p| p.route.hops.iter().filter_map(|h| h.hop_ref))
            .filter(|r| !keep.contains(r))
            .collect();
        if missing.is_empty() {
            return keep;
        }
        keep.extend(missing);
    }
}

/// Materialize a profile's route: every reference hop is replaced by the
/// referenced profile's resolved chain (its hops, then its target), so the
/// transport, ssh argv and password seeding see only concrete nodes.
fn resolve_profile(profile: &SessionProfile, all: &[SessionProfile]) -> Result<SessionProfile, String> {
    let mut hops = Vec::new();
    let mut path = vec![profile.id];
    for hop in &profile.route.hops {
        expand_hop(hop, all, &mut path, &mut hops)?;
    }
    let mut resolved = profile.clone();
    resolved.route.hops = hops;
    Ok(resolved)
}

/// `path` is the chain of profiles currently being expanded — a reference back
/// into it means an infinite chain, not a valid route.
fn expand_hop(
    hop: &HostProfile,
    all: &[SessionProfile],
    path: &mut Vec<ProfileId>,
    out: &mut Vec<HostProfile>,
) -> Result<(), String> {
    let Some(rid) = hop.hop_ref else {
        out.push(hop.clone());
        return Ok(());
    };
    let Some(referenced) = all.iter().find(|p| p.id == rid) else {
        return Err("хоп ссылается на удалённый хост".into());
    };
    if path.contains(&rid) {
        return Err(format!("цикл ссылок хопов через «{}»", referenced.display_name));
    }
    path.push(rid);
    for h in &referenced.route.hops {
        expand_hop(h, all, path, out)?;
    }
    out.push(referenced.route.target.clone());
    path.pop();
    Ok(())
}

fn node_json(h: &HostProfile) -> Value {
    if let Some(rid) = h.hop_ref {
        return json!({"ref": rid.to_string()});
    }
    let (auth, key, key_stored) = match &h.auth_method {
        AuthMethod::Password => ("password", String::new(), false),
        AuthMethod::Agent => ("agent", String::new(), false),
        AuthMethod::PublicKey { key_path, key_data, .. } => {
            ("key", key_path.clone(), key_data.is_some())
        }
    };
    json!({"user": h.username, "host": h.address, "port": h.port, "auth": auth, "key": key,
           "key_stored": key_stored, "password": h.password.clone().unwrap_or_default()})
}

fn host_items(profiles: &[SessionProfile]) -> Value {
    Value::Array(
        profiles
            .iter()
            .map(|p| {
                // Badge and breadcrumb show the materialized route; a broken
                // reference falls back to the stored one (connect surfaces
                // the error). `jumps` stays as stored — it feeds the editor.
                let resolved = resolve_profile(p, profiles).unwrap_or_else(|_| p.clone());
                json!({
                    "id": p.id.to_string(),
                    "name": p.display_name,
                    "endpoint": p.target().endpoint(),
                    "hops": resolved.route.hops.len(),
                    "auth": p.target().auth_method.label(),
                    "route": resolved.route.breadcrumb(),
                    "tags": p.tags,
                    "sudo_command": p.sudo.command,
                    "sudo_password": p.sudo.password,
                    "jumps": p.route.hops.iter().map(node_json).collect::<Vec<_>>(),
                    "target": node_json(p.target()),
                })
            })
            .collect(),
    )
}

/// Build a [`HostProfile`] node from a `{user,host,port,auth,key}` JSON object.
/// A `{ref: <profile-id>}` object becomes a reference hop (see `hop_ref`).
fn node_from_json(v: &Value) -> HostProfile {
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let hop_ref = v
        .get("ref")
        .and_then(|x| x.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .map(ProfileId::new);
    let host = s("host");
    let auth = match v.get("auth").and_then(|x| x.as_str()).unwrap_or("agent") {
        "password" => AuthMethod::Password,
        "key" => AuthMethod::PublicKey {
            key_path: {
                let k = s("key");
                if k.is_empty() { "~/.ssh/id_ed25519".into() } else { k }
            },
            passphrase_protected: false,
            // `Some("")` is a marker "copy requested": save_host replaces it
            // with the key file's content (or the previously stored copy).
            key_data: v
                .get("key_store")
                .and_then(|x| x.as_bool())
                .unwrap_or(false)
                .then(String::new),
        },
        _ => AuthMethod::Agent,
    };
    let user = {
        let u = s("user");
        if u.is_empty() { "root".into() } else { u }
    };
    // Only keep a stored password for password auth; clear it when switching to
    // key/agent so a stale secret never lingers in the profile.
    let password = match auth {
        AuthMethod::Password => {
            let p = s("password");
            if p.is_empty() { None } else { Some(p) }
        }
        _ => None,
    };
    HostProfile {
        id: HostId::new(uuid::Uuid::new_v4()),
        name: host.clone(),
        address: host,
        port: v.get("port").and_then(|x| x.as_u64()).unwrap_or(22) as u16,
        username: user,
        auth_method: auth,
        password,
        tags: vec![],
        color: None,
        icon: None,
        hop_ref,
    }
}

/// Build a [`SessionProfile`] from the modal's `{id?,name,jumps[],target}` JSON.
fn profile_from_json(host: &Value) -> SessionProfile {
    let id = host
        .get("id")
        .and_then(|x| x.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .map(ProfileId::new)
        .unwrap_or_else(|| ProfileId::new(uuid::Uuid::new_v4()));
    let jumps = host
        .get("jumps")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter(|j| {
                    !j.get("host").and_then(|h| h.as_str()).unwrap_or("").is_empty()
                        || j.get("ref").and_then(|r| r.as_str()).is_some()
                })
                .map(node_from_json)
                .collect()
        })
        .unwrap_or_default();
    let target = node_from_json(host.get("target").unwrap_or(&Value::Null));
    let tags = host
        .get("tags")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|t| t.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let nz = |k: &str| {
        host.get(k)
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
    };
    let sudo = SudoConfig {
        command: nz("sudo_command"),
        password: nz("sudo_password"),
    };
    SessionProfile {
        id,
        display_name: host
            .get("name")
            .and_then(|x| x.as_str())
            .unwrap_or("host")
            .to_string(),
        route: Route {
            hops: jumps,
            target,
            policy: RoutePolicy::DirectTcpIp,
        },
        terminal_preferences: TerminalPreferences::default(),
        transfer_preferences: TransferPreferences::default(),
        tags,
        sudo,
        color: None,
        icon: None,
    }
}

/// Build the `ssh` argv (leading "ssh" included) that reproduces this profile's
/// hop chain for an external terminal. Jump hosts collapse into one
/// `-J user@host:port,…` (ProxyJump); the target carries its own port and key.
/// Stored passwords aren't placed on the command line (they'd leak into `ps`);
/// [`open_in_external_terminal`] injects them via an `SSH_ASKPASS` helper.
/// The profile's chain as external-ssh arguments. The second value lists
/// transient secret files backing the argv (a key vaulted in the config is
/// materialized as a 0600 file — external ssh reads keys only from disk);
/// the caller removes them once ssh no longer needs them.
pub(crate) fn build_ssh_argv(profile: &SessionProfile) -> (Vec<String>, Vec<std::path::PathBuf>) {
    let mut argv = vec!["ssh".to_string()];
    let mut temp_keys = Vec::new();
    let hops = &profile.route.hops;
    if !hops.is_empty() {
        let chain = hops
            .iter()
            .map(|h| format!("{}@{}:{}", h.username, h.address, h.port))
            .collect::<Vec<_>>()
            .join(",");
        argv.push("-J".into());
        argv.push(chain);
    }
    let target = profile.target();
    if target.port != 22 {
        argv.push("-p".into());
        argv.push(target.port.to_string());
    }
    if let AuthMethod::PublicKey { key_path, key_data, .. } = &target.auth_method {
        let identity = match key_data {
            Some(pem) => write_transient_key(pem)
                .map(|p| {
                    let s = p.display().to_string();
                    temp_keys.push(p);
                    s
                })
                .ok(),
            None => None,
        }
        .or_else(|| (!key_path.is_empty()).then(|| key_path.clone()));
        if let Some(p) = identity {
            argv.push("-i".into());
            argv.push(p);
        }
    }
    // Pin ssh to the profile's auth method: a fat ssh-agent otherwise offers
    // every key first and the server drops the connection with "Too many
    // authentication failures" before the profile's key/password gets a turn.
    // Command-line -o applies to the -J hops too, so only pin when the whole
    // chain authenticates the same way.
    let uniform = hops.iter().all(|h| {
        std::mem::discriminant(&h.auth_method) == std::mem::discriminant(&target.auth_method)
    });
    if uniform {
        match &target.auth_method {
            AuthMethod::PublicKey { .. } => {
                argv.push("-o".into());
                argv.push("IdentitiesOnly=yes".into());
            }
            AuthMethod::Password => {
                argv.push("-o".into());
                argv.push("PreferredAuthentications=password,keyboard-interactive".into());
            }
            AuthMethod::Agent => {}
        }
    }
    argv.push(format!("{}@{}", target.username, target.address));
    (argv, temp_keys)
}

/// A vaulted private key written to a throwaway 0600 file in
/// `$XDG_RUNTIME_DIR` (tmpfs), for external ssh/rsync. Callers delete it.
fn write_transient_key(pem: &str) -> std::io::Result<std::path::PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_dir())
        .unwrap_or_else(std::env::temp_dir);
    let path = dir.join(format!("hopterm-key-{}.pem", uuid::Uuid::new_v4()));
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?;
    f.write_all(pem.as_bytes())?;
    Ok(path)
}

/// Write a throwaway `SSH_ASKPASS` helper that answers ssh's password prompts
/// from the profile's stored credentials. `creds` is `(user@host, password)`
/// per password-auth node; the helper matches the host in the prompt so a
/// multi-hop chain with different passwords is handled. Lives in
/// `$XDG_RUNTIME_DIR` (tmpfs, 0700) when available, mode 0700, and is removed by
/// the caller shortly after. Consistent with HopTerm already storing these
/// passwords in `~/.hopterm`.
pub(crate) fn write_askpass_helper(creds: &[(String, String)]) -> std::io::Result<std::path::PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let dir = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_dir())
        .unwrap_or_else(std::env::temp_dir);
    let path = dir.join(format!("hopterm-askpass-{}.sh", uuid::Uuid::new_v4()));

    // Single-quote for POSIX sh: wrap in '' and escape embedded quotes as '\''.
    let sq = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
    let mut body = String::from(
        "#!/bin/sh\n# HopTerm askpass (transient) — answers ssh password prompts.\np=\"$*\"\ncase \"$p\" in\n",
    );
    for (key, pw) in creds {
        body.push_str(&format!("  *{}*) printf '%s\\n' {} ;;\n", sq(key), sq(pw)));
    }
    // All passwords identical → use it as a catch-all so unusual prompt wording
    // still authenticates; otherwise answer nothing rather than the wrong one.
    let distinct: std::collections::HashSet<&String> = creds.iter().map(|(_, p)| p).collect();
    if distinct.len() == 1 {
        body.push_str(&format!("  *) printf '%s\\n' {} ;;\n", sq(&creds[0].1)));
    } else {
        body.push_str("  *) printf '%s\\n' '' ;;\n");
    }
    body.push_str("esac\n");

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(&path)?;
    f.write_all(body.as_bytes())?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    Ok(path)
}

/// Stored passwords along the chain (jumps + target) as `(user@host, password)`
/// pairs for the askpass helper. Key/agent nodes need nothing here — the whole
/// point is to not re-prompt for what HopTerm has.
pub(crate) fn password_creds(profile: &SessionProfile) -> Vec<(String, String)> {
    profile
        .route
        .hops
        .iter()
        .chain(std::iter::once(profile.target()))
        .filter_map(|n| match &n.auth_method {
            AuthMethod::Password => n
                .password
                .as_ref()
                .filter(|p| !p.is_empty())
                .map(|p| (format!("{}@{}", n.username, n.address), p.clone())),
            _ => None,
        })
        .collect()
}

/// Launch the profile's SSH session in a detached external terminal. Honours
/// `$TERMINAL`, then tries gnome-terminal / fly-term / xterm and a few common
/// fallbacks — each with its own "run this command" flag. Returns the terminal
/// that was launched, or an error string if none could be started.
fn open_in_external_terminal(profile: &SessionProfile) -> Result<String, String> {
    let (mut argv, temp_keys) = build_ssh_argv(profile);
    if !temp_keys.is_empty() {
        // Like the askpass helper below: gone once auth has had time to finish.
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(120));
            for p in temp_keys {
                let _ = std::fs::remove_file(p);
            }
        });
    }
    let creds = password_creds(profile);

    // Feed those passwords to ssh through a transient askpass helper so nothing
    // is re-typed. With a forced askpass ssh would also route the host-key prompt
    // to it — accept-new avoids that and matches HopTerm's own TOFU (new host
    // accepted, changed host rejected).
    let mut run_argv: Vec<String> = Vec::new();
    if !creds.is_empty() {
        argv.push("-o".into());
        argv.push("StrictHostKeyChecking=accept-new".into());
        match write_askpass_helper(&creds) {
            Ok(path) => {
                run_argv.push("env".into());
                run_argv.push(format!("SSH_ASKPASS={}", path.display()));
                run_argv.push("SSH_ASKPASS_REQUIRE=force".into());
                // Delete the helper once auth has had time to complete.
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_secs(120));
                    let _ = std::fs::remove_file(&path);
                });
            }
            Err(_) => { /* fall back to plain ssh — it will prompt */ }
        }
    }
    run_argv.extend(argv);

    // (binary, flag preceding the command). "--" / "-e" / "-x" are the usual
    // spellings; "" means the terminal takes the command as trailing args.
    let mut candidates: Vec<(String, &str)> = Vec::new();
    if let Ok(t) = std::env::var("TERMINAL") {
        let t = t.trim().to_string();
        if !t.is_empty() {
            let sep = match t.rsplit('/').next().unwrap_or(&t) {
                "gnome-terminal" => "--",
                "kitty" => "",
                "xfce4-terminal" => "-x",
                _ => "-e",
            };
            candidates.push((t, sep));
        }
    }
    for (bin, sep) in [
        ("gnome-terminal", "--"),
        ("fly-term", "-e"),
        ("xterm", "-e"),
        ("konsole", "-e"),
        ("xfce4-terminal", "-x"),
        ("alacritty", "-e"),
        ("kitty", ""),
        ("x-terminal-emulator", "-e"),
    ] {
        candidates.push((bin.to_string(), sep));
    }

    let mut last_err =
        String::from("не найден терминал (gnome-terminal / fly-term / xterm). Задайте $TERMINAL");
    for (bin, sep) in &candidates {
        let mut cmd = Command::new(bin);
        if !sep.is_empty() {
            cmd.arg(sep);
        }
        // fly-term's `-e` takes the command as ONE string (its documented
        // usage is `-e "cmd"`), not a trailing argv like xterm's.
        if bin.rsplit('/').next() == Some("fly-term") {
            cmd.arg(join_command(&run_argv));
        } else {
            cmd.args(&run_argv);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        match cmd.spawn() {
            Ok(mut child) => {
                // Reap on window close so it never lingers as a zombie, without
                // blocking the command loop.
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
                return Ok(bin.clone());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => last_err = format!("{bin}: {e}"),
        }
    }
    Err(last_err)
}

/// Shell script run on the target to shadow the user's X session with x11vnc,
/// bound to loopback. `display` empty = auto: DISPLAY + XAUTHORITY are read from
/// the user's own `gnome-shell` so we attach to their real desktop, not a GDM
/// greeter / Xwayland `:0` that a naive "first X socket" pick would grab. Fallbacks:
/// a user-owned X socket, the X server's `-auth`, then the GDM / `$HOME` cookie.
/// `-forever` keeps it serving across viewer reconnects; `-timeout` bounds startup;
/// it dies when the SSH session closes. (x11vnc is X11-only — a Wayland session
/// makes it exit with "Wayland display server detected".)
/// Start a VNC server on the host with `server_cmd`, tunnel a free local port
/// to remote 127.0.0.1:5900 (registered as a normal forward so disconnect
/// tears it down), and open a local VNC viewer.
async fn vnc_desktop_flow(
    conn: Arc<dyn SshConnection>,
    proxy: EventLoopProxy<UserEvent>,
    forwards: Forwards,
    sessions: Sessions,
    session_key: String,
    label: String,
    server_cmd: String,
) {
    let conn_vnc = conn.clone();
    let proxy_vnc = proxy.clone();
    tokio::spawn(async move {
        // Drain the server's output. A non-zero exit comes back as an Err
        // carrying its stderr — surface it instead of failing silently
        // (that opaque failure is what reads as "server closes connection").
        match conn_vnc.exec_stream(&server_cmd).await {
            Ok(mut s) => loop {
                match s.next_chunk().await {
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(e) => {
                        emit(&proxy_vnc, json!({"ev":"toast","error":true,
                            "text": format!("VNC-сервер на хосте: {e}")}));
                        break;
                    }
                }
            },
            Err(e) => emit(&proxy_vnc, json!({"ev":"toast","error":true,
                "text": format!("VNC-сервер — запуск не удался: {e}")})),
        }
    });
    let Some(bound) =
        register_desktop_forward(&conn, &proxy, &forwards, &sessions, session_key, label, 5900)
            .await
    else {
        return;
    };
    // Give the server a moment to bind before the viewer dials in.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let text = match open_vnc_viewer(bound) {
        Ok(bin) => format!("Рабочий стол открыт в {bin} — 127.0.0.1:{bound}"),
        Err(e) => format!("VNC готов на 127.0.0.1:{bound}. {e}"),
    };
    emit(&proxy, json!({"ev":"toast","text": text}));
}

/// The port gnome-remote-desktop actually listens on, from the probe output.
/// 3389 is only the default: port negotiation moves grd when 3389 is taken.
fn rdp_port_of(probe_out: &str) -> u16 {
    probe_out
        .lines()
        .find_map(|l| l.trim().strip_prefix("RDP_PORT="))
        .and_then(|p| p.parse().ok())
        .unwrap_or(3389)
}

/// Tunnel to the host's already-listening gnome-remote-desktop (RDP) and open
/// a local RDP client.
async fn rdp_connect_flow(
    conn: Arc<dyn SshConnection>,
    proxy: EventLoopProxy<UserEvent>,
    forwards: Forwards,
    sessions: Sessions,
    session_key: String,
    label: String,
    remote_port: u16,
) {
    let Some(bound) =
        register_desktop_forward(&conn, &proxy, &forwards, &sessions, session_key, label, remote_port)
            .await
    else {
        return;
    };
    let text = match open_rdp_viewer(bound) {
        Ok(bin) => format!("Рабочий стол (RDP) открыт в {bin} — 127.0.0.1:{bound}"),
        Err(e) => format!("RDP готов на 127.0.0.1:{bound}. {e}"),
    };
    emit(&proxy, json!({"ev":"toast","text": text}));
}

/// Forward a free local port to the host's loopback `remote_port` and register
/// it in the forwards list. Returns the bound local port.
async fn register_desktop_forward(
    conn: &Arc<dyn SshConnection>,
    proxy: &EventLoopProxy<UserEvent>,
    forwards: &Forwards,
    sessions: &Sessions,
    session_key: String,
    label: String,
    remote_port: u16,
) -> Option<u16> {
    let pf = match conn.forward_local("127.0.0.1", 0, "127.0.0.1", remote_port).await {
        Ok(pf) => pf,
        Err(e) => {
            emit(proxy, json!({"ev":"toast","error":true,
                "text": format!("Рабочий стол — проброс не удался: {e}")}));
            return None;
        }
    };
    let bound = pf.local_port();
    let items = {
        let mut fw = forwards.lock().unwrap();
        if !sessions.lock().unwrap().contains_key(&session_key) {
            return None;
        }
        fw.insert(
            uuid::Uuid::new_v4().to_string(),
            ActiveForward {
                pf,
                kind: "local",
                session_key,
                local_port: bound,
                remote_host: "127.0.0.1".to_string(),
                remote_port,
                label,
            },
        );
        forwards_json(&fw)
    };
    emit(proxy, json!({"ev":"forwards","items":items}));
    Some(bound)
}

/// `waypipe ssh <chain> <app>` as a detached local process: waypipe proxies
/// the Wayland protocol, so the remote app's window renders locally. Stored
/// passwords ride the same askpass helper as the external terminal. A child
/// dying within the first seconds surfaces its stderr as a toast — otherwise
/// the only trace of a failed launch is a stray system notification.
fn spawn_waypipe_app(
    profile: &SessionProfile,
    app: &str,
    proxy: EventLoopProxy<UserEvent>,
) -> Result<(), String> {
    use std::io::Read;

    let (mut ssh_argv, temp_keys) = build_ssh_argv(profile);
    ssh_argv.remove(0); // waypipe invokes ssh itself
    let creds = password_creds(profile);
    let mut cmd = Command::new("waypipe");
    // --no-gpu: the DMABUF path segfaults inside the NVIDIA EGL driver
    // (waypipe 0.11 + libnvidia-eglcore, seen live); shared memory works
    // everywhere and costs nothing for ordinary apps. waypipe forwards this
    // option to its remote server half itself.
    cmd.arg("--no-gpu")
        .arg("ssh")
        .args(["-o".to_string(), "StrictHostKeyChecking=accept-new".to_string()])
        .args(&ssh_argv)
        .arg(app)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut cleanup = temp_keys;
    if !creds.is_empty() {
        if let Ok(path) = write_askpass_helper(&creds) {
            cmd.env("SSH_ASKPASS", &path).env("SSH_ASKPASS_REQUIRE", "force");
            cleanup.push(path);
        }
    }
    let spawned = cmd.spawn().map_err(|e| e.to_string());
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(120));
        for p in cleanup {
            let _ = std::fs::remove_file(p);
        }
    });
    let mut child = spawned?;

    // Bounded stderr tail, collected as it streams so the child never blocks
    // on a full pipe.
    let tail = Arc::new(Mutex::new(Vec::<u8>::new()));
    let mut err = child.stderr.take().expect("stderr piped");
    let tail2 = tail.clone();
    std::thread::spawn(move || {
        let mut chunk = [0u8; 1024];
        while let Ok(n) = err.read(&mut chunk) {
            if n == 0 {
                break;
            }
            let mut t = tail2.lock().unwrap();
            t.extend_from_slice(&chunk[..n]);
            if t.len() > 8192 {
                let cut = t.len() - 4096;
                t.drain(..cut);
            }
        }
    });

    let app_name = app.to_string();
    std::thread::spawn(move || {
        for _ in 0..70 {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        let text = String::from_utf8_lossy(&tail.lock().unwrap()).into_owned();
                        emit(&proxy, json!({"ev":"toast","error":true,
                            "text":format!("waypipe ({app_name}): {}", last_lines(&text, 3))}));
                    }
                    return;
                }
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(100)),
                Err(_) => return,
            }
        }
        let _ = child.wait(); // long-lived = the app is running; just reap it
    });
    Ok(())
}

/// argv joined into one command string: plain tokens as-is (survives a naive
/// space split), tokens with specials single-quoted (survives a shell).
fn join_command(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if a.is_empty() || a.chars().any(|c| c.is_whitespace() || "'\"\\$".contains(c)) {
                format!("'{}'", a.replace('\'', "'\\''"))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn local_tool_exists(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn last_lines(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(n)..].join(" | ")
}

/// Launch a native RDP client at the tunneled gnome-remote-desktop port.
fn open_rdp_viewer(port: u16) -> Result<String, String> {
    let uri = format!("rdp://127.0.0.1:{port}");
    let addr = format!("/v:127.0.0.1:{port}");
    let candidates: Vec<(&str, Vec<String>)> = vec![
        ("remmina", vec!["-c".into(), uri.clone()]),
        ("xfreerdp3", vec![addr.clone()]),
        ("xfreerdp", vec![addr.clone()]),
        ("wlfreerdp", vec![addr.clone()]),
    ];
    let mut last_err = String::from(
        "RDP-клиент не найден (remmina / freerdp2-x11) — установите любой и подключитесь к адресу выше",
    );
    for (bin, args) in &candidates {
        let mut cmd = Command::new(bin);
        cmd.args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        match cmd.spawn() {
            Ok(mut child) => {
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
                return Ok(bin.to_string());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => last_err = format!("{bin}: {e}"),
        }
    }
    Err(last_err)
}

/// Run a remote command and gather its whole output. A transport error after
/// some output still returns what arrived — probes prefer partial truth.
async fn exec_collect(conn: &Arc<dyn SshConnection>, cmd: &str) -> Result<String, String> {
    let mut s = conn.exec_stream(cmd).await.map_err(|e| e.to_string())?;
    let mut out: Vec<u8> = Vec::new();
    loop {
        match s.next_chunk().await {
            Ok(Some(chunk)) => out.extend(chunk),
            Ok(None) => break,
            Err(e) if out.is_empty() => return Err(e.to_string()),
            Err(_) => break,
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// One probe deciding the desktop road: the host's graphical session type
/// (X11 / GNOME on Wayland / wlroots) plus which tools are already there.
/// NB: gnome-shell on Wayland creates the display itself, so its environ has
/// no WAYLAND_DISPLAY — XDG_SESSION_TYPE is the reliable marker. "RDP=ON"
/// means the *user's* gnome-remote-desktop sharing is enabled (grdctl); the
/// bare 3389 listener can be the system login-screen service.
const DESKTOP_DETECT_CMD: &str = r#"U=$(id -u); TYPE=NONE
export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$U}
export DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}
for c in sway Hyprland hyprland river wayfire labwc niri; do
  pgrep -u "$U" -x "$c" >/dev/null 2>&1 && TYPE=WLROOTS && break
done
if [ "$TYPE" = NONE ]; then
  for p in $(pgrep -u "$U" -x gnome-shell 2>/dev/null); do
    if tr '\0' '\n' < "/proc/$p/environ" 2>/dev/null \
       | grep -qE '^(WAYLAND_DISPLAY=|XDG_SESSION_TYPE=wayland)'; then
      TYPE=GNOME_WAYLAND
    else
      TYPE=X11
    fi
    break
  done
fi
[ "$TYPE" = NONE ] && pgrep -u "$U" -x kwin_wayland >/dev/null 2>&1 && TYPE=WAYLAND_OTHER
if [ "$TYPE" = NONE ]; then
  for s in /tmp/.X11-unix/X*; do [ -O "$s" ] && TYPE=X11 && break; done
fi
echo "TYPE=$TYPE"
grdctl status 2>/dev/null | sed -n '/^RDP/,/^VNC/p' | grep -q 'Status: enabled' \
  && echo RDP=ON || echo RDP=OFF
# The ACTUAL grd listening port: with "negotiate port" grd silently moves to
# 3390+ when 3389 is taken (e.g. by xrdp — connecting there would open a
# second broken session instead of the live desktop). grd runs as this user,
# so ss shows its process name without root.
LC_ALL=C ss -ltnp 2>/dev/null | sed -n 's/.*:\([0-9][0-9]*\) .*gnome-remote.*/RDP_PORT=\1/p' | head -1
command -v x11vnc >/dev/null 2>&1 && echo X11VNC=OK || echo X11VNC=MISSING
command -v wayvnc >/dev/null 2>&1 && echo WAYVNC=OK || echo WAYVNC=MISSING"#;

/// wayvnc attached to the live wlroots compositor (loopback only), mirroring
/// [`remote_x11vnc_cmd`]: environment is lifted from the compositor process.
fn remote_wayvnc_cmd() -> String {
    r#"U=$(id -u); WD=''; XRD=''
for c in sway Hyprland hyprland river wayfire labwc niri; do
  for p in $(pgrep -u "$U" -x "$c" 2>/dev/null); do
    e=$(tr '\0' '\n' < "/proc/$p/environ" 2>/dev/null)
    WD=$(printf '%s\n' "$e" | sed -n 's/^WAYLAND_DISPLAY=//p' | head -1)
    XRD=$(printf '%s\n' "$e" | sed -n 's/^XDG_RUNTIME_DIR=//p' | head -1)
    [ -n "$WD" ] && break 2
  done
done
XRD=${XRD:-/run/user/$U}; WD=${WD:-wayland-1}
XDG_RUNTIME_DIR="$XRD" WAYLAND_DISPLAY="$WD" wayvnc 127.0.0.1 5900"#
        .to_string()
}

fn remote_x11vnc_cmd(display: &str) -> String {
    format!(
        r#"D='{display}'; XA=''
if [ -z "$D" ]; then
  for p in $(pgrep -u "$(id -u)" gnome-shell 2>/dev/null); do
    e=$(tr '\0' '\n' < "/proc/$p/environ" 2>/dev/null)
    D=$(printf '%s\n' "$e" | sed -n 's/^DISPLAY=//p' | head -1)
    XA=$(printf '%s\n' "$e" | sed -n 's/^XAUTHORITY=//p' | head -1)
    [ -n "$D" ] && break
  done
fi
[ -n "$D" ] || for s in /tmp/.X11-unix/X*; do [ -O "$s" ] && D=":${{s##*/X}}" && break; done
D=${{D:-:0}}
[ -r "$XA" ] || XA=$(ps -u "$(id -u)" -o args= 2>/dev/null | sed -n 's/.* -auth \([^ ]*\).*/\1/p' | head -1)
[ -r "$XA" ] || XA=/run/user/$(id -u)/gdm/Xauthority
[ -r "$XA" ] || XA="$HOME/.Xauthority"
x11vnc -display "$D" -auth "$XA" -localhost -rfbport 5900 -nopw -forever -shared -timeout 60 -noxdamage -quiet"#
    )
}

/// Launch a native VNC viewer pointed at a loopback port (the SSH tunnel to the
/// remote `x11vnc`). Returns the launched binary's name, or an error naming what
/// to do by hand. `$VNCVIEWER` overrides the search.
fn open_vnc_viewer(port: u16) -> Result<String, String> {
    let uri = format!("vnc://127.0.0.1:{port}");
    let raw = format!("127.0.0.1::{port}"); // double colon = literal port, not a display number
    let mut candidates: Vec<(String, Vec<String>)> = Vec::new();
    if let Ok(v) = std::env::var("VNCVIEWER") {
        let v = v.trim().to_string();
        if !v.is_empty() {
            candidates.push((v, vec![raw.clone()]));
        }
    }
    for (bin, args) in [
        ("remmina", vec!["-c".to_string(), uri.clone()]),
        ("vinagre", vec![uri.clone()]),
        ("gvncviewer", vec![raw.clone()]),
        ("vncviewer", vec![raw.clone()]), // TigerVNC / TightVNC
        ("xtightvncviewer", vec![raw.clone()]),
        ("xvnc4viewer", vec![raw.clone()]),
    ] {
        candidates.push((bin.to_string(), args));
    }

    let mut last_err = String::from(
        "VNC-клиент не найден (remmina / vinagre / gvncviewer / vncviewer) — \
         установите любой и подключитесь к адресу выше, или задайте $VNCVIEWER",
    );
    for (bin, args) in &candidates {
        let mut cmd = Command::new(bin);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        match cmd.spawn() {
            Ok(mut child) => {
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
                return Ok(bin.clone());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => last_err = format!("{bin}: {e}"),
        }
    }
    Err(last_err)
}

fn describe_state(state: &ConnectionState) -> String {
    match state {
        ConnectionState::Disconnected => "отключено".into(),
        ConnectionState::Resolving => "разрешение адреса…".into(),
        ConnectionState::Connecting { index, total } => {
            format!("подключение к хопу {}/{}…", index + 1, total)
        }
        ConnectionState::Authenticating { index, total } => {
            format!("аутентификация на хопе {}/{}…", index + 1, total)
        }
        ConnectionState::Connected => "подключено".into(),
        ConnectionState::Reconnecting { attempt } => format!("переподключение ({attempt})…"),
        ConnectionState::Failed { hop_index, message } => {
            format!("сбой на хопе {}: {message}", hop_index + 1)
        }
    }
}

#[cfg(test)]
mod hop_ref_tests {
    use super::*;

    fn node(addr: &str) -> HostProfile {
        HostProfile {
            id: HostId::new(uuid::Uuid::new_v4()),
            name: addr.into(),
            address: addr.into(),
            port: 22,
            username: "root".into(),
            auth_method: AuthMethod::Agent,
            password: None,
            tags: vec![],
            color: None,
            icon: None,
            hop_ref: None,
        }
    }

    fn ref_hop(to: ProfileId) -> HostProfile {
        HostProfile { hop_ref: Some(to), ..node("") }
    }

    fn profile(name: &str, hops: Vec<HostProfile>, target: &str) -> SessionProfile {
        SessionProfile {
            id: ProfileId::new(uuid::Uuid::new_v4()),
            display_name: name.into(),
            route: Route { hops, target: node(target), policy: RoutePolicy::DirectTcpIp },
            terminal_preferences: Default::default(),
            transfer_preferences: Default::default(),
            tags: vec![],
            sudo: Default::default(),
            color: None,
            icon: None,
        }
    }

    #[test]
    fn expands_nested_reference_chains() {
        let gate = profile("gate", vec![node("bastion")], "gate.example");
        let app = profile("app", vec![ref_hop(gate.id)], "app.example");
        let all = vec![gate.clone(), app.clone()];

        let r = resolve_profile(&app, &all).unwrap();
        let addrs: Vec<&str> = r.route.hops.iter().map(|h| h.address.as_str()).collect();
        // the referenced host contributes its own chain, then itself
        assert_eq!(addrs, ["bastion", "gate.example"]);
        assert_eq!(r.route.target.address, "app.example");

        // an inline hop passes through untouched
        let plain = profile("plain", vec![node("direct")], "t");
        assert_eq!(resolve_profile(&plain, &all).unwrap().route.hops[0].address, "direct");
    }

    #[test]
    fn rejects_cycles_and_dangling_refs() {
        let mut a = profile("a", vec![], "a.example");
        let b = profile("b", vec![ref_hop(a.id)], "b.example");
        a.route.hops = vec![ref_hop(b.id)];
        let all = vec![a.clone(), b.clone()];
        assert!(resolve_profile(&a, &all).unwrap_err().contains("цикл"));

        let dangling = profile("d", vec![ref_hop(ProfileId::new(uuid::Uuid::new_v4()))], "t");
        assert!(resolve_profile(&dangling, &all).is_err());
    }

    #[test]
    fn vault_keys_reads_carries_and_fails() {
        let dir = std::env::temp_dir().join(format!("hopterm-vault-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let key_file = dir.join("k.pem").display().to_string();
        std::fs::write(&key_file, "PEM-BODY").unwrap();
        let requested = |path: &str| AuthMethod::PublicKey {
            key_path: path.into(),
            passphrase_protected: false,
            key_data: Some(String::new()),
        };
        let stored = |n: &HostProfile| match &n.auth_method {
            AuthMethod::PublicKey { key_data, .. } => key_data.clone(),
            _ => None,
        };

        let mut p = profile("p", vec![], "t");
        p.route.target.auth_method = requested(&key_file);
        vault_keys(&mut p, None).unwrap();
        assert_eq!(stored(&p.route.target).as_deref(), Some("PEM-BODY"));

        // key file deleted -> the copy carries over from the old profile
        std::fs::remove_file(&key_file).unwrap();
        let old = p.clone();
        let mut p2 = profile("p", vec![], "t");
        p2.route.target.auth_method = requested(&key_file);
        vault_keys(&mut p2, Some(&old)).unwrap();
        assert_eq!(stored(&p2.route.target).as_deref(), Some("PEM-BODY"));

        // no file, nothing to carry -> explicit error, not a silent save
        let mut p3 = profile("p", vec![], "t");
        p3.route.target.auth_method = requested(&key_file);
        assert!(vault_keys(&mut p3, None).unwrap_err().contains("не прочитан"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_closure_pulls_referenced_hosts() {
        let bastion = profile("bastion", vec![], "b.example");
        let gate = profile("gate", vec![ref_hop(bastion.id)], "g.example");
        let app = profile("app", vec![ref_hop(gate.id)], "a.example");
        let lone = profile("lone", vec![], "l.example");
        let all = vec![bastion.clone(), gate.clone(), app.clone(), lone.clone()];

        let keep = ref_closure([app.id].into_iter(), &all);
        assert_eq!(keep.len(), 3); // app -> gate -> bastion, but not lone
        assert!(keep.contains(&bastion.id) && !keep.contains(&lone.id));
    }
}

#[cfg(test)]
mod glob_tests {
    use super::{glob_match, is_glob};

    #[test]
    fn matches_wildcards() {
        assert!(is_glob("/a/b/*"));
        assert!(is_glob("file?.log"));
        assert!(!is_glob("/a/b/c.txt"));

        assert!(glob_match("*", "anything.tar.gz"));
        assert!(glob_match("*.log", "app.log"));
        assert!(glob_match("perf_*", "perf_results"));
        assert!(glob_match("perf_results_?", "perf_results_3"));
        assert!(glob_match("a*b*c", "axxbyyc"));

        assert!(!glob_match("*.log", "app.txt"));
        assert!(!glob_match("perf_?", "perf_12"));
        assert!(!glob_match("abc", "abcd"));
    }

    /// Mirror the backend's on-the-fly extraction: gunzip + untar a streamed
    /// archive into a directory, summing entry sizes for the progress total.
    #[test]
    fn extracts_streamed_gzip_tar() {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        {
            let mut b = tar::Builder::new(&mut enc);
            for (name, body) in [("a.txt", b"hello".as_slice()), ("b.log", b"world!!".as_slice())] {
                let mut h = tar::Header::new_gnu();
                h.set_size(body.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, name, body).unwrap();
            }
            b.finish().unwrap();
        }
        let gz_bytes = enc.finish().unwrap();

        let dir = std::env::temp_dir().join(format!("hopterm-tar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let gz = flate2::read::GzDecoder::new(std::io::Cursor::new(gz_bytes));
        let mut archive = tar::Archive::new(gz);
        let mut total = 0u64;
        for entry in archive.entries().unwrap() {
            let mut e = entry.unwrap();
            total += e.header().size().unwrap();
            e.unpack_in(&dir).unwrap();
        }
        assert_eq!(total, 12);
        assert_eq!(std::fs::read_to_string(dir.join("a.txt")).unwrap(), "hello");
        assert_eq!(std::fs::read_to_string(dir.join("b.log")).unwrap(), "world!!");
        std::fs::remove_dir_all(&dir).ok();
    }
}
