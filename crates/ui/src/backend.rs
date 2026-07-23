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

fn emit(proxy: &EventLoopProxy<UserEvent>, value: Value) {
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
    let prompter: Arc<dyn SecretPrompter> = Arc::new(WebPrompter {
        proxy: proxy.clone(),
        pending: pending.clone(),
        stored_pw: stored_pw.clone(),
    });
    let asker = host_key_asker(proxy.clone(), pending.clone());
    let services = Services::production(prompter, Some(asker), &settings);
    let manager = SessionManager::new(services);

    let mut loaded = manager.services().store.load_profiles().unwrap_or_default();
    if loaded.is_empty() {
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
                let profile = profiles
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|p| p.id.to_string() == profile_id)
                    .cloned();
                if let Some(profile) = profile {
                    spawn_connect(profile, manager.clone(), proxy.clone(), sessions.clone(), sudo, id.clone(), forwards.clone());
                }
            }

            // Reproduce the profile's hop chain as a plain `ssh` command and hand
            // it to an external terminal emulator (gnome-terminal / fly-term / …).
            "open_external" => {
                let profile = profiles
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|p| p.id.to_string() == id)
                    .cloned();
                match profile {
                    Some(profile) => match open_in_external_terminal(&profile) {
                        Ok(term) => emit(&proxy, json!({"ev":"toast",
                            "text": format!("Открыто во внешнем терминале ({term})")})),
                        Err(e) => emit(&proxy, json!({"ev":"toast", "error": true,
                            "text": format!("Внешний терминал — {e}")})),
                    },
                    None => emit(&proxy, json!({"ev":"toast", "error": true,
                        "text": "Хост не найден"})),
                }
            }

            "save_host" => {
                if let Some(host) = msg.get("host") {
                    let profile = profile_from_json(host);
                    let _ = manager.services().store.save_profile(&profile);
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
                    let _ = manager.services().store.delete_profile(pid);
                    {
                        let mut ps = profiles.lock().unwrap();
                        ps.retain(|p| p.id != pid);
                        seed_stored_passwords(&stored_pw, &ps);
                    }
                    emit(&proxy, json!({"ev":"hosts","items":host_items(&profiles.lock().unwrap())}));
                }
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
                let local = msg.get("local").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let remote = msg.get("remote").and_then(|v| v.as_str()).unwrap_or("").to_string();
                start_transfer(
                    &sessions, &manager, &proxy, &transfers, &id, "up", local, remote,
                );
            }

            "download" => {
                let remote = msg.get("remote").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let name = remote.rsplit('/').next().unwrap_or("file").to_string();
                // A "download" command can pin a destination folder; otherwise ~/Downloads.
                let dir = match msg.get("local_dir").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                    Some(d) => {
                        let expanded = if let Some(rest) = d.strip_prefix("~/") {
                            format!("{}/{rest}", std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
                        } else if d == "~" {
                            std::env::var("HOME").unwrap_or_else(|_| "/tmp".into())
                        } else {
                            d.to_string()
                        };
                        let _ = std::fs::create_dir_all(&expanded);
                        expanded
                    }
                    None => download_dir(),
                };
                if is_glob(&remote) {
                    // SFTP has no glob — expand the pattern client-side and fetch
                    // every matching file into the destination folder.
                    start_glob_download(&sessions, &manager, &proxy, &transfers, &id, dir, remote);
                } else {
                    let local = format!("{}/{name}", dir.trim_end_matches('/'));
                    start_transfer(
                        &sessions, &manager, &proxy, &transfers, &id, "down", local, remote,
                    );
                }
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

fn node_json(h: &HostProfile) -> Value {
    let (auth, key) = match &h.auth_method {
        AuthMethod::Password => ("password", String::new()),
        AuthMethod::Agent => ("agent", String::new()),
        AuthMethod::PublicKey { key_path, .. } => ("key", key_path.clone()),
    };
    json!({"user": h.username, "host": h.address, "port": h.port, "auth": auth, "key": key,
           "password": h.password.clone().unwrap_or_default()})
}

fn host_items(profiles: &[SessionProfile]) -> Value {
    Value::Array(
        profiles
            .iter()
            .map(|p| {
                json!({
                    "id": p.id.to_string(),
                    "name": p.display_name,
                    "endpoint": p.target().endpoint(),
                    "hops": p.route.hops.len(),
                    "auth": p.target().auth_method.label(),
                    "route": p.route.breadcrumb(),
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
fn node_from_json(v: &Value) -> HostProfile {
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let host = s("host");
    let auth = match v.get("auth").and_then(|x| x.as_str()).unwrap_or("agent") {
        "password" => AuthMethod::Password,
        "key" => AuthMethod::PublicKey {
            key_path: {
                let k = s("key");
                if k.is_empty() { "~/.ssh/id_ed25519".into() } else { k }
            },
            passphrase_protected: false,
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
                .filter(|j| !j.get("host").and_then(|h| h.as_str()).unwrap_or("").is_empty())
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
fn build_ssh_argv(profile: &SessionProfile) -> Vec<String> {
    let mut argv = vec!["ssh".to_string()];
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
    if let AuthMethod::PublicKey { key_path, .. } = &target.auth_method {
        if !key_path.is_empty() {
            argv.push("-i".into());
            argv.push(key_path.clone());
        }
    }
    argv.push(format!("{}@{}", target.username, target.address));
    argv
}

/// Write a throwaway `SSH_ASKPASS` helper that answers ssh's password prompts
/// from the profile's stored credentials. `creds` is `(user@host, password)`
/// per password-auth node; the helper matches the host in the prompt so a
/// multi-hop chain with different passwords is handled. Lives in
/// `$XDG_RUNTIME_DIR` (tmpfs, 0700) when available, mode 0700, and is removed by
/// the caller shortly after. Consistent with HopTerm already storing these
/// passwords in `~/.hopterm`.
fn write_askpass_helper(creds: &[(String, String)]) -> std::io::Result<std::path::PathBuf> {
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

/// Launch the profile's SSH session in a detached external terminal. Honours
/// `$TERMINAL`, then tries gnome-terminal / fly-term / xterm and a few common
/// fallbacks — each with its own "run this command" flag. Returns the terminal
/// that was launched, or an error string if none could be started.
fn open_in_external_terminal(profile: &SessionProfile) -> Result<String, String> {
    let mut argv = build_ssh_argv(profile);

    // Stored passwords along the chain (jumps + target). Key/agent nodes need
    // nothing here — the whole point is to not re-prompt for what HopTerm has.
    let creds: Vec<(String, String)> = profile
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
        .collect();

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
        cmd.args(&run_argv)
            .stdin(Stdio::null())
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
