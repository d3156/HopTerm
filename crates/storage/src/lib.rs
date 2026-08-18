//! JSON-backed storage for `~/.hopterm/` (spec §10).
//!
//! Layout (matches the mockup's Settings view):
//! ```text
//! ~/.hopterm/
//!   config.json     # settings + saved profiles + saved routes; optionally
//!                   # PIN-encrypted (see `Envelope`)
//!   known_hosts     # pinned host keys (one per line, fingerprint form)
//!   keys/           # imported private keys (referenced by path)
//! ```
//!
//! A legacy `config.toml` from pre-JSON versions is migrated automatically on
//! first read (rewritten as `config.json`, original removed).
//!
//! The store is deliberately synchronous: the config is small and only touched
//! at startup and on edits, so an async API would add noise for no benefit.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hopterm_domain::{
    AppSettings, ConfigEncryption, HostKey, JumpRoute, ProfileId, ProfileStore, SessionProfile,
    StorageError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod crypto;

/// Resolved on-disk locations.
#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
    pub config_file: PathBuf,
    pub legacy_config_file: PathBuf,
    pub known_hosts_file: PathBuf,
    pub keys_dir: PathBuf,
}

impl Paths {
    /// `~/.hopterm/...` — the location the mockup advertises. Falls back to the
    /// current dir if the home directory can't be resolved (headless CI).
    pub fn default_location() -> Self {
        let home = directories::BaseDirs::new()
            .map(|b| b.home_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        Self::under(home.join(".hopterm"))
    }

    /// Build the layout under an explicit root (used by tests).
    pub fn under(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            config_file: root.join("config.json"),
            legacy_config_file: root.join("config.toml"),
            known_hosts_file: root.join("known_hosts"),
            keys_dir: root.join("keys"),
            root,
        }
    }

    fn ensure_root(&self) -> Result<(), StorageError> {
        std::fs::create_dir_all(&self.root).map_err(|e| StorageError::Io {
            path: self.root.display().to_string(),
            message: e.to_string(),
        })
    }
}

/// Full on-disk config document (`config.json`).
#[derive(Debug, Default, Serialize, Deserialize)]
struct ConfigDoc {
    #[serde(default)]
    settings: AppSettings,
    #[serde(default)]
    profiles: Vec<SessionProfile>,
    #[serde(default)]
    routes: Vec<JumpRoute>,
}

/// What `config.json` holds when PIN encryption is on. `data` is the plain
/// [`ConfigDoc`] JSON sealed by [`crypto::seal`].
#[derive(Serialize, Deserialize)]
struct Envelope {
    kdf: String,
    /// base64, [`crypto::SALT_LEN`] bytes.
    salt: String,
    /// base64, `nonce(12) || ciphertext+tag(16)`.
    data: String,
}

const KDF_NAME: &str = "argon2id";

/// Key material of an unlocked encrypted config, shared across store clones.
#[derive(Clone)]
struct CryptoState {
    key: [u8; crypto::KEY_LEN],
    salt: [u8; crypto::SALT_LEN],
}

impl std::fmt::Debug for CryptoState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CryptoState(..)")
    }
}

/// The concrete [`ProfileStore`].
#[derive(Debug, Clone)]
pub struct JsonStore {
    paths: Paths,
    /// When `false` (mockup toggle "Сохранять конфиг на диск"), writes are no-ops
    /// and the config lives only in memory for the session.
    persist: bool,
    /// `Some` once an encrypted config is unlocked (or encryption enabled).
    crypto: Arc<Mutex<Option<CryptoState>>>,
}

impl JsonStore {
    pub fn new(paths: Paths) -> Self {
        Self { paths, persist: true, crypto: Arc::new(Mutex::new(None)) }
    }

    pub fn with_persistence(mut self, persist: bool) -> Self {
        self.persist = persist;
        self
    }

    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    fn read_doc(&self) -> Result<ConfigDoc, StorageError> {
        let text = match std::fs::read_to_string(&self.paths.config_file) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return self.read_legacy_or_default()
            }
            Err(e) => return Err(io_error(&self.paths.config_file, e)),
        };
        let json = match parse_envelope(&text)? {
            Some(env) => self.decrypt_envelope(&env)?,
            None => text,
        };
        serde_json::from_str(&json).map_err(|e| StorageError::Serde(e.to_string()))
    }

    /// Migration path for pre-JSON versions: read `config.toml` once, rewrite
    /// it as `config.json` and remove the original — an orphaned plaintext copy
    /// would silently survive a later encryption switch.
    fn read_legacy_or_default(&self) -> Result<ConfigDoc, StorageError> {
        let text = match std::fs::read_to_string(&self.paths.legacy_config_file) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ConfigDoc::default()),
            Err(e) => return Err(io_error(&self.paths.legacy_config_file, e)),
        };
        let doc = toml::from_str(&text).map_err(|e| StorageError::Serde(e.to_string()))?;
        if self.persist {
            self.write_doc(&doc)?;
            let _ = std::fs::remove_file(&self.paths.legacy_config_file);
        }
        Ok(doc)
    }

    fn decrypt_envelope(&self, env: &Envelope) -> Result<String, StorageError> {
        let state = self.crypto.lock().unwrap().clone().ok_or_else(|| {
            StorageError::Crypto("config is encrypted — PIN required".into())
        })?;
        let data = b64_decode(&env.data)?;
        let plain = crypto::open(&state.key, &data)
            .ok_or_else(|| StorageError::Crypto("wrong key or corrupted data".into()))?;
        String::from_utf8(plain).map_err(|e| StorageError::Crypto(e.to_string()))
    }

    /// `config.json` parsed as an encryption envelope, if it is one.
    fn read_envelope(&self) -> Result<Option<Envelope>, StorageError> {
        match std::fs::read_to_string(&self.paths.config_file) {
            Ok(text) => parse_envelope(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error(&self.paths.config_file, e)),
        }
    }

    fn write_doc(&self, doc: &ConfigDoc) -> Result<(), StorageError> {
        if !self.persist {
            return Ok(());
        }
        self.paths.ensure_root()?;
        let json = serde_json::to_string_pretty(doc).map_err(|e| StorageError::Serde(e.to_string()))?;
        let state = self.crypto.lock().unwrap().clone();
        let text = match state {
            Some(state) => {
                let env = Envelope {
                    kdf: KDF_NAME.into(),
                    salt: B64.encode(state.salt),
                    data: B64.encode(crypto::seal(&state.key, json.as_bytes())),
                };
                serde_json::to_string_pretty(&env).expect("envelope always serializes")
            }
            None => json,
        };
        atomic_write(&self.paths.config_file, text.as_bytes())
    }
}

impl ProfileStore for JsonStore {
    fn load_profiles(&self) -> Result<Vec<SessionProfile>, StorageError> {
        Ok(self.read_doc()?.profiles)
    }

    fn save_profile(&self, profile: &SessionProfile) -> Result<(), StorageError> {
        let mut doc = self.read_doc()?;
        match doc.profiles.iter_mut().find(|p| p.id == profile.id) {
            Some(slot) => *slot = profile.clone(),
            None => doc.profiles.push(profile.clone()),
        }
        self.write_doc(&doc)
    }

    fn delete_profile(&self, id: ProfileId) -> Result<(), StorageError> {
        let mut doc = self.read_doc()?;
        let before = doc.profiles.len();
        doc.profiles.retain(|p| p.id != id);
        if doc.profiles.len() == before {
            return Err(StorageError::NotFound(id.to_string()));
        }
        self.write_doc(&doc)
    }

    fn load_routes(&self) -> Result<Vec<JumpRoute>, StorageError> {
        Ok(self.read_doc()?.routes)
    }

    fn save_route(&self, route: &JumpRoute) -> Result<(), StorageError> {
        let mut doc = self.read_doc()?;
        match doc.routes.iter_mut().find(|r| r.id == route.id) {
            Some(slot) => *slot = route.clone(),
            None => doc.routes.push(route.clone()),
        }
        self.write_doc(&doc)
    }

    fn load_settings(&self) -> Result<AppSettings, StorageError> {
        Ok(self.read_doc()?.settings)
    }

    fn save_settings(&self, settings: &AppSettings) -> Result<(), StorageError> {
        let mut doc = self.read_doc()?;
        doc.settings = settings.clone();
        self.write_doc(&doc)
    }

    fn config_encryption(&self) -> ConfigEncryption {
        if self.crypto.lock().unwrap().is_some() {
            return ConfigEncryption::Unlocked;
        }
        match self.read_envelope() {
            Ok(None) => ConfigEncryption::Plain,
            // A broken envelope is still an encrypted config, never `Plain`.
            Ok(Some(_)) | Err(_) => ConfigEncryption::Locked,
        }
    }

    fn unlock_config(&self, pin: &str) -> Result<bool, StorageError> {
        let Some(env) = self.read_envelope()? else {
            return Ok(true);
        };
        let salt: [u8; crypto::SALT_LEN] = b64_decode(&env.salt)?
            .try_into()
            .map_err(|_| StorageError::Crypto("bad salt length".into()))?;
        let key = crypto::derive_key(pin, &salt);
        if crypto::open(&key, &b64_decode(&env.data)?).is_none() {
            return Ok(false);
        }
        *self.crypto.lock().unwrap() = Some(CryptoState { key, salt });
        Ok(true)
    }

    fn set_config_pin(&self, pin: Option<&str>) -> Result<(), StorageError> {
        let doc = self.read_doc()?;
        *self.crypto.lock().unwrap() = pin.map(|pin| {
            let salt = crypto::random_salt();
            CryptoState { key: crypto::derive_key(pin, &salt), salt }
        });
        self.write_doc(&doc)?;
        if pin.is_some() {
            // Plaintext leftovers beside an encrypted config defeat its purpose.
            let _ = std::fs::remove_file(&self.paths.legacy_config_file);
            let _ = std::fs::remove_file(self.paths.legacy_config_file.with_extension("toml.bak"));
        }
        Ok(())
    }
}

/// `Some` if `text` is an encryption envelope; `Err` if it pretends to be one
/// but is unusable — a broken envelope must never read as an empty plain config
/// (all [`ConfigDoc`] fields are defaulted), or a later save would clobber it.
fn parse_envelope(text: &str) -> Result<Option<Envelope>, StorageError> {
    let Ok(probe) = serde_json::from_str::<Value>(text) else {
        return Ok(None);
    };
    if probe.get("kdf").is_none() {
        return Ok(None);
    }
    let env: Envelope = serde_json::from_str(text)
        .map_err(|e| StorageError::Crypto(format!("bad envelope: {e}")))?;
    if env.kdf != KDF_NAME {
        return Err(StorageError::Crypto(format!("unknown kdf: {}", env.kdf)));
    }
    Ok(Some(env))
}

fn io_error(path: &Path, e: std::io::Error) -> StorageError {
    StorageError::Io { path: path.display().to_string(), message: e.to_string() }
}

fn b64_decode(s: &str) -> Result<Vec<u8>, StorageError> {
    B64.decode(s).map_err(|e| StorageError::Crypto(format!("base64: {e}")))
}

/// Pinned host keys file (`known_hosts`), one `host:port algo fingerprint` line.
#[derive(Debug, Clone)]
pub struct KnownHostsFile {
    path: PathBuf,
    persist: bool,
}

impl KnownHostsFile {
    pub fn new(path: PathBuf, persist: bool) -> Self {
        Self { path, persist }
    }

    pub fn load(&self) -> Result<Vec<HostKey>, StorageError> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(StorageError::Io {
                    path: self.path.display().to_string(),
                    message: e.to_string(),
                })
            }
        };
        Ok(text.lines().filter_map(parse_known_host_line).collect())
    }

    pub fn append(&self, key: &HostKey) -> Result<(), StorageError> {
        if !self.persist {
            return Ok(());
        }
        let mut keys = self.load()?;
        keys.retain(|k| !(k.host == key.host && k.port == key.port));
        keys.push(key.clone());
        let body: String = keys
            .iter()
            .map(|k| format!("{}:{} {} {}\n", k.host, k.port, k.algorithm, k.fingerprint_sha256))
            .collect();
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| StorageError::Io {
                path: parent.display().to_string(),
                message: e.to_string(),
            })?;
        }
        atomic_write(&self.path, body.as_bytes())
    }
}

fn parse_known_host_line(line: &str) -> Option<HostKey> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut it = line.split_whitespace();
    let host_port = it.next()?;
    let algorithm = it.next()?.to_string();
    let fingerprint_sha256 = it.next()?.to_string();
    let (host, port) = host_port.rsplit_once(':')?;
    Some(HostKey {
        host: host.to_string(),
        port: port.parse().ok()?,
        algorithm,
        fingerprint_sha256,
    })
}

/// Write `bytes` to `path` via a temp file + rename, so a crash never leaves a
/// half-written config.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|e| StorageError::Io {
        path: tmp.display().to_string(),
        message: e.to_string(),
    })?;
    std::fs::rename(&tmp, path).map_err(|e| StorageError::Io {
        path: path.display().to_string(),
        message: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hopterm_domain::*;
    use uuid::Uuid;

    fn sample_profile() -> SessionProfile {
        let target = HostProfile {
            id: HostId::new(Uuid::nil()),
            name: "prod".into(),
            address: "192.168.1.100".into(),
            port: 22,
            username: "admin".into(),
            auth_method: AuthMethod::PublicKey {
                key_path: "~/.ssh/prod_key".into(),
                passphrase_protected: false,
            },
            password: None,
            tags: vec!["production".into()],
            color: None,
            icon: None,
            hop_ref: None,
        };
        SessionProfile {
            id: ProfileId::new(Uuid::nil()),
            display_name: "prod-backend-01".into(),
            route: Route { hops: vec![], target, policy: RoutePolicy::DirectTcpIp },
            terminal_preferences: TerminalPreferences::default(),
            transfer_preferences: TransferPreferences::default(),
            tags: vec![],
            sudo: SudoConfig::default(),
            color: None,
            icon: None,
        }
    }

    #[test]
    fn round_trips_a_profile() {
        let dir = std::env::temp_dir().join(format!("hopterm-test-{}", std::process::id()));
        let store = JsonStore::new(Paths::under(&dir));
        let p = sample_profile();
        store.save_profile(&p).unwrap();
        let loaded = store.load_profiles().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].display_name, "prod-backend-01");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn round_trips_a_stored_password() {
        let dir = std::env::temp_dir().join(format!("hopterm-pw-test-{}", std::process::id()));
        let store = JsonStore::new(Paths::under(&dir));
        let mut p = sample_profile();
        p.route.target.auth_method = AuthMethod::Password;
        p.route.target.password = Some("s3cr3t-pw".into());
        store.save_profile(&p).unwrap();
        let loaded = store.load_profiles().unwrap();
        assert_eq!(loaded[0].target().password.as_deref(), Some("s3cr3t-pw"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn migrates_legacy_toml() {
        let dir = std::env::temp_dir().join(format!("hopterm-mig-test-{}", std::process::id()));
        let paths = Paths::under(&dir);
        std::fs::create_dir_all(&paths.root).unwrap();
        let doc = ConfigDoc { profiles: vec![sample_profile()], ..Default::default() };
        std::fs::write(&paths.legacy_config_file, toml::to_string_pretty(&doc).unwrap()).unwrap();

        let store = JsonStore::new(paths.clone());
        let loaded = store.load_profiles().unwrap();
        assert_eq!(loaded[0].display_name, "prod-backend-01");
        assert!(paths.config_file.exists());
        assert!(!paths.legacy_config_file.exists(), "plaintext original must not survive");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pin_encryption_round_trip() {
        let dir = std::env::temp_dir().join(format!("hopterm-enc-test-{}", std::process::id()));
        let paths = Paths::under(&dir);
        let store = JsonStore::new(paths.clone());
        store.save_profile(&sample_profile()).unwrap();
        assert_eq!(store.config_encryption(), ConfigEncryption::Plain);

        let bak = paths.legacy_config_file.with_extension("toml.bak");
        std::fs::write(&bak, "leftover").unwrap();
        store.set_config_pin(Some("1234")).unwrap();
        assert_eq!(store.config_encryption(), ConfigEncryption::Unlocked);
        assert_eq!(store.load_profiles().unwrap().len(), 1);
        assert!(!bak.exists(), "plaintext leftovers must be removed on encryption");

        // A fresh store (new app run) sees an encrypted config and needs the PIN.
        let reopened = JsonStore::new(Paths::under(&dir));
        assert_eq!(reopened.config_encryption(), ConfigEncryption::Locked);
        assert!(reopened.load_profiles().is_err());
        assert!(!reopened.unlock_config("0000").unwrap());
        assert!(reopened.unlock_config("1234").unwrap());
        assert_eq!(reopened.load_profiles().unwrap()[0].display_name, "prod-backend-01");

        reopened.set_config_pin(None).unwrap();
        assert_eq!(reopened.config_encryption(), ConfigEncryption::Plain);
        assert_eq!(JsonStore::new(Paths::under(&dir)).load_profiles().unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn malformed_envelope_never_reads_as_plain() {
        let dir = std::env::temp_dir().join(format!("hopterm-badenv-test-{}", std::process::id()));
        let paths = Paths::under(&dir);
        std::fs::create_dir_all(&paths.root).unwrap();
        std::fs::write(&paths.config_file, r#"{"kdf":"argon2id","salt":123}"#).unwrap();

        let store = JsonStore::new(paths);
        assert_eq!(store.config_encryption(), ConfigEncryption::Locked);
        assert!(store.load_profiles().is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
