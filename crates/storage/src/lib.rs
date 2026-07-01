//! TOML-backed storage for `~/.hopterm/` (spec §10).
//!
//! Layout (matches the mockup's Settings view):
//! ```text
//! ~/.hopterm/
//!   config.toml     # settings + saved profiles + saved routes
//!   known_hosts     # pinned host keys (one per line, fingerprint form)
//!   keys/           # imported private keys (referenced by path)
//! ```
//!
//! The store is deliberately synchronous: the config is small and only touched
//! at startup and on edits, so an async API would add noise for no benefit.

use std::path::{Path, PathBuf};

use hopterm_domain::{
    AppSettings, HostKey, JumpRoute, ProfileId, ProfileStore, SessionProfile, StorageError,
};
use serde::{Deserialize, Serialize};

/// Resolved on-disk locations.
#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
    pub config_file: PathBuf,
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
            config_file: root.join("config.toml"),
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

/// Full on-disk config document (`config.toml`).
#[derive(Debug, Default, Serialize, Deserialize)]
struct ConfigDoc {
    #[serde(default)]
    settings: AppSettings,
    #[serde(default)]
    profiles: Vec<SessionProfile>,
    #[serde(default)]
    routes: Vec<JumpRoute>,
}

/// The concrete [`ProfileStore`].
#[derive(Debug, Clone)]
pub struct TomlStore {
    paths: Paths,
    /// When `false` (mockup toggle "Сохранять конфиг на диск"), writes are no-ops
    /// and the config lives only in memory for the session.
    persist: bool,
}

impl TomlStore {
    pub fn new(paths: Paths) -> Self {
        Self { paths, persist: true }
    }

    pub fn with_persistence(mut self, persist: bool) -> Self {
        self.persist = persist;
        self
    }

    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    fn read_doc(&self) -> Result<ConfigDoc, StorageError> {
        match std::fs::read_to_string(&self.paths.config_file) {
            Ok(text) => toml::from_str(&text).map_err(|e| StorageError::Serde(e.to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ConfigDoc::default()),
            Err(e) => Err(StorageError::Io {
                path: self.paths.config_file.display().to_string(),
                message: e.to_string(),
            }),
        }
    }

    fn write_doc(&self, doc: &ConfigDoc) -> Result<(), StorageError> {
        if !self.persist {
            return Ok(());
        }
        self.paths.ensure_root()?;
        let text = toml::to_string_pretty(doc).map_err(|e| StorageError::Serde(e.to_string()))?;
        atomic_write(&self.paths.config_file, text.as_bytes())
    }
}

impl ProfileStore for TomlStore {
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
        let store = TomlStore::new(Paths::under(&dir));
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
        let store = TomlStore::new(Paths::under(&dir));
        let mut p = sample_profile();
        p.route.target.auth_method = AuthMethod::Password;
        p.route.target.password = Some("s3cr3t-pw".into());
        store.save_profile(&p).unwrap();
        let loaded = store.load_profiles().unwrap();
        assert_eq!(loaded[0].target().password.as_deref(), Some("s3cr3t-pw"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
