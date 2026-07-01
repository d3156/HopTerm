//! Security layer: credentials, host-key verification, trust policy (spec §6.3).
//!
//! Two responsibilities:
//! * [`CredentialStore`] impls that resolve secrets *lazily* and keep them out of
//!   profiles and logs.
//! * A [`HostVerifier`] that pins keys in `known_hosts` and enforces the chosen
//!   [`TrustPolicy`].

use std::sync::Mutex;

use async_trait::async_trait;
use hopterm_domain::{
    CredentialStore, HostId, HostKey, HostKeyDecision, HostVerifier, SecurityError, TrustPolicy,
};
use hopterm_storage::KnownHostsFile;

pub mod fingerprint;

pub use fingerprint::sha256_fingerprint;

/// Something that can ask the user for a secret (wired to a GUI dialog, §5.1).
#[async_trait]
pub trait SecretPrompter: Send + Sync {
    async fn prompt_password(&self, host: HostId, username: &str) -> Option<String>;
    async fn prompt_passphrase(&self, key_path: &str) -> Option<String>;
}

/// Resolves secrets by prompting (GUI) with a small in-memory cache so the user
/// isn't asked twice within a session. Private keys are read from disk.
pub struct PromptCredentialStore {
    prompter: std::sync::Arc<dyn SecretPrompter>,
    cache: Mutex<std::collections::HashMap<String, String>>,
}

impl PromptCredentialStore {
    pub fn new(prompter: std::sync::Arc<dyn SecretPrompter>) -> Self {
        Self {
            prompter,
            cache: Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn cached(&self, key: &str) -> Option<String> {
        self.cache.lock().unwrap().get(key).cloned()
    }
    fn store(&self, key: &str, val: &str) {
        self.cache.lock().unwrap().insert(key.to_string(), val.to_string());
    }
}

#[async_trait]
impl CredentialStore for PromptCredentialStore {
    async fn password(&self, host: HostId, username: &str) -> Result<String, SecurityError> {
        let ck = format!("pw:{host}:{username}");
        if let Some(v) = self.cached(&ck) {
            return Ok(v);
        }
        let v = self
            .prompter
            .prompt_password(host, username)
            .await
            .ok_or_else(|| SecurityError::MissingCredential(format!("{username}@{host}")))?;
        self.store(&ck, &v);
        Ok(v)
    }

    async fn passphrase(&self, key_path: &str) -> Result<String, SecurityError> {
        let ck = format!("pp:{key_path}");
        if let Some(v) = self.cached(&ck) {
            return Ok(v);
        }
        let v = self
            .prompter
            .prompt_passphrase(key_path)
            .await
            .ok_or_else(|| SecurityError::MissingCredential(key_path.to_string()))?;
        self.store(&ck, &v);
        Ok(v)
    }

    async fn private_key(&self, key_path: &str) -> Result<Vec<u8>, SecurityError> {
        let path = expand_tilde(key_path);
        tokio::fs::read(&path)
            .await
            .map_err(|e| SecurityError::KeyLoad(format!("{path}: {e}")))
    }
}

/// Preloaded credentials for tests and the offline mock (no prompting).
#[derive(Default)]
pub struct MemoryCredentialStore {
    pub passwords: std::collections::HashMap<String, String>,
    pub passphrases: std::collections::HashMap<String, String>,
}

#[async_trait]
impl CredentialStore for MemoryCredentialStore {
    async fn password(&self, _host: HostId, username: &str) -> Result<String, SecurityError> {
        self.passwords
            .get(username)
            .cloned()
            .ok_or_else(|| SecurityError::MissingCredential(username.to_string()))
    }
    async fn passphrase(&self, key_path: &str) -> Result<String, SecurityError> {
        self.passphrases
            .get(key_path)
            .cloned()
            .ok_or_else(|| SecurityError::MissingCredential(key_path.to_string()))
    }
    async fn private_key(&self, key_path: &str) -> Result<Vec<u8>, SecurityError> {
        let path = expand_tilde(key_path);
        std::fs::read(&path).map_err(|e| SecurityError::KeyLoad(format!("{path}: {e}")))
    }
}

/// `known_hosts`-backed verifier enforcing a [`TrustPolicy`] (§5.1, §6.3).
pub struct KnownHostsVerifier {
    file: KnownHostsFile,
    policy: TrustPolicy,
    /// Cached pinned keys; refreshed on `remember`.
    pinned: Mutex<Vec<HostKey>>,
}

impl KnownHostsVerifier {
    pub fn new(file: KnownHostsFile, policy: TrustPolicy) -> Self {
        let pinned = file.load().unwrap_or_default();
        Self {
            file,
            policy,
            pinned: Mutex::new(pinned),
        }
    }

    fn find(&self, host: &str, port: u16) -> Option<HostKey> {
        self.pinned
            .lock()
            .unwrap()
            .iter()
            .find(|k| k.host == host && k.port == port)
            .cloned()
    }
}

impl HostVerifier for KnownHostsVerifier {
    fn check(&self, key: &HostKey) -> Result<HostKeyDecision, SecurityError> {
        match self.find(&key.host, key.port) {
            Some(pinned) if pinned.fingerprint_sha256 == key.fingerprint_sha256 => {
                // Even a matching key prompts under AlwaysAsk.
                if self.policy == TrustPolicy::AlwaysAsk {
                    Ok(HostKeyDecision::Unknown { key: key.clone() })
                } else {
                    Ok(HostKeyDecision::Trusted)
                }
            }
            Some(pinned) => Ok(HostKeyDecision::Mismatch {
                expected: pinned,
                presented: key.clone(),
            }),
            None => match self.policy {
                // Strict refuses unknown keys outright (caller maps to rejection).
                TrustPolicy::Strict => Ok(HostKeyDecision::Mismatch {
                    expected: HostKey {
                        host: key.host.clone(),
                        port: key.port,
                        algorithm: "(none pinned)".into(),
                        fingerprint_sha256: "(strict policy)".into(),
                    },
                    presented: key.clone(),
                }),
                _ => Ok(HostKeyDecision::Unknown { key: key.clone() }),
            },
        }
    }

    fn remember(&self, key: &HostKey) -> Result<(), SecurityError> {
        self.file
            .append(key)
            .map_err(|e| SecurityError::Keystore(e.to_string()))?;
        let mut pinned = self.pinned.lock().unwrap();
        pinned.retain(|k| !(k.host == key.host && k.port == key.port));
        pinned.push(key.clone());
        Ok(())
    }
}

/// A [`HostVerifier`] that asks the user to confirm a first-contact key via a
/// supplied (blocking) callback, then pins it (§5.1 "явное подтверждение").
///
/// Wraps a [`KnownHostsVerifier`]: known keys pass silently, mismatches are
/// rejected, and unknown keys trigger `ask`. The callback returns `true` to
/// trust+pin or `false` to reject. The callback runs on the connecting task's
/// thread and may block while a GUI dialog is shown.
pub struct InteractiveHostVerifier {
    inner: KnownHostsVerifier,
    ask: std::sync::Arc<dyn Fn(&HostKey) -> bool + Send + Sync>,
}

impl InteractiveHostVerifier {
    pub fn new(
        inner: KnownHostsVerifier,
        ask: std::sync::Arc<dyn Fn(&HostKey) -> bool + Send + Sync>,
    ) -> Self {
        Self { inner, ask }
    }
}

impl HostVerifier for InteractiveHostVerifier {
    fn check(&self, key: &HostKey) -> Result<HostKeyDecision, SecurityError> {
        match self.inner.check(key)? {
            HostKeyDecision::Trusted => Ok(HostKeyDecision::Trusted),
            mismatch @ HostKeyDecision::Mismatch { .. } => Ok(mismatch),
            HostKeyDecision::Unknown { key } => {
                if (self.ask)(&key) {
                    self.inner.remember(&key)?;
                    Ok(HostKeyDecision::Trusted)
                } else {
                    // User declined: present as a mismatch so the transport aborts
                    // before any credential is sent.
                    Ok(HostKeyDecision::Mismatch {
                        expected: key.clone(),
                        presented: key,
                    })
                }
            }
        }
    }

    fn remember(&self, key: &HostKey) -> Result<(), SecurityError> {
        self.inner.remember(key)
    }
}

/// Expand a leading `~/` to the user's home directory.
pub fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(base) = directories_home() {
            return format!("{base}/{rest}");
        }
    }
    path.to_string()
}

fn directories_home() -> Option<String> {
    std::env::var("HOME").ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tofu_unknown_then_trusted_after_remember() {
        let dir = std::env::temp_dir().join(format!("hopterm-kh-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = KnownHostsFile::new(dir.join("known_hosts"), true);
        let v = KnownHostsVerifier::new(file, TrustPolicy::TrustOnFirstUse);
        let key = HostKey {
            host: "h".into(),
            port: 22,
            algorithm: "ssh-ed25519".into(),
            fingerprint_sha256: "SHA256:abc".into(),
        };
        assert!(matches!(v.check(&key).unwrap(), HostKeyDecision::Unknown { .. }));
        v.remember(&key).unwrap();
        assert!(matches!(v.check(&key).unwrap(), HostKeyDecision::Trusted));

        let evil = HostKey { fingerprint_sha256: "SHA256:evil".into(), ..key.clone() };
        assert!(matches!(v.check(&evil).unwrap(), HostKeyDecision::Mismatch { .. }));
        std::fs::remove_dir_all(&dir).ok();
    }
}
