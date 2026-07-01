//! Orchestration layer (spec §7.1.2).
//!
//! This crate wires the lower layers into a few service handles and a
//! [`SessionManager`] that the GUI drives. The GUI depends only on this crate
//! and on `domain`; it never names `russh`, `russh-sftp` or `alacritty_terminal`
//! directly (§7.2).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use hopterm_domain::*;
use hopterm_security::{
    InteractiveHostVerifier, KnownHostsVerifier, PromptCredentialStore, SecretPrompter,
};
use hopterm_ssh::RusshTransport;
use hopterm_storage::{KnownHostsFile, Paths, TomlStore};
use uuid::Uuid;

/// A blocking callback that asks the user to trust a first-contact host key.
pub type HostKeyAsk = Arc<dyn Fn(&HostKey) -> bool + Send + Sync>;

pub mod demo;
pub mod mock;

pub use mock::MockTransport;

/// The set of service handles every command needs, behind trait objects so the
/// real and mock implementations are interchangeable.
#[derive(Clone)]
pub struct Services {
    pub transport: Arc<dyn SshTransport>,
    pub store: Arc<dyn ProfileStore>,
    pub verifier: Arc<dyn HostVerifier>,
    pub creds: Arc<dyn CredentialStore>,
}

impl Services {
    /// Build the production service set: real `russh` transport, TOML store at
    /// `~/.hopterm/`, `known_hosts` verifier and a prompting credential store.
    /// `host_key_ask`, if provided, turns first-contact keys into interactive
    /// confirmations instead of silent trust-on-first-use.
    pub fn production(
        prompter: Arc<dyn SecretPrompter>,
        host_key_ask: Option<HostKeyAsk>,
        settings: &AppSettings,
    ) -> Self {
        Self::assemble(
            Arc::new(RusshTransport::default()),
            prompter,
            host_key_ask,
            settings,
        )
    }

    /// Build an offline service set backed by [`MockTransport`] — used for the
    /// `--demo` mode and UI development.
    pub fn demo(
        prompter: Arc<dyn SecretPrompter>,
        host_key_ask: Option<HostKeyAsk>,
        settings: &AppSettings,
    ) -> Self {
        Self::assemble(Arc::new(MockTransport), prompter, host_key_ask, settings)
    }

    fn assemble(
        transport: Arc<dyn SshTransport>,
        prompter: Arc<dyn SecretPrompter>,
        host_key_ask: Option<HostKeyAsk>,
        settings: &AppSettings,
    ) -> Self {
        let paths = Paths::default_location();
        let store = TomlStore::new(paths.clone()).with_persistence(settings.persist_config);
        let known_hosts =
            KnownHostsFile::new(paths.known_hosts_file.clone(), settings.persist_config);
        let base = KnownHostsVerifier::new(known_hosts, settings.trust_policy);
        let verifier: Arc<dyn HostVerifier> = match host_key_ask {
            Some(ask) => Arc::new(InteractiveHostVerifier::new(base, ask)),
            None => Arc::new(base),
        };
        let creds = PromptCredentialStore::new(prompter);
        Self {
            transport,
            store: Arc::new(store),
            verifier,
            creds: Arc::new(creds),
        }
    }
}

/// Tracks live sessions and brokers connect / shell / transfer commands.
#[derive(Clone)]
pub struct SessionManager {
    services: Services,
    sessions: Arc<Mutex<HashMap<SessionId, Arc<dyn SshConnection>>>>,
}

impl SessionManager {
    pub fn new(services: Services) -> Self {
        Self {
            services,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn services(&self) -> &Services {
        &self.services
    }

    /// Connect a profile's route end-to-end and register the live connection.
    /// `observer` receives per-hop state for the UI indicator (§9.1).
    pub async fn connect(
        &self,
        profile: &SessionProfile,
        observer: &dyn ConnectionObserver,
    ) -> Result<SessionId, AppError> {
        let conn = self
            .services
            .transport
            .connect(
                &profile.route,
                &*self.services.creds,
                &*self.services.verifier,
                observer,
            )
            .await?;
        let id = SessionId::new(Uuid::new_v4());
        let conn: Arc<dyn SshConnection> = Arc::from(conn);
        self.sessions.lock().unwrap().insert(id, conn);
        Ok(id)
    }

    /// The live connection for a session, if still open.
    pub fn connection(&self, id: SessionId) -> Option<Arc<dyn SshConnection>> {
        self.sessions.lock().unwrap().get(&id).cloned()
    }

    /// Open an interactive shell on an existing session.
    pub async fn open_shell(
        &self,
        id: SessionId,
        size: PtySize,
    ) -> Result<Box<dyn ShellChannel>, AppError> {
        let conn = self
            .connection(id)
            .ok_or_else(|| AppError::Message("no such session".into()))?;
        Ok(conn.open_shell(size).await?)
    }

    /// Tear down and forget a session.
    pub async fn close(&self, id: SessionId) -> Result<(), AppError> {
        let conn = self.sessions.lock().unwrap().remove(&id);
        if let Some(conn) = conn {
            conn.disconnect().await?;
        }
        Ok(())
    }

    pub fn live_session_ids(&self) -> Vec<SessionId> {
        self.sessions.lock().unwrap().keys().copied().collect()
    }
}
