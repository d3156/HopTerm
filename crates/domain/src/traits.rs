//! Inter-layer contracts (spec §7, deliverable §15.7).
//!
//! These traits are the only thing the upper layers (`app`, `ui`) know about the
//! lower layers. `russh`, `russh-sftp` and `alacritty_terminal` live entirely
//! behind them, satisfying the "GUI must not know the SSH transport" rule (§7.2).
//!
//! Async methods use [`async_trait`] so the traits stay object-safe and can be
//! held as `Arc<dyn ...>` by the orchestration layer.

use async_trait::async_trait;

use crate::entities::*;
use crate::error::{SecurityError, SshError, StorageError, TransferError};
use crate::terminal::{Grid, PtySize};

// ---------------------------------------------------------------------------
// SSH transport / routing (`ssh` crate)
// ---------------------------------------------------------------------------

/// Establishes connections, including multi-hop chains, and hands back a live
/// [`SshConnection`]. Implemented by the `ssh` crate over `russh`; the chain
/// builder ("routing" layer, §7.1.4) lives behind this single entry point so
/// the same path-building logic serves both shells and transfers (§5.2).
#[async_trait]
pub trait SshTransport: Send + Sync {
    /// Build `local -> hop1 -> ... -> target`, authenticating and verifying the
    /// host key at every node. `observer` receives per-hop progress so the UI
    /// can animate the connection indicator and localise failures (§6.2, §11).
    async fn connect(
        &self,
        route: &Route,
        creds: &dyn CredentialStore,
        verifier: &dyn HostVerifier,
        observer: &dyn ConnectionObserver,
    ) -> Result<Box<dyn SshConnection>, SshError>;
}

/// Receives lifecycle transitions during connect/reconnect (§9.1 indicator).
pub trait ConnectionObserver: Send + Sync {
    fn on_state(&self, state: ConnectionState);
}

/// A live connection to the *target* host, reached through the full chain. All
/// channels (shell, exec, sftp) are multiplexed over the final hop's transport.
#[async_trait]
pub trait SshConnection: Send + Sync {
    /// Request a PTY + interactive shell. Returns a duplex channel the app pumps
    /// bytes through (§5.3). `size` sizes the PTY for TUIs.
    async fn open_shell(&self, size: PtySize) -> Result<Box<dyn ShellChannel>, SshError>;

    /// Run one command to completion, capturing stdout/stderr and exit status.
    /// Used by "quick commands" (mockup) and route testing (§9.2).
    async fn exec(&self, command: &str) -> Result<ExecOutput, SshError>;

    /// Run a command and stream its stdout in chunks instead of buffering it
    /// (used to pipe a remote `tar` archive through to a local extractor without
    /// staging the whole thing in memory). §5.5 large transfers.
    async fn exec_stream(&self, command: &str) -> Result<Box<dyn ExecStream>, SshError>;

    /// Open an SFTP subsystem over this connection for file transfer (§5.5).
    async fn open_sftp(&self) -> Result<Box<dyn SftpSession>, SshError>;

    /// Current connection state (§8.4).
    fn state(&self) -> ConnectionState;

    /// Start a **local TCP port-forward** (`ssh -L`): bind `bind_addr:local_port`
    /// on this machine and tunnel every accepted connection through the whole
    /// chain to `remote_host:remote_port` on the target's network. Pass
    /// `local_port == 0` to let the OS pick a free port (read it back from the
    /// returned handle). The forward lives until its [`PortForward::stop`] is
    /// called or the handle is dropped.
    ///
    /// The default implementation reports that forwarding is unsupported, so
    /// transports that don't implement it (e.g. the mock) need no changes.
    async fn forward_local(
        &self,
        bind_addr: &str,
        local_port: u16,
        remote_host: &str,
        remote_port: u16,
    ) -> Result<Box<dyn PortForward>, SshError> {
        let _ = (bind_addr, local_port, remote_host, remote_port);
        Err(SshError::Other(
            "проброс портов не поддерживается этим транспортом".into(),
        ))
    }

    /// Start a **dynamic SOCKS5 proxy** (`ssh -D`): bind `bind_addr:local_port`
    /// as a local SOCKS5 server and tunnel each of its CONNECT requests through
    /// the chain to the client-chosen target. Point a browser/app at
    /// `socks5://bind_addr:local_port` to route traffic via the target host.
    /// `local_port == 0` lets the OS pick. Same default (unsupported) as
    /// [`Self::forward_local`].
    async fn forward_socks(
        &self,
        bind_addr: &str,
        local_port: u16,
    ) -> Result<Box<dyn PortForward>, SshError> {
        let _ = (bind_addr, local_port);
        Err(SshError::Other(
            "SOCKS-прокси не поддерживается этим транспортом".into(),
        ))
    }

    /// Gracefully tear down the whole chain.
    async fn disconnect(&self) -> Result<(), SshError>;
}

/// A live local port-forward listener. Dropping it (or calling [`Self::stop`])
/// stops accepting new connections and tears the tunnel down.
pub trait PortForward: Send + Sync {
    /// The local port actually bound — meaningful when `0` was requested and the
    /// OS assigned one.
    fn local_port(&self) -> u16;

    /// Stop the forward: close the listener and abort in-flight tunnels.
    fn stop(&self);
}

/// The duplex byte pipe for an interactive shell.
#[async_trait]
pub trait ShellChannel: Send {
    /// Send keystrokes / pasted text to the remote PTY.
    async fn write_input(&mut self, data: &[u8]) -> Result<(), SshError>;

    /// Await the next chunk of terminal output. `Ok(None)` == channel closed.
    async fn read_output(&mut self) -> Result<Option<Vec<u8>>, SshError>;

    /// Inform the remote PTY of a window resize (§5.3 resize).
    async fn resize(&mut self, size: PtySize) -> Result<(), SshError>;
}

/// Streaming stdout of a remote [`SshConnection::exec_stream`], delivered in
/// chunks like a download. `Ok(None)` marks end of stream; a non-zero remote
/// exit surfaces as `Err`.
#[async_trait]
pub trait ExecStream: Send {
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, SshError>;
}

/// Captured result of a one-shot [`SshConnection::exec`].
#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: Option<u32>,
}

// ---------------------------------------------------------------------------
// File transfer (`transfer` crate)
// ---------------------------------------------------------------------------

/// An open SFTP session bound to a connection. Reuses the existing SSH chain,
/// never builds its own (§5.2 "переиспользование логики маршрутизации").
#[async_trait]
pub trait SftpSession: Send + Sync {
    /// List a remote directory (§5.5 directory listing).
    async fn list_dir(&self, path: &str) -> Result<Vec<RemoteEntry>, TransferError>;

    /// Stat a single entry (§5.5 stat).
    async fn stat(&self, path: &str) -> Result<RemoteEntry, TransferError>;

    /// Resolve a (possibly relative) path to its absolute form, so the file
    /// browser can navigate with stable paths.
    async fn canonicalize(&self, path: &str) -> Result<String, TransferError>;

    async fn mkdir(&self, path: &str) -> Result<(), TransferError>;
    async fn rename(&self, from: &str, to: &str) -> Result<(), TransferError>;
    async fn remove(&self, path: &str) -> Result<(), TransferError>;

    /// Upload `local_path` -> `remote_path`, reporting bytes through `progress`.
    /// Honour cancellation via [`CancelToken`] (§5.5 cancel, large files).
    async fn upload(
        &self,
        local_path: &str,
        remote_path: &str,
        progress: &dyn ProgressSink,
        cancel: &CancelToken,
    ) -> Result<(), TransferError>;

    /// Download `remote_path` -> `local_path`.
    async fn download(
        &self,
        remote_path: &str,
        local_path: &str,
        progress: &dyn ProgressSink,
        cancel: &CancelToken,
    ) -> Result<(), TransferError>;
}

/// Runtime-agnostic progress callback so the domain never depends on a specific
/// channel type.
pub trait ProgressSink: Send + Sync {
    fn on_progress(&self, transferred: u64, total: u64);
}

/// Cooperative cancellation flag shared with a running transfer (§5.5 cancel).
#[derive(Debug, Clone, Default)]
pub struct CancelToken {
    inner: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.inner.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    pub fn is_cancelled(&self) -> bool {
        self.inner.load(std::sync::atomic::Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// Storage (`storage` crate)
// ---------------------------------------------------------------------------

/// Persistence for everything in the config dir (`~/.hopterm/`, §10).
/// Synchronous: the config is small and read at startup / on edits.
pub trait ProfileStore: Send + Sync {
    fn load_profiles(&self) -> Result<Vec<SessionProfile>, StorageError>;
    fn save_profile(&self, profile: &SessionProfile) -> Result<(), StorageError>;
    fn delete_profile(&self, id: ProfileId) -> Result<(), StorageError>;

    fn load_routes(&self) -> Result<Vec<JumpRoute>, StorageError>;
    fn save_route(&self, route: &JumpRoute) -> Result<(), StorageError>;

    fn load_settings(&self) -> Result<AppSettings, StorageError>;
    fn save_settings(&self, settings: &AppSettings) -> Result<(), StorageError>;
}

/// Global, non-secret application settings (mockup "Настройки", §10).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AppSettings {
    pub theme: Theme,
    pub trust_policy: TrustPolicy,
    /// Persist config to disk at all (mockup toggle).
    pub persist_config: bool,
    /// Store hop passwords in the OS keychain (mockup toggle).
    pub store_passwords: bool,
    /// Confirm before destructive `exec` commands (mockup toggle).
    pub confirm_exec: bool,
    pub keepalive_interval_secs: u64,
    pub connect_timeout_secs: u64,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme: Theme::Dark,
            trust_policy: TrustPolicy::default(),
            persist_config: true,
            store_passwords: true,
            confirm_exec: false,
            keepalive_interval_secs: 30,
            connect_timeout_secs: 20,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    Dark,
    Light,
}

// ---------------------------------------------------------------------------
// Security (`security` crate)
// ---------------------------------------------------------------------------

/// Resolves secrets on demand so they never live in profiles or logs (§6.3).
#[async_trait]
pub trait CredentialStore: Send + Sync {
    /// Password for a node, by stable host id. May prompt or hit a keychain.
    async fn password(&self, host: HostId, username: &str) -> Result<String, SecurityError>;

    /// Passphrase to decrypt a private key file.
    async fn passphrase(&self, key_path: &str) -> Result<String, SecurityError>;

    /// Raw private key bytes for public-key auth.
    async fn private_key(&self, key_path: &str) -> Result<Vec<u8>, SecurityError>;
}

/// Checks presented host keys against pinned ones and applies trust policy
/// (§5.1, §6.3). Implemented by the `security` crate over `storage`.
pub trait HostVerifier: Send + Sync {
    /// Decide what to do with a freshly presented key.
    fn check(&self, key: &HostKey) -> Result<HostKeyDecision, SecurityError>;

    /// Pin a key after the user accepted it (TOFU / explicit confirm, §5.1).
    fn remember(&self, key: &HostKey) -> Result<(), SecurityError>;
}

// ---------------------------------------------------------------------------
// Terminal (`terminal` crate)
// ---------------------------------------------------------------------------

/// Stateful VT/ANSI engine: bytes in, [`Grid`] snapshots out (§5.3).
/// Implemented over `alacritty_terminal`; the GUI only ever sees [`Grid`].
pub trait TerminalBackend: Send {
    /// Feed raw bytes received from the [`ShellChannel`].
    fn feed(&mut self, bytes: &[u8]);

    /// Resize the screen model (paired with a PTY resize).
    fn resize(&mut self, size: PtySize);

    /// Current visible screen for painting.
    fn snapshot(&self) -> Grid;

    /// Plain-text of the scrollback + screen for selection/copy (§5.3).
    fn selection_text(&self, start: (u16, u16), end: (u16, u16)) -> String;

    /// Scroll the viewport within the scrollback buffer.
    fn scroll(&mut self, delta_lines: i32);
}
