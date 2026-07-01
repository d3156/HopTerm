//! Domain entities — the persisted and in-flight data model (spec §8).
//!
//! Design rules:
//! * Profiles never embed plaintext secrets. A profile describes *which* auth
//!   method to use; the actual password / passphrase is resolved at connect time
//!   through [`crate::traits::CredentialStore`] (spec §6.3).
//! * Everything is `serde`-serializable so [`crate::traits::ProfileStore`] can
//!   round-trip it to TOML (spec §10).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Strongly-typed id wrapper so a `HostId` can never be passed where a
/// `SessionId` is expected.
macro_rules! typed_id {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// Allocate a fresh random id. Callers in pure code can also build
            /// one from an existing [`Uuid`] to keep determinism in tests.
            pub fn new(id: Uuid) -> Self {
                Self(id)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

typed_id!(/// Identifies a reusable [`HostProfile`] node.
    HostId);
typed_id!(/// Identifies a saved [`JumpRoute`].
    RouteId);
typed_id!(/// Identifies a saved [`SessionProfile`].
    ProfileId);
typed_id!(/// Identifies a live [`ActiveSession`].
    SessionId);
typed_id!(/// Identifies a [`TransferJob`].
    JobId);

/// How to authenticate to a single node. The variants carry only *non-secret*
/// material — secrets are fetched lazily from the credential layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthMethod {
    /// Interactive / stored password. The value is resolved at runtime.
    Password,
    /// Public-key auth. `passphrase_protected` drives the passphrase prompt.
    PublicKey {
        key_path: String,
        #[serde(default)]
        passphrase_protected: bool,
    },
    /// Delegate to a running SSH agent (`SSH_AUTH_SOCK`).
    Agent,
}

impl Default for AuthMethod {
    fn default() -> Self {
        AuthMethod::Agent
    }
}

impl AuthMethod {
    /// Short label for badges in the UI (mockup: `ed25519` / `password`).
    pub fn label(&self) -> &'static str {
        match self {
            AuthMethod::Password => "password",
            AuthMethod::PublicKey { .. } => "key",
            AuthMethod::Agent => "agent",
        }
    }
}

/// A single reachable node: one entry in a hop chain (spec §8.1 `HostProfile`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostProfile {
    pub id: HostId,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub username: String,
    pub auth_method: AuthMethod,
    /// Optional password stored alongside the profile (plaintext in config) for
    /// `AuthMethod::Password`. When `None`, the password is prompted at connect
    /// time and never persisted. Mirrors [`SudoConfig::password`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

impl HostProfile {
    /// `user@host:port`, the canonical short form shown in breadcrumbs.
    pub fn endpoint(&self) -> String {
        format!("{}@{}:{}", self.username, self.address, self.port)
    }
}

/// Policy that governs how a route is established and re-established (spec §8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutePolicy {
    /// Build hop-by-hop using `direct-tcpip` channels (the default, spec §5.2).
    DirectTcpIp,
    /// Reserved for a future native ProxyJump-style optimisation.
    ProxyJump,
}

impl Default for RoutePolicy {
    fn default() -> Self {
        RoutePolicy::DirectTcpIp
    }
}

/// An ordered `local -> hop1 -> ... -> target` path (spec §4.2). The chain length
/// is unbounded by design.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// Intermediate jump hosts, in traversal order. Empty == direct connection.
    #[serde(default)]
    pub hops: Vec<HostProfile>,
    /// The final destination.
    pub target: HostProfile,
    #[serde(default)]
    pub policy: RoutePolicy,
}

impl Route {
    /// Every node we must authenticate to, in order: `[hops..., target]`.
    pub fn nodes(&self) -> Vec<&HostProfile> {
        self.hops.iter().chain(std::iter::once(&self.target)).collect()
    }

    /// Number of authenticated hops including the target.
    pub fn len(&self) -> usize {
        self.hops.len() + 1
    }

    pub fn is_empty(&self) -> bool {
        false // a route always has a target
    }

    /// `true` when there are intermediate jump hosts.
    pub fn is_multi_hop(&self) -> bool {
        !self.hops.is_empty()
    }

    /// `localhost → a@h:p → ... → target`, for the breadcrumb in the UI (§9.3).
    pub fn breadcrumb(&self) -> String {
        let mut parts = vec!["localhost".to_string()];
        parts.extend(self.nodes().iter().map(|n| n.endpoint()));
        parts.join(" → ")
    }
}

/// A named, reusable hop chain (spec §8.2 `JumpRoute`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JumpRoute {
    pub id: RouteId,
    pub name: String,
    pub route: Route,
}

/// Per-session terminal preferences (spec §8.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalPreferences {
    pub font_family: String,
    pub font_size: u16,
    pub scrollback_lines: u32,
    /// `$TERM` advertised to the remote (e.g. `xterm-256color`).
    pub term: String,
}

impl Default for TerminalPreferences {
    fn default() -> Self {
        Self {
            font_family: "JetBrains Mono".into(),
            font_size: 14,
            scrollback_lines: 10_000,
            term: "xterm-256color".into(),
        }
    }
}

/// Conflict resolution when a transfer target already exists (spec §5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictPolicy {
    Overwrite,
    Rename,
    Skip,
    /// Ask the user each time.
    Prompt,
}

impl Default for ConflictPolicy {
    fn default() -> Self {
        ConflictPolicy::Prompt
    }
}

/// Per-session transfer preferences (spec §8.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferPreferences {
    pub default_remote_dir: Option<String>,
    pub default_local_dir: Option<String>,
    pub conflict_policy: ConflictPolicy,
    /// `tar -czf` before download, per the mockup's settings toggle.
    pub compress_downloads: bool,
}

impl Default for TransferPreferences {
    fn default() -> Self {
        Self {
            default_remote_dir: None,
            default_local_dir: None,
            conflict_policy: ConflictPolicy::default(),
            compress_downloads: false,
        }
    }
}

/// Optional privilege escalation run right after the shell opens (the
/// "Подключиться с sudo" flow). `command` is one of `sudo su` / `sudo -s` /
/// `su` / `su root`; `password` is fed to the prompt if set.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SudoConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// A saved connection — the entity behind a "host card" in the mockup
/// (spec §8.3 `SessionProfile`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionProfile {
    pub id: ProfileId,
    pub display_name: String,
    pub route: Route,
    #[serde(default)]
    pub terminal_preferences: TerminalPreferences,
    #[serde(default)]
    pub transfer_preferences: TransferPreferences,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Privilege escalation for the "connect with sudo" button.
    #[serde(default)]
    pub sudo: SudoConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

impl SessionProfile {
    pub fn target(&self) -> &HostProfile {
        &self.route.target
    }
}

/// Lifecycle state of a live connection, with enough detail to drive the
/// connection indicator and per-hop diagnostics (spec §6.2, §9.1, §11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ConnectionState {
    Disconnected,
    /// Resolving DNS / preparing the first socket.
    Resolving,
    /// TCP + transport handshake to hop `index` of `total`.
    Connecting { index: usize, total: usize },
    /// Authenticating to hop `index` of `total`.
    Authenticating { index: usize, total: usize },
    /// Fully established; shell channel open.
    Connected,
    /// A transient failure is being retried (spec §5.1 reconnect).
    Reconnecting { attempt: u32 },
    /// Terminal failure. `hop_index` localises the fault (spec §6.2).
    Failed { hop_index: usize, message: String },
}

impl ConnectionState {
    pub fn is_live(&self) -> bool {
        matches!(self, ConnectionState::Connected)
    }
    pub fn is_busy(&self) -> bool {
        matches!(
            self,
            ConnectionState::Resolving
                | ConnectionState::Connecting { .. }
                | ConnectionState::Authenticating { .. }
                | ConnectionState::Reconnecting { .. }
        )
    }
}

/// A live shell session (spec §8.4 `ActiveSession`).
#[derive(Debug, Clone)]
pub struct ActiveSession {
    pub session_id: SessionId,
    pub profile_id: Option<ProfileId>,
    pub display_name: String,
    pub connection_state: ConnectionState,
    pub current_route: Route,
    /// Best-effort remote working directory, when discoverable.
    pub remote_pwd: Option<String>,
    /// Unix epoch seconds; `None` until connected. The runtime stamps this.
    pub started_at: Option<i64>,
}

/// Upload vs download (spec §8.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferDirection {
    Upload,
    Download,
}

/// State machine for a transfer (spec §8.5, §5.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TransferStatus {
    Queued,
    Running,
    Paused,
    Completed,
    Cancelled,
    Failed { message: String },
}

/// One file transfer (spec §8.5 `TransferJob`).
#[derive(Debug, Clone)]
pub struct TransferJob {
    pub job_id: JobId,
    pub direction: TransferDirection,
    pub local_path: String,
    pub remote_path: String,
    /// Total size in bytes (0 if unknown until stat completes).
    pub size: u64,
    /// Bytes moved so far.
    pub transferred: u64,
    pub status: TransferStatus,
    pub associated_session: SessionId,
}

impl TransferJob {
    /// Progress in `0.0..=1.0`; `0.0` while size is unknown.
    pub fn progress(&self) -> f32 {
        if self.size == 0 {
            return match self.status {
                TransferStatus::Completed => 1.0,
                _ => 0.0,
            };
        }
        (self.transferred as f32 / self.size as f32).clamp(0.0, 1.0)
    }
}

/// A remote filesystem entry returned by SFTP listings (spec §5.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteEntry {
    pub name: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    /// Unix mode bits, when available.
    pub mode: Option<u32>,
    /// Modified time, unix epoch seconds.
    pub modified: Option<i64>,
}

/// A presented host public key for verification (spec §5.1, §8 host-key).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostKey {
    pub host: String,
    pub port: u16,
    /// Key algorithm, e.g. `ssh-ed25519`.
    pub algorithm: String,
    /// `SHA256:...` base64 fingerprint, as `ssh-keygen -l` prints it.
    pub fingerprint_sha256: String,
}

impl HostKey {
    pub fn host_port(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Trust model for host-key checking (spec §6.3 "clear security model").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustPolicy {
    /// Accept-and-remember the first time, reject on later mismatch.
    TrustOnFirstUse,
    /// Always prompt the user, even for known keys.
    AlwaysAsk,
    /// Only connect to keys already in `known_hosts`.
    Strict,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        TrustPolicy::TrustOnFirstUse
    }
}

/// Result of checking a presented [`HostKey`] against storage (spec §5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyDecision {
    /// Key already pinned and matches — proceed silently.
    Trusted,
    /// First contact — UI must show the fingerprint and ask (TOFU).
    Unknown { key: HostKey },
    /// Pinned key differs from presented one — likely MITM, hard stop.
    Mismatch { expected: HostKey, presented: HostKey },
}
