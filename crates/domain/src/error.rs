//! Structured, layer-aware errors (spec §6.2, §11).
//!
//! Errors carry enough structure that the UI can localise a multi-hop failure
//! to a specific hop and show technical detail in the error dialog (§5.4), while
//! never leaking secrets into messages (§6.3, §11).

use thiserror::Error;

/// Errors from the SSH transport / routing layers.
#[derive(Debug, Error, Clone)]
pub enum SshError {
    /// DNS / TCP failure reaching a node.
    #[error("hop {hop_index}: network error reaching {endpoint}: {source_msg}")]
    Network {
        hop_index: usize,
        endpoint: String,
        source_msg: String,
    },

    /// Transport handshake / key exchange failed.
    #[error("hop {hop_index}: SSH handshake failed with {endpoint}: {source_msg}")]
    Handshake {
        hop_index: usize,
        endpoint: String,
        source_msg: String,
    },

    /// Authentication rejected. Never includes the attempted secret.
    #[error("hop {hop_index}: authentication failed for {username}@{endpoint}")]
    Auth {
        hop_index: usize,
        endpoint: String,
        username: String,
    },

    /// Host-key verification refused the connection.
    #[error("hop {hop_index}: host key rejected for {endpoint}: {reason}")]
    HostKeyRejected {
        hop_index: usize,
        endpoint: String,
        reason: String,
    },

    /// Opening a channel (shell / direct-tcpip / sftp) failed.
    #[error("hop {hop_index}: failed to open {channel} channel: {source_msg}")]
    Channel {
        hop_index: usize,
        channel: String,
        source_msg: String,
    },

    /// The session dropped after being established (spec §6.2).
    #[error("session disconnected: {0}")]
    Disconnected(String),

    /// Operation exceeded its deadline (spec §5.1 timeout).
    #[error("operation timed out after {0}s")]
    Timeout(u64),

    #[error("ssh error: {0}")]
    Other(String),
}

impl SshError {
    /// The hop the fault is attributed to, for per-hop diagnostics in the UI.
    pub fn hop_index(&self) -> Option<usize> {
        match self {
            SshError::Network { hop_index, .. }
            | SshError::Handshake { hop_index, .. }
            | SshError::Auth { hop_index, .. }
            | SshError::HostKeyRejected { hop_index, .. }
            | SshError::Channel { hop_index, .. } => Some(*hop_index),
            _ => None,
        }
    }
}

/// Errors from the SFTP / transfer layer.
#[derive(Debug, Error, Clone)]
pub enum TransferError {
    #[error("sftp protocol error: {0}")]
    Protocol(String),
    #[error("local IO error for {path}: {message}")]
    LocalIo { path: String, message: String },
    #[error("remote path not found: {0}")]
    NotFound(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("transfer cancelled")]
    Cancelled,
    #[error("transport error: {0}")]
    Transport(#[from] SshError),
    #[error("transfer error: {0}")]
    Other(String),
}

/// Errors from the storage layer (profiles, settings, known_hosts).
#[derive(Debug, Error, Clone)]
pub enum StorageError {
    #[error("io error at {path}: {message}")]
    Io { path: String, message: String },
    #[error("serialization error: {0}")]
    Serde(String),
    #[error("entity not found: {0}")]
    NotFound(String),
}

/// Errors from the security / credential layer.
#[derive(Debug, Error, Clone)]
pub enum SecurityError {
    #[error("credential not available for {0}")]
    MissingCredential(String),
    #[error("keystore error: {0}")]
    Keystore(String),
    #[error("key load error: {0}")]
    KeyLoad(String),
}

/// Errors from the terminal layer.
#[derive(Debug, Error, Clone)]
pub enum TerminalError {
    #[error("pty error: {0}")]
    Pty(String),
    #[error("terminal error: {0}")]
    Other(String),
}

/// Top-level application error that any user command can surface.
#[derive(Debug, Error, Clone)]
pub enum AppError {
    #[error(transparent)]
    Ssh(#[from] SshError),
    #[error(transparent)]
    Transfer(#[from] TransferError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Security(#[from] SecurityError),
    #[error(transparent)]
    Terminal(#[from] TerminalError),
    #[error("{0}")]
    Message(String),
}

pub type Result<T, E = AppError> = std::result::Result<T, E>;
