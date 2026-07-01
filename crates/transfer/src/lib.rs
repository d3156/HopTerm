//! SFTP-over-SSH transfer layer (spec §5.5).
//!
//! This crate is transport-agnostic: it is handed an already-open byte stream
//! (the SFTP subsystem channel built by the `ssh` crate over the *existing*
//! multi-hop chain, §5.2) and speaks SFTP over it. It never opens its own
//! sockets, so file transfers automatically traverse the same jump hosts as the
//! shell session.

use async_trait::async_trait;
use hopterm_domain::{
    CancelToken, ProgressSink, RemoteEntry, SftpSession as SftpSessionTrait, TransferError,
};
use russh_sftp::client::SftpSession as RusshSftpSession;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Chunk size for streamed up/downloads. 32 KiB balances syscall overhead
/// against responsiveness of progress + cancellation (§5.5 large files).
const CHUNK: usize = 32 * 1024;

/// Concrete [`SftpSessionTrait`] backed by `russh-sftp`.
pub struct RusshSftp {
    inner: RusshSftpSession,
}

impl RusshSftp {
    /// Wrap an open SFTP-subsystem stream (an SSH channel turned into a duplex
    /// stream by the `ssh` crate).
    pub async fn open_over_stream<S>(stream: S) -> Result<Self, TransferError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let inner = RusshSftpSession::new(stream)
            .await
            .map_err(|e| TransferError::Protocol(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Borrow the underlying session for advanced callers.
    pub fn inner(&self) -> &RusshSftpSession {
        &self.inner
    }
}

fn map_err(e: russh_sftp::client::error::Error) -> TransferError {
    use russh_sftp::client::error::Error as E;
    match e {
        E::Status(s) => {
            let msg = s.error_message.clone();
            // 2 == SSH_FX_NO_SUCH_FILE, 3 == SSH_FX_PERMISSION_DENIED.
            match s.status_code as u32 {
                2 => TransferError::NotFound(msg),
                3 => TransferError::PermissionDenied(msg),
                _ => TransferError::Protocol(msg),
            }
        }
        other => TransferError::Protocol(other.to_string()),
    }
}

fn basename(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

#[async_trait]
impl SftpSessionTrait for RusshSftp {
    async fn list_dir(&self, path: &str) -> Result<Vec<RemoteEntry>, TransferError> {
        let dir = self.inner.read_dir(path.to_string()).await.map_err(map_err)?;
        let mut out = Vec::new();
        for entry in dir {
            let meta = entry.metadata();
            let ft = entry.file_type();
            out.push(RemoteEntry {
                name: entry.file_name(),
                is_dir: ft.is_dir(),
                is_symlink: ft.is_symlink(),
                size: meta.len(),
                mode: meta.permissions,
                modified: meta.mtime.map(|m| m as i64),
            });
        }
        Ok(out)
    }

    async fn stat(&self, path: &str) -> Result<RemoteEntry, TransferError> {
        let meta = self.inner.metadata(path.to_string()).await.map_err(map_err)?;
        Ok(RemoteEntry {
            name: basename(path),
            is_dir: meta.is_dir(),
            is_symlink: meta.is_symlink(),
            size: meta.len(),
            mode: meta.permissions,
            modified: meta.mtime.map(|m| m as i64),
        })
    }

    async fn canonicalize(&self, path: &str) -> Result<String, TransferError> {
        self.inner.canonicalize(path.to_string()).await.map_err(map_err)
    }

    async fn mkdir(&self, path: &str) -> Result<(), TransferError> {
        self.inner.create_dir(path.to_string()).await.map_err(map_err)
    }

    async fn rename(&self, from: &str, to: &str) -> Result<(), TransferError> {
        self.inner
            .rename(from.to_string(), to.to_string())
            .await
            .map_err(map_err)
    }

    async fn remove(&self, path: &str) -> Result<(), TransferError> {
        // Try file first; fall back to directory removal.
        match self.inner.remove_file(path.to_string()).await {
            Ok(()) => Ok(()),
            Err(_) => self.inner.remove_dir(path.to_string()).await.map_err(map_err),
        }
    }

    async fn upload(
        &self,
        local_path: &str,
        remote_path: &str,
        progress: &dyn ProgressSink,
        cancel: &CancelToken,
    ) -> Result<(), TransferError> {
        let mut local =
            tokio::fs::File::open(local_path)
                .await
                .map_err(|e| TransferError::LocalIo {
                    path: local_path.to_string(),
                    message: e.to_string(),
                })?;
        let total = local.metadata().await.map(|m| m.len()).unwrap_or(0);

        let mut remote = self
            .inner
            .create(remote_path.to_string())
            .await
            .map_err(map_err)?;

        let mut buf = vec![0u8; CHUNK];
        let mut transferred = 0u64;
        progress.on_progress(0, total);
        loop {
            if cancel.is_cancelled() {
                return Err(TransferError::Cancelled);
            }
            let n = local.read(&mut buf).await.map_err(|e| TransferError::LocalIo {
                path: local_path.to_string(),
                message: e.to_string(),
            })?;
            if n == 0 {
                break;
            }
            remote
                .write_all(&buf[..n])
                .await
                .map_err(|e| TransferError::Protocol(e.to_string()))?;
            transferred += n as u64;
            progress.on_progress(transferred, total);
        }
        remote
            .shutdown()
            .await
            .map_err(|e| TransferError::Protocol(e.to_string()))?;
        Ok(())
    }

    async fn download(
        &self,
        remote_path: &str,
        local_path: &str,
        progress: &dyn ProgressSink,
        cancel: &CancelToken,
    ) -> Result<(), TransferError> {
        let total = self
            .inner
            .metadata(remote_path.to_string())
            .await
            .map(|m| m.len())
            .unwrap_or(0);

        let mut remote = self.inner.open(remote_path.to_string()).await.map_err(map_err)?;
        let mut local =
            tokio::fs::File::create(local_path)
                .await
                .map_err(|e| TransferError::LocalIo {
                    path: local_path.to_string(),
                    message: e.to_string(),
                })?;

        let mut buf = vec![0u8; CHUNK];
        let mut transferred = 0u64;
        progress.on_progress(0, total);
        loop {
            if cancel.is_cancelled() {
                return Err(TransferError::Cancelled);
            }
            let n = remote
                .read(&mut buf)
                .await
                .map_err(|e| TransferError::Protocol(e.to_string()))?;
            if n == 0 {
                break;
            }
            local
                .write_all(&buf[..n])
                .await
                .map_err(|e| TransferError::LocalIo {
                    path: local_path.to_string(),
                    message: e.to_string(),
                })?;
            transferred += n as u64;
            progress.on_progress(transferred, total);
        }
        local.flush().await.map_err(|e| TransferError::LocalIo {
            path: local_path.to_string(),
            message: e.to_string(),
        })?;
        Ok(())
    }
}
