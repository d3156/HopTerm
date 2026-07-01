//! Offline mock transport (spec §7.1.2 — wiring; lets the GUI run without a
//! live SSH server). It implements the very same [`SshTransport`] contract as
//! the real `russh` transport, so the UI is identical whether it talks to a real
//! host or this stand-in. Great for demos, UI work and tests.

use async_trait::async_trait;
use hopterm_domain::*;
use tokio::sync::mpsc;

/// A transport that "connects" instantly and serves a canned interactive shell.
#[derive(Debug, Clone, Default)]
pub struct MockTransport;

#[async_trait]
impl SshTransport for MockTransport {
    async fn connect(
        &self,
        route: &Route,
        _creds: &dyn CredentialStore,
        _verifier: &dyn HostVerifier,
        observer: &dyn ConnectionObserver,
    ) -> Result<Box<dyn SshConnection>, SshError> {
        let total = route.len();
        observer.on_state(ConnectionState::Resolving);
        for index in 0..total {
            observer.on_state(ConnectionState::Connecting { index, total });
            observer.on_state(ConnectionState::Authenticating { index, total });
        }
        observer.on_state(ConnectionState::Connected);
        Ok(Box::new(MockConnection {
            banner: route.breadcrumb(),
        }))
    }
}

struct MockConnection {
    banner: String,
}

#[async_trait]
impl SshConnection for MockConnection {
    async fn open_shell(&self, _size: PtySize) -> Result<Box<dyn ShellChannel>, SshError> {
        Ok(Box::new(MockShell::spawn(&self.banner)))
    }

    async fn exec(&self, command: &str) -> Result<ExecOutput, SshError> {
        Ok(ExecOutput {
            stdout: format!("(mock) executed: {command}\n").into_bytes(),
            stderr: Vec::new(),
            exit_status: Some(0),
        })
    }

    async fn exec_stream(&self, _command: &str) -> Result<Box<dyn ExecStream>, SshError> {
        Ok(Box::new(MockExecStream))
    }

    async fn open_sftp(&self) -> Result<Box<dyn SftpSession>, SshError> {
        Ok(Box::new(MockSftp))
    }

    fn state(&self) -> ConnectionState {
        ConnectionState::Connected
    }

    async fn disconnect(&self) -> Result<(), SshError> {
        Ok(())
    }
}

/// A toy shell: prints a coloured welcome banner, then line-echoes input with a
/// prompt so the terminal pipeline (channel -> VT engine -> GUI) is exercised.
struct MockShell {
    out_rx: mpsc::Receiver<Vec<u8>>,
    in_tx: mpsc::Sender<Vec<u8>>,
}

impl MockShell {
    fn spawn(banner: &str) -> Self {
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(64);
        let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(64);

        let welcome = format!(
            "\x1b[1;36mHopTerm\x1b[0m mock session\r\n\
             route: \x1b[33m{banner}\x1b[0m\r\n\
             type something; \x1b[2mEnter\x1b[0m echoes it back.\r\n\x1b[32m$\x1b[0m "
        );

        tokio::spawn(async move {
            if out_tx.send(welcome.into_bytes()).await.is_err() {
                return;
            }
            while let Some(bytes) = in_rx.recv().await {
                // Echo raw keystrokes; on Enter, emit a fresh prompt.
                let mut echo = bytes.clone();
                if bytes.contains(&b'\r') {
                    echo = echo
                        .into_iter()
                        .flat_map(|b| if b == b'\r' { vec![b'\r', b'\n'] } else { vec![b] })
                        .collect();
                    echo.extend_from_slice(b"\x1b[32m$\x1b[0m ");
                }
                if out_tx.send(echo).await.is_err() {
                    break;
                }
            }
        });

        Self { out_rx, in_tx }
    }
}

#[async_trait]
impl ShellChannel for MockShell {
    async fn write_input(&mut self, data: &[u8]) -> Result<(), SshError> {
        self.in_tx
            .send(data.to_vec())
            .await
            .map_err(|_| SshError::Disconnected("mock shell closed".into()))
    }

    async fn read_output(&mut self) -> Result<Option<Vec<u8>>, SshError> {
        Ok(self.out_rx.recv().await)
    }

    async fn resize(&mut self, _size: PtySize) -> Result<(), SshError> {
        Ok(())
    }
}

/// Yields no output then ends (the mock has no real `tar` to stream).
struct MockExecStream;

#[async_trait]
impl ExecStream for MockExecStream {
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, SshError> {
        Ok(None)
    }
}

struct MockSftp;

#[async_trait]
impl SftpSession for MockSftp {
    async fn list_dir(&self, _path: &str) -> Result<Vec<RemoteEntry>, TransferError> {
        Ok(vec![
            RemoteEntry { name: "var".into(), is_dir: true, is_symlink: false, size: 4096, mode: Some(0o755), modified: None },
            RemoteEntry { name: "etc".into(), is_dir: true, is_symlink: false, size: 4096, mode: Some(0o755), modified: None },
            RemoteEntry { name: "logs_2026-06.tar.gz".into(), is_dir: false, is_symlink: false, size: 89_500_000, mode: Some(0o644), modified: None },
        ])
    }
    async fn stat(&self, path: &str) -> Result<RemoteEntry, TransferError> {
        Ok(RemoteEntry { name: path.into(), is_dir: false, is_symlink: false, size: 0, mode: None, modified: None })
    }
    async fn canonicalize(&self, path: &str) -> Result<String, TransferError> { Ok(path.to_string()) }
    async fn mkdir(&self, _path: &str) -> Result<(), TransferError> { Ok(()) }
    async fn rename(&self, _from: &str, _to: &str) -> Result<(), TransferError> { Ok(()) }
    async fn remove(&self, _path: &str) -> Result<(), TransferError> { Ok(()) }
    async fn upload(&self, _l: &str, _r: &str, progress: &dyn ProgressSink, _c: &CancelToken) -> Result<(), TransferError> {
        progress.on_progress(100, 100);
        Ok(())
    }
    async fn download(&self, _r: &str, _l: &str, progress: &dyn ProgressSink, _c: &CancelToken) -> Result<(), TransferError> {
        progress.on_progress(100, 100);
        Ok(())
    }
}
