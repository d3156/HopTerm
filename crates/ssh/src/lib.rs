//! russh-based SSH transport and multi-hop chain builder (spec §5.1, §5.2).
//!
//! The whole "routing" layer (§7.1.4) lives here, behind the single
//! [`SshTransport`] entry point. A chain `local -> hop1 -> ... -> target` is
//! built by:
//! 1. TCP-connecting to the first hop and running an SSH handshake over it;
//! 2. for every further hop, opening a `direct-tcpip` channel on the *previous*
//!    hop, turning it into a byte stream, and running a fresh SSH handshake over
//!    that stream (`connect_stream`).
//!
//! Every intermediate [`Handle`] is kept alive for the lifetime of the
//! connection — dropping one would collapse the tunnel beneath it. All shell,
//! exec and SFTP channels are opened on the *last* hop, so they transparently
//! traverse the whole chain (§5.2 "переиспользование логики маршрутизации").

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use russh::client::{self, Handle, Msg};
use russh::keys::{decode_secret_key, ssh_key, PrivateKeyWithHashAlg};
use russh::{Channel, ChannelMsg, Disconnect};
use hopterm_domain::{
    AuthMethod, ConnectionObserver, ConnectionState, CredentialStore, ExecOutput, ExecStream,
    HostKey, HostKeyDecision, HostProfile, HostVerifier, PtySize, Route, ShellChannel, SftpSession,
    SshConnection, SshError, SshTransport,
};

mod shell;
pub use shell::RusshShell;

/// Tunables for the transport (timeouts, keepalive — spec §5.1).
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub connect_timeout: Duration,
    pub keepalive_interval: Duration,
    pub inactivity_timeout: Option<Duration>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(20),
            keepalive_interval: Duration::from_secs(30),
            inactivity_timeout: None,
        }
    }
}

/// The concrete [`SshTransport`] over `russh`.
#[derive(Debug, Clone, Default)]
pub struct RusshTransport {
    config: TransportConfig,
}

impl RusshTransport {
    pub fn new(config: TransportConfig) -> Self {
        Self { config }
    }

    fn russh_config(&self) -> Arc<client::Config> {
        Arc::new(client::Config {
            inactivity_timeout: self.config.inactivity_timeout,
            keepalive_interval: Some(self.config.keepalive_interval),
            ..Default::default()
        })
    }
}

/// Captures the server's host key during the handshake so we can verify it
/// out-of-band, before sending any credentials (§6.3 — no secret before trust).
#[derive(Clone, Default)]
struct CaptureHandler {
    captured: Arc<Mutex<Option<ssh_key::PublicKey>>>,
}

impl client::Handler for CaptureHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        *self.captured.lock().unwrap() = Some(server_public_key.clone());
        // Accept at the transport level; the real decision happens in
        // `verify_host_key` once we can consult the pinned key store.
        Ok(true)
    }
}

fn host_key_of(node: &HostProfile, key: &ssh_key::PublicKey) -> HostKey {
    HostKey {
        host: node.address.clone(),
        port: node.port,
        algorithm: key.algorithm().to_string(),
        fingerprint_sha256: key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
    }
}

#[async_trait]
impl SshTransport for RusshTransport {
    async fn connect(
        &self,
        route: &Route,
        creds: &dyn CredentialStore,
        verifier: &dyn HostVerifier,
        observer: &dyn ConnectionObserver,
    ) -> Result<Box<dyn SshConnection>, SshError> {
        let nodes = route.nodes();
        let total = nodes.len();
        let config = self.russh_config();

        observer.on_state(ConnectionState::Resolving);
        let mut chain: Vec<Handle<CaptureHandler>> = Vec::with_capacity(total);

        for (idx, node) in nodes.iter().enumerate() {
            observer.on_state(ConnectionState::Connecting { index: idx, total });
            let handler = CaptureHandler::default();
            let captured = handler.captured.clone();

            let mut handle = if idx == 0 {
                // First hop: real TCP connection from localhost.
                let addr = format!("{}:{}", node.address, node.port);
                let tcp = tokio::time::timeout(
                    self.config.connect_timeout,
                    tokio::net::TcpStream::connect(&addr),
                )
                .await
                .map_err(|_| SshError::Timeout(self.config.connect_timeout.as_secs()))?
                .map_err(|e| SshError::Network {
                    hop_index: idx,
                    endpoint: node.endpoint(),
                    source_msg: e.to_string(),
                })?;
                client::connect_stream(config.clone(), tcp, handler)
                    .await
                    .map_err(|e| SshError::Handshake {
                        hop_index: idx,
                        endpoint: node.endpoint(),
                        source_msg: e.to_string(),
                    })?
            } else {
                // Subsequent hop: tunnel a direct-tcpip channel over the
                // previous hop and handshake over it.
                let prev = chain.last().expect("previous hop exists");
                let channel = prev
                    .channel_open_direct_tcpip(
                        node.address.clone(),
                        node.port as u32,
                        "127.0.0.1".to_string(),
                        0,
                    )
                    .await
                    .map_err(|e| SshError::Channel {
                        hop_index: idx,
                        channel: "direct-tcpip".into(),
                        source_msg: e.to_string(),
                    })?;
                let stream = channel.into_stream();
                client::connect_stream(config.clone(), stream, handler)
                    .await
                    .map_err(|e| SshError::Handshake {
                        hop_index: idx,
                        endpoint: node.endpoint(),
                        source_msg: e.to_string(),
                    })?
            };

            verify_host_key(idx, node, &captured, verifier, &handle).await?;

            observer.on_state(ConnectionState::Authenticating { index: idx, total });
            authenticate(&mut handle, idx, node, creds).await?;

            chain.push(handle);
        }

        observer.on_state(ConnectionState::Connected);
        Ok(Box::new(RusshConnection {
            chain,
            state: Mutex::new(ConnectionState::Connected),
        }))
    }
}

/// Consult the pinned-key store and apply trust policy (§5.1, §6.3).
async fn verify_host_key(
    idx: usize,
    node: &HostProfile,
    captured: &Arc<Mutex<Option<ssh_key::PublicKey>>>,
    verifier: &dyn HostVerifier,
    handle: &Handle<CaptureHandler>,
) -> Result<(), SshError> {
    let key = captured.lock().unwrap().clone();
    let Some(key) = key else {
        return Ok(()); // No key presented (e.g. test transport) — nothing to pin.
    };
    let hk = host_key_of(node, &key);
    let decision = verifier.check(&hk).map_err(|e| SshError::HostKeyRejected {
        hop_index: idx,
        endpoint: node.endpoint(),
        reason: e.to_string(),
    })?;
    match decision {
        HostKeyDecision::Trusted => Ok(()),
        HostKeyDecision::Unknown { key } => {
            // Trust-on-first-use: pin and proceed. An AlwaysAsk policy is wired
            // to an interactive confirm at the app layer before reaching here.
            verifier.remember(&key).map_err(|e| SshError::HostKeyRejected {
                hop_index: idx,
                endpoint: node.endpoint(),
                reason: e.to_string(),
            })?;
            tracing::info!(hop = idx, endpoint = %node.endpoint(), fingerprint = %hk.fingerprint_sha256, "pinned new host key (TOFU)");
            Ok(())
        }
        HostKeyDecision::Mismatch { .. } => {
            let _ = handle
                .disconnect(Disconnect::ByApplication, "host key mismatch", "")
                .await;
            Err(SshError::HostKeyRejected {
                hop_index: idx,
                endpoint: node.endpoint(),
                reason: format!(
                    "presented host key {} does not match the pinned key — possible MITM",
                    hk.fingerprint_sha256
                ),
            })
        }
    }
}

/// Authenticate to a single hop using its configured method (§5.1).
async fn authenticate(
    handle: &mut Handle<CaptureHandler>,
    idx: usize,
    node: &HostProfile,
    creds: &dyn CredentialStore,
) -> Result<(), SshError> {
    let user = node.username.clone();
    let auth_failed = || SshError::Auth {
        hop_index: idx,
        endpoint: node.endpoint(),
        username: user.clone(),
    };
    let to_handshake = |e: russh::Error| SshError::Handshake {
        hop_index: idx,
        endpoint: node.endpoint(),
        source_msg: e.to_string(),
    };
    let to_sec = |msg: String| SshError::Other(format!("hop {idx}: {msg}"));

    let success = match &node.auth_method {
        AuthMethod::Password => {
            let pw = creds
                .password(node.id, &node.username)
                .await
                .map_err(|e| to_sec(e.to_string()))?;
            handle
                .authenticate_password(user.clone(), pw)
                .await
                .map_err(to_handshake)?
                .success()
        }
        AuthMethod::PublicKey {
            key_path,
            passphrase_protected,
        } => {
            let bytes = creds
                .private_key(key_path)
                .await
                .map_err(|e| to_sec(e.to_string()))?;
            let pem = String::from_utf8(bytes)
                .map_err(|e| to_sec(format!("private key is not valid UTF-8: {e}")))?;
            let passphrase = if *passphrase_protected {
                Some(
                    creds
                        .passphrase(key_path)
                        .await
                        .map_err(|e| to_sec(e.to_string()))?,
                )
            } else {
                None
            };
            let key = decode_secret_key(&pem, passphrase.as_deref())
                .map_err(|e| to_sec(format!("failed to load private key: {e}")))?;
            let hash_alg = if key.algorithm().is_rsa() {
                handle.best_supported_rsa_hash().await.ok().flatten().flatten()
            } else {
                None
            };
            let kwa = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
            handle
                .authenticate_publickey(user.clone(), kwa)
                .await
                .map_err(to_handshake)?
                .success()
        }
        AuthMethod::Agent => authenticate_agent(handle, &user).await.map_err(to_sec)?,
    };

    if success {
        Ok(())
    } else {
        Err(auth_failed())
    }
}

/// Best-effort SSH-agent auth: try every identity the agent offers (§5.1).
async fn authenticate_agent(
    handle: &mut Handle<CaptureHandler>,
    user: &str,
) -> Result<bool, String> {
    use russh::keys::agent::client::AgentClient;
    use russh::keys::agent::AgentIdentity;

    let mut agent = AgentClient::connect_env()
        .await
        .map_err(|e| format!("cannot reach SSH agent (SSH_AUTH_SOCK): {e}"))?;
    let identities = agent
        .request_identities()
        .await
        .map_err(|e| format!("agent identity query failed: {e}"))?;

    for id in identities {
        if let AgentIdentity::PublicKey { key, .. } = id {
            match handle
                .authenticate_publickey_with(user.to_string(), key, None, &mut agent)
                .await
            {
                Ok(result) if result.success() => return Ok(true),
                _ => continue,
            }
        }
    }
    Ok(false)
}

/// A connected chain. The last [`Handle`] is the target; earlier ones are kept
/// alive only to hold the tunnels open.
struct RusshConnection {
    chain: Vec<Handle<CaptureHandler>>,
    state: Mutex<ConnectionState>,
}

impl RusshConnection {
    fn target(&self) -> &Handle<CaptureHandler> {
        self.chain.last().expect("chain always has a target")
    }
}

#[async_trait]
impl SshConnection for RusshConnection {
    async fn open_shell(&self, size: PtySize) -> Result<Box<dyn ShellChannel>, SshError> {
        let channel = self.open_session_channel().await?;
        channel
            .request_pty(
                true,
                "xterm-256color",
                size.cols as u32,
                size.rows as u32,
                size.pixel_width as u32,
                size.pixel_height as u32,
                &[],
            )
            .await
            .map_err(|e| SshError::Channel {
                hop_index: self.chain.len() - 1,
                channel: "pty".into(),
                source_msg: e.to_string(),
            })?;
        channel.request_shell(true).await.map_err(|e| SshError::Channel {
            hop_index: self.chain.len() - 1,
            channel: "shell".into(),
            source_msg: e.to_string(),
        })?;
        Ok(Box::new(RusshShell::spawn(channel)))
    }

    async fn exec(&self, command: &str) -> Result<ExecOutput, SshError> {
        let mut channel = self.open_session_channel().await?;
        channel
            .exec(true, command.as_bytes())
            .await
            .map_err(|e| SshError::Channel {
                hop_index: self.chain.len() - 1,
                channel: "exec".into(),
                source_msg: e.to_string(),
            })?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_status = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }
        Ok(ExecOutput {
            stdout,
            stderr,
            exit_status,
        })
    }

    async fn exec_stream(&self, command: &str) -> Result<Box<dyn ExecStream>, SshError> {
        let channel = self.open_session_channel().await?;
        channel
            .exec(true, command.as_bytes())
            .await
            .map_err(|e| SshError::Channel {
                hop_index: self.chain.len() - 1,
                channel: "exec".into(),
                source_msg: e.to_string(),
            })?;
        Ok(Box::new(RusshExecStream {
            channel,
            stderr: Vec::new(),
            exit: None,
            done: false,
        }))
    }

    async fn open_sftp(&self) -> Result<Box<dyn SftpSession>, SshError> {
        let channel = self.open_session_channel().await?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| SshError::Channel {
                hop_index: self.chain.len() - 1,
                channel: "sftp".into(),
                source_msg: e.to_string(),
            })?;
        let stream = channel.into_stream();
        let sftp = hopterm_transfer::RusshSftp::open_over_stream(stream)
            .await
            .map_err(|e| SshError::Channel {
                hop_index: self.chain.len() - 1,
                channel: "sftp".into(),
                source_msg: e.to_string(),
            })?;
        Ok(Box::new(sftp))
    }

    fn state(&self) -> ConnectionState {
        self.state.lock().unwrap().clone()
    }

    async fn disconnect(&self) -> Result<(), SshError> {
        *self.state.lock().unwrap() = ConnectionState::Disconnected;
        // Tear down from target back to the first hop.
        for handle in self.chain.iter().rev() {
            let _ = handle
                .disconnect(Disconnect::ByApplication, "client closed session", "")
                .await;
        }
        Ok(())
    }
}

/// Streams stdout of a remote `exec` channel chunk by chunk, accumulating stderr
/// so a non-zero exit can be reported with a useful message.
struct RusshExecStream {
    channel: Channel<Msg>,
    stderr: Vec<u8>,
    exit: Option<u32>,
    done: bool,
}

#[async_trait]
impl ExecStream for RusshExecStream {
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, SshError> {
        if self.done {
            return Ok(None);
        }
        while let Some(msg) = self.channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => return Ok(Some(data.to_vec())),
                ChannelMsg::ExtendedData { data, .. } => self.stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => self.exit = Some(exit_status),
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }
        self.done = true;
        if let Some(code) = self.exit.filter(|c| *c != 0) {
            let msg = String::from_utf8_lossy(&self.stderr).trim().to_string();
            return Err(SshError::Other(format!("команда завершилась с кодом {code}: {msg}")));
        }
        Ok(None)
    }
}

impl RusshConnection {
    async fn open_session_channel(&self) -> Result<Channel<Msg>, SshError> {
        self.target()
            .channel_open_session()
            .await
            .map_err(|e| SshError::Channel {
                hop_index: self.chain.len() - 1,
                channel: "session".into(),
                source_msg: e.to_string(),
            })
    }
}
