//! Interactive shell channel pump (spec §5.3).
//!
//! A russh [`Channel`] can't be read and written through the same `&mut`
//! simultaneously, so we split it into halves and run a single pump task that
//! bridges the SSH channel to ergonomic tokio mpsc channels. The
//! [`ShellChannel`] facade then just talks to those mpsc endpoints, keeping the
//! upper layers free of any russh types.

use async_trait::async_trait;
use russh::client::Msg;
use russh::{Channel, ChannelMsg};
use hopterm_domain::{PtySize, ShellChannel, SshError};
use tokio::sync::mpsc;

/// Control messages sent from the facade into the pump task.
enum ShellCmd {
    Input(Vec<u8>),
    Resize(PtySize),
}

/// [`ShellChannel`] over a live russh session channel.
pub struct RusshShell {
    out_rx: mpsc::Receiver<Vec<u8>>,
    cmd_tx: mpsc::Sender<ShellCmd>,
}

impl RusshShell {
    /// Take ownership of an opened+PTY-requested channel and start pumping.
    pub fn spawn(channel: Channel<Msg>) -> Self {
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(256);
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<ShellCmd>(64);

        let (mut read_half, write_half) = channel.split();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = read_half.wait() => match msg {
                        Some(ChannelMsg::Data { data }) => {
                            if out_tx.send(data.to_vec()).await.is_err() {
                                break;
                            }
                        }
                        Some(ChannelMsg::ExtendedData { data, .. }) => {
                            // Fold stderr into the same byte stream the VT parser sees.
                            let _ = out_tx.send(data.to_vec()).await;
                        }
                        Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                        _ => {}
                    },
                    cmd = cmd_rx.recv() => match cmd {
                        Some(ShellCmd::Input(bytes)) => {
                            if write_half.data_bytes(bytes).await.is_err() {
                                break;
                            }
                        }
                        Some(ShellCmd::Resize(s)) => {
                            let _ = write_half
                                .window_change(
                                    s.cols as u32,
                                    s.rows as u32,
                                    s.pixel_width as u32,
                                    s.pixel_height as u32,
                                )
                                .await;
                        }
                        None => break,
                    },
                }
            }
            tracing::debug!("shell pump task ended");
        });

        Self { out_rx, cmd_tx }
    }
}

#[async_trait]
impl ShellChannel for RusshShell {
    async fn write_input(&mut self, data: &[u8]) -> Result<(), SshError> {
        self.cmd_tx
            .send(ShellCmd::Input(data.to_vec()))
            .await
            .map_err(|_| SshError::Disconnected("shell channel closed".into()))
    }

    async fn read_output(&mut self) -> Result<Option<Vec<u8>>, SshError> {
        Ok(self.out_rx.recv().await)
    }

    async fn resize(&mut self, size: PtySize) -> Result<(), SshError> {
        self.cmd_tx
            .send(ShellCmd::Resize(size))
            .await
            .map_err(|_| SshError::Disconnected("shell channel closed".into()))
    }
}
