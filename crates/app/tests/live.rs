//! LIVE integration tests against real LAN hosts (d3156@192.168.0.93 / .95).
//!
//! These are `#[ignore]`d by default because they need those hosts reachable.
//! Run explicitly:
//!     cargo test -p hopterm-app --test live -- --ignored --nocapture
//!
//! They exercise the *real* `RusshTransport` (not the mock): password / key /
//! agent auth, single- and multi-hop chains (`direct-tcpip`), shell `exec`, and
//! SFTP upload/download over the chain.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use hopterm_app::{HostKeyAsk, SessionManager, Services};
use hopterm_domain::*;
use hopterm_security::{KnownHostsVerifier, MemoryCredentialStore, SecretPrompter};
use hopterm_ssh::RusshTransport;
use hopterm_storage::KnownHostsFile;
use uuid::Uuid;

const H93: &str = "192.168.0.93";
const H95: &str = "192.168.0.95";
const USER: &str = "d3156";
const PASS: &str = "12345678";
const KEY: &str = "~/.ssh/id_ed25519";

fn node(host: &str, auth: AuthMethod) -> HostProfile {
    HostProfile {
        id: HostId::new(Uuid::new_v4()),
        name: host.into(),
        address: host.into(),
        port: 22,
        username: USER.into(),
        auth_method: auth,
        password: None,
        tags: vec![],
        color: None,
        icon: None,
    }
}

fn password_creds() -> MemoryCredentialStore {
    let mut passwords = HashMap::new();
    passwords.insert(USER.to_string(), PASS.to_string());
    MemoryCredentialStore {
        passwords,
        passphrases: HashMap::new(),
    }
}

fn tofu_verifier() -> KnownHostsVerifier {
    let path =
        std::env::temp_dir().join(format!("hopterm-live-known-hosts-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    KnownHostsVerifier::new(KnownHostsFile::new(path, false), TrustPolicy::TrustOnFirstUse)
}

/// Prints each per-hop transition — evidence that the chain builder works.
struct PrintObserver;
impl ConnectionObserver for PrintObserver {
    fn on_state(&self, state: ConnectionState) {
        eprintln!("  [state] {state:?}");
    }
}

struct DummyProgress;
impl ProgressSink for DummyProgress {
    fn on_progress(&self, transferred: u64, total: u64) {
        eprintln!("  [transfer] {transferred}/{total}");
    }
}

async fn connect_and_id(route: &Route, creds: &MemoryCredentialStore) -> Box<dyn SshConnection> {
    let transport = RusshTransport::default();
    let verifier = tofu_verifier();
    transport
        .connect(route, creds, &verifier, &PrintObserver)
        .await
        .expect("connect failed")
}

async fn exec(conn: &dyn SshConnection, cmd: &str) -> String {
    let out = conn.exec(cmd).await.expect("exec failed");
    let s = String::from_utf8_lossy(&out.stdout).to_string();
    eprintln!("  $ {cmd}\n{s}");
    s
}

#[tokio::test]
#[ignore]
async fn live_password_single_hop() {
    let route = Route {
        hops: vec![],
        target: node(H93, AuthMethod::Password),
        policy: RoutePolicy::DirectTcpIp,
    };
    let conn = connect_and_id(&route, &password_creds()).await;
    let out = exec(&*conn, "whoami; hostname -I 2>/dev/null | tr -d '\\n'").await;
    assert!(out.contains(USER));
    conn.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore]
async fn live_key_single_hop() {
    let route = Route {
        hops: vec![],
        target: node(
            H93,
            AuthMethod::PublicKey {
                key_path: KEY.into(),
                passphrase_protected: false,
            },
        ),
        policy: RoutePolicy::DirectTcpIp,
    };
    // Empty creds: key bytes are read from disk by MemoryCredentialStore.
    let conn = connect_and_id(&route, &password_creds()).await;
    let out = exec(&*conn, "echo KEY_AUTH_OK; whoami").await;
    assert!(out.contains("KEY_AUTH_OK"));
    conn.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore]
async fn live_agent_single_hop() {
    let route = Route {
        hops: vec![],
        target: node(H93, AuthMethod::Agent),
        policy: RoutePolicy::DirectTcpIp,
    };
    let conn = connect_and_id(&route, &password_creds()).await;
    let out = exec(&*conn, "echo AGENT_AUTH_OK").await;
    assert!(out.contains("AGENT_AUTH_OK"));
    conn.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore]
async fn live_multi_hop_two_nodes() {
    // local -> .93 -> .95
    let route = Route {
        hops: vec![node(H93, AuthMethod::Password)],
        target: node(H95, AuthMethod::Password),
        policy: RoutePolicy::DirectTcpIp,
    };
    eprintln!("multi-hop route: {}", route.breadcrumb());
    let conn = connect_and_id(&route, &password_creds()).await;
    let out = exec(&*conn, "hostname -I 2>/dev/null | tr -d '\\n'; echo; whoami").await;
    assert!(out.contains(USER));
    conn.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore]
async fn live_multi_hop_three_nodes() {
    // local -> .93 -> .95 -> .93  (proves n-hop chaining, n>2)
    let route = Route {
        hops: vec![
            node(H93, AuthMethod::Password),
            node(H95, AuthMethod::Password),
        ],
        target: node(H93, AuthMethod::Password),
        policy: RoutePolicy::DirectTcpIp,
    };
    eprintln!("3-node route: {}", route.breadcrumb());
    let conn = connect_and_id(&route, &password_creds()).await;
    let out = exec(&*conn, "echo THREE_HOP_OK; whoami").await;
    assert!(out.contains("THREE_HOP_OK"));
    conn.disconnect().await.unwrap();
}

struct PasswordPrompter;
#[async_trait]
impl SecretPrompter for PasswordPrompter {
    async fn prompt_password(&self, _h: HostId, _u: &str) -> Option<String> {
        Some(PASS.to_string())
    }
    async fn prompt_passphrase(&self, _k: &str) -> Option<String> {
        None
    }
}

/// Full production wiring: Services (real transport + PromptCredentialStore +
/// InteractiveHostVerifier) driven through SessionManager, with the host-key
/// callback auto-accepting first contact — exactly the GUI's path.
#[tokio::test]
#[ignore]
async fn live_app_production_path() {
    let mut settings = AppSettings::default();
    settings.persist_config = false; // don't touch ~/.hopterm during the test
    let ask: HostKeyAsk = Arc::new(|key| {
        eprintln!("  [host-key] auto-accepting {}", key.fingerprint_sha256);
        true
    });
    let services = Services::production(Arc::new(PasswordPrompter), Some(ask), &settings);
    let manager = SessionManager::new(services);

    let profile = SessionProfile {
        id: ProfileId::new(Uuid::new_v4()),
        display_name: "live-93".into(),
        route: Route {
            hops: vec![],
            target: node(H93, AuthMethod::Password),
            policy: RoutePolicy::DirectTcpIp,
        },
        terminal_preferences: TerminalPreferences::default(),
        transfer_preferences: TransferPreferences::default(),
        tags: vec![],
        sudo: SudoConfig::default(),
        color: None,
        icon: None,
    };

    let id = manager.connect(&profile, &PrintObserver).await.unwrap();
    let conn = manager.connection(id).expect("connection registered");
    let out = conn.exec("echo APP_PATH_OK; whoami").await.unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    eprintln!("  app-path output:\n{s}");
    assert!(s.contains("APP_PATH_OK"));
    manager.close(id).await.unwrap();
}

/// Reproduces the GUI flicker headlessly: open an interactive shell on a real
/// host and confirm it stays open and emits a prompt (rather than closing
/// immediately, which would loop auto-reconnect).
#[tokio::test]
#[ignore]
async fn live_shell_stays_open() {
    let route = Route {
        hops: vec![],
        target: node(H93, AuthMethod::Password),
        policy: RoutePolicy::DirectTcpIp,
    };
    let conn = connect_and_id(&route, &password_creds()).await;
    let mut shell = conn.open_shell(PtySize::new(80, 24)).await.expect("open shell");

    // Read a few chunks with a deadline; collect what the shell emits.
    let mut got = Vec::new();
    for _ in 0..5 {
        match tokio::time::timeout(std::time::Duration::from_secs(3), shell.read_output()).await {
            Ok(Ok(Some(bytes))) => {
                eprintln!("  shell chunk: {:?}", String::from_utf8_lossy(&bytes));
                got.extend_from_slice(&bytes);
                if !got.is_empty() {
                    break;
                }
            }
            Ok(Ok(None)) => panic!("shell closed immediately (the flicker bug)"),
            Ok(Err(e)) => panic!("shell read error: {e}"),
            Err(_) => break, // timed out waiting; that's fine if we already have data
        }
    }
    assert!(!got.is_empty(), "shell produced no output");

    // Send a command and confirm it echoes / produces output.
    shell.write_input(b"echo SHELL_LIVE_OK\r").await.unwrap();
    let mut echoed = Vec::new();
    for _ in 0..10 {
        match tokio::time::timeout(std::time::Duration::from_secs(3), shell.read_output()).await {
            Ok(Ok(Some(b))) => {
                echoed.extend_from_slice(&b);
                if String::from_utf8_lossy(&echoed).contains("SHELL_LIVE_OK") {
                    break;
                }
            }
            _ => break,
        }
    }
    assert!(
        String::from_utf8_lossy(&echoed).contains("SHELL_LIVE_OK"),
        "shell did not echo command output"
    );
    conn.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore]
async fn live_sftp_roundtrip() {
    let route = Route {
        hops: vec![node(H93, AuthMethod::Password)],
        target: node(H95, AuthMethod::Password),
        policy: RoutePolicy::DirectTcpIp,
    };
    let conn = connect_and_id(&route, &password_creds()).await;
    let sftp = conn.open_sftp().await.expect("open sftp");

    // List home directory.
    let entries = sftp.list_dir(".").await.expect("list_dir");
    eprintln!("  remote `.` has {} entries", entries.len());

    // Upload a local temp file, download it back, compare, clean up.
    let local_up = std::env::temp_dir().join("hopterm_up.txt");
    let local_down = std::env::temp_dir().join("hopterm_down.txt");
    let payload = b"hopterm sftp roundtrip over a multi-hop chain\n";
    std::fs::write(&local_up, payload).unwrap();
    let remote = format!("/tmp/hopterm_live_{}.txt", std::process::id());

    let cancel = CancelToken::new();
    sftp.upload(local_up.to_str().unwrap(), &remote, &DummyProgress, &cancel)
        .await
        .expect("upload");
    sftp.download(&remote, local_down.to_str().unwrap(), &DummyProgress, &cancel)
        .await
        .expect("download");

    let got = std::fs::read(&local_down).unwrap();
    assert_eq!(got, payload, "downloaded bytes must match uploaded");
    eprintln!("  SFTP roundtrip OK ({} bytes)", got.len());

    sftp.remove(&remote).await.ok();
    let _ = std::fs::remove_file(&local_up);
    let _ = std::fs::remove_file(&local_down);
    conn.disconnect().await.unwrap();
}
