//! End-to-end pipeline test over the offline mock transport:
//! `SessionManager::connect` -> `open_shell` -> read bytes -> feed the VT engine
//! -> assert the rendered grid. This exercises the same domain contracts the
//! real `russh` transport implements, so the GUI path is validated headlessly.

use std::sync::Arc;

use async_trait::async_trait;
use hopterm_app::{demo::demo_profiles, SessionManager, Services};
use hopterm_domain::*;
use hopterm_security::SecretPrompter;
use hopterm_terminal::AlacrittyTerminal;

struct NoPrompt;
#[async_trait]
impl SecretPrompter for NoPrompt {
    async fn prompt_password(&self, _h: HostId, _u: &str) -> Option<String> {
        None
    }
    async fn prompt_passphrase(&self, _k: &str) -> Option<String> {
        None
    }
}

struct NopObserver;
impl ConnectionObserver for NopObserver {
    fn on_state(&self, _s: ConnectionState) {}
}

#[tokio::test]
async fn connect_open_shell_and_render() {
    let settings = AppSettings::default();
    let services = Services::demo(Arc::new(NoPrompt), None, &settings);
    let manager = SessionManager::new(services);

    // Use the multi-hop "k8s-master" profile (2 jump hosts + target).
    let profile = demo_profiles()
        .into_iter()
        .find(|p| p.display_name == "k8s-master")
        .unwrap();
    assert!(profile.route.is_multi_hop());
    assert_eq!(profile.route.len(), 3);

    let id = manager.connect(&profile, &NopObserver).await.unwrap();
    let mut shell = manager.open_shell(id, PtySize::new(80, 24)).await.unwrap();

    // Drain the banner the mock shell emits on open.
    let mut term = AlacrittyTerminal::new(PtySize::new(80, 24));
    let first = shell.read_output().await.unwrap().unwrap();
    term.feed(&first);
    assert!(term.snapshot().row_text(0).contains("HopTerm"));

    // Type a line and confirm it is echoed back through the pipeline.
    shell.write_input(b"whoami\r").await.unwrap();
    let echo = shell.read_output().await.unwrap().unwrap();
    term.feed(&echo);
    let text: String = (0..24)
        .map(|r| term.snapshot().row_text(r))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("whoami"));

    manager.close(id).await.unwrap();
}
