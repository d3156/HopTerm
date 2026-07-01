//! Demo data mirroring the four hosts in the UI mockup (`index.html`), so the
//! app shows something meaningful on first launch / in `--demo` mode.

use hopterm_domain::*;
use uuid::Uuid;

fn host(name: &str, user: &str, addr: &str, port: u16, auth: AuthMethod) -> HostProfile {
    HostProfile {
        id: HostId::new(Uuid::new_v4()),
        name: name.into(),
        address: addr.into(),
        port,
        username: user.into(),
        auth_method: auth,
        password: None,
        tags: vec![],
        color: None,
        icon: None,
    }
}

fn key(path: &str) -> AuthMethod {
    AuthMethod::PublicKey {
        key_path: path.into(),
        passphrase_protected: false,
    }
}

fn profile(name: &str, tags: &[&str], hops: Vec<HostProfile>, target: HostProfile) -> SessionProfile {
    SessionProfile {
        id: ProfileId::new(Uuid::new_v4()),
        display_name: name.into(),
        route: Route {
            hops,
            target,
            policy: RoutePolicy::DirectTcpIp,
        },
        terminal_preferences: TerminalPreferences::default(),
        transfer_preferences: TransferPreferences::default(),
        tags: tags.iter().map(|s| s.to_string()).collect(),
        sudo: SudoConfig::default(),
        color: None,
        icon: None,
    }
}

/// The four mockup hosts, with realistic multi-hop chains.
pub fn demo_profiles() -> Vec<SessionProfile> {
    vec![
        profile(
            "prod-backend-01",
            &["production"],
            vec![host("bastion-eu", "ops", "bastion.example.com", 22, key("~/.ssh/bastion"))],
            host("prod-backend-01", "admin", "192.168.1.100", 22, key("~/.ssh/prod_key")),
        ),
        profile(
            "k8s-master",
            &["production"],
            vec![
                host("bastion-eu", "ops", "bastion.example.com", 22, AuthMethod::Agent),
                host("jump2", "ubuntu", "10.10.0.5", 2222, key("~/.ssh/jump2_key")),
            ],
            host("k8s-master", "ubuntu", "10.0.0.5", 2222, AuthMethod::Password),
        ),
        profile(
            "bastion-eu",
            &["bastion"],
            vec![],
            host("bastion-eu", "ops", "bastion.example.com", 22, key("~/.ssh/bastion")),
        ),
        profile(
            "dev-sandbox",
            &["dev"],
            vec![
                host("bastion-eu", "ops", "bastion.example.com", 22, AuthMethod::Agent),
                host("gw", "dev", "10.20.0.1", 22, AuthMethod::Agent),
                host("router", "dev", "10.30.0.1", 22, AuthMethod::Agent),
            ],
            host("dev-sandbox", "dev", "172.16.0.20", 22, key("~/.ssh/id_rsa")),
        ),
    ]
}
