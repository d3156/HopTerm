//! Helper (ignored) that seeds a real-host profile into `~/.hopterm/config.toml`
//! so the GUI can be driven against the LAN test host. Run explicitly:
//!     cargo test -p hopterm-app --test seed -- --ignored --nocapture

use hopterm_domain::*;
use hopterm_storage::{Paths, TomlStore};
use uuid::Uuid;

#[test]
#[ignore]
fn seed_real_profile() {
    let store = TomlStore::new(Paths::default_location());
    let target = HostProfile {
        id: HostId::new(Uuid::new_v4()),
        name: "live-93".into(),
        address: "192.168.0.93".into(),
        port: 22,
        username: "d3156".into(),
        auth_method: AuthMethod::PublicKey {
            key_path: "~/.ssh/id_ed25519".into(),
            passphrase_protected: false,
        },
        password: None,
        tags: vec!["lan".into()],
        color: None,
        icon: None,
    };
    let profile = SessionProfile {
        id: ProfileId::new(Uuid::new_v4()),
        display_name: "live-93".into(),
        route: Route {
            hops: vec![],
            target,
            policy: RoutePolicy::DirectTcpIp,
        },
        terminal_preferences: TerminalPreferences::default(),
        transfer_preferences: TransferPreferences::default(),
        tags: vec!["lan".into(), "production".into()],
        sudo: SudoConfig {
            command: Some("sudo -s".into()),
            password: None,
        },
        color: None,
        icon: None,
    };
    store.save_profile(&profile).unwrap();
    eprintln!("seeded profile into {:?}", store.paths().config_file);
}
