//! Structured logging & diagnostics (spec §11).
//!
//! * One place to initialise `tracing` for the whole app.
//! * A [`redact`] helper so secrets never reach the log sink (§6.3, §11).

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialise the global tracing subscriber.
///
/// Honours `RUST_LOG`; falls back to `info` (or `debug` when `debug == true`,
/// the mockup's "debug diagnostics" mode). Safe to call once at startup.
pub fn init(verbose: bool) {
    let default = if verbose { "hopterm=debug,info" } else { "hopterm=info,warn" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));

    let fmt_layer = fmt::layer()
        .with_target(true)
        .with_level(true)
        .with_ansi(true);

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .try_init();

    tracing::info!(verbose, "hopterm logging initialised");
}

/// Mask a secret for logging: keep nothing but the length class.
///
/// `redact("hunter2") == "***(7)"`. Use this anywhere a credential might
/// otherwise be formatted into a span or message (§6.3).
pub fn redact(secret: &str) -> String {
    if secret.is_empty() {
        "***(empty)".to_string()
    } else {
        format!("***({})", secret.len())
    }
}

/// Redact everything after the last path separator is *kept*; the rest of a key
/// path is fine to log, but never the key material itself. Provided for symmetry
/// and to document intent at call sites.
pub fn key_ref(path: &str) -> &str {
    path
}
