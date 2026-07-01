//! # hopterm-domain
//!
//! The pure, IO-free core of HopTerm. This crate defines:
//!
//! * **Entities** ([`entities`]) — the data model from the spec (§8): host profiles,
//!   jump routes, sessions, transfer jobs, host keys.
//! * **Errors** ([`error`]) — structured, layer-aware error types that keep
//!   per-hop diagnostics (§6.2, §11).
//! * **Traits** ([`traits`]) — the contracts between the architectural layers
//!   (§7). The GUI and the orchestration layer talk to SSH / transfer / storage
//!   exclusively through these abstractions, never to `russh` directly (§7.2).
//!
//! Nothing here performs IO or pulls in a runtime, so every higher layer can
//! depend on it cheaply and it stays trivially testable.

pub mod entities;
pub mod error;
pub mod terminal;
pub mod traits;

pub use entities::*;
pub use error::*;
pub use terminal::{Attrs, Cell, Color, CursorShape, Grid, PtySize};
pub use traits::*;
