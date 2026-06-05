//! Fingerprint profile management.
//!
//! A [`TlsProfile`] fully describes the ClientHello characteristics of a
//! specific client (Chrome, Firefox, Safari, etc.).  The entire TLS engine
//! is driven by these data-only structures — adding a new client fingerprint
//! only requires creating a new profile JSON, no code changes.
//!
//! ## Sub-modules
//!
//! - [`types`] — Core data structures ([`TlsProfile`], [`ExtensionSpec`],
//!   [`GreaseConfig`](types::GreaseConfig), etc.)
//! - [`presets`] — Built-in profiles for Chrome, Firefox, and Safari.
//! - [`loader`] — Load custom profiles from JSON files or strings.
//! - [`synthesis`] — Structural validation (and, later, generation) for
//!   randomized/synthesized fingerprints.

pub mod loader;
pub mod presets;
pub mod synthesis;
pub mod types;

// Re-export commonly used types at the profile module level.
pub use synthesis::{validate, InvalidSpec};
pub use types::{ExtensionSource, ExtensionSpec, TlsProfile, TlsVersion};
