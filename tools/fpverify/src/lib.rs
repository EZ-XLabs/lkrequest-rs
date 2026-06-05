//! Fingerprint comparison & discovery — a **client-agnostic** core.
//!
//! This crate (`publish = false` for now) holds the reusable, byte-level
//! fingerprint machinery: canonical (normalized) fingerprint types, the
//! GREASE/shape normalizer, the per-profile shape spec, the shape-aware
//! comparator, heuristic shape discovery, and capture decoding.
//! See `docs/fingerprint-regression-design.md`.
//!
//! ## Client-agnostic invariant (keep it extractable)
//!
//! Everything here operates on **raw/parsed fingerprint bytes** (a parsed
//! ClientHello, H2 frames, a QUIC Initial) — it does NOT depend on `lkrequest`
//! or any specific HTTP client. This is deliberate: the same tooling is useful
//! to any browser-emulation / anti-bot project, so the core must stay
//! extractable (and one day publishable). **Do not add an `lkrequest`
//! dependency here.** The lkrequest-specific regression gate (which emits
//! lkrequest's own bytes via `lktls`/`lkh2`/`lkquic` and compares committed
//! goldens) lives separately in `lkrequest/tests/` with `fpverify` as a
//! dev-dependency.
//!
//! Nothing in the user-facing dependency path depends on this crate: end users
//! depend on `lkrequest` / `lkrequest-ffi`, which never pull `fpverify` in.

pub mod canonical;
pub mod compare;
pub mod shape;

pub use canonical::{
    tokenize, CanonicalExtSource, CanonicalExtension, CanonicalTlsFingerprint, GREASE_TOKEN,
};
pub use compare::{canonicalize_tls, diff_json, diff_tls, diff_values, FieldDiff};
pub use shape::TlsShapeSpec;
