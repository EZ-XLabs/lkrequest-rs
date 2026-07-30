//! # lktls — Sans-I/O TLS Fingerprint Protocol Engine
//!
//! `lktls` is a Sans-I/O TLS protocol engine for fine-grained control over
//! TLS handshakes, enabling precise simulation of any client's TLS fingerprint
//! (Chrome, Firefox, Safari, OkHttp3, etc.).
//!
//! This crate contains **only protocol logic** — no network I/O, no async
//! runtime dependency. The I/O adapter (TlsConnector, TlsStream) lives in
//! the `lkrequest` crate.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │         Fingerprint Profile (data)           │
//! │  chrome_131 / firefox_133 / safari_18 / ...  │
//! ├─────────────────────────────────────────────┤
//! │         ClientHello Builder (bytes)           │
//! │  Encodes extensions in profile-specified      │
//! │  order with exact cipher suite lists          │
//! ├─────────────────────────────────────────────┤
//! │     Handshake State Machine (TLS 1.3/1.2)    │
//! ├─────────────────────────────────────────────┤
//! │       Record Layer (AEAD encrypt/decrypt)     │
//! ├─────────────────────────────────────────────┤
//! │     Crypto Backend (ring / aws-lc-rs)         │
//! └─────────────────────────────────────────────┘
//! ```

use std::sync::Arc;

/// Callback type for TLS key logging (SSLKEYLOGFILE format).
///
/// Each invocation receives one complete line (without trailing newline)
/// in the [NSS Key Log format](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format).
///
/// Wireshark uses these lines to decrypt captured TLS traffic.
pub type KeyLogCallback = Arc<dyn Fn(&str) + Send + Sync>;

/// Callback invoked with the ClientHello **handshake message** bytes (the
/// `0x01`-prefixed handshake, before TLS-record / QUIC-CRYPTO framing) the moment
/// they are produced — the exact outbound TLS fingerprint, including any
/// per-connection GREASE/shuffle and the real (outer) ECH ClientHello. The bytes
/// are directly parseable with `lkprofile::parse_client_hello`. Fired inline by
/// both the TCP and QUIC handshake drivers, so keep the callback cheap and
/// non-blocking. Observation/diagnostics only — it cannot alter the handshake.
pub type ClientHelloCallback = Arc<dyn Fn(&[u8]) + Send + Sync>;

pub mod crypto;
pub mod ech;
pub mod error;
pub mod extensions;
pub mod handshake;
pub mod profile;
pub mod record;
pub mod session_store;
pub mod verify;
