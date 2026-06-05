//! Encrypted Client Hello (ECH) — real ECH encryption support.
//!
//! ECH encrypts the "real" ClientHello (containing the true SNI) inside
//! an outer ClientHello (with a public-facing SNI), preventing network
//! intermediaries from seeing which server the client is connecting to.
//!
//! This module implements the client-side of draft-ietf-tls-esni-24:
//!
//! - [`config`] — Parse ECHConfigList wire-format (from DNS HTTPS records) into structured data.
//! - [`hpke`] — HPKE encryption wrapper for sealing the inner ClientHello.
//! - [`inner`] — Construct and encode the EncodedClientHelloInner with
//!   padding and `ech_outer_extensions` compression.
//!
//! ## Usage Flow
//!
//! 1. Obtain an ECHConfigList (from DNS HTTPS records or server retry configs)
//! 2. Parse it via [`config::parse_ech_config_list`]
//! 3. Build the inner ClientHello via [`inner::encode_client_hello_inner`]
//! 4. Encrypt it via [`hpke::ech_hpke_seal`]
//! 5. Embed the encrypted payload in the outer ClientHello's ECH extension

pub mod config;
pub mod hpke;
pub mod inner;
