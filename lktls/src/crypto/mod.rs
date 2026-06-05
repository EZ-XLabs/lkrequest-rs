//! Cryptographic operations — thin wrappers around `ring` and `aws-lc-rs`.
//!
//! This module provides the crypto primitives needed by the TLS engine:
//!
//! - [`aead`] — Authenticated encryption (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305)
//! - [`kx`] — Key exchange (X25519, P-256 ECDH, X25519MLKEM768 hybrid post-quantum)
//! - [`hkdf`] — HKDF for TLS 1.3 key derivation (RFC 8446 Section 7.1)
//! - [`prf`] — PRF for TLS 1.2 key derivation (RFC 5246 Section 5)
//! - [`tls12_cipher`] — TLS 1.2 record-layer ciphers (GCM, ChaCha20, CBC+HMAC)

pub mod aead;
pub mod hkdf;
pub mod kx;
pub mod prf;
pub mod quic;
pub mod tls12_cipher;

/// Encode a byte slice as a lowercase hex string.
pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
