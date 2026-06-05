//! TLS handshake message construction and parsing.
//!
//! This module contains:
//! - [`client_hello`]: Byte-level ClientHello builder driven by a [`TlsProfile`](crate::profile::types::TlsProfile).
//! - [`server_hello`]: ServerHello parser (extracts version, cipher suite, key share, etc.).
//! - [`tls12`]: TLS 1.2 handshake state machine (full + abbreviated with session ticket resumption).
//! - [`tls13`]: TLS 1.3 handshake state machine (with PSK resumption and HelloRetryRequest support).
//!
//! The [`content_type`] and [`handshake_type`] sub-modules provide TLS protocol constants.

pub mod client_hello;
pub mod driver;
pub mod server_hello;
pub mod tls12;
pub mod tls13;

/// TLS ContentType constants.
pub mod content_type {
    pub const CHANGE_CIPHER_SPEC: u8 = 0x14;
    pub const ALERT: u8 = 0x15;
    pub const HANDSHAKE: u8 = 0x16;
    pub const APPLICATION_DATA: u8 = 0x17;
}

/// TLS HandshakeType constants.
pub mod handshake_type {
    pub const CLIENT_HELLO: u8 = 0x01;
    pub const SERVER_HELLO: u8 = 0x02;
    pub const NEW_SESSION_TICKET: u8 = 0x04;
    pub const ENCRYPTED_EXTENSIONS: u8 = 0x08;
    pub const CERTIFICATE: u8 = 0x0b;
    /// CertificateRequest (RFC 8446 Section 4.3.2).
    pub const CERTIFICATE_REQUEST: u8 = 0x0d;
    pub const CERTIFICATE_VERIFY: u8 = 0x0f;
    /// CertificateStatus (OCSP Stapling, RFC 6066 Section 8).
    /// Sent by server in TLS 1.2 between Certificate and ServerKeyExchange.
    pub const CERTIFICATE_STATUS: u8 = 0x16;
    pub const FINISHED: u8 = 0x14;
    /// CompressedCertificate (RFC 8879).
    pub const COMPRESSED_CERTIFICATE: u8 = 0x19;
    pub const KEY_UPDATE: u8 = 0x18;
    /// Synthetic message type used for HRR transcript replacement (RFC 8446 Section 4.4.1).
    pub const MESSAGE_HASH: u8 = 0xFE;
}
