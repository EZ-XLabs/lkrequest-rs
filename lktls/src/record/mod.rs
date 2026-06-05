//! TLS Record Layer — framing and encryption/decryption of records.
//!
//! The record layer sits between the handshake/application layer and the
//! transport (TCP).  It handles:
//! - Framing: splitting data into TLS records with type/version/length headers
//! - Encryption: AEAD encryption of outgoing records
//! - Decryption: AEAD decryption of incoming records
//! - Sequence number management
//!
//! Supports both TLS 1.3 and TLS 1.2 record formats:
//! - TLS 1.3: nonce = IV XOR seq_num, outer type = APPLICATION_DATA, inner type appended
//! - TLS 1.2 GCM: nonce = implicit_iv(4) || explicit_nonce(8), original content type
//! - TLS 1.2 ChaCha20: nonce = IV XOR seq_num (like TLS 1.3), original content type

pub mod reader;
pub mod writer;

use crate::crypto::tls12_cipher::{Tls12CbcCipher, Tls12Chacha20Cipher, Tls12GcmCipher};

/// TLS 1.2 record-layer cipher.
///
/// Wraps the GCM, ChaCha20-Poly1305, or CBC+HMAC cipher for the record reader/writer.
pub enum Tls12RecordCipher {
    /// AES-GCM (128 or 256): uses 4-byte implicit IV + 8-byte explicit nonce.
    Gcm(Tls12GcmCipher),
    /// ChaCha20-Poly1305: uses 12-byte IV XOR seq_num (same as TLS 1.3).
    Chacha20(Tls12Chacha20Cipher),
    /// AES-CBC + HMAC: legacy MAC-then-encrypt mode.
    Cbc(Tls12CbcCipher),
}

/// Maximum TLS record payload size (2^14 = 16384 bytes).
pub const MAX_RECORD_PAYLOAD: usize = 16384;

/// TLS record header size: ContentType (1) + Version (2) + Length (2).
pub const RECORD_HEADER_SIZE: usize = 5;

/// A parsed TLS record header.
#[derive(Debug, Clone)]
pub struct RecordHeader {
    /// Content type (handshake, application_data, alert, etc.).
    pub content_type: u8,
    /// Protocol version on the wire (usually 0x0303).
    pub version: u16,
    /// Length of the record payload.
    pub length: u16,
}

impl RecordHeader {
    /// Parse a record header from exactly 5 bytes.
    pub fn from_bytes(bytes: &[u8; 5]) -> Self {
        Self {
            content_type: bytes[0],
            version: u16::from_be_bytes([bytes[1], bytes[2]]),
            length: u16::from_be_bytes([bytes[3], bytes[4]]),
        }
    }

    /// Encode the header into 5 bytes.
    pub fn to_bytes(&self) -> [u8; 5] {
        let ver = self.version.to_be_bytes();
        let len = self.length.to_be_bytes();
        [self.content_type, ver[0], ver[1], len[0], len[1]]
    }
}
