//! TLS Record writer — encrypts and frames outgoing TLS records.
//!
//! The `RecordWriter` takes application data and handshake messages, wraps them
//! in TLS record framing, and optionally encrypts them.  Before keys are
//! established, records are emitted in plaintext.  After key installation via
//! [`RecordWriter::set_keys`] or [`RecordWriter::set_tls12_keys`], all
//! outgoing records are AEAD-encrypted.
//!
//! Supports two flush strategies:
//! - **Immediate**: each record is returned immediately (default).
//! - **Coalesce**: multiple records are buffered and returned together on
//!   [`RecordWriter::flush`], ensuring critical messages (e.g. ClientHello)
//!   are sent in a single TCP segment.

use super::{RecordHeader, Tls12RecordCipher, MAX_RECORD_PAYLOAD};
use crate::crypto::aead::Aead;
use crate::error::{Result, TlsError};
use crate::handshake::content_type;

/// Flush strategy for record output.
///
/// Controls whether records are emitted immediately or coalesced into
/// fewer TCP segments for better fingerprint control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FlushStrategy {
    /// Emit each record immediately.
    #[default]
    Immediate,
    /// Coalesce multiple small records before flushing.
    /// This ensures critical messages (like ClientHello) are sent in a single
    /// TCP segment, avoiding middlebox detection of TLS record splitting.
    Coalesce,
}

/// Writes TLS records, encrypting them once keys are established.
pub struct RecordWriter {
    /// Write sequence number (for AEAD nonce construction).
    seq_num: u64,
    /// TLS 1.3 AEAD encryption key + IV (None before keys are established).
    aead: Option<Aead>,
    /// TLS 1.2 record cipher (None if using TLS 1.3 or plaintext).
    tls12_cipher: Option<Tls12RecordCipher>,
    /// Flush strategy.
    flush_strategy: FlushStrategy,
    /// Internal buffer for coalesced records.
    coalesce_buf: Vec<u8>,
    /// Whether the first record (ClientHello) has been sent.
    /// RFC 8446 Section 5.1: initial ClientHello uses version 0x0301,
    /// all subsequent records use 0x0303.
    first_record_sent: bool,
}

impl RecordWriter {
    /// Create a new record writer (plaintext mode — no encryption).
    pub fn new() -> Self {
        Self {
            seq_num: 0,
            aead: None,
            tls12_cipher: None,
            flush_strategy: FlushStrategy::Immediate,
            coalesce_buf: Vec::new(),
            first_record_sent: false,
        }
    }

    /// Mark that the initial record has already been sent.
    ///
    /// Subsequent plaintext records will use version 0x0303 instead of 0x0301.
    /// Used for CH2 after HRR (the initial ClientHello was already sent).
    pub fn mark_post_initial(&mut self) {
        self.first_record_sent = true;
    }

    /// Set the flush strategy.
    pub fn set_flush_strategy(&mut self, strategy: FlushStrategy) {
        self.flush_strategy = strategy;
    }

    /// Flush any coalesced records, returning all buffered bytes.
    ///
    /// In `Immediate` mode this always returns empty.
    /// In `Coalesce` mode this returns any buffered records.
    pub fn flush(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.coalesce_buf)
    }

    /// Install TLS 1.3 encryption keys. All subsequent records will be encrypted.
    /// Resets the sequence number to 0.
    pub fn set_keys(&mut self, aead: Aead) {
        self.aead = Some(aead);
        self.tls12_cipher = None;
        self.seq_num = 0;
    }

    /// Install TLS 1.2 encryption keys. All subsequent records will be encrypted.
    /// Resets the sequence number to 0.
    pub fn set_tls12_keys(&mut self, cipher: Tls12RecordCipher) {
        self.tls12_cipher = Some(cipher);
        self.aead = None;
        self.seq_num = 0;
    }

    /// Wrap data into one or more TLS records.
    ///
    /// Before keys are established, this produces plaintext records.
    /// After keys are set, the payload is AEAD-encrypted per the negotiated version.
    ///
    /// For large payloads, the data is split into multiple records of at most
    /// `MAX_RECORD_PAYLOAD` bytes each.
    ///
    /// In `Immediate` mode, returns all record bytes concatenated.
    /// In `Coalesce` mode, buffers records internally — call [`Self::flush`] to retrieve.
    pub fn write_record(&mut self, content_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let mut output = Vec::new();

        if payload.is_empty() {
            let record = self.encode_single_record(content_type, &[])?;
            match self.flush_strategy {
                FlushStrategy::Immediate => output.extend_from_slice(&record),
                FlushStrategy::Coalesce => self.coalesce_buf.extend_from_slice(&record),
            }
            return Ok(output);
        }

        // Split into MAX_RECORD_PAYLOAD-sized chunks
        for chunk in payload.chunks(MAX_RECORD_PAYLOAD) {
            let record = self.encode_single_record(content_type, chunk)?;
            match self.flush_strategy {
                FlushStrategy::Immediate => output.extend_from_slice(&record),
                FlushStrategy::Coalesce => self.coalesce_buf.extend_from_slice(&record),
            }
        }

        Ok(output)
    }

    /// Encode a single TLS record.
    fn encode_single_record(&mut self, actual_content_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
        if self.tls12_cipher.is_some() {
            self.encode_tls12_encrypted_record(actual_content_type, payload)
        } else if self.aead.is_some() {
            self.encode_tls13_encrypted_record(actual_content_type, payload)
        } else {
            self.encode_plaintext_record(actual_content_type, payload)
        }
    }

    /// Encode a plaintext (unencrypted) TLS record.
    fn encode_plaintext_record(&mut self, ct: u8, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() > MAX_RECORD_PAYLOAD {
            return Err(TlsError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "record payload too large",
            )));
        }

        // RFC 8446 Section 5.1: initial ClientHello MAY use 0x0301,
        // all subsequent records MUST use 0x0303.
        let version = if !self.first_record_sent {
            self.first_record_sent = true;
            0x0301 // TLS 1.0 for initial ClientHello (compat)
        } else {
            0x0303 // TLS 1.2 for all subsequent records
        };

        let header = RecordHeader {
            content_type: ct,
            version,
            length: payload.len() as u16,
        };

        let mut record = Vec::with_capacity(5 + payload.len());
        record.extend_from_slice(&header.to_bytes());
        record.extend_from_slice(payload);
        Ok(record)
    }

    /// Encode a TLS 1.3 encrypted record.
    ///
    /// Structure:
    /// - Header: content_type=APPLICATION_DATA, version=0x0303, length
    /// - Encrypted payload: [actual_payload + inner_content_type] encrypted with AEAD
    ///
    /// The inner content type is appended to the plaintext before encryption,
    /// and the outer content type is always APPLICATION_DATA (0x17).
    fn encode_tls13_encrypted_record(
        &mut self,
        actual_content_type: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let aead = self.aead.as_ref().unwrap();
        // Build inner plaintext: payload + content_type byte
        let mut inner = Vec::with_capacity(payload.len() + 1);
        inner.extend_from_slice(payload);
        inner.push(actual_content_type); // TLS 1.3 inner content type

        // The encrypted length = inner plaintext length + AEAD tag (16 bytes)
        let encrypted_len = inner.len() + aead.algorithm().tag_len();

        // Build the record header (used as AAD)
        let header = RecordHeader {
            content_type: content_type::APPLICATION_DATA, // always 0x17 on wire
            version: 0x0303,                              // TLS 1.2 on wire
            length: encrypted_len as u16,
        };
        let header_bytes = header.to_bytes();

        // Encrypt with AAD = record header
        let ciphertext = aead.encrypt(self.seq_num, &header_bytes, &inner)?;
        self.seq_num = self
            .seq_num
            .checked_add(1)
            .ok_or_else(|| TlsError::CryptoError("write sequence number overflow".to_string()))?;

        // Assemble: header + ciphertext
        let mut record = Vec::with_capacity(5 + ciphertext.len());
        record.extend_from_slice(&header_bytes);
        record.extend_from_slice(&ciphertext);
        Ok(record)
    }

    /// Encode a TLS 1.2 encrypted record.
    ///
    /// Key differences from TLS 1.3:
    /// - Outer content type is the ORIGINAL type (not APPLICATION_DATA)
    /// - No inner content type byte
    /// - AAD = seq_num(8) + content_type(1) + version(2) + plaintext_length(2)
    /// - GCM: 8-byte explicit nonce prepended to ciphertext
    /// - ChaCha20: no explicit nonce (nonce = IV XOR seq_num)
    fn encode_tls12_encrypted_record(
        &mut self,
        actual_content_type: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = self.tls12_cipher.as_ref().unwrap();

        // TLS 1.2 AAD: seq_num(8) || content_type(1) || version(2) || plaintext_length(2)
        let mut aad = [0u8; 13];
        aad[..8].copy_from_slice(&self.seq_num.to_be_bytes());
        aad[8] = actual_content_type;
        aad[9] = 0x03;
        aad[10] = 0x03; // version 0x0303
        let payload_len = payload.len() as u16;
        aad[11] = (payload_len >> 8) as u8;
        aad[12] = payload_len as u8;

        let ciphertext = match cipher {
            Tls12RecordCipher::Gcm(gcm) => {
                // GCM: returns explicit_nonce(8) + encrypted + tag(16)
                gcm.encrypt(self.seq_num, &aad, payload)?
            }
            Tls12RecordCipher::Chacha20(chacha) => {
                // ChaCha20: returns encrypted + tag(16), no explicit nonce
                chacha.encrypt(self.seq_num, &aad, payload)?
            }
            Tls12RecordCipher::Cbc(cbc) => {
                // CBC: returns iv(16) + encrypted(plaintext + mac + padding)
                cbc.encrypt(self.seq_num, &aad, payload)?
            }
        };
        self.seq_num = self
            .seq_num
            .checked_add(1)
            .ok_or_else(|| TlsError::CryptoError("write sequence number overflow".to_string()))?;

        // Record header with original content type
        let header = RecordHeader {
            content_type: actual_content_type,
            version: 0x0303,
            length: ciphertext.len() as u16,
        };
        let header_bytes = header.to_bytes();

        let mut record = Vec::with_capacity(5 + ciphertext.len());
        record.extend_from_slice(&header_bytes);
        record.extend_from_slice(&ciphertext);
        Ok(record)
    }
}

impl Default for RecordWriter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::{Aead as AeadCipher, AeadAlgorithm};
    use crate::crypto::tls12_cipher::Tls12GcmCipher;
    use crate::record::reader::RecordReader;

    #[test]
    fn test_write_plaintext_record() {
        let mut writer = RecordWriter::new();
        let record = writer.write_record(0x16, b"ClientHello").unwrap();

        // Header: type=0x16, version=0x0301, length=11
        assert_eq!(record[0], 0x16);
        assert_eq!(record[1], 0x03);
        assert_eq!(record[2], 0x01);
        assert_eq!(u16::from_be_bytes([record[3], record[4]]), 11);
        assert_eq!(&record[5..], b"ClientHello");
    }

    #[test]
    fn test_write_empty_record() {
        let mut writer = RecordWriter::new();
        let record = writer.write_record(0x14, &[]).unwrap(); // CCS
        assert_eq!(record.len(), 5); // just the header
        assert_eq!(record[0], 0x14);
        assert_eq!(u16::from_be_bytes([record[3], record[4]]), 0);
    }

    #[test]
    fn test_tls13_encrypted_record_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0x01u8; 12];

        let mut writer = RecordWriter::new();
        writer.set_keys(AeadCipher::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap());

        let plaintext = b"secret handshake data";
        let record = writer.write_record(0x16, plaintext).unwrap();

        // Outer content type should be APPLICATION_DATA (0x17)
        assert_eq!(record[0], 0x17);
        // Outer version should be 0x0303
        assert_eq!(record[1], 0x03);
        assert_eq!(record[2], 0x03);

        // Decrypt with a reader
        let mut reader = RecordReader::new();
        reader.set_keys(AeadCipher::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap());
        reader.feed(&record);

        let result = reader.next_record().unwrap().unwrap();
        assert_eq!(result.content_type, 0x16); // inner content type = handshake
        assert_eq!(result.payload, plaintext);
    }

    #[test]
    fn test_tls12_gcm_encrypted_record_roundtrip() {
        let key = [0x42u8; 16];
        let implicit_iv = [0x01, 0x02, 0x03, 0x04];

        let mut writer = RecordWriter::new();
        writer.mark_post_initial();
        writer.set_tls12_keys(Tls12RecordCipher::Gcm(
            Tls12GcmCipher::new(&key, &implicit_iv, false).unwrap(),
        ));

        let plaintext = b"Hello TLS 1.2 GCM!";
        let record = writer.write_record(0x16, plaintext).unwrap();

        // Outer content type should be HANDSHAKE (0x16) — not APPLICATION_DATA
        assert_eq!(record[0], 0x16);
        assert_eq!(record[1], 0x03);
        assert_eq!(record[2], 0x03);

        // Record length = 8 (explicit nonce) + payload_len + 16 (tag)
        let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        assert_eq!(record_len, 8 + plaintext.len() + 16);

        // Decrypt with a TLS 1.2 reader
        let mut reader = RecordReader::new();
        reader.set_tls12_keys(Tls12RecordCipher::Gcm(
            Tls12GcmCipher::new(&key, &implicit_iv, false).unwrap(),
        ));
        reader.feed(&record);

        let result = reader.next_record().unwrap().unwrap();
        assert_eq!(result.content_type, 0x16); // original content type preserved
        assert_eq!(result.payload, plaintext);
    }

    #[test]
    fn test_large_payload_splits() {
        let mut writer = RecordWriter::new();
        // Payload larger than MAX_RECORD_PAYLOAD
        let large = vec![0xAA; MAX_RECORD_PAYLOAD + 100];
        let records = writer.write_record(0x17, &large).unwrap();

        // Should produce 2 records
        // First record: header (5) + MAX_RECORD_PAYLOAD
        let first_len = 5 + MAX_RECORD_PAYLOAD;
        assert_eq!(records[0], 0x17);
        assert_eq!(
            u16::from_be_bytes([records[3], records[4]]),
            MAX_RECORD_PAYLOAD as u16
        );

        // Second record at offset first_len
        assert_eq!(records[first_len], 0x17);
        assert_eq!(
            u16::from_be_bytes([records[first_len + 3], records[first_len + 4]]),
            100
        );
    }

    #[test]
    fn test_tls13_encrypted_multiple_records_seq_num() {
        let key = [0x42u8; 16];
        let iv = [0x01u8; 12];

        let mut writer = RecordWriter::new();
        writer.set_keys(AeadCipher::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap());

        let r1 = writer.write_record(0x16, b"first").unwrap();
        let r2 = writer.write_record(0x16, b"second").unwrap();

        // Both should decrypt with correct sequence numbers
        let mut reader = RecordReader::new();
        reader.set_keys(AeadCipher::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap());

        reader.feed(&r1);
        reader.feed(&r2);

        let p1 = reader.next_record().unwrap().unwrap();
        assert_eq!(p1.payload, b"first");

        let p2 = reader.next_record().unwrap().unwrap();
        assert_eq!(p2.payload, b"second");
    }
}
