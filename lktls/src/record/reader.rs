//! TLS Record reader — reads and decrypts incoming TLS records.
//!
//! The `RecordReader` accumulates bytes from the transport and produces
//! [`PlaintextRecord`]s.  Before keys are established (during the initial
//! handshake), records are returned as-is.  After key installation via
//! [`RecordReader::set_keys`] or [`RecordReader::set_tls12_keys`], all
//! incoming records are automatically decrypted and their sequence numbers
//! are tracked for AEAD nonce construction.

use super::{RecordHeader, Tls12RecordCipher, MAX_RECORD_PAYLOAD, RECORD_HEADER_SIZE};
use crate::crypto::aead::Aead;
use crate::error::{Result, TlsError};
use crate::handshake::content_type;

/// A decrypted TLS record.
#[derive(Debug)]
pub struct PlaintextRecord {
    /// The actual content type.
    /// For TLS 1.3 encrypted records, this is extracted from the last byte
    /// of the decrypted payload (inner content type), not the record header.
    /// For TLS 1.2, this is the content type from the record header.
    pub content_type: u8,
    /// The decrypted payload (without inner content type byte for TLS 1.3).
    pub payload: Vec<u8>,
}

/// Reads TLS records from a byte stream, decrypting them once keys are
/// established.
pub struct RecordReader {
    /// Buffer for accumulating incoming bytes.
    buf: Vec<u8>,
    /// Read sequence number (for AEAD nonce construction).
    seq_num: u64,
    /// TLS 1.3 AEAD decryption key + IV (None before keys are established).
    aead: Option<Aead>,
    /// TLS 1.2 record cipher (None if using TLS 1.3 or plaintext).
    tls12_cipher: Option<Tls12RecordCipher>,
}

impl RecordReader {
    /// Create a new record reader (plaintext mode — no decryption).
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(MAX_RECORD_PAYLOAD + RECORD_HEADER_SIZE + 256),
            seq_num: 0,
            aead: None,
            tls12_cipher: None,
        }
    }

    /// Install TLS 1.3 decryption keys. All subsequent records will be decrypted.
    /// Resets the sequence number to 0.
    pub fn set_keys(&mut self, aead: Aead) {
        self.aead = Some(aead);
        self.tls12_cipher = None;
        self.seq_num = 0;
    }

    /// Install TLS 1.2 decryption keys. All subsequent records will be decrypted.
    /// Resets the sequence number to 0.
    pub fn set_tls12_keys(&mut self, cipher: Tls12RecordCipher) {
        self.tls12_cipher = Some(cipher);
        self.aead = None;
        self.seq_num = 0;
    }

    /// Feed raw bytes from the transport into the reader.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Returns the number of buffered bytes not yet consumed.
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    /// Try to read the next complete TLS record.
    ///
    /// Returns `Ok(None)` if not enough data is available yet.
    /// Returns `Ok(Some(record))` when a complete record is available.
    pub fn next_record(&mut self) -> Result<Option<PlaintextRecord>> {
        // Step 1: Do we have a complete header?
        if self.buf.len() < RECORD_HEADER_SIZE {
            return Ok(None);
        }

        let header = RecordHeader::from_bytes(self.buf[..RECORD_HEADER_SIZE].try_into().unwrap());

        let payload_len = header.length as usize;
        let is_encrypted = self.aead.is_some() || self.tls12_cipher.is_some();
        // RFC 8446 §5.1 / RFC 5246 §6.2.1: plaintext records are limited to
        // 2^14 bytes; encrypted records may add up to 256 bytes of overhead.
        let max_len = if is_encrypted {
            MAX_RECORD_PAYLOAD + 256
        } else {
            MAX_RECORD_PAYLOAD
        };
        if payload_len > max_len {
            return Err(TlsError::UnexpectedMessage(format!(
                "TLS record too large: {} bytes (max {})",
                payload_len, max_len,
            )));
        }

        // Step 2: Do we have the full record?
        let total_len = RECORD_HEADER_SIZE + payload_len;
        if self.buf.len() < total_len {
            return Ok(None);
        }

        // Step 3: Extract the record payload
        let raw_payload = self.buf[RECORD_HEADER_SIZE..total_len].to_vec();
        // Remove the consumed record from the buffer
        self.buf.drain(..total_len);

        // Step 4a: TLS 1.2 decryption — decrypt ALL records after keys installed
        if let Some(ref tls12_cipher) = self.tls12_cipher {
            // In TLS 1.2, after CCS, ALL records are encrypted.
            // The content type in the header is the real content type.
            // AAD = seq_num(8) + content_type(1) + version(2) + plaintext_length(2)

            let plaintext = match tls12_cipher {
                Tls12RecordCipher::Gcm(gcm) => {
                    // GCM: raw_payload = explicit_nonce(8) + ciphertext + tag(16)
                    // Plaintext length = record payload length - 8 - 16
                    if raw_payload.len() < 8 + 16 {
                        return Err(TlsError::CryptoError("TLS 1.2 GCM record too short".into()));
                    }
                    let plaintext_len = raw_payload.len() - 8 - 16;
                    let mut aad = [0u8; 13];
                    aad[..8].copy_from_slice(&self.seq_num.to_be_bytes());
                    aad[8] = header.content_type;
                    aad[9] = (header.version >> 8) as u8;
                    aad[10] = header.version as u8;
                    aad[11] = (plaintext_len >> 8) as u8;
                    aad[12] = plaintext_len as u8;

                    gcm.decrypt(&aad, &raw_payload)?
                }
                Tls12RecordCipher::Chacha20(chacha) => {
                    // ChaCha20: raw_payload = ciphertext + tag(16), no explicit nonce
                    if raw_payload.len() < 16 {
                        return Err(TlsError::CryptoError(
                            "TLS 1.2 ChaCha20 record too short".into(),
                        ));
                    }
                    let plaintext_len = raw_payload.len() - 16;
                    let mut aad = [0u8; 13];
                    aad[..8].copy_from_slice(&self.seq_num.to_be_bytes());
                    aad[8] = header.content_type;
                    aad[9] = (header.version >> 8) as u8;
                    aad[10] = header.version as u8;
                    aad[11] = (plaintext_len >> 8) as u8;
                    aad[12] = plaintext_len as u8;

                    chacha.decrypt(self.seq_num, &aad, &raw_payload)?
                }
                Tls12RecordCipher::Cbc(cbc) => {
                    // CBC: raw_payload = iv(16) + encrypted(plaintext + mac + padding)
                    // AAD uses record payload length (which includes IV + encrypted data).
                    // The CBC cipher internally rebuilds the correct AAD with plaintext length.
                    let mut aad = [0u8; 13];
                    aad[..8].copy_from_slice(&self.seq_num.to_be_bytes());
                    aad[8] = header.content_type;
                    aad[9] = (header.version >> 8) as u8;
                    aad[10] = header.version as u8;
                    // For CBC, pass the record payload length in AAD; the cipher
                    // will reconstruct the correct plaintext length internally.
                    let rpl = raw_payload.len() as u16;
                    aad[11] = (rpl >> 8) as u8;
                    aad[12] = rpl as u8;

                    cbc.decrypt(&aad, &raw_payload)?
                }
            };
            self.seq_num = self.seq_num.checked_add(1).ok_or_else(|| {
                TlsError::UnexpectedMessage("record sequence number overflow".to_string())
            })?;

            return Ok(Some(PlaintextRecord {
                content_type: header.content_type,
                payload: plaintext,
            }));
        }

        // Step 4b: TLS 1.3 decryption — only APPLICATION_DATA records
        if let Some(ref aead) = self.aead {
            if header.content_type == content_type::APPLICATION_DATA {
                // TLS 1.3: encrypted records use content_type APPLICATION_DATA on the wire.
                // AAD = the 5-byte record header (with the encrypted length).
                let aad = header.to_bytes();
                let plaintext = aead.decrypt(self.seq_num, &aad, &raw_payload)?;
                self.seq_num = self.seq_num.checked_add(1).ok_or_else(|| {
                    TlsError::UnexpectedMessage("record sequence number overflow".to_string())
                })?;

                // TLS 1.3: the last non-zero byte of the decrypted payload is the
                // inner content type. Strip trailing zeros and the content type byte.
                let (inner_ct, inner_payload) = strip_inner_content_type(&plaintext)?;

                return Ok(Some(PlaintextRecord {
                    content_type: inner_ct,
                    payload: inner_payload,
                }));
            }
        }

        // Plaintext record (no encryption) or non-application_data during handshake
        Ok(Some(PlaintextRecord {
            content_type: header.content_type,
            payload: raw_payload,
        }))
    }
}

impl Default for RecordReader {
    fn default() -> Self {
        Self::new()
    }
}

/// Strip the TLS 1.3 inner content type from a decrypted record payload.
///
/// The inner content type is the last non-zero byte. Everything after (zeros)
/// is padding and is stripped.
fn strip_inner_content_type(plaintext: &[u8]) -> Result<(u8, Vec<u8>)> {
    // Find the last non-zero byte (the inner content type)
    let ct_pos = plaintext.iter().rposition(|&b| b != 0).ok_or_else(|| {
        TlsError::UnexpectedMessage("Decrypted record has no content type".to_string())
    })?;

    let inner_content_type = plaintext[ct_pos];
    let inner_payload = plaintext[..ct_pos].to_vec();

    Ok((inner_content_type, inner_payload))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::AeadAlgorithm;
    use crate::crypto::tls12_cipher::Tls12GcmCipher;

    #[test]
    fn test_read_plaintext_record() {
        let mut reader = RecordReader::new();

        // Build a handshake record: type=0x16, version=0x0303, length=5
        let payload = b"hello";
        let mut record = vec![0x16, 0x03, 0x03, 0x00, 0x05];
        record.extend_from_slice(payload);

        reader.feed(&record);
        let result = reader.next_record().unwrap().unwrap();
        assert_eq!(result.content_type, 0x16);
        assert_eq!(result.payload, b"hello");
    }

    #[test]
    fn test_partial_feed() {
        let mut reader = RecordReader::new();

        // Feed only the header first
        reader.feed(&[0x16, 0x03, 0x03, 0x00, 0x03]);
        assert!(reader.next_record().unwrap().is_none());

        // Feed the payload
        reader.feed(&[0x01, 0x02, 0x03]);
        let result = reader.next_record().unwrap().unwrap();
        assert_eq!(result.payload, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_multiple_records() {
        let mut reader = RecordReader::new();

        // Two records back to back
        let mut data = Vec::new();
        data.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x02, 0xAA, 0xBB]);
        data.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x01, 0xCC]);
        reader.feed(&data);

        let r1 = reader.next_record().unwrap().unwrap();
        assert_eq!(r1.content_type, 0x16);
        assert_eq!(r1.payload, vec![0xAA, 0xBB]);

        let r2 = reader.next_record().unwrap().unwrap();
        assert_eq!(r2.content_type, 0x17);
        assert_eq!(r2.payload, vec![0xCC]);

        assert!(reader.next_record().unwrap().is_none());
    }

    #[test]
    fn test_tls13_encrypted_record_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0x01u8; 12];

        // Build inner plaintext: payload + inner content type
        let inner_payload = b"handshake data";
        let mut plaintext_with_ct = inner_payload.to_vec();
        plaintext_with_ct.push(0x16); // inner content type = handshake

        // Compute the expected ciphertext length to build the header (AAD) first
        let ct_len = plaintext_with_ct.len() + 16; // payload + AEAD tag
        let header_bytes: [u8; 5] = [0x17, 0x03, 0x03, (ct_len >> 8) as u8, ct_len as u8];

        // Encrypt with the header as AAD
        let enc = Aead::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap();
        let ct = enc.encrypt(0, &header_bytes, &plaintext_with_ct).unwrap();
        assert_eq!(ct.len(), ct_len);

        // Assemble the full TLS record
        let mut record = header_bytes.to_vec();
        record.extend_from_slice(&ct);

        // Decrypt via RecordReader
        let mut reader = RecordReader::new();
        reader.set_keys(Aead::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap());
        reader.feed(&record);

        let result = reader.next_record().unwrap().unwrap();
        assert_eq!(result.content_type, 0x16); // inner content type
        assert_eq!(result.payload, inner_payload);
    }

    #[test]
    fn test_tls12_gcm_encrypted_record_roundtrip() {
        let key = [0x42u8; 16];
        let implicit_iv = [0x01, 0x02, 0x03, 0x04];

        // Use the writer to create a TLS 1.2 encrypted record
        use crate::record::writer::RecordWriter;
        let mut writer = RecordWriter::new();
        writer.mark_post_initial();
        writer.set_tls12_keys(Tls12RecordCipher::Gcm(
            Tls12GcmCipher::new(&key, &implicit_iv, false).unwrap(),
        ));

        let plaintext = b"TLS 1.2 GCM reader test";
        let record = writer.write_record(0x16, plaintext).unwrap();

        // Decrypt with reader
        let mut reader = RecordReader::new();
        reader.set_tls12_keys(Tls12RecordCipher::Gcm(
            Tls12GcmCipher::new(&key, &implicit_iv, false).unwrap(),
        ));
        reader.feed(&record);

        let result = reader.next_record().unwrap().unwrap();
        assert_eq!(result.content_type, 0x16);
        assert_eq!(result.payload, plaintext);
    }

    #[test]
    fn test_tls12_gcm_multiple_records() {
        let key = [0x42u8; 16];
        let implicit_iv = [0xAA, 0xBB, 0xCC, 0xDD];

        use crate::record::writer::RecordWriter;
        let mut writer = RecordWriter::new();
        writer.mark_post_initial();
        writer.set_tls12_keys(Tls12RecordCipher::Gcm(
            Tls12GcmCipher::new(&key, &implicit_iv, false).unwrap(),
        ));

        let r1 = writer.write_record(0x16, b"first").unwrap();
        let r2 = writer.write_record(0x17, b"second").unwrap();

        let mut reader = RecordReader::new();
        reader.set_tls12_keys(Tls12RecordCipher::Gcm(
            Tls12GcmCipher::new(&key, &implicit_iv, false).unwrap(),
        ));

        reader.feed(&r1);
        reader.feed(&r2);

        let p1 = reader.next_record().unwrap().unwrap();
        assert_eq!(p1.content_type, 0x16);
        assert_eq!(p1.payload, b"first");

        let p2 = reader.next_record().unwrap().unwrap();
        assert_eq!(p2.content_type, 0x17);
        assert_eq!(p2.payload, b"second");
    }

    #[test]
    fn test_strip_inner_content_type() {
        // Normal case: payload + content_type byte
        let data = vec![0x01, 0x02, 0x03, 0x16];
        let (ct, payload) = strip_inner_content_type(&data).unwrap();
        assert_eq!(ct, 0x16);
        assert_eq!(payload, vec![0x01, 0x02, 0x03]);

        // With trailing zero padding
        let data_padded = vec![0x01, 0x02, 0x16, 0x00, 0x00];
        let (ct, payload) = strip_inner_content_type(&data_padded).unwrap();
        assert_eq!(ct, 0x16);
        assert_eq!(payload, vec![0x01, 0x02]);
    }

    #[test]
    fn test_record_too_large() {
        let mut reader = RecordReader::new();
        // Record claiming to be 20000 bytes (> MAX_RECORD_PAYLOAD + 256)
        reader.feed(&[0x16, 0x03, 0x03, 0x4E, 0x20]);
        let result = reader.next_record();
        assert!(result.is_err());
    }
}
