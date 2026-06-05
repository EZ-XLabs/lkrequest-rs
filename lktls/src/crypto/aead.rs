//! AEAD (Authenticated Encryption with Associated Data) operations.
//!
//! Supports:
//! - AES-128-GCM (TLS_AES_128_GCM_SHA256)
//! - AES-256-GCM (TLS_AES_256_GCM_SHA384)
//! - ChaCha20-Poly1305 (TLS_CHACHA20_POLY1305_SHA256)

use aws_lc_rs::aead;

use crate::error::{Result, TlsError};

/// Supported AEAD algorithms for TLS record protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    /// AES-128-GCM (TLS_AES_128_GCM_SHA256, 0x1301). 16-byte key.
    Aes128Gcm,
    /// AES-256-GCM (TLS_AES_256_GCM_SHA384, 0x1302). 32-byte key.
    Aes256Gcm,
    /// ChaCha20-Poly1305 (TLS_CHACHA20_POLY1305_SHA256, 0x1303). 32-byte key.
    Chacha20Poly1305,
}

impl AeadAlgorithm {
    /// Key length in bytes.
    pub fn key_len(&self) -> usize {
        match self {
            AeadAlgorithm::Aes128Gcm => 16,
            AeadAlgorithm::Aes256Gcm => 32,
            AeadAlgorithm::Chacha20Poly1305 => 32,
        }
    }

    /// Nonce (IV) length in bytes.
    pub fn nonce_len(&self) -> usize {
        12 // All three use 12-byte nonces
    }

    /// Authentication tag length in bytes.
    pub fn tag_len(&self) -> usize {
        16 // All three use 16-byte tags
    }

    /// Resolve from a TLS 1.3 cipher suite code point.
    pub fn from_cipher_suite(suite: u16) -> Option<Self> {
        match suite {
            0x1301 => Some(AeadAlgorithm::Aes128Gcm),
            0x1302 => Some(AeadAlgorithm::Aes256Gcm),
            0x1303 => Some(AeadAlgorithm::Chacha20Poly1305),
            _ => None,
        }
    }

    fn aead_algorithm_ref(&self) -> &'static aead::Algorithm {
        match self {
            AeadAlgorithm::Aes128Gcm => &aead::AES_128_GCM,
            AeadAlgorithm::Aes256Gcm => &aead::AES_256_GCM,
            AeadAlgorithm::Chacha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }
}

/// An AEAD encryptor/decryptor for TLS record protection.
///
/// In TLS 1.3, nonces are constructed by XOR-ing the per-record sequence number
/// with the IV derived from the traffic secret. This struct handles the
/// nonce construction and delegates to aws-lc-rs for the actual cryptography.
pub struct Aead {
    algorithm: AeadAlgorithm,
    /// The opening (decryption) key.
    opening_key: aead::LessSafeKey,
    /// The sealing (encryption) key — separate instance for the same key material.
    sealing_key: aead::LessSafeKey,
    /// The 12-byte IV (used to construct per-record nonces via XOR with seq num).
    iv: [u8; 12],
}

impl Aead {
    /// Create a new AEAD instance with the given algorithm, key bytes, and IV.
    ///
    /// The `key` must be `algorithm.key_len()` bytes.
    /// The `iv` must be 12 bytes.
    pub fn new(algorithm: AeadAlgorithm, key: &[u8], iv: &[u8]) -> Result<Self> {
        if key.len() != algorithm.key_len() {
            return Err(TlsError::CryptoError(format!(
                "AEAD key length mismatch: expected {}, got {}",
                algorithm.key_len(),
                key.len()
            )));
        }
        if iv.len() != 12 {
            return Err(TlsError::CryptoError(format!(
                "AEAD IV length mismatch: expected 12, got {}",
                iv.len()
            )));
        }

        let ring_algo = algorithm.aead_algorithm_ref();
        let unbound_key1 = aead::UnboundKey::new(ring_algo, key)
            .map_err(|_| TlsError::CryptoError("Failed to create AEAD key".to_string()))?;
        let unbound_key2 = aead::UnboundKey::new(ring_algo, key)
            .map_err(|_| TlsError::CryptoError("Failed to create AEAD key".to_string()))?;

        let mut iv_arr = [0u8; 12];
        iv_arr.copy_from_slice(iv);

        Ok(Self {
            algorithm,
            opening_key: aead::LessSafeKey::new(unbound_key1),
            sealing_key: aead::LessSafeKey::new(unbound_key2),
            iv: iv_arr,
        })
    }

    /// The AEAD algorithm.
    pub fn algorithm(&self) -> AeadAlgorithm {
        self.algorithm
    }

    /// Construct a nonce by XOR-ing the IV with a 64-bit sequence number.
    ///
    /// This is the TLS 1.3 nonce construction (RFC 8446 Section 5.3):
    /// The 64-bit sequence number is left-padded with zeros to 12 bytes,
    /// then XOR-ed with the IV.
    pub fn make_nonce(&self, seq_num: u64) -> aead::Nonce {
        let mut nonce = self.iv;
        let seq_bytes = seq_num.to_be_bytes(); // 8 bytes
                                               // XOR the last 8 bytes of the IV with the sequence number
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        aead::Nonce::assume_unique_for_key(nonce)
    }

    /// Encrypt `plaintext` with the given sequence number and AAD.
    ///
    /// Returns ciphertext + authentication tag appended.
    pub fn encrypt(&self, seq_num: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.make_nonce(seq_num);
        let aad = aead::Aad::from(aad);

        let mut in_out = Vec::with_capacity(plaintext.len() + self.algorithm.tag_len());
        in_out.extend_from_slice(plaintext);

        self.sealing_key
            .seal_in_place_append_tag(nonce, aad, &mut in_out)
            .map_err(|_| TlsError::CryptoError("AEAD encryption failed".to_string()))?;

        Ok(in_out)
    }

    /// Decrypt `ciphertext` (which includes the appended auth tag) with the
    /// given sequence number and AAD.
    ///
    /// Returns the plaintext.
    pub fn decrypt(&self, seq_num: u64, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.make_nonce(seq_num);
        let aad = aead::Aad::from(aad);

        let mut in_out = ciphertext.to_vec();
        let plaintext = self
            .opening_key
            .open_in_place(nonce, aad, &mut in_out)
            .map_err(|_| TlsError::CryptoError("AEAD decryption failed".to_string()))?;

        let len = plaintext.len();
        in_out.truncate(len);
        Ok(in_out)
    }
}

impl std::fmt::Debug for Aead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aead")
            .field("algorithm", &self.algorithm)
            .field("iv", &"[redacted]")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128gcm_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0x01u8; 12];
        let aead = Aead::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap();

        let plaintext = b"Hello, TLS 1.3!";
        let aad = b"additional data";
        let ciphertext = aead.encrypt(0, aad, plaintext).unwrap();

        assert_ne!(&ciphertext[..plaintext.len()], plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // 16-byte tag

        let decrypted = aead.decrypt(0, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes128gcm_nist_known_answer() {
        // NIST GCM AES-128 test case 1 (the canonical empty-input vector):
        // key = 0^16, IV = 0^12, plaintext = "", AAD = "" → ciphertext is the
        // 16-byte tag 0x58e2fccefa7e3061367f1d57a4e7455a. With iv = 0 and
        // seq_num = 0 the per-record nonce (iv XOR seq) is all-zero, matching the
        // vector — so this validates the AEAD output against a reference, not
        // just a self-consistent round-trip.
        let aead = Aead::new(AeadAlgorithm::Aes128Gcm, &[0u8; 16], &[0u8; 12]).unwrap();
        let out = aead.encrypt(0, &[], &[]).unwrap();
        assert_eq!(
            out,
            vec![
                0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
                0x45, 0x5a,
            ]
        );
    }

    #[test]
    fn test_aes256gcm_roundtrip() {
        let key = [0xAA; 32];
        let iv = [0xBB; 12];
        let aead = Aead::new(AeadAlgorithm::Aes256Gcm, &key, &iv).unwrap();

        let plaintext = b"AES-256-GCM test data";
        let ciphertext = aead.encrypt(42, &[], plaintext).unwrap();
        let decrypted = aead.decrypt(42, &[], &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20poly1305_roundtrip() {
        let key = [0xCC; 32];
        let iv = [0xDD; 12];
        let aead = Aead::new(AeadAlgorithm::Chacha20Poly1305, &key, &iv).unwrap();

        let plaintext = b"ChaCha20-Poly1305 test";
        let ciphertext = aead.encrypt(100, b"aad", plaintext).unwrap();
        let decrypted = aead.decrypt(100, b"aad", &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_seq_num_fails_decrypt() {
        let key = [0x42u8; 16];
        let iv = [0x01u8; 12];
        let aead = Aead::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap();

        let ciphertext = aead.encrypt(0, &[], b"test").unwrap();
        // Decrypt with wrong sequence number should fail
        let result = aead.decrypt(1, &[], &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails_decrypt() {
        let key = [0x42u8; 16];
        let iv = [0x01u8; 12];
        let aead = Aead::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap();

        let ciphertext = aead.encrypt(0, b"correct aad", b"test").unwrap();
        let result = aead.decrypt(0, b"wrong aad", &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_construction() {
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        ];
        let key = [0u8; 16];
        let aead = Aead::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap();

        // seq_num = 0 → nonce = IV
        let nonce0 = aead.make_nonce(0);
        assert_eq!(nonce0.as_ref(), &iv);

        // seq_num = 1 → last byte XOR'd with 1
        let nonce1 = aead.make_nonce(1);
        let mut expected = iv;
        expected[11] ^= 1;
        assert_eq!(nonce1.as_ref(), &expected);
    }

    #[test]
    fn test_from_cipher_suite() {
        assert_eq!(
            AeadAlgorithm::from_cipher_suite(0x1301),
            Some(AeadAlgorithm::Aes128Gcm)
        );
        assert_eq!(
            AeadAlgorithm::from_cipher_suite(0x1302),
            Some(AeadAlgorithm::Aes256Gcm)
        );
        assert_eq!(
            AeadAlgorithm::from_cipher_suite(0x1303),
            Some(AeadAlgorithm::Chacha20Poly1305)
        );
        assert_eq!(AeadAlgorithm::from_cipher_suite(0xFFFF), None);
    }

    #[test]
    fn test_invalid_key_length() {
        let result = Aead::new(AeadAlgorithm::Aes128Gcm, &[0u8; 32], &[0u8; 12]);
        assert!(result.is_err()); // AES-128 needs 16-byte key, not 32
    }
}
