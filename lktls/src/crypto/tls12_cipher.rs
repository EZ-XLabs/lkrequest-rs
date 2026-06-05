//! TLS 1.2 record-layer ciphers.
//!
//! TLS 1.2 supports two families of cipher suites for record protection:
//!
//! - **GCM (AEAD)**: Modern, secure. Uses 4-byte implicit IV + 8-byte explicit nonce.
//!   Examples: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
//!
//! - **CBC + HMAC**: Legacy. Uses MAC-then-encrypt with block cipher padding.
//!   Examples: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xC013)
//!
//! This module abstracts both behind a common [`Tls12CipherSuite`] enum.

use crate::error::{Result, TlsError};

/// Key exchange algorithm used by a TLS 1.2 cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls12KeyExchange {
    /// ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) — provides forward secrecy.
    Ecdhe,
    /// Static RSA — client encrypts pre-master secret with server's RSA public key.
    Rsa,
}

/// A TLS 1.2 cipher suite's record-protection parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls12CipherSuite {
    /// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02B)
    EcdheEcdsaAes128GcmSha256,
    /// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
    EcdheRsaAes128GcmSha256,
    /// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xC02C)
    EcdheEcdsaAes256GcmSha384,
    /// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xC030)
    EcdheRsaAes256GcmSha384,
    /// TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA9)
    EcdheEcdsaChacha20Poly1305,
    /// TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA8)
    EcdheRsaChacha20Poly1305,
    /// TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xC013) — legacy CBC
    EcdheRsaAes128CbcSha,
    /// TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xC014) — legacy CBC
    EcdheRsaAes256CbcSha,
    /// TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xC027) — legacy CBC
    EcdheRsaAes128CbcSha256,
    /// TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xC028) — legacy CBC
    EcdheRsaAes256CbcSha384,
    /// TLS_RSA_WITH_AES_256_CBC_SHA (0x0035) — static RSA key exchange, legacy CBC
    RsaAes256CbcSha,
    /// TLS_RSA_WITH_AES_128_CBC_SHA (0x002F) — static RSA key exchange, legacy CBC
    RsaAes128CbcSha,
    /// TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003D) — static RSA key exchange, legacy CBC
    RsaAes256CbcSha256,
    /// TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003C) — static RSA key exchange, legacy CBC
    RsaAes128CbcSha256,
    /// TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009C) — static RSA key exchange, GCM
    RsaAes128GcmSha256,
    /// TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009D) — static RSA key exchange, GCM
    RsaAes256GcmSha384,
}

impl Tls12CipherSuite {
    /// Resolve from a TLS cipher suite code point.
    pub fn from_code_point(code: u16) -> Option<Self> {
        match code {
            0xC02B => Some(Self::EcdheEcdsaAes128GcmSha256),
            0xC02F => Some(Self::EcdheRsaAes128GcmSha256),
            0xC02C => Some(Self::EcdheEcdsaAes256GcmSha384),
            0xC030 => Some(Self::EcdheRsaAes256GcmSha384),
            0xCCA9 => Some(Self::EcdheEcdsaChacha20Poly1305),
            0xCCA8 => Some(Self::EcdheRsaChacha20Poly1305),
            0xC013 => Some(Self::EcdheRsaAes128CbcSha),
            0xC014 => Some(Self::EcdheRsaAes256CbcSha),
            0xC027 => Some(Self::EcdheRsaAes128CbcSha256),
            0xC028 => Some(Self::EcdheRsaAes256CbcSha384),
            0x0035 => Some(Self::RsaAes256CbcSha),
            0x002F => Some(Self::RsaAes128CbcSha),
            0x003D => Some(Self::RsaAes256CbcSha256),
            0x003C => Some(Self::RsaAes128CbcSha256),
            0x009C => Some(Self::RsaAes128GcmSha256),
            0x009D => Some(Self::RsaAes256GcmSha384),
            _ => None,
        }
    }

    /// Return the TLS cipher suite code point.
    pub fn code_point(self) -> u16 {
        match self {
            Self::EcdheEcdsaAes128GcmSha256 => 0xC02B,
            Self::EcdheRsaAes128GcmSha256 => 0xC02F,
            Self::EcdheEcdsaAes256GcmSha384 => 0xC02C,
            Self::EcdheRsaAes256GcmSha384 => 0xC030,
            Self::EcdheEcdsaChacha20Poly1305 => 0xCCA9,
            Self::EcdheRsaChacha20Poly1305 => 0xCCA8,
            Self::EcdheRsaAes128CbcSha => 0xC013,
            Self::EcdheRsaAes256CbcSha => 0xC014,
            Self::EcdheRsaAes128CbcSha256 => 0xC027,
            Self::EcdheRsaAes256CbcSha384 => 0xC028,
            Self::RsaAes256CbcSha => 0x0035,
            Self::RsaAes128CbcSha => 0x002F,
            Self::RsaAes256CbcSha256 => 0x003D,
            Self::RsaAes128CbcSha256 => 0x003C,
            Self::RsaAes128GcmSha256 => 0x009C,
            Self::RsaAes256GcmSha384 => 0x009D,
        }
    }

    /// Key exchange algorithm used by this cipher suite.
    pub fn key_exchange(&self) -> Tls12KeyExchange {
        match self {
            Self::RsaAes256CbcSha
            | Self::RsaAes128CbcSha
            | Self::RsaAes256CbcSha256
            | Self::RsaAes128CbcSha256
            | Self::RsaAes128GcmSha256
            | Self::RsaAes256GcmSha384 => Tls12KeyExchange::Rsa,
            _ => Tls12KeyExchange::Ecdhe,
        }
    }

    /// Whether this suite uses AEAD (GCM/ChaCha20).
    pub fn is_aead(&self) -> bool {
        matches!(
            self,
            Self::EcdheEcdsaAes128GcmSha256
                | Self::EcdheRsaAes128GcmSha256
                | Self::EcdheEcdsaAes256GcmSha384
                | Self::EcdheRsaAes256GcmSha384
                | Self::EcdheEcdsaChacha20Poly1305
                | Self::EcdheRsaChacha20Poly1305
                | Self::RsaAes128GcmSha256
                | Self::RsaAes256GcmSha384
        )
    }

    /// Whether this suite uses CBC + HMAC.
    pub fn is_cbc(&self) -> bool {
        !self.is_aead()
    }

    /// Encryption key length in bytes.
    pub fn enc_key_len(&self) -> usize {
        match self {
            Self::EcdheEcdsaAes128GcmSha256
            | Self::EcdheRsaAes128GcmSha256
            | Self::EcdheRsaAes128CbcSha
            | Self::EcdheRsaAes128CbcSha256
            | Self::RsaAes128CbcSha
            | Self::RsaAes128CbcSha256
            | Self::RsaAes128GcmSha256 => 16,

            Self::EcdheEcdsaAes256GcmSha384
            | Self::EcdheRsaAes256GcmSha384
            | Self::EcdheEcdsaChacha20Poly1305
            | Self::EcdheRsaChacha20Poly1305
            | Self::EcdheRsaAes256CbcSha
            | Self::EcdheRsaAes256CbcSha384
            | Self::RsaAes256CbcSha
            | Self::RsaAes256CbcSha256
            | Self::RsaAes256GcmSha384 => 32,
        }
    }

    /// MAC key length (0 for AEAD suites).
    pub fn mac_key_len(&self) -> usize {
        match self {
            _ if self.is_aead() => 0,
            Self::EcdheRsaAes128CbcSha
            | Self::EcdheRsaAes256CbcSha
            | Self::RsaAes128CbcSha
            | Self::RsaAes256CbcSha => 20, // HMAC-SHA1
            Self::EcdheRsaAes128CbcSha256 | Self::RsaAes128CbcSha256 | Self::RsaAes256CbcSha256 => {
                32
            } // HMAC-SHA256
            Self::EcdheRsaAes256CbcSha384 => 48, // HMAC-SHA384
            _ => 0,
        }
    }

    /// Fixed IV length (4 for GCM, 16 for CBC, 12 for ChaCha20).
    pub fn fixed_iv_len(&self) -> usize {
        match self {
            _ if self.is_cbc() => 16,
            Self::EcdheEcdsaChacha20Poly1305 | Self::EcdheRsaChacha20Poly1305 => 12,
            _ => 4, // GCM: 4-byte implicit IV
        }
    }

    /// The PRF algorithm for this cipher suite.
    pub fn prf_algorithm(&self) -> super::prf::PrfAlgorithm {
        match self {
            Self::EcdheEcdsaAes256GcmSha384
            | Self::EcdheRsaAes256GcmSha384
            | Self::EcdheRsaAes256CbcSha384
            | Self::RsaAes256GcmSha384 => super::prf::PrfAlgorithm::Sha384,
            _ => super::prf::PrfAlgorithm::Sha256,
        }
    }

    /// The hash algorithm for transcript hashing.
    pub fn hash_algorithm(&self) -> crate::crypto::hkdf::HkdfAlgorithm {
        match self {
            Self::EcdheEcdsaAes256GcmSha384
            | Self::EcdheRsaAes256GcmSha384
            | Self::EcdheRsaAes256CbcSha384
            | Self::RsaAes256GcmSha384 => crate::crypto::hkdf::HkdfAlgorithm::Sha384,
            _ => crate::crypto::hkdf::HkdfAlgorithm::Sha256,
        }
    }
}

// ---------------------------------------------------------------------------
// GCM cipher for TLS 1.2
// ---------------------------------------------------------------------------

/// TLS 1.2 GCM cipher — uses a 4-byte implicit IV + 8-byte explicit nonce.
///
/// The nonce construction differs from TLS 1.3:
/// - TLS 1.2 GCM: nonce = implicit_iv (4 bytes) || explicit_nonce (8 bytes, sent with record)
/// - TLS 1.3: nonce = iv (12 bytes) XOR seq_num
pub struct Tls12GcmCipher {
    opening_key: aws_lc_rs::aead::LessSafeKey,
    sealing_key: aws_lc_rs::aead::LessSafeKey,
    /// 4-byte implicit IV (from key block).
    implicit_iv: [u8; 4],
}

impl Tls12GcmCipher {
    /// Create a new TLS 1.2 GCM cipher.
    ///
    /// * `key` — encryption key (16 or 32 bytes)
    /// * `implicit_iv` — 4-byte implicit IV from key block
    /// * `is_aes_256` — true for AES-256-GCM, false for AES-128-GCM
    pub fn new(key: &[u8], implicit_iv: &[u8; 4], is_aes_256: bool) -> Result<Self> {
        let algo = if is_aes_256 {
            &aws_lc_rs::aead::AES_256_GCM
        } else {
            &aws_lc_rs::aead::AES_128_GCM
        };

        let opening = aws_lc_rs::aead::UnboundKey::new(algo, key)
            .map_err(|_| TlsError::CryptoError("Failed to create GCM opening key".into()))?;
        let sealing = aws_lc_rs::aead::UnboundKey::new(algo, key)
            .map_err(|_| TlsError::CryptoError("Failed to create GCM sealing key".into()))?;

        Ok(Self {
            opening_key: aws_lc_rs::aead::LessSafeKey::new(opening),
            sealing_key: aws_lc_rs::aead::LessSafeKey::new(sealing),
            implicit_iv: *implicit_iv,
        })
    }

    /// Encrypt a TLS 1.2 record.
    ///
    /// Returns: 8-byte explicit_nonce || ciphertext || 16-byte tag
    ///
    /// The AAD for TLS 1.2 is: seq_num(8) || content_type(1) || version(2) || length(2)
    pub fn encrypt(&self, seq_num: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let explicit_nonce = seq_num.to_be_bytes();

        // Build 12-byte nonce: implicit_iv(4) || explicit_nonce(8)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&self.implicit_iv);
        nonce_bytes[4..].copy_from_slice(&explicit_nonce);
        let nonce = aws_lc_rs::aead::Nonce::assume_unique_for_key(nonce_bytes);

        let aad = aws_lc_rs::aead::Aad::from(aad);
        let mut in_out = Vec::with_capacity(8 + plaintext.len() + 16);
        // Prepend explicit nonce
        in_out.extend_from_slice(&explicit_nonce);
        in_out.extend_from_slice(plaintext);

        // Encrypt only the plaintext portion (after the explicit nonce)
        let mut encrypt_buf = plaintext.to_vec();
        self.sealing_key
            .seal_in_place_append_tag(nonce, aad, &mut encrypt_buf)
            .map_err(|_| TlsError::CryptoError("TLS 1.2 GCM encryption failed".into()))?;

        let mut result = Vec::with_capacity(8 + encrypt_buf.len());
        result.extend_from_slice(&explicit_nonce);
        result.extend_from_slice(&encrypt_buf);
        Ok(result)
    }

    /// Decrypt a TLS 1.2 record.
    ///
    /// Input: 8-byte explicit_nonce || ciphertext || 16-byte tag
    /// Returns: plaintext
    pub fn decrypt(&self, aad: &[u8], ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>> {
        if ciphertext_with_nonce.len() < 8 + 16 {
            return Err(TlsError::CryptoError("TLS 1.2 GCM record too short".into()));
        }

        let explicit_nonce = &ciphertext_with_nonce[..8];
        let encrypted = &ciphertext_with_nonce[8..];

        // Build 12-byte nonce: implicit_iv(4) || explicit_nonce(8)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&self.implicit_iv);
        nonce_bytes[4..].copy_from_slice(explicit_nonce);
        let nonce = aws_lc_rs::aead::Nonce::assume_unique_for_key(nonce_bytes);

        let aad = aws_lc_rs::aead::Aad::from(aad);
        let mut in_out = encrypted.to_vec();
        let plaintext = self
            .opening_key
            .open_in_place(nonce, aad, &mut in_out)
            .map_err(|_| TlsError::CryptoError("TLS 1.2 GCM decryption failed".into()))?;

        let len = plaintext.len();
        in_out.truncate(len);
        Ok(in_out)
    }
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 cipher for TLS 1.2
// ---------------------------------------------------------------------------

/// TLS 1.2 ChaCha20-Poly1305 cipher.
///
/// Uses the same nonce construction as TLS 1.3 (XOR with seq_num) per RFC 7905.
pub struct Tls12Chacha20Cipher {
    opening_key: aws_lc_rs::aead::LessSafeKey,
    sealing_key: aws_lc_rs::aead::LessSafeKey,
    /// 12-byte IV (from key block).
    iv: [u8; 12],
}

impl Tls12Chacha20Cipher {
    pub fn new(key: &[u8; 32], iv: &[u8; 12]) -> Result<Self> {
        let algo = &aws_lc_rs::aead::CHACHA20_POLY1305;
        let opening = aws_lc_rs::aead::UnboundKey::new(algo, key)
            .map_err(|_| TlsError::CryptoError("Failed to create ChaCha20 key".into()))?;
        let sealing = aws_lc_rs::aead::UnboundKey::new(algo, key)
            .map_err(|_| TlsError::CryptoError("Failed to create ChaCha20 key".into()))?;

        Ok(Self {
            opening_key: aws_lc_rs::aead::LessSafeKey::new(opening),
            sealing_key: aws_lc_rs::aead::LessSafeKey::new(sealing),
            iv: *iv,
        })
    }

    fn make_nonce(&self, seq_num: u64) -> aws_lc_rs::aead::Nonce {
        let mut nonce = self.iv;
        let seq_bytes = seq_num.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        aws_lc_rs::aead::Nonce::assume_unique_for_key(nonce)
    }

    pub fn encrypt(&self, seq_num: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.make_nonce(seq_num);
        let mut buf = plaintext.to_vec();
        self.sealing_key
            .seal_in_place_append_tag(nonce, aws_lc_rs::aead::Aad::from(aad), &mut buf)
            .map_err(|_| TlsError::CryptoError("TLS 1.2 ChaCha20 encryption failed".into()))?;
        Ok(buf)
    }

    pub fn decrypt(&self, seq_num: u64, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.make_nonce(seq_num);
        let mut buf = ciphertext.to_vec();
        let plaintext = self
            .opening_key
            .open_in_place(nonce, aws_lc_rs::aead::Aad::from(aad), &mut buf)
            .map_err(|_| TlsError::CryptoError("TLS 1.2 ChaCha20 decryption failed".into()))?;
        let len = plaintext.len();
        buf.truncate(len);
        Ok(buf)
    }
}

// ---------------------------------------------------------------------------
// CBC + HMAC cipher for TLS 1.2 (using RustCrypto `aes` crate)
// ---------------------------------------------------------------------------

use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// TLS 1.2 CBC + HMAC cipher.
///
/// Uses MAC-then-encrypt (RFC 5246 Section 6.2.3.2):
/// 1. Compute HMAC over `seq_num || content_type || version || length || plaintext`
/// 2. Assemble: `plaintext || mac || tls_padding`
/// 3. Generate random 16-byte IV
/// 4. AES-CBC encrypt the assembled data
/// 5. Output: `iv(16) || encrypted_data`
pub struct Tls12CbcCipher {
    /// Encryption key bytes (16 or 32 bytes for AES-128/256).
    enc_key: Vec<u8>,
    /// MAC key bytes (for HMAC-SHA1 or HMAC-SHA256/384).
    mac_key: Vec<u8>,
    /// HMAC algorithm to use.
    mac_algorithm: CbcMacAlgorithm,
    /// AES block size (always 16).
    block_size: usize,
}

/// MAC algorithm used with CBC cipher suites.
#[derive(Debug, Clone, Copy)]
pub enum CbcMacAlgorithm {
    /// HMAC-SHA1 (20-byte MAC)
    HmacSha1,
    /// HMAC-SHA256 (32-byte MAC)
    HmacSha256,
    /// HMAC-SHA384 (48-byte MAC)
    HmacSha384,
}

impl CbcMacAlgorithm {
    pub fn mac_len(&self) -> usize {
        match self {
            CbcMacAlgorithm::HmacSha1 => 20,
            CbcMacAlgorithm::HmacSha256 => 32,
            CbcMacAlgorithm::HmacSha384 => 48,
        }
    }

    fn hmac_algorithm_ref(&self) -> aws_lc_rs::hmac::Algorithm {
        match self {
            CbcMacAlgorithm::HmacSha1 => aws_lc_rs::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            CbcMacAlgorithm::HmacSha256 => aws_lc_rs::hmac::HMAC_SHA256,
            CbcMacAlgorithm::HmacSha384 => aws_lc_rs::hmac::HMAC_SHA384,
        }
    }
}

impl Tls12CbcCipher {
    /// Create a new TLS 1.2 CBC cipher.
    pub fn new(enc_key: &[u8], mac_key: &[u8], mac_algorithm: CbcMacAlgorithm) -> Self {
        Self {
            enc_key: enc_key.to_vec(),
            mac_key: mac_key.to_vec(),
            mac_algorithm,
            block_size: 16,
        }
    }

    /// Compute HMAC over the TLS 1.2 record fields.
    ///
    /// Input to HMAC: `seq_num(8) || content_type(1) || version(2) || length(2) || plaintext`
    /// (This is the same 13-byte AAD used by GCM, but for CBC the AAD carries the
    /// *plaintext* length, and the plaintext itself is also fed into the HMAC.)
    fn compute_mac(&self, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let hmac_key =
            aws_lc_rs::hmac::Key::new(self.mac_algorithm.hmac_algorithm_ref(), &self.mac_key);
        let mut ctx = aws_lc_rs::hmac::Context::with_key(&hmac_key);
        ctx.update(aad);
        ctx.update(plaintext);
        ctx.sign().as_ref().to_vec()
    }

    /// Encrypt a TLS 1.2 CBC record (MAC-then-encrypt).
    ///
    /// Returns: `iv(16) || encrypted(plaintext || mac || padding)`
    ///
    /// The `aad` parameter: `seq_num(8) || content_type(1) || version(2) || plaintext_length(2)`
    pub fn encrypt(&self, _seq_num: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mac = self.compute_mac(aad, plaintext);
        let mac_len = mac.len();

        // Compute TLS padding (RFC 5246 Section 6.2.3.2):
        // Total = plaintext + mac + padding_length + 1 must be multiple of block_size.
        // All padding bytes (including the last padding_length byte) = padding_length.
        let content_len = plaintext.len() + mac_len;
        let padding_length = self.block_size - ((content_len + 1) % self.block_size);
        // padding_length can be 0..block_size-1, total padding bytes = padding_length + 1
        let total_padding = padding_length + 1;

        // Assemble: plaintext || mac || padding
        let padded_len = content_len + total_padding;
        let mut data = Vec::with_capacity(padded_len);
        data.extend_from_slice(plaintext);
        data.extend_from_slice(&mac);
        data.resize(padded_len, padding_length as u8);

        debug_assert_eq!(data.len() % self.block_size, 0);

        // Generate random IV (16 bytes)
        let mut iv = [0u8; 16];
        let rng = aws_lc_rs::rand::SystemRandom::new();
        aws_lc_rs::rand::SecureRandom::fill(&rng, &mut iv)
            .map_err(|_| TlsError::CryptoError("Failed to generate CBC IV".into()))?;

        // AES-CBC encrypt (no padding — we already handled it)
        let encrypted = self.cbc_encrypt(&iv, &mut data)?;

        // Output: iv || encrypted_data
        let mut result = Vec::with_capacity(16 + encrypted.len());
        result.extend_from_slice(&iv);
        result.extend_from_slice(&encrypted);
        Ok(result)
    }

    /// Decrypt a TLS 1.2 CBC record.
    ///
    /// Input: `iv(16) || encrypted_data`
    /// Returns: plaintext (after removing MAC and padding)
    ///
    /// The `aad` parameter: `seq_num(8) || content_type(1) || version(2) || plaintext_length(2)`
    /// Note: for decryption the plaintext_length in AAD must be reconstructed after decryption.
    pub fn decrypt(&self, aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 16 + self.block_size {
            return Err(TlsError::CryptoError("TLS 1.2 CBC record too short".into()));
        }

        let iv: [u8; 16] = data[..16].try_into().unwrap();
        let ciphertext = &data[16..];

        if !ciphertext.len().is_multiple_of(self.block_size) {
            return Err(TlsError::CryptoError(
                "TLS 1.2 CBC ciphertext not block-aligned".into(),
            ));
        }

        // AES-CBC decrypt
        let decrypted = self.cbc_decrypt(&iv, ciphertext)?;

        // Validate and remove TLS padding (constant-time for padding oracle resistance).
        // The last byte is padding_length. All preceding `padding_length` bytes must equal it.
        let padding_length = *decrypted
            .last()
            .ok_or_else(|| TlsError::CryptoError("Empty CBC plaintext".into()))?
            as usize;

        let total_padding = padding_length + 1;
        let mac_len = self.mac_algorithm.mac_len();

        if decrypted.len() < total_padding + mac_len {
            return Err(TlsError::CryptoError(
                "TLS 1.2 CBC record too short after decrypt".into(),
            ));
        }

        // Verify padding bytes (constant-time: check all bytes, don't early exit)
        let mut padding_ok: u8 = 0;
        let pad_start = decrypted.len() - total_padding;
        for &b in &decrypted[pad_start..] {
            padding_ok |= b ^ (padding_length as u8);
        }

        // Extract MAC and plaintext
        let content_end = decrypted.len() - total_padding;
        let plaintext_end = content_end - mac_len;
        let plaintext = &decrypted[..plaintext_end];
        let received_mac = &decrypted[plaintext_end..content_end];

        // Recompute MAC over plaintext with corrected AAD.
        // The AAD from the caller has the *record* payload length (ciphertext length).
        // We need to rebuild AAD with the actual plaintext length.
        let mut mac_aad = aad.to_vec();
        if mac_aad.len() >= 13 {
            let pt_len = plaintext_end as u16;
            mac_aad[11] = (pt_len >> 8) as u8;
            mac_aad[12] = pt_len as u8;
        }

        // Constant-time MAC verification using aws_lc_rs::hmac
        let hmac_key =
            aws_lc_rs::hmac::Key::new(self.mac_algorithm.hmac_algorithm_ref(), &self.mac_key);
        let mac_input = [&mac_aad[..], plaintext].concat();
        let mac_ok = aws_lc_rs::hmac::verify(&hmac_key, &mac_input, received_mac);

        // Combine padding and MAC checks — reject if either failed
        // We always compute MAC even if padding is bad to avoid timing side channels.
        if padding_ok != 0 || mac_ok.is_err() {
            return Err(TlsError::CryptoError(
                "TLS 1.2 CBC MAC or padding verification failed".into(),
            ));
        }

        Ok(plaintext.to_vec())
    }

    /// Raw AES-CBC encrypt (no padding — input must be block-aligned).
    fn cbc_encrypt(&self, iv: &[u8; 16], data: &mut [u8]) -> Result<Vec<u8>> {
        let msg_len = data.len();
        match self.enc_key.len() {
            16 => {
                let key: [u8; 16] = self.enc_key[..].try_into().unwrap();
                let encryptor = Aes128CbcEnc::new(&key.into(), iv.into());
                let ct = encryptor
                    .encrypt_padded_mut::<NoPadding>(data, msg_len)
                    .map_err(|_| TlsError::CryptoError("AES-128-CBC encryption failed".into()))?;
                Ok(ct.to_vec())
            }
            32 => {
                let key: [u8; 32] = self.enc_key[..].try_into().unwrap();
                let encryptor = Aes256CbcEnc::new(&key.into(), iv.into());
                let ct = encryptor
                    .encrypt_padded_mut::<NoPadding>(data, msg_len)
                    .map_err(|_| TlsError::CryptoError("AES-256-CBC encryption failed".into()))?;
                Ok(ct.to_vec())
            }
            other => Err(TlsError::CryptoError(format!(
                "Invalid CBC key length: {other}"
            ))),
        }
    }

    /// Raw AES-CBC decrypt (no padding — input must be block-aligned).
    fn cbc_decrypt(&self, iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut buf = ciphertext.to_vec();
        match self.enc_key.len() {
            16 => {
                let key: [u8; 16] = self.enc_key[..].try_into().unwrap();
                let decryptor = Aes128CbcDec::new(&key.into(), iv.into());
                let pt = decryptor
                    .decrypt_padded_mut::<NoPadding>(&mut buf)
                    .map_err(|_| TlsError::CryptoError("AES-128-CBC decryption failed".into()))?;
                Ok(pt.to_vec())
            }
            32 => {
                let key: [u8; 32] = self.enc_key[..].try_into().unwrap();
                let decryptor = Aes256CbcDec::new(&key.into(), iv.into());
                let pt = decryptor
                    .decrypt_padded_mut::<NoPadding>(&mut buf)
                    .map_err(|_| TlsError::CryptoError("AES-256-CBC decryption failed".into()))?;
                Ok(pt.to_vec())
            }
            other => Err(TlsError::CryptoError(format!(
                "Invalid CBC key length: {other}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_suite_resolution() {
        assert!(Tls12CipherSuite::from_code_point(0xC02F).unwrap().is_aead());
        assert!(Tls12CipherSuite::from_code_point(0xC013).unwrap().is_cbc());
        assert!(Tls12CipherSuite::from_code_point(0xFFFF).is_none());
    }

    #[test]
    fn test_gcm_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0x01, 0x02, 0x03, 0x04];
        let cipher = Tls12GcmCipher::new(&key, &iv, false).unwrap();

        // AAD: seq_num(8) || content_type(1) || version(2) || length(2)
        let aad = [0, 0, 0, 0, 0, 0, 0, 1, 0x17, 0x03, 0x03, 0x00, 0x0F];
        let plaintext = b"Hello, TLS 1.2!";

        let ciphertext = cipher.encrypt(1, &aad, plaintext).unwrap();
        // Should have 8-byte explicit nonce + ciphertext + 16-byte tag
        assert_eq!(ciphertext.len(), 8 + plaintext.len() + 16);

        let decrypted = cipher.decrypt(&aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20_roundtrip() {
        let key = [0xAA; 32];
        let iv = [0xBB; 12];
        let cipher = Tls12Chacha20Cipher::new(&key, &iv).unwrap();

        let aad = [0, 0, 0, 0, 0, 0, 0, 1, 0x17, 0x03, 0x03, 0x00, 0x10];
        let plaintext = b"ChaCha20 TLS 1.2";

        let ciphertext = cipher.encrypt(1, &aad, plaintext).unwrap();
        let decrypted = cipher.decrypt(1, &aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cbc_aes128_sha1_roundtrip() {
        let enc_key = [0x42u8; 16];
        let mac_key = [0xAA; 20];
        let cipher = Tls12CbcCipher::new(&enc_key, &mac_key, CbcMacAlgorithm::HmacSha1);

        // AAD: seq_num(8) || content_type(1) || version(2) || plaintext_length(2)
        let plaintext = b"Hello, TLS 1.2 CBC!";
        let pt_len = plaintext.len() as u16;
        let aad = [
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,    // seq_num = 1
            0x17, // content_type = application_data
            0x03,
            0x03, // version = TLS 1.2
            (pt_len >> 8) as u8,
            pt_len as u8,
        ];

        let ciphertext = cipher.encrypt(1, &aad, plaintext).unwrap();

        // Ciphertext: iv(16) + encrypted(plaintext + mac(20) + padding)
        assert!(ciphertext.len() >= 16 + 16); // at least IV + one block
        assert_eq!((ciphertext.len() - 16) % 16, 0); // encrypted part is block-aligned

        // For decryption, AAD carries the *record* payload length (ciphertext - iv = encrypted part)
        let record_payload_len = (ciphertext.len() - 16) as u16;
        let dec_aad = [
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
            0x17,
            0x03,
            0x03,
            (record_payload_len >> 8) as u8,
            record_payload_len as u8,
        ];

        let decrypted = cipher.decrypt(&dec_aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cbc_aes256_sha256_roundtrip() {
        let enc_key = [0x55u8; 32];
        let mac_key = [0xBB; 32];
        let cipher = Tls12CbcCipher::new(&enc_key, &mac_key, CbcMacAlgorithm::HmacSha256);

        let plaintext = b"AES-256-CBC with HMAC-SHA256 test data that spans multiple blocks!!";
        let pt_len = plaintext.len() as u16;
        let aad = [
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            5,
            0x17,
            0x03,
            0x03,
            (pt_len >> 8) as u8,
            pt_len as u8,
        ];

        let ciphertext = cipher.encrypt(5, &aad, plaintext).unwrap();
        assert_eq!((ciphertext.len() - 16) % 16, 0);

        let record_payload_len = (ciphertext.len() - 16) as u16;
        let dec_aad = [
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            5,
            0x17,
            0x03,
            0x03,
            (record_payload_len >> 8) as u8,
            record_payload_len as u8,
        ];

        let decrypted = cipher.decrypt(&dec_aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cbc_empty_plaintext() {
        let enc_key = [0x42u8; 16];
        let mac_key = [0xAA; 20];
        let cipher = Tls12CbcCipher::new(&enc_key, &mac_key, CbcMacAlgorithm::HmacSha1);

        let plaintext = b"";
        let aad = [0, 0, 0, 0, 0, 0, 0, 0, 0x17, 0x03, 0x03, 0x00, 0x00];

        let ciphertext = cipher.encrypt(0, &aad, plaintext).unwrap();

        let record_payload_len = (ciphertext.len() - 16) as u16;
        let dec_aad = [
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0x17,
            0x03,
            0x03,
            (record_payload_len >> 8) as u8,
            record_payload_len as u8,
        ];

        let decrypted = cipher.decrypt(&dec_aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext.as_ref());
    }

    #[test]
    fn test_cbc_tampered_ciphertext_fails() {
        let enc_key = [0x42u8; 16];
        let mac_key = [0xAA; 20];
        let cipher = Tls12CbcCipher::new(&enc_key, &mac_key, CbcMacAlgorithm::HmacSha1);

        let plaintext = b"tamper test";
        let pt_len = plaintext.len() as u16;
        let aad = [
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
            0x17,
            0x03,
            0x03,
            (pt_len >> 8) as u8,
            pt_len as u8,
        ];

        let mut ciphertext = cipher.encrypt(1, &aad, plaintext).unwrap();

        // Tamper with encrypted data (flip a bit after the IV)
        if ciphertext.len() > 20 {
            ciphertext[20] ^= 0x01;
        }

        let record_payload_len = (ciphertext.len() - 16) as u16;
        let dec_aad = [
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
            0x17,
            0x03,
            0x03,
            (record_payload_len >> 8) as u8,
            record_payload_len as u8,
        ];

        let result = cipher.decrypt(&dec_aad, &ciphertext);
        assert!(result.is_err());
    }
}
