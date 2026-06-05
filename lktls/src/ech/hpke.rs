//! HPKE encryption wrapper for ECH.
//!
//! Wraps the `hpke` crate to provide a simple, ECH-specific interface for
//! encrypting the EncodedClientHelloInner with HPKE `SetupBaseS` + `Seal`.
//!
//! ## Two-phase API
//!
//! Per draft-ietf-tls-esni-24 Section 5.2, the outer ClientHello AAD must
//! contain the **real** `enc` value (with only the `payload` field zeroed).
//! This requires a two-phase flow:
//!
//! 1. [`ech_hpke_setup`] — run HPKE `SetupBaseS` to obtain `enc` and an
//!    opaque sender context.
//! 2. [`EchHpkeSenderCtx::seal`] — once the caller has built the correct AAD
//!    (with real `enc` filled in), seal the plaintext.
//!
//! A one-shot [`ech_hpke_seal`] convenience function is also provided for
//! cases where the caller pre-computes the AAD.
//!
//! Supports:
//! - KEM: DHKEM(X25519, HKDF-SHA256) = 0x0020
//! - KDF: HKDF-SHA256 = 0x0001
//! - AEAD: AES-128-GCM (0x0001) or ChaCha20Poly1305 (0x0003)

use crate::error::{Result, TlsError};

use super::config::{EchConfig, HpkeSymmetricCipherSuite};

/// AEAD tag length (both AES-128-GCM and ChaCha20Poly1305 use 16 bytes).
pub const AEAD_TAG_LEN: usize = 16;

/// Result of an ECH HPKE seal operation.
#[derive(Debug)]
pub struct EchHpkeSealResult {
    /// The HPKE encapsulated key (32 bytes for X25519).
    pub enc: Vec<u8>,
    /// The AEAD ciphertext (EncodedClientHelloInner + AEAD tag).
    pub ciphertext: Vec<u8>,
}

/// Opaque HPKE sender context returned by [`ech_hpke_setup`].
///
/// Holds the encryption context created by `setup_sender`.  Call `seal`
/// once the AAD (with real `enc`) is ready.
#[allow(private_interfaces)]
pub enum EchHpkeSenderCtx {
    #[doc(hidden)]
    Aes128Gcm(Box<dyn SealOnce>),
    #[doc(hidden)]
    ChaCha20Poly1305(Box<dyn SealOnce>),
}

impl EchHpkeSenderCtx {
    /// Seal (encrypt) the plaintext with the given AAD.
    ///
    /// The AAD **must** contain the real `enc` value (with payload zeroed)
    /// per draft-ietf-tls-esni-24 Section 5.2.
    pub fn seal(self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Aes128Gcm(ctx) => ctx.seal(plaintext, aad),
            Self::ChaCha20Poly1305(ctx) => ctx.seal(plaintext, aad),
        }
    }
}

/// Result of [`ech_hpke_setup`]: the encapsulated key and the sender context.
pub struct EchHpkeSetupResult {
    /// The HPKE encapsulated key (32 bytes for X25519).
    pub enc: Vec<u8>,
    /// The sender context — call [`EchHpkeSenderCtx::seal`] with the final AAD.
    pub sender_ctx: EchHpkeSenderCtx,
}

/// Phase 1: Run HPKE `SetupBaseS` to obtain `enc` and a sender context.
///
/// The caller can then embed the returned `enc` into the outer ClientHello,
/// build the correct AAD (with real `enc` + zeroed payload), and finally
/// call [`EchHpkeSenderCtx::seal`].
pub fn ech_hpke_setup(
    ech_config: &EchConfig,
    cipher_suite: &HpkeSymmetricCipherSuite,
) -> Result<EchHpkeSetupResult> {
    let mut info = Vec::with_capacity(8 + ech_config.raw_config.len());
    info.extend_from_slice(b"tls ech\x00");
    info.extend_from_slice(&ech_config.raw_config);

    match cipher_suite.aead_id {
        0x0001 => setup_aes128gcm(ech_config, &info),
        0x0003 => setup_chacha20poly1305(ech_config, &info),
        other => Err(TlsError::CryptoError(format!(
            "unsupported ECH AEAD: 0x{other:04x}"
        ))),
    }
}

/// One-shot convenience: encrypt an EncodedClientHelloInner for ECH using HPKE.
///
/// Combines `setup_sender` + `seal` in a single call.  The caller must
/// ensure the `aad` already contains the correct `enc` value (or accept
/// that both `enc` and `payload` are placeholders — useful for tests).
pub fn ech_hpke_seal(
    ech_config: &EchConfig,
    cipher_suite: &HpkeSymmetricCipherSuite,
    encoded_inner: &[u8],
    aad: &[u8],
) -> Result<EchHpkeSealResult> {
    let setup = ech_hpke_setup(ech_config, cipher_suite)?;
    let ciphertext = setup.sender_ctx.seal(encoded_inner, aad)?;
    Ok(EchHpkeSealResult {
        enc: setup.enc,
        ciphertext,
    })
}

/// Return the ciphertext overhead for the given AEAD (always 16 for supported AEADs).
pub fn aead_overhead(aead_id: u16) -> usize {
    match aead_id {
        0x0001..=0x0003 => AEAD_TAG_LEN,
        _ => AEAD_TAG_LEN, // conservative default
    }
}

// ---------------------------------------------------------------------------
// Internal: type-erased seal trait
// ---------------------------------------------------------------------------

/// Internal trait to allow storing heterogeneous HPKE sender contexts.
trait SealOnce: Send {
    fn seal(self: Box<Self>, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
}

// ---------------------------------------------------------------------------
// AES-128-GCM
// ---------------------------------------------------------------------------

struct Aes128GcmSender {
    ctx: ::hpke::aead::AeadCtxS<
        ::hpke::aead::AesGcm128,
        ::hpke::kdf::HkdfSha256,
        ::hpke::kem::X25519HkdfSha256,
    >,
}

impl SealOnce for Aes128GcmSender {
    fn seal(mut self: Box<Self>, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.ctx
            .seal(plaintext, aad)
            .map_err(|e| TlsError::CryptoError(format!("HPKE seal failed: {e}")))
    }
}

fn setup_aes128gcm(ech_config: &EchConfig, info: &[u8]) -> Result<EchHpkeSetupResult> {
    use ::hpke::aead::AesGcm128;
    use ::hpke::kdf::HkdfSha256;
    use ::hpke::kem::X25519HkdfSha256;
    use ::hpke::{Deserializable, Kem, OpModeS, Serializable};
    use rand_core::TryRngCore;

    let pk = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&ech_config.public_key)
        .map_err(|e| TlsError::CryptoError(format!("invalid ECH public key: {e}")))?;

    let mut rng = rand_core::OsRng.unwrap_err();

    let (enc_key, sender_ctx) = ::hpke::setup_sender::<AesGcm128, HkdfSha256, X25519HkdfSha256, _>(
        &OpModeS::Base,
        &pk,
        info,
        &mut rng,
    )
    .map_err(|e| TlsError::CryptoError(format!("HPKE setup_sender failed: {e}")))?;

    let enc = enc_key.to_bytes().to_vec();

    Ok(EchHpkeSetupResult {
        enc,
        sender_ctx: EchHpkeSenderCtx::Aes128Gcm(Box::new(Aes128GcmSender { ctx: sender_ctx })),
    })
}

// ---------------------------------------------------------------------------
// ChaCha20Poly1305
// ---------------------------------------------------------------------------

struct ChaCha20Poly1305Sender {
    ctx: ::hpke::aead::AeadCtxS<
        ::hpke::aead::ChaCha20Poly1305,
        ::hpke::kdf::HkdfSha256,
        ::hpke::kem::X25519HkdfSha256,
    >,
}

impl SealOnce for ChaCha20Poly1305Sender {
    fn seal(mut self: Box<Self>, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.ctx
            .seal(plaintext, aad)
            .map_err(|e| TlsError::CryptoError(format!("HPKE seal failed: {e}")))
    }
}

fn setup_chacha20poly1305(ech_config: &EchConfig, info: &[u8]) -> Result<EchHpkeSetupResult> {
    use ::hpke::aead::ChaCha20Poly1305;
    use ::hpke::kdf::HkdfSha256;
    use ::hpke::kem::X25519HkdfSha256;
    use ::hpke::{Deserializable, Kem, OpModeS, Serializable};
    use rand_core::TryRngCore;

    let pk = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&ech_config.public_key)
        .map_err(|e| TlsError::CryptoError(format!("invalid ECH public key: {e}")))?;

    let mut rng = rand_core::OsRng.unwrap_err();

    let (enc_key, sender_ctx) = ::hpke::setup_sender::<
        ChaCha20Poly1305,
        HkdfSha256,
        X25519HkdfSha256,
        _,
    >(&OpModeS::Base, &pk, info, &mut rng)
    .map_err(|e| TlsError::CryptoError(format!("HPKE setup_sender failed: {e}")))?;

    let enc = enc_key.to_bytes().to_vec();

    Ok(EchHpkeSetupResult {
        enc,
        sender_ctx: EchHpkeSenderCtx::ChaCha20Poly1305(Box::new(ChaCha20Poly1305Sender {
            ctx: sender_ctx,
        })),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ech::config::{self, KEM_X25519_HKDF_SHA256};

    /// Generate a real X25519 key pair for testing.
    fn generate_test_keypair() -> (Vec<u8>, Vec<u8>) {
        use ::hpke::kem::X25519HkdfSha256;
        use ::hpke::{Kem, Serializable};

        use rand_core::TryRngCore;
        let (sk, pk) = X25519HkdfSha256::gen_keypair(&mut rand_core::OsRng.unwrap_err());
        (sk.to_bytes().to_vec(), pk.to_bytes().to_vec())
    }

    fn make_test_config(
        public_key: Vec<u8>,
        aead_id: u16,
    ) -> (EchConfig, HpkeSymmetricCipherSuite) {
        // Build raw_config bytes
        let mut contents = Vec::new();
        contents.push(42); // config_id
        contents.extend_from_slice(&KEM_X25519_HKDF_SHA256.to_be_bytes());
        contents.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
        contents.extend_from_slice(&public_key);
        // cipher suite
        contents.extend_from_slice(&4u16.to_be_bytes());
        contents.extend_from_slice(&0x0001u16.to_be_bytes()); // HKDF-SHA256
        contents.extend_from_slice(&aead_id.to_be_bytes());
        contents.push(32); // max_name_length
        let pn = b"public.example.com";
        contents.push(pn.len() as u8);
        contents.extend_from_slice(pn);
        contents.extend_from_slice(&0u16.to_be_bytes()); // no extensions

        let mut raw_config = Vec::new();
        raw_config.extend_from_slice(&config::ECH_CONFIG_VERSION.to_be_bytes());
        raw_config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        raw_config.extend_from_slice(&contents);

        let config = EchConfig {
            version: config::ECH_CONFIG_VERSION,
            config_id: 42,
            kem_id: KEM_X25519_HKDF_SHA256,
            public_key,
            cipher_suites: vec![HpkeSymmetricCipherSuite {
                kdf_id: 0x0001,
                aead_id,
            }],
            maximum_name_length: 32,
            public_name: "public.example.com".to_string(),
            raw_config,
        };

        let cs = HpkeSymmetricCipherSuite {
            kdf_id: 0x0001,
            aead_id,
        };

        (config, cs)
    }

    #[test]
    fn test_seal_aes128gcm_produces_valid_output() {
        let (_sk, pk) = generate_test_keypair();
        let (config, cs) = make_test_config(pk, 0x0001);

        let plaintext = b"hello inner client hello";
        let aad = b"outer client hello aad";

        let result = ech_hpke_seal(&config, &cs, plaintext, aad).unwrap();
        assert_eq!(result.enc.len(), 32); // X25519 public key
        assert_eq!(result.ciphertext.len(), plaintext.len() + AEAD_TAG_LEN);
    }

    #[test]
    fn test_seal_chacha20poly1305_produces_valid_output() {
        let (_sk, pk) = generate_test_keypair();
        let (config, cs) = make_test_config(pk, 0x0003);

        let plaintext = b"hello inner client hello for firefox";
        let aad = b"outer ch aad";

        let result = ech_hpke_seal(&config, &cs, plaintext, aad).unwrap();
        assert_eq!(result.enc.len(), 32);
        assert_eq!(result.ciphertext.len(), plaintext.len() + AEAD_TAG_LEN);
    }

    #[test]
    fn test_seal_produces_different_ciphertext_each_call() {
        let (_sk, pk) = generate_test_keypair();
        let (config, cs) = make_test_config(pk, 0x0001);

        let plaintext = b"same input";
        let aad = b"same aad";

        let r1 = ech_hpke_seal(&config, &cs, plaintext, aad).unwrap();
        let r2 = ech_hpke_seal(&config, &cs, plaintext, aad).unwrap();

        // enc should differ (different ephemeral keys)
        assert_ne!(r1.enc, r2.enc);
        // ciphertext should differ
        assert_ne!(r1.ciphertext, r2.ciphertext);
    }

    #[test]
    fn test_unsupported_aead_returns_error() {
        let (_sk, pk) = generate_test_keypair();
        let (config, mut cs) = make_test_config(pk, 0x0001);
        cs.aead_id = 0x9999; // unsupported

        let result = ech_hpke_seal(&config, &cs, b"test", b"aad");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Two-phase API tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_two_phase_setup_returns_32_byte_enc() {
        let (_sk, pk) = generate_test_keypair();
        let (config, cs) = make_test_config(pk, 0x0001);

        let setup = ech_hpke_setup(&config, &cs).unwrap();
        assert_eq!(setup.enc.len(), 32, "X25519 enc should be 32 bytes");
    }

    #[test]
    fn test_two_phase_seal_produces_correct_length() {
        let (_sk, pk) = generate_test_keypair();
        let (config, cs) = make_test_config(pk, 0x0001);

        let plaintext = b"test plaintext data";
        let aad = b"additional authenticated data";

        let setup = ech_hpke_setup(&config, &cs).unwrap();
        let ciphertext = setup.sender_ctx.seal(plaintext, aad).unwrap();
        assert_eq!(
            ciphertext.len(),
            plaintext.len() + AEAD_TAG_LEN,
            "ciphertext = plaintext + 16-byte tag"
        );
    }

    #[test]
    fn test_two_phase_chacha20_seal_works() {
        let (_sk, pk) = generate_test_keypair();
        let (config, cs) = make_test_config(pk, 0x0003);

        let setup = ech_hpke_setup(&config, &cs).unwrap();
        assert_eq!(setup.enc.len(), 32);
        let ct = setup.sender_ctx.seal(b"firefox test", b"aad").unwrap();
        assert_eq!(ct.len(), 12 + AEAD_TAG_LEN);
    }

    #[test]
    fn test_two_phase_setup_unsupported_aead() {
        let (_sk, pk) = generate_test_keypair();
        let (config, mut cs) = make_test_config(pk, 0x0001);
        cs.aead_id = 0xFFFF;

        assert!(ech_hpke_setup(&config, &cs).is_err());
    }

    // -----------------------------------------------------------------------
    // Encrypt-then-decrypt round-trip (closed loop)
    // -----------------------------------------------------------------------

    /// Helper: decrypt with the private key to verify the ciphertext is correct.
    fn hpke_decrypt_aes128gcm(
        sk_bytes: &[u8],
        enc_bytes: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        info: &[u8],
    ) -> Vec<u8> {
        use ::hpke::aead::AesGcm128;
        use ::hpke::kdf::HkdfSha256;
        use ::hpke::kem::X25519HkdfSha256;
        use ::hpke::{Deserializable, Kem, OpModeR};

        let sk = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(sk_bytes).expect("valid sk");
        let enc = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(enc_bytes).expect("valid enc");

        let mut recv_ctx = ::hpke::setup_receiver::<AesGcm128, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &sk,
            &enc,
            info,
        )
        .expect("setup_receiver");

        recv_ctx.open(ciphertext, aad).expect("open (decrypt)")
    }

    /// Helper: decrypt ChaCha20 variant.
    fn hpke_decrypt_chacha20(
        sk_bytes: &[u8],
        enc_bytes: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        info: &[u8],
    ) -> Vec<u8> {
        use ::hpke::aead::ChaCha20Poly1305;
        use ::hpke::kdf::HkdfSha256;
        use ::hpke::kem::X25519HkdfSha256;
        use ::hpke::{Deserializable, Kem, OpModeR};

        let sk = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(sk_bytes).expect("valid sk");
        let enc = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(enc_bytes).expect("valid enc");

        let mut recv_ctx =
            ::hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
                &OpModeR::Base,
                &sk,
                &enc,
                info,
            )
            .expect("setup_receiver");

        recv_ctx.open(ciphertext, aad).expect("open (decrypt)")
    }

    fn build_hpke_info(config: &EchConfig) -> Vec<u8> {
        let mut info = Vec::with_capacity(8 + config.raw_config.len());
        info.extend_from_slice(b"tls ech\x00");
        info.extend_from_slice(&config.raw_config);
        info
    }

    #[test]
    fn test_seal_decrypt_roundtrip_aes128gcm() {
        let (sk, pk) = generate_test_keypair();
        let (config, cs) = make_test_config(pk, 0x0001);

        let plaintext = b"secret inner client hello bytes!";
        let aad = b"outer client hello AAD for verification";

        let result = ech_hpke_seal(&config, &cs, plaintext, aad).unwrap();
        let info = build_hpke_info(&config);

        let decrypted = hpke_decrypt_aes128gcm(&sk, &result.enc, &result.ciphertext, aad, &info);
        assert_eq!(decrypted, plaintext, "round-trip decryption must match");
    }

    #[test]
    fn test_seal_decrypt_roundtrip_chacha20() {
        let (sk, pk) = generate_test_keypair();
        let (config, cs) = make_test_config(pk, 0x0003);

        let plaintext = b"firefox secret inner hello";
        let aad = b"firefox outer aad";

        let result = ech_hpke_seal(&config, &cs, plaintext, aad).unwrap();
        let info = build_hpke_info(&config);

        let decrypted = hpke_decrypt_chacha20(&sk, &result.enc, &result.ciphertext, aad, &info);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_two_phase_decrypt_roundtrip_aes128gcm() {
        let (sk, pk) = generate_test_keypair();
        let (config, cs) = make_test_config(pk, 0x0001);
        let info = build_hpke_info(&config);

        let plaintext = b"two-phase roundtrip test";

        // Phase 1: setup → get enc
        let setup = ech_hpke_setup(&config, &cs).unwrap();
        let enc = setup.enc.clone();

        // Phase 2: build AAD containing real enc, then seal
        let mut aad = Vec::new();
        aad.extend_from_slice(b"outer-with-real-enc:");
        aad.extend_from_slice(&enc);

        let ciphertext = setup.sender_ctx.seal(plaintext, &aad).unwrap();

        // Decrypt with private key using the SAME aad (with real enc)
        let decrypted = hpke_decrypt_aes128gcm(&sk, &enc, &ciphertext, &aad, &info);
        assert_eq!(decrypted, plaintext, "two-phase roundtrip must match");
    }

    #[test]
    fn test_wrong_aad_fails_decrypt() {
        let (sk, pk) = generate_test_keypair();
        let (config, cs) = make_test_config(pk, 0x0001);
        let info = build_hpke_info(&config);

        let plaintext = b"test aad mismatch";
        let correct_aad = b"correct aad";
        let wrong_aad = b"wrong aad!!";

        let result = ech_hpke_seal(&config, &cs, plaintext, correct_aad).unwrap();

        // Decrypt with wrong AAD should fail
        use ::hpke::aead::AesGcm128;
        use ::hpke::kdf::HkdfSha256;
        use ::hpke::kem::X25519HkdfSha256;
        use ::hpke::{Deserializable, Kem, OpModeR};

        let sk_obj = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&sk).unwrap();
        let enc_obj = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&result.enc).unwrap();
        let mut recv = ::hpke::setup_receiver::<AesGcm128, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &sk_obj,
            &enc_obj,
            &info,
        )
        .unwrap();

        let open_result = recv.open(&result.ciphertext, wrong_aad);
        assert!(open_result.is_err(), "decrypt with wrong AAD must fail");
    }
}
