//! Key Exchange — ECDH operations (X25519, P-256, P-384) and hybrid post-quantum (X25519MLKEM768).

use aws_lc_rs::agreement::{self, EphemeralPrivateKey};
use aws_lc_rs::rand::SystemRandom;

use crate::error::{Result, TlsError};

/// Supported key exchange groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KxGroup {
    /// X25519 (code-point 0x001d).
    X25519,
    /// secp256r1 / P-256 (code-point 0x0017).
    Secp256r1,
    /// secp384r1 / P-384 (code-point 0x0018).
    Secp384r1,
    /// X25519MLKEM768 — hybrid post-quantum (code-point 0x11EC / 4588).
    ///
    /// Combines classical X25519 ECDH with ML-KEM-768 (NIST FIPS 203).
    /// Used by Chrome 124+ for post-quantum key exchange.
    X25519MlKem768,
}

impl KxGroup {
    /// TLS NamedGroup code-point.
    pub fn code_point(&self) -> u16 {
        match self {
            KxGroup::X25519 => 0x001d,
            KxGroup::Secp256r1 => 0x0017,
            KxGroup::Secp384r1 => 0x0018,
            KxGroup::X25519MlKem768 => 0x11ec,
        }
    }

    /// Resolve a code-point to a `KxGroup`.
    pub fn from_code_point(cp: u16) -> Option<Self> {
        match cp {
            0x001d => Some(KxGroup::X25519),
            0x0017 => Some(KxGroup::Secp256r1),
            0x0018 => Some(KxGroup::Secp384r1),
            0x11ec => Some(KxGroup::X25519MlKem768),
            _ => None,
        }
    }
}

/// Internal private key storage — supports both classical and hybrid schemes.
pub(crate) enum PrivateKeyInner {
    /// Classical ECDH (X25519, P-256, or P-384).
    Classical(EphemeralPrivateKey),
    /// Hybrid X25519 + ML-KEM-768.
    Hybrid {
        x25519: EphemeralPrivateKey,
        mlkem_dk: aws_lc_rs::kem::DecapsulationKey,
    },
}

/// An ephemeral key pair for key exchange.
///
/// Holds the private key (consumed later by [`compute_shared_secret`]) and
/// the public key bytes (included in the `key_share` ClientHello extension).
pub struct EphemeralKeyPair {
    /// The named group this key belongs to.
    pub group: KxGroup,
    /// The public key bytes to include in the key_share extension.
    pub public_key: Vec<u8>,
    /// The private key — consumed during key agreement.
    pub(crate) private_key: PrivateKeyInner,
}

impl std::fmt::Debug for EphemeralKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralKeyPair")
            .field("group", &self.group)
            .field("public_key", &format!("[{} bytes]", self.public_key.len()))
            .field("private_key", &"<opaque>")
            .finish()
    }
}

/// Generate a fresh ephemeral key pair for the given group.
pub fn generate_key_pair(group: KxGroup) -> Result<EphemeralKeyPair> {
    match group {
        KxGroup::X25519 | KxGroup::Secp256r1 | KxGroup::Secp384r1 => {
            generate_classical_key_pair(group)
        }
        KxGroup::X25519MlKem768 => generate_hybrid_key_pair(),
    }
}

/// Generate a classical ECDH key pair.
fn generate_classical_key_pair(group: KxGroup) -> Result<EphemeralKeyPair> {
    let rng = SystemRandom::new();
    let algorithm = match group {
        KxGroup::X25519 => &agreement::X25519,
        KxGroup::Secp256r1 => &agreement::ECDH_P256,
        KxGroup::Secp384r1 => &agreement::ECDH_P384,
        _ => unreachable!(),
    };

    let private_key = EphemeralPrivateKey::generate(algorithm, &rng)
        .map_err(|_| TlsError::CryptoError(format!("failed to generate {:?} key pair", group)))?;

    let public_key = private_key
        .compute_public_key()
        .map_err(|_| TlsError::CryptoError("failed to compute public key".to_string()))?;

    Ok(EphemeralKeyPair {
        group,
        public_key: public_key.as_ref().to_vec(),
        private_key: PrivateKeyInner::Classical(private_key),
    })
}

/// Generate a hybrid X25519 + ML-KEM-768 key pair.
///
/// The public key is the concatenation (per draft-ietf-tls-ecdhe-mlkem):
///   X25519_public_key (32 bytes) || ML-KEM-768_encapsulation_key (1184 bytes)
/// Total: 1216 bytes.
fn generate_hybrid_key_pair() -> Result<EphemeralKeyPair> {
    let rng = SystemRandom::new();

    let x25519_priv = EphemeralPrivateKey::generate(&agreement::X25519, &rng)
        .map_err(|_| TlsError::CryptoError("failed to generate X25519 key".to_string()))?;
    let x25519_pub = x25519_priv
        .compute_public_key()
        .map_err(|_| TlsError::CryptoError("failed to compute X25519 public key".to_string()))?;

    let mlkem_dk = aws_lc_rs::kem::DecapsulationKey::generate(&aws_lc_rs::kem::ML_KEM_768)
        .map_err(|_| TlsError::CryptoError("failed to generate ML-KEM-768 key".to_string()))?;
    let mlkem_ek = mlkem_dk.encapsulation_key().map_err(|_| {
        TlsError::CryptoError("failed to get ML-KEM-768 encapsulation key".to_string())
    })?;
    let mlkem_pub = mlkem_ek.key_bytes().map_err(|_| {
        TlsError::CryptoError("failed to serialize ML-KEM-768 encapsulation key".to_string())
    })?;

    // Client key_share format (per draft-ietf-tls-ecdhe-mlkem Section 4.1):
    //   ML-KEM-768 encapsulation key (1184B) || X25519 public key (32B) = 1216B
    // Note: ML-KEM comes FIRST for X25519MLKEM768 (reversed from the group name)
    let mut public_key = Vec::with_capacity(mlkem_pub.as_ref().len() + 32);
    public_key.extend_from_slice(mlkem_pub.as_ref());
    public_key.extend_from_slice(x25519_pub.as_ref());

    Ok(EphemeralKeyPair {
        group: KxGroup::X25519MlKem768,
        public_key,
        private_key: PrivateKeyInner::Hybrid {
            x25519: x25519_priv,
            mlkem_dk,
        },
    })
}

/// Perform key agreement: our private key + peer's public key → shared secret.
///
/// This **consumes** the ephemeral key pair (the private key can only be used once).
pub fn compute_shared_secret(our_key: EphemeralKeyPair, peer_public_key: &[u8]) -> Result<Vec<u8>> {
    match our_key.private_key {
        PrivateKeyInner::Classical(private_key) => {
            let algorithm = match our_key.group {
                KxGroup::X25519 => &agreement::X25519,
                KxGroup::Secp256r1 => &agreement::ECDH_P256,
                KxGroup::Secp384r1 => &agreement::ECDH_P384,
                _ => unreachable!(),
            };
            let peer_key = agreement::UnparsedPublicKey::new(algorithm, peer_public_key);
            agreement::agree_ephemeral(
                private_key,
                peer_key,
                TlsError::CryptoError("ECDH key agreement failed".to_string()),
                |shared_secret| Ok(shared_secret.to_vec()),
            )
        }
        PrivateKeyInner::Hybrid { x25519, mlkem_dk } => {
            compute_hybrid_shared_secret(x25519, mlkem_dk, peer_public_key)
        }
    }
}

/// Compute the hybrid X25519 + ML-KEM-768 shared secret.
///
/// Server's key_share (per draft-ietf-tls-ecdhe-mlkem):
///   X25519_server_public_key (32 bytes) || ML-KEM-768_ciphertext (1088 bytes)
/// Total: 1120 bytes.
///
/// Shared secret:
///   ML-KEM-768_shared_secret (32 bytes) || X25519_shared_secret (32 bytes)
/// Total: 64 bytes.
fn compute_hybrid_shared_secret(
    x25519_priv: EphemeralPrivateKey,
    mlkem_dk: aws_lc_rs::kem::DecapsulationKey,
    server_share: &[u8],
) -> Result<Vec<u8>> {
    tracing::debug!(
        "compute_hybrid_shared_secret: server_share_len={}",
        server_share.len()
    );
    // Server key_share format (per draft-ietf-tls-ecdhe-mlkem):
    //   ML-KEM-768 ciphertext (1088 bytes) || X25519 public key (32 bytes)
    // Note: server sends ML-KEM FIRST, then ECDHE (opposite of client order!)
    const MLKEM768_CT_LEN: usize = 1088;
    const X25519_PUB_LEN: usize = 32;
    if server_share.len() != MLKEM768_CT_LEN + X25519_PUB_LEN {
        return Err(TlsError::CryptoError(format!(
            "X25519MLKEM768 server share wrong size: expected {}, got {}",
            MLKEM768_CT_LEN + X25519_PUB_LEN,
            server_share.len()
        )));
    }

    let mlkem_ciphertext = &server_share[..MLKEM768_CT_LEN];
    let x25519_server_pub = &server_share[MLKEM768_CT_LEN..];

    // X25519 key agreement (first 32 bytes of server_share)
    let x25519_peer = agreement::UnparsedPublicKey::new(&agreement::X25519, x25519_server_pub);
    let x25519_secret = agreement::agree_ephemeral(
        x25519_priv,
        x25519_peer,
        TlsError::CryptoError("X25519 key agreement failed in hybrid".to_string()),
        |secret| Ok(secret.to_vec()),
    )?;

    // ML-KEM-768 decapsulation (first 1088 bytes of server_share)
    let mlkem_ct = aws_lc_rs::kem::Ciphertext::from(mlkem_ciphertext);
    let mlkem_secret = mlkem_dk
        .decapsulate(mlkem_ct)
        .map_err(|e| TlsError::CryptoError(format!("ML-KEM-768 decapsulation failed: {e}")))?;

    // Combine: ML-KEM secret || X25519 secret (per draft-ietf-tls-ecdhe-mlkem)
    let mut shared_secret = Vec::with_capacity(mlkem_secret.as_ref().len() + x25519_secret.len());
    shared_secret.extend_from_slice(mlkem_secret.as_ref());
    shared_secret.extend_from_slice(&x25519_secret);

    Ok(shared_secret)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_x25519() {
        let kp = generate_key_pair(KxGroup::X25519).unwrap();
        assert_eq!(kp.group, KxGroup::X25519);
        assert_eq!(kp.public_key.len(), 32);
    }

    #[test]
    fn test_generate_p256() {
        let kp = generate_key_pair(KxGroup::Secp256r1).unwrap();
        assert_eq!(kp.group, KxGroup::Secp256r1);
        assert_eq!(kp.public_key.len(), 65); // uncompressed point
    }

    #[test]
    fn test_generate_p384() {
        let kp = generate_key_pair(KxGroup::Secp384r1).unwrap();
        assert_eq!(kp.group, KxGroup::Secp384r1);
        assert_eq!(kp.public_key.len(), 97); // uncompressed point (1 + 48 + 48)
    }

    #[test]
    fn test_generate_x25519mlkem768() {
        let kp = generate_key_pair(KxGroup::X25519MlKem768).unwrap();
        assert_eq!(kp.group, KxGroup::X25519MlKem768);
        // X25519MLKEM768 client share = ML-KEM-768 encapsulation key (1184 B)
        // followed by the X25519 public key (32 B) — ML-KEM first, per
        // draft-kwiatkowski-tls-ecdhe-mlkem; total 1216 B. (The concatenation
        // order itself is gated on the wire by the ClientHello fingerprint
        // tests; here the components aren't exposed separately to split.)
        assert_eq!(kp.public_key.len(), 1184 + 32);
    }

    #[test]
    fn test_p384_shared_secret() {
        let alice = generate_key_pair(KxGroup::Secp384r1).unwrap();
        let bob = generate_key_pair(KxGroup::Secp384r1).unwrap();
        let bob_pub = bob.public_key.clone();
        let alice_pub = alice.public_key.clone();

        let secret_a = compute_shared_secret(alice, &bob_pub).unwrap();
        let secret_b = compute_shared_secret(bob, &alice_pub).unwrap();
        assert_eq!(secret_a, secret_b);
        assert_eq!(secret_a.len(), 48); // P-384 shared secret is 48 bytes
    }

    #[test]
    fn test_code_point_roundtrip() {
        for group in [
            KxGroup::X25519,
            KxGroup::Secp256r1,
            KxGroup::Secp384r1,
            KxGroup::X25519MlKem768,
        ] {
            let cp = group.code_point();
            let resolved = KxGroup::from_code_point(cp).unwrap();
            assert_eq!(group, resolved);
        }
    }

    #[test]
    fn test_p384_code_point() {
        assert_eq!(KxGroup::Secp384r1.code_point(), 0x0018);
        assert_eq!(KxGroup::from_code_point(0x0018), Some(KxGroup::Secp384r1));
        assert_eq!(KxGroup::from_code_point(24), Some(KxGroup::Secp384r1));
    }

    #[test]
    fn test_x25519mlkem768_code_point() {
        assert_eq!(KxGroup::X25519MlKem768.code_point(), 0x11ec);
        assert_eq!(
            KxGroup::from_code_point(4588),
            Some(KxGroup::X25519MlKem768)
        );
    }
}
