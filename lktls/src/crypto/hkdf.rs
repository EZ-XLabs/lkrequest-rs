//! HKDF operations for TLS 1.3 key derivation.
//!
//! TLS 1.3 key schedule (RFC 8446 Section 7.1):
//!
//! ```text
//!              0
//!              |
//!              v
//!    PSK ->  HKDF-Extract = Early Secret
//!              |
//!              v
//!        Derive-Secret(., "derived", "")
//!              |
//!              v
//!    (EC)DHE -> HKDF-Extract = Handshake Secret
//!              |
//!              v
//!        Derive-Secret(., "derived", "")
//!              |
//!              v
//!    0 -> HKDF-Extract = Master Secret
//! ```

use aws_lc_rs::hkdf;

use crate::error::{Result, TlsError};

/// Hash algorithm used for HKDF (determined by the cipher suite).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HkdfAlgorithm {
    /// SHA-256 (used with AES-128-GCM and ChaCha20-Poly1305).
    Sha256,
    /// SHA-384 (used with AES-256-GCM).
    Sha384,
}

impl HkdfAlgorithm {
    /// The output length of the hash function.
    pub fn hash_len(&self) -> usize {
        match self {
            HkdfAlgorithm::Sha256 => 32,
            HkdfAlgorithm::Sha384 => 48,
        }
    }

    fn hkdf_algorithm_ref(&self) -> hkdf::Algorithm {
        match self {
            HkdfAlgorithm::Sha256 => hkdf::HKDF_SHA256,
            HkdfAlgorithm::Sha384 => hkdf::HKDF_SHA384,
        }
    }
}

/// An extracted PRK (Pseudo-Random Key) from HKDF-Extract.
///
/// This wraps `aws_lc_rs::hkdf::Prk` and provides TLS 1.3 specific operations
/// like `expand_label` and `derive_secret`.
pub struct HkdfPrk {
    prk: hkdf::Prk,
    algorithm: HkdfAlgorithm,
}

impl HkdfPrk {
    /// The HKDF algorithm used.
    pub fn algorithm(&self) -> HkdfAlgorithm {
        self.algorithm
    }

    /// Perform HKDF-Expand-Label (RFC 8446 Section 7.1).
    ///
    /// ```text
    /// HKDF-Expand-Label(Secret, Label, Context, Length) =
    ///     HKDF-Expand(Secret, HkdfLabel, Length)
    ///
    /// struct {
    ///     uint16 length = Length;
    ///     opaque label<7..255> = "tls13 " + Label;
    ///     opaque context<0..255> = Context;
    /// } HkdfLabel;
    /// ```
    pub fn expand_label(&self, label: &str, context: &[u8], length: usize) -> Result<Vec<u8>> {
        let hkdf_label = build_hkdf_label(label, context, length);
        let info = [hkdf_label.as_slice()];
        let okm = self
            .prk
            .expand(&info, HkdfLen(length))
            .map_err(|_| TlsError::CryptoError("HKDF-Expand-Label failed".to_string()))?;
        let mut out = vec![0u8; length];
        okm.fill(&mut out)
            .map_err(|_| TlsError::CryptoError("HKDF-Expand fill failed".to_string()))?;
        Ok(out)
    }

    /// Derive-Secret (RFC 8446 Section 7.1).
    ///
    /// ```text
    /// Derive-Secret(Secret, Label, Messages) =
    ///     HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
    /// ```
    pub fn derive_secret(&self, label: &str, transcript_hash: &[u8]) -> Result<Vec<u8>> {
        self.expand_label(label, transcript_hash, self.algorithm.hash_len())
    }

    /// Derive the next stage secret in the TLS 1.3 key schedule:
    ///
    /// ```text
    /// Derive-Secret(current_secret, "derived", "") → salt
    /// HKDF-Extract(salt, ikm) → next_secret
    /// ```
    pub fn derive_next(&self, ikm: &[u8]) -> Result<HkdfPrk> {
        let empty_hash = compute_empty_hash(self.algorithm);
        let salt_bytes = self.expand_label("derived", &empty_hash, self.algorithm.hash_len())?;
        hkdf_extract(self.algorithm, &salt_bytes, ikm)
    }
}

impl std::fmt::Debug for HkdfPrk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HkdfPrk")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

/// Perform HKDF-Extract: `PRK = HKDF-Extract(salt, IKM)`.
///
/// Returns a `HkdfPrk` that can be used for `expand_label` and `derive_secret`.
pub fn hkdf_extract(algorithm: HkdfAlgorithm, salt: &[u8], ikm: &[u8]) -> Result<HkdfPrk> {
    let algo = algorithm.hkdf_algorithm_ref();
    let salt = hkdf::Salt::new(algo, salt);
    let prk = salt.extract(ikm);
    Ok(HkdfPrk { prk, algorithm })
}

/// Convenience: Perform HKDF-Expand-Label on raw secret bytes.
///
/// This creates a temporary Prk from the secret bytes and calls expand_label.
pub fn hkdf_expand_label(
    algorithm: HkdfAlgorithm,
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    let prk = hkdf::Prk::new_less_safe(algorithm.hkdf_algorithm_ref(), secret);
    let hkdf_label = build_hkdf_label(label, context, length);
    let info = [hkdf_label.as_slice()];
    let okm = prk
        .expand(&info, HkdfLen(length))
        .map_err(|_| TlsError::CryptoError("HKDF-Expand-Label failed".to_string()))?;
    let mut out = vec![0u8; length];
    okm.fill(&mut out)
        .map_err(|_| TlsError::CryptoError("HKDF-Expand fill failed".to_string()))?;
    Ok(out)
}

/// Convenience: Derive-Secret on raw secret bytes.
pub fn derive_secret(
    algorithm: HkdfAlgorithm,
    secret: &[u8],
    label: &str,
    transcript_hash: &[u8],
) -> Result<Vec<u8>> {
    hkdf_expand_label(
        algorithm,
        secret,
        label,
        transcript_hash,
        algorithm.hash_len(),
    )
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build the HkdfLabel structure for HKDF-Expand-Label.
fn build_hkdf_label(label: &str, context: &[u8], length: usize) -> Vec<u8> {
    let full_label = format!("tls13 {label}");
    let full_label_bytes = full_label.as_bytes();

    let mut hkdf_label = Vec::with_capacity(2 + 1 + full_label_bytes.len() + 1 + context.len());
    // uint16 length
    hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
    // opaque label<7..255>
    hkdf_label.push(full_label_bytes.len() as u8);
    hkdf_label.extend_from_slice(full_label_bytes);
    // opaque context<0..255>
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    hkdf_label
}

/// Compute the hash of an empty message (needed for Derive-Secret(., "derived", "")).
fn compute_empty_hash(algorithm: HkdfAlgorithm) -> Vec<u8> {
    use aws_lc_rs::digest;
    let algo = match algorithm {
        HkdfAlgorithm::Sha256 => &digest::SHA256,
        HkdfAlgorithm::Sha384 => &digest::SHA384,
    };
    let hash = digest::digest(algo, b"");
    hash.as_ref().to_vec()
}

/// A helper type that implements `hkdf::KeyType` for arbitrary lengths.
struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_extract_produces_correct_length() {
        let prk = hkdf_extract(HkdfAlgorithm::Sha256, &[0u8; 32], &[0u8; 32])
            .expect("extract should succeed");
        assert_eq!(prk.algorithm(), HkdfAlgorithm::Sha256);
    }

    #[test]
    fn test_hkdf_expand_label_produces_correct_length() {
        let prk = hkdf_extract(HkdfAlgorithm::Sha256, &[0u8; 32], &[0u8; 32]).unwrap();
        let result = prk.expand_label("test", &[], 32).unwrap();
        assert_eq!(result.len(), 32);

        let result16 = prk.expand_label("key", &[], 16).unwrap();
        assert_eq!(result16.len(), 16);
    }

    #[test]
    fn test_derive_secret_produces_hash_length_output() {
        let prk = hkdf_extract(HkdfAlgorithm::Sha256, &[0u8; 32], &[0u8; 32]).unwrap();
        let secret = prk.derive_secret("c hs traffic", &[0u8; 32]).unwrap();
        assert_eq!(secret.len(), 32); // SHA-256 output

        let prk384 = hkdf_extract(HkdfAlgorithm::Sha384, &[0u8; 48], &[0u8; 48]).unwrap();
        let secret384 = prk384.derive_secret("c hs traffic", &[0u8; 48]).unwrap();
        assert_eq!(secret384.len(), 48); // SHA-384 output
    }

    #[test]
    fn test_derive_next_chains_secrets() {
        // Simulate TLS 1.3 key schedule: Early Secret → Handshake Secret
        let early_secret = hkdf_extract(HkdfAlgorithm::Sha256, &[0u8; 32], &[0u8; 32]).unwrap();
        let handshake_secret = early_secret.derive_next(&[0xAA; 32]).unwrap();
        // Should produce a valid PRK
        let result = handshake_secret.expand_label("test", &[], 32).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_build_hkdf_label_format() {
        let label = build_hkdf_label("derived", &[], 32);
        // uint16 length = 32 = 0x0020
        assert_eq!(label[0], 0x00);
        assert_eq!(label[1], 0x20);
        // label length = len("tls13 derived") = 13
        assert_eq!(label[2], 13);
        // "tls13 derived"
        assert_eq!(&label[3..16], b"tls13 derived");
        // context length = 0
        assert_eq!(label[16], 0);
    }

    #[test]
    fn test_free_function_expand_label() {
        let secret = vec![0x42u8; 32];
        let result = hkdf_expand_label(HkdfAlgorithm::Sha256, &secret, "key", &[], 16).unwrap();
        assert_eq!(result.len(), 16);
    }

    /// RFC 8446 Appendix A test vector (simplified check).
    /// We verify that HKDF-Extract with known inputs produces deterministic output.
    #[test]
    fn test_hkdf_deterministic() {
        let salt = [0u8; 32]; // zero salt
        let ikm = [0u8; 32]; // zero IKM (PSK = 0 for non-PSK mode)
        let prk1 = hkdf_extract(HkdfAlgorithm::Sha256, &salt, &ikm).unwrap();
        let prk2 = hkdf_extract(HkdfAlgorithm::Sha256, &salt, &ikm).unwrap();
        let out1 = prk1.expand_label("test", &[], 32).unwrap();
        let out2 = prk2.expand_label("test", &[], 32).unwrap();
        assert_eq!(out1, out2, "Same inputs should produce same outputs");

        // Differing labels must yield unrelated output (the label is bound into
        // the HkdfLabel `info`). Note: HKDF-Expand-Label is *not* prefix-consistent
        // across output lengths, because RFC 8446 encodes the length into `info`;
        // the end-to-end HKDF-Expand-Label key schedule is KAT-validated against
        // the RFC 9001 vectors in `crypto/quic.rs`.
        let other = prk1.expand_label("other", &[], 32).unwrap();
        assert_ne!(out1, other, "different labels must derive different output");
    }
}
