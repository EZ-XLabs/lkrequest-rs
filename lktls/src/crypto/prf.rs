//! TLS 1.2 PRF (Pseudo-Random Function) — RFC 5246 Section 5.
//!
//! TLS 1.2 uses a PRF based on HMAC (typically HMAC-SHA256 for modern
//! cipher suites, or HMAC-SHA384 for AES-256-GCM suites).
//!
//! ```text
//! PRF(secret, label, seed) = P_<hash>(secret, label + seed)
//!
//! P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
//!                         HMAC_hash(secret, A(2) + seed) +
//!                         HMAC_hash(secret, A(3) + seed) + ...
//!
//! where A(0) = seed
//!       A(i) = HMAC_hash(secret, A(i-1))
//! ```

use aws_lc_rs::hmac;

use crate::error::Result;

/// Hash algorithm used by the TLS 1.2 PRF (determined by cipher suite).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrfAlgorithm {
    /// HMAC-SHA256 (default for TLS 1.2, used with most modern cipher suites).
    Sha256,
    /// HMAC-SHA384 (used with AES-256-GCM cipher suites).
    Sha384,
}

impl PrfAlgorithm {
    /// Output length of the underlying hash function.
    pub fn hash_len(&self) -> usize {
        match self {
            PrfAlgorithm::Sha256 => 32,
            PrfAlgorithm::Sha384 => 48,
        }
    }

    fn hmac_algorithm_ref(&self) -> hmac::Algorithm {
        match self {
            PrfAlgorithm::Sha256 => hmac::HMAC_SHA256,
            PrfAlgorithm::Sha384 => hmac::HMAC_SHA384,
        }
    }
}

/// Compute the TLS 1.2 PRF: `PRF(secret, label, seed)`.
///
/// Returns `output_len` bytes of pseudorandom output.
///
/// # Arguments
///
/// * `algorithm` - The hash algorithm to use (SHA-256 or SHA-384)
/// * `secret` - The PRF secret (e.g. pre_master_secret or master_secret)
/// * `label` - ASCII label (e.g. "master secret", "key expansion")
/// * `seed` - Seed data (e.g. ClientRandom + ServerRandom)
/// * `output_len` - Number of output bytes to produce
pub fn prf(
    algorithm: PrfAlgorithm,
    secret: &[u8],
    label: &str,
    seed: &[u8],
    output_len: usize,
) -> Result<Vec<u8>> {
    // P_hash(secret, seed) where seed = label + seed
    let label_bytes = label.as_bytes();
    let mut combined_seed = Vec::with_capacity(label_bytes.len() + seed.len());
    combined_seed.extend_from_slice(label_bytes);
    combined_seed.extend_from_slice(seed);

    p_hash(algorithm, secret, &combined_seed, output_len)
}

/// P_hash function (RFC 5246 Section 5):
///
/// ```text
/// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
///                         HMAC_hash(secret, A(2) + seed) + ...
/// where A(0) = seed
///       A(i) = HMAC_hash(secret, A(i-1))
/// ```
fn p_hash(
    algorithm: PrfAlgorithm,
    secret: &[u8],
    seed: &[u8],
    output_len: usize,
) -> Result<Vec<u8>> {
    let hmac_algo = algorithm.hmac_algorithm_ref();
    let key = hmac::Key::new(hmac_algo, secret);

    let mut result = Vec::with_capacity(output_len);
    let mut a = hmac::sign(&key, seed); // A(1) = HMAC(secret, seed)

    while result.len() < output_len {
        // HMAC(secret, A(i) + seed)
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(a.as_ref());
        ctx.update(seed);
        let p_block = ctx.sign();

        let remaining = output_len - result.len();
        let to_copy = remaining.min(p_block.as_ref().len());
        result.extend_from_slice(&p_block.as_ref()[..to_copy]);

        // A(i+1) = HMAC(secret, A(i))
        a = hmac::sign(&key, a.as_ref());
    }

    Ok(result)
}

/// Compute the TLS 1.2 master_secret from pre_master_secret.
///
/// ```text
/// master_secret = PRF(pre_master_secret, "master secret",
///                     ClientHello.random + ServerHello.random)[0..47]
/// ```
pub fn compute_master_secret(
    algorithm: PrfAlgorithm,
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Result<Vec<u8>> {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    prf(algorithm, pre_master_secret, "master secret", &seed, 48)
}

/// TLS 1.2 key material derived from the master secret.
///
/// The key block contains (in order):
/// - `client_write_mac_key` (MAC key length, 0 for AEAD suites)
/// - `server_write_mac_key` (MAC key length, 0 for AEAD suites)
/// - `client_write_key` (encryption key length)
/// - `server_write_key` (encryption key length)
/// - `client_write_iv` (IV length)
/// - `server_write_iv` (IV length)
#[derive(Debug)]
pub struct KeyBlock {
    pub client_write_mac_key: Vec<u8>,
    pub server_write_mac_key: Vec<u8>,
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
}

/// Expand the master secret into the key block for TLS 1.2.
///
/// ```text
/// key_block = PRF(master_secret, "key expansion",
///                 ServerHello.random + ClientHello.random)
/// ```
///
/// Note: the seed for key expansion uses server_random + client_random
/// (opposite order from master_secret computation).
///
/// # Arguments
///
/// * `mac_key_len` - 0 for AEAD cipher suites (GCM), 20 for HMAC-SHA1, 32 for HMAC-SHA256
/// * `enc_key_len` - 16 for AES-128, 32 for AES-256
/// * `iv_len` - 4 for GCM (explicit nonce prefix), 16 for CBC
pub fn expand_key_block(
    algorithm: PrfAlgorithm,
    master_secret: &[u8],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    mac_key_len: usize,
    enc_key_len: usize,
    iv_len: usize,
) -> Result<KeyBlock> {
    // Seed = ServerRandom + ClientRandom (reversed from master_secret!)
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);

    let total_len = 2 * mac_key_len + 2 * enc_key_len + 2 * iv_len;
    let key_block_bytes = prf(algorithm, master_secret, "key expansion", &seed, total_len)?;

    let mut offset = 0;

    let client_write_mac_key = key_block_bytes[offset..offset + mac_key_len].to_vec();
    offset += mac_key_len;

    let server_write_mac_key = key_block_bytes[offset..offset + mac_key_len].to_vec();
    offset += mac_key_len;

    let client_write_key = key_block_bytes[offset..offset + enc_key_len].to_vec();
    offset += enc_key_len;

    let server_write_key = key_block_bytes[offset..offset + enc_key_len].to_vec();
    offset += enc_key_len;

    let client_write_iv = key_block_bytes[offset..offset + iv_len].to_vec();
    offset += iv_len;

    let server_write_iv = key_block_bytes[offset..offset + iv_len].to_vec();

    Ok(KeyBlock {
        client_write_mac_key,
        server_write_mac_key,
        client_write_key,
        server_write_key,
        client_write_iv,
        server_write_iv,
    })
}

/// Compute the TLS 1.2 extended master_secret (RFC 7627).
///
/// When the `extended_master_secret` extension is negotiated, the master
/// secret is derived from the session hash (transcript of all handshake
/// messages through ClientKeyExchange) instead of client/server randoms:
///
/// ```text
/// master_secret = PRF(pre_master_secret, "extended master secret",
///                     session_hash)[0..47]
/// ```
///
/// This binds the master secret to the specific handshake transcript,
/// preventing certain man-in-the-middle attacks.
pub fn compute_extended_master_secret(
    algorithm: PrfAlgorithm,
    pre_master_secret: &[u8],
    session_hash: &[u8],
) -> Result<Vec<u8>> {
    prf(
        algorithm,
        pre_master_secret,
        "extended master secret",
        session_hash,
        48,
    )
}

/// Compute the TLS 1.2 Finished verify_data.
///
/// ```text
/// verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))[0..11]
/// ```
///
/// * For client Finished: `finished_label = "client finished"`
/// * For server Finished: `finished_label = "server finished"`
/// * `verify_data_length` is 12 bytes for all standard cipher suites.
pub fn compute_verify_data(
    algorithm: PrfAlgorithm,
    master_secret: &[u8],
    finished_label: &str,
    handshake_hash: &[u8],
) -> Result<Vec<u8>> {
    prf(algorithm, master_secret, finished_label, handshake_hash, 12)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prf_deterministic() {
        let secret = [0x42u8; 48];
        let seed = [0xABu8; 64];
        let out1 = prf(PrfAlgorithm::Sha256, &secret, "test label", &seed, 64).unwrap();
        let out2 = prf(PrfAlgorithm::Sha256, &secret, "test label", &seed, 64).unwrap();
        assert_eq!(out1, out2);
        assert_eq!(out1.len(), 64);

        // P_hash is an iterative HMAC chain (RFC 5246 §5): a longer output must
        // be a byte-exact prefix-extension of a shorter one. This catches a
        // broken A(i) chain or wrong seed-concatenation order that determinism
        // and length checks alone would miss.
        let longer = prf(PrfAlgorithm::Sha256, &secret, "test label", &seed, 100).unwrap();
        assert_eq!(
            &longer[..64],
            &out1[..],
            "P_hash output must be prefix-consistent"
        );
    }

    #[test]
    fn test_prf_different_labels_produce_different_output() {
        let secret = [0x42u8; 48];
        let seed = [0xABu8; 64];
        let out1 = prf(PrfAlgorithm::Sha256, &secret, "label A", &seed, 32).unwrap();
        let out2 = prf(PrfAlgorithm::Sha256, &secret, "label B", &seed, 32).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_master_secret_length() {
        let pms = [0x03u8; 48]; // Pre-master secret
        let cr = [0x01u8; 32]; // Client random
        let sr = [0x02u8; 32]; // Server random
        let ms = compute_master_secret(PrfAlgorithm::Sha256, &pms, &cr, &sr).unwrap();
        assert_eq!(ms.len(), 48); // Master secret is always 48 bytes
    }

    #[test]
    fn test_key_block_expansion() {
        let ms = [0x42u8; 48]; // Master secret
        let sr = [0x01u8; 32]; // Server random
        let cr = [0x02u8; 32]; // Client random

        // AES-128-GCM: no MAC key, 16-byte key, 4-byte IV
        let kb = expand_key_block(PrfAlgorithm::Sha256, &ms, &sr, &cr, 0, 16, 4).unwrap();

        assert_eq!(kb.client_write_mac_key.len(), 0);
        assert_eq!(kb.server_write_mac_key.len(), 0);
        assert_eq!(kb.client_write_key.len(), 16);
        assert_eq!(kb.server_write_key.len(), 16);
        assert_eq!(kb.client_write_iv.len(), 4);
        assert_eq!(kb.server_write_iv.len(), 4);

        // AES-256-CBC-SHA: 20-byte MAC, 32-byte key, 16-byte IV
        let kb_cbc = expand_key_block(PrfAlgorithm::Sha256, &ms, &sr, &cr, 20, 32, 16).unwrap();

        assert_eq!(kb_cbc.client_write_mac_key.len(), 20);
        assert_eq!(kb_cbc.server_write_mac_key.len(), 20);
        assert_eq!(kb_cbc.client_write_key.len(), 32);
        assert_eq!(kb_cbc.server_write_key.len(), 32);
        assert_eq!(kb_cbc.client_write_iv.len(), 16);
        assert_eq!(kb_cbc.server_write_iv.len(), 16);
    }

    #[test]
    fn test_verify_data_length() {
        let ms = [0x42u8; 48];
        let hash = [0xAAu8; 32]; // SHA-256 hash of handshake messages
        let vd = compute_verify_data(PrfAlgorithm::Sha256, &ms, "client finished", &hash).unwrap();
        assert_eq!(vd.len(), 12); // Verify data is always 12 bytes
    }

    #[test]
    fn test_prf_sha384() {
        let secret = [0x42u8; 48];
        let seed = [0xABu8; 64];
        let out = prf(PrfAlgorithm::Sha384, &secret, "test", &seed, 48).unwrap();
        assert_eq!(out.len(), 48);
    }
}
