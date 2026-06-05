//! TLS 1.3 `pre_shared_key` extension (type 0x0029 / 41).
//!
//! RFC 8446 Section 4.2.11.
//!
//! This extension MUST be the last extension in the ClientHello.
//! It contains PSK identities and binders used for session resumption.
//!
//! # Wire format (ClientHello)
//!
//! ```text
//! struct {
//!     opaque identity<1..2^16-1>;
//!     uint32 obfuscated_ticket_age;
//! } PskIdentity;
//!
//! opaque PskBinderEntry<32..255>;
//!
//! struct {
//!     PskIdentity identities<7..2^16-1>;
//!     PskBinderEntry binders<33..2^16-1>;
//! } OfferedPsks;
//! ```
//!
//! # Binder calculation
//!
//! The binder is computed over a truncated transcript that includes all of the
//! ClientHello up to (but not including) the binders list. This requires a
//! two-pass approach:
//!
//! 1. First pass: encode the full extension with placeholder binder bytes.
//! 2. Compute the truncated transcript hash (CH bytes up to binder list).
//! 3. Second pass: compute the real binder and overwrite the placeholder.

use aws_lc_rs::hmac;

use crate::crypto::hkdf::{hkdf_expand_label, HkdfAlgorithm};
use crate::error::{Result, TlsError};

/// Extension type code for `pre_shared_key`.
pub const PRE_SHARED_KEY_TYPE: u16 = 0x0029;

/// A single PSK identity offered in the ClientHello.
#[derive(Debug, Clone)]
pub struct PskIdentity {
    /// The opaque ticket/identity bytes.
    pub identity: Vec<u8>,
    /// The obfuscated ticket age (TLS 1.3).
    pub obfuscated_ticket_age: u32,
}

/// Encode the `pre_shared_key` extension for a ClientHello.
///
/// Returns `(extension_bytes, binder_offset)` where `binder_offset` is the
/// absolute byte offset within `extension_bytes` where the binder value starts
/// (after the binder length byte). This allows the caller to overwrite the
/// placeholder binder with the real computed value.
///
/// # Arguments
///
/// * `identities` - PSK identities to offer (typically just one for session resumption).
/// * `binder_len` - The length of each binder (hash output length: 32 for SHA-256, 48 for SHA-384).
pub fn encode_psk_extension(identities: &[PskIdentity], binder_len: usize) -> (Vec<u8>, usize) {
    let mut buf = Vec::with_capacity(256);

    // Extension type
    buf.extend_from_slice(&PRE_SHARED_KEY_TYPE.to_be_bytes());

    // Placeholder for extension data length (filled later)
    let ext_len_pos = buf.len();
    buf.extend_from_slice(&[0u8; 2]);

    let ext_data_start = buf.len();

    // --- Identities list ---
    // identities length (2 bytes) placeholder
    let identities_len_pos = buf.len();
    buf.extend_from_slice(&[0u8; 2]);

    let identities_start = buf.len();
    for id in identities {
        // identity length (2 bytes)
        buf.extend_from_slice(&(id.identity.len() as u16).to_be_bytes());
        // identity data
        buf.extend_from_slice(&id.identity);
        // obfuscated_ticket_age (4 bytes)
        buf.extend_from_slice(&id.obfuscated_ticket_age.to_be_bytes());
    }
    let identities_len = buf.len() - identities_start;
    buf[identities_len_pos..identities_len_pos + 2]
        .copy_from_slice(&(identities_len as u16).to_be_bytes());

    // --- Binders list ---
    // binders length (2 bytes)
    let total_binders_len = identities.len() * (1 + binder_len);
    buf.extend_from_slice(&(total_binders_len as u16).to_be_bytes());

    // For each identity, write a placeholder binder
    let mut binder_offsets = Vec::with_capacity(identities.len());
    for _ in identities {
        buf.push(binder_len as u8); // binder length byte
        let binder_value_offset = buf.len();
        binder_offsets.push(binder_value_offset);
        buf.extend_from_slice(&vec![0u8; binder_len]); // placeholder zeros
    }

    // Fill in extension data length
    let ext_data_len = buf.len() - ext_data_start;
    buf[ext_len_pos..ext_len_pos + 2].copy_from_slice(&(ext_data_len as u16).to_be_bytes());

    // Return the first binder offset (we typically only have one identity)
    let first_binder_offset = binder_offsets.first().copied().unwrap_or(0);
    (buf, first_binder_offset)
}

/// Compute the number of bytes in the binders portion of the PSK extension.
///
/// This is used to determine the "truncated ClientHello" for binder computation:
/// `truncated_ch = ch_bytes[..ch_bytes.len() - binders_size]`
///
/// `binders_size` includes the 2-byte binders list length + all binder entries.
pub fn binders_size(num_identities: usize, binder_len: usize) -> usize {
    2 + num_identities * (1 + binder_len) // 2 (list len) + N * (1 len byte + binder)
}

/// Compute the total byte length of a `pre_shared_key` extension for a single
/// identity, **without** building the extension.
///
/// This is used by the padding calculation in `build_client_hello` so that
/// padding is computed with full knowledge of the PSK extension size,
/// matching BoringSSL / Chrome behavior.
pub fn psk_extension_length(identity_len: usize, binder_len: usize) -> usize {
    // extension_type(2) + extension_data_length(2)
    // + identities_list_length(2) + identity_length(2) + identity(N) + obfuscated_ticket_age(4)
    // + binders_list_length(2) + binder_length_byte(1) + binder(M)
    2 + 2 + 2 + 2 + identity_len + 4 + 2 + 1 + binder_len
}

/// Compute a PSK binder value.
///
/// ```text
/// binder_key = Derive-Secret(early_secret, "res binder" | "ext binder", "")
/// finished_key = HKDF-Expand-Label(binder_key, "finished", "", Hash.length)
/// binder = HMAC(finished_key, Transcript-Hash(truncated_client_hello))
/// ```
///
/// For session resumption (as opposed to external PSK), the label is `"res binder"`.
///
/// # Arguments
///
/// * `hkdf_algo` - The HKDF algorithm (from the PSK's cipher suite).
/// * `resumption_psk` - The PSK derived from the NewSessionTicket.
/// * `transcript_hash` - Hash of the truncated ClientHello (everything before binders).
pub fn compute_psk_binder(
    hkdf_algo: HkdfAlgorithm,
    resumption_psk: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8>> {
    let hash_len = hkdf_algo.hash_len();

    // Step 1: Early Secret = HKDF-Extract(salt=0, ikm=PSK)
    let zero_salt = vec![0u8; hash_len];
    let early_secret = crate::crypto::hkdf::hkdf_extract(hkdf_algo, &zero_salt, resumption_psk)?;

    // Step 2: binder_key = Derive-Secret(Early Secret, "res binder", "")
    //         which is HKDF-Expand-Label(ES, "res binder", Hash(""), Hash.length)
    let empty_hash = compute_empty_hash(hkdf_algo);
    let binder_key = early_secret.derive_secret("res binder", &empty_hash)?;

    // Step 3: finished_key = HKDF-Expand-Label(binder_key, "finished", "", Hash.length)
    let finished_key = hkdf_expand_label(hkdf_algo, &binder_key, "finished", &[], hash_len)?;

    // Step 4: binder = HMAC(finished_key, transcript_hash)
    let hmac_algo = match hkdf_algo {
        HkdfAlgorithm::Sha256 => hmac::HMAC_SHA256,
        HkdfAlgorithm::Sha384 => hmac::HMAC_SHA384,
    };
    let key = hmac::Key::new(hmac_algo, &finished_key);
    let tag = hmac::sign(&key, transcript_hash);

    Ok(tag.as_ref().to_vec())
}

/// Compute the Early Secret from a PSK, returning it for use in the key schedule
/// when the server accepts the PSK.
///
/// This avoids recomputing the Early Secret when we already computed it for the binder.
pub fn compute_early_secret(
    hkdf_algo: HkdfAlgorithm,
    resumption_psk: &[u8],
) -> Result<crate::crypto::hkdf::HkdfPrk> {
    let hash_len = hkdf_algo.hash_len();
    let zero_salt = vec![0u8; hash_len];
    crate::crypto::hkdf::hkdf_extract(hkdf_algo, &zero_salt, resumption_psk)
}

/// Parse the `pre_shared_key` extension from a ServerHello.
///
/// The server responds with a single `selected_identity` (u16) indicating
/// which PSK identity from the ClientHello was accepted.
pub fn parse_server_psk(data: &[u8]) -> Result<u16> {
    if data.len() < 2 {
        return Err(TlsError::HandshakeFailure(
            "pre_shared_key server extension too short".to_string(),
        ));
    }
    Ok(u16::from_be_bytes([data[0], data[1]]))
}

/// Compute the hash of an empty message.
fn compute_empty_hash(algorithm: HkdfAlgorithm) -> Vec<u8> {
    use aws_lc_rs::digest;
    let algo = match algorithm {
        HkdfAlgorithm::Sha256 => &digest::SHA256,
        HkdfAlgorithm::Sha384 => &digest::SHA384,
    };
    digest::digest(algo, b"").as_ref().to_vec()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_psk_extension_structure() {
        let identities = vec![PskIdentity {
            identity: vec![0x01, 0x02, 0x03, 0x04],
            obfuscated_ticket_age: 12345,
        }];

        let (ext_bytes, binder_offset) = encode_psk_extension(&identities, 32);

        // Extension type = 0x0029
        assert_eq!(ext_bytes[0], 0x00);
        assert_eq!(ext_bytes[1], 0x29);

        // Verify extension is well-formed
        let ext_data_len = u16::from_be_bytes([ext_bytes[2], ext_bytes[3]]) as usize;
        assert_eq!(ext_data_len, ext_bytes.len() - 4);

        // Binder offset should point inside the buffer
        assert!(binder_offset > 0);
        assert!(binder_offset + 32 <= ext_bytes.len());
    }

    #[test]
    fn test_binders_size_calculation() {
        // 1 identity, SHA-256 (32-byte binder)
        assert_eq!(binders_size(1, 32), 2 + 1 + 32); // 35
                                                     // 2 identities, SHA-384 (48-byte binder)
        assert_eq!(binders_size(2, 48), 2 + 2 * (1 + 48)); // 100
    }

    #[test]
    fn test_compute_psk_binder_produces_correct_length() {
        let psk = vec![0xAA; 32];
        let transcript = vec![0xBB; 32];

        let binder = compute_psk_binder(HkdfAlgorithm::Sha256, &psk, &transcript).unwrap();
        assert_eq!(binder.len(), 32);

        // SHA-384
        let psk384 = vec![0xAA; 48];
        let transcript384 = vec![0xBB; 48];
        let binder384 = compute_psk_binder(HkdfAlgorithm::Sha384, &psk384, &transcript384).unwrap();
        assert_eq!(binder384.len(), 48);
    }

    #[test]
    fn test_compute_psk_binder_deterministic() {
        let psk = vec![0x42; 32];
        let transcript = vec![0x55; 32];

        let b1 = compute_psk_binder(HkdfAlgorithm::Sha256, &psk, &transcript).unwrap();
        let b2 = compute_psk_binder(HkdfAlgorithm::Sha256, &psk, &transcript).unwrap();
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_parse_server_psk() {
        let data = [0x00, 0x00]; // selected_identity = 0
        assert_eq!(parse_server_psk(&data).unwrap(), 0);

        let data = [0x00, 0x01]; // selected_identity = 1
        assert_eq!(parse_server_psk(&data).unwrap(), 1);
    }

    #[test]
    fn test_psk_extension_length_matches_encode() {
        let identities = vec![PskIdentity {
            identity: vec![0xAA; 200],
            obfuscated_ticket_age: 0,
        }];
        let (encoded, _) = encode_psk_extension(&identities, 32);
        let predicted = psk_extension_length(200, 32);
        assert_eq!(encoded.len(), predicted);
    }
}
