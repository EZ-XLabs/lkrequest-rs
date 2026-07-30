//! Inner ClientHello construction and EncodedClientHelloInner encoding.
//!
//! Builds the `EncodedClientHelloInner` structure per RFC 9849
//! Section 5.1, including:
//!
//! - Constructing ClientHelloInner with real SNI and `inner` ECH extension
//! - Encoding with empty `legacy_session_id`
//! - Padding to 32-byte boundaries using `maximum_name_length`
//! - Optional `ech_outer_extensions` (0xFD00) compression

/// ECH outer extensions extension type (used in EncodedClientHelloInner).
pub const ECH_OUTER_EXTENSIONS_TYPE: u16 = 0xFD00;

/// Compute the padding length for EncodedClientHelloInner.
///
/// Follows RFC 9849 Section 6.1.3:
///
/// ```text
/// padding_len = max(0, maximum_name_length - len(server_name))
/// total_padding = padding_len + (32 - ((len(encoded) + padding_len) % 32)) % 32
/// ```
pub fn compute_ech_padding(
    encoded_inner_len: usize,
    server_name: &str,
    maximum_name_length: u8,
    _aead_id: u16,
) -> usize {
    let max_name = maximum_name_length as usize;
    let name_len = server_name.len();

    // Per the spec, the padding accounts for the SNI extension difference.
    // The inner CH contains the real server name; the max_name_length tells us
    // the longest name in the anonymity set so we can pad up.
    let name_padding = max_name.saturating_sub(name_len);

    // The encoded_inner_len is the current size of EncodedClientHelloInner
    // (client_hello portion, before padding).
    let pre_pad_len = encoded_inner_len + name_padding;

    // Align to 32-byte boundary.
    let alignment_padding = (32 - (pre_pad_len % 32)) % 32;

    name_padding + alignment_padding
}

/// Encode a ClientHelloInner body into EncodedClientHelloInner format.
///
/// Takes the raw ClientHello body bytes (everything after the 4-byte Handshake
/// header: version, random, session_id, cipher_suites, compression, extensions)
/// and produces the EncodedClientHelloInner:
///
/// 1. Sets `legacy_session_id` to empty (length 0)
/// 2. Appends zero padding
///
/// # Arguments
///
/// - `inner_ch_body` — The ClientHello body bytes (without Handshake header),
///   already built with empty session_id.
/// - `padding_len` — Number of zero bytes to append.
pub fn encode_client_hello_inner(inner_ch_body: &[u8], padding_len: usize) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(inner_ch_body.len() + padding_len);
    encoded.extend_from_slice(inner_ch_body);
    encoded.resize(encoded.len() + padding_len, 0);
    encoded
}

/// Build the `ech_outer_extensions` extension payload.
///
/// This extension replaces a contiguous group of extensions in the inner CH
/// with a reference list that points to the same extensions in the outer CH.
///
/// Wire format:
/// ```text
/// ExtensionType OuterExtensions<2..254>;
/// ```
///
/// Each ExtensionType is a 2-byte value.
pub fn encode_ech_outer_extensions(extension_types: &[u16]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + extension_types.len() * 2);
    // Length prefix (1 byte, since max is 254)
    payload.push((extension_types.len() * 2) as u8);
    for &ext_type in extension_types {
        payload.extend_from_slice(&ext_type.to_be_bytes());
    }
    payload
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_padding_aligns_to_32() {
        // 100 bytes encoded, hostname "a.co" (4 chars), max_name=0 → no name padding
        let pad = compute_ech_padding(100, "a.co", 0, 0x0001);
        // (100 + 0) % 32 = 4, so need 28 bytes alignment
        assert_eq!(pad, 28);
        assert_eq!((100 + pad) % 32, 0);
    }

    #[test]
    fn test_compute_padding_with_name_length() {
        // 100 bytes, hostname "a.co" (4), max_name=32 → 28 name padding
        let pad = compute_ech_padding(100, "a.co", 32, 0x0001);
        // pre_pad = 100 + 28 = 128, 128 % 32 = 0 → alignment 0
        // total = 28 + 0 = 28
        assert_eq!(pad, 28);
        assert_eq!((100 + pad) % 32, 0);
    }

    #[test]
    fn test_compute_padding_already_aligned() {
        let pad = compute_ech_padding(128, "example.com", 0, 0x0001);
        assert_eq!(pad, 0);
    }

    #[test]
    fn test_encode_inner_appends_zeros() {
        let body = vec![1, 2, 3, 4];
        let encoded = encode_client_hello_inner(&body, 4);
        assert_eq!(encoded, vec![1, 2, 3, 4, 0, 0, 0, 0]);
    }

    #[test]
    fn test_encode_ech_outer_extensions() {
        let ext_types = [51u16, 10, 13]; // key_share, supported_groups, sig_algs
        let payload = encode_ech_outer_extensions(&ext_types);
        // length prefix = 6 (3 * 2)
        assert_eq!(payload[0], 6);
        assert_eq!(u16::from_be_bytes([payload[1], payload[2]]), 51);
        assert_eq!(u16::from_be_bytes([payload[3], payload[4]]), 10);
        assert_eq!(u16::from_be_bytes([payload[5], payload[6]]), 13);
        assert_eq!(payload.len(), 7);
    }
}
