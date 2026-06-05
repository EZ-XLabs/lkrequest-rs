//! HPACK header compression (RFC 7541).
//!
//! Decoder wraps the `hpack` crate; encoder uses our own `hpack_enc`
//! module with Huffman support and policy-driven encoding.

use crate::hpack_enc;
use fluke_hpack::Decoder as HpackDecoder;

/// Convert `Vec<u8>` to `String`, reusing the allocation when valid UTF-8
/// (the common case for HTTP/2 headers). Falls back to lossy replacement only
/// for non-UTF-8 bytes.
fn vec_to_string_lossy(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }
}

// ─── Decoder ─────────────────────────────────────────────────────────────────

pub struct HeaderDecoder {
    decoder: HpackDecoder<'static>,
}

impl std::fmt::Debug for HeaderDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeaderDecoder").finish()
    }
}

impl HeaderDecoder {
    pub fn new(table_size: usize) -> Self {
        let mut decoder = HpackDecoder::new();
        if table_size != 4096 {
            decoder.set_max_table_size(table_size);
        }
        Self { decoder }
    }

    pub fn with_default_size() -> Self {
        Self::new(4096)
    }

    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<(String, String)>, HpackError> {
        self.decoder
            .decode(data)
            .map(|headers| {
                headers
                    .into_iter()
                    .map(|(name, value)| (vec_to_string_lossy(name), vec_to_string_lossy(value)))
                    .collect()
            })
            .map_err(|e| HpackError::DecodingError(format!("{e:?}")))
    }

    pub fn set_max_table_size(&mut self, size: usize) {
        self.decoder.set_max_table_size(size);
    }
}

impl Default for HeaderDecoder {
    fn default() -> Self {
        Self::with_default_size()
    }
}

// ─── Encoder ─────────────────────────────────────────────────────────────────

pub struct HeaderEncoder {
    encoder: hpack_enc::Encoder,
}

impl std::fmt::Debug for HeaderEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeaderEncoder").finish()
    }
}

impl HeaderEncoder {
    pub fn new(table_size: usize) -> Self {
        Self {
            encoder: hpack_enc::Encoder::new(table_size),
        }
    }

    pub fn with_default_size() -> Self {
        Self::new(4096)
    }

    pub fn encode<'a, I>(&mut self, headers: I) -> Vec<u8>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        self.encoder.encode(headers)
    }

    pub fn encode_owned<N: AsRef<str>, V: AsRef<str>>(&mut self, headers: &[(N, V)]) -> Vec<u8> {
        self.encoder.encode_owned(headers)
    }

    pub fn encode_with_policy<N: AsRef<str>, V: AsRef<str>>(
        &mut self,
        headers: &[(N, V)],
        policy: &dyn crate::policy::HpackEncodePolicy,
    ) -> Vec<u8> {
        self.encoder.encode_with_policy(headers, policy)
    }

    pub fn set_max_table_size(&mut self, size: usize) {
        self.encoder.set_max_table_size(size);
    }
}

impl Default for HeaderEncoder {
    fn default() -> Self {
        Self::with_default_size()
    }
}

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum HpackError {
    DecodingError(String),
    EncodingError(String),
}

impl std::fmt::Display for HpackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DecodingError(msg) => write!(f, "HPACK decoding error: {msg}"),
            Self::EncodingError(msg) => write!(f, "HPACK encoding error: {msg}"),
        }
    }
}

impl std::error::Error for HpackError {}

// ─── Pseudo-header helpers ───────────────────────────────────────────────────

pub fn get_pseudo_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
type HeaderPair = (String, String);

#[cfg(test)]
pub(crate) fn extract_pseudo_headers(headers: &[HeaderPair]) -> (Vec<HeaderPair>, Vec<HeaderPair>) {
    let mut pseudo = Vec::new();
    let mut regular = Vec::new();
    for (name, value) in headers {
        if name.starts_with(':') {
            pseudo.push((name.clone(), value.clone()));
        } else {
            regular.push((name.clone(), value.clone()));
        }
    }
    (pseudo, regular)
}

#[cfg(test)]
pub(crate) fn get_method(headers: &[(String, String)]) -> Option<&str> {
    get_pseudo_header(headers, ":method")
}

#[cfg(test)]
pub(crate) fn get_path(headers: &[(String, String)]) -> Option<&str> {
    get_pseudo_header(headers, ":path")
}

#[cfg(test)]
pub(crate) fn get_authority(headers: &[(String, String)]) -> Option<&str> {
    get_pseudo_header(headers, ":authority")
}

pub fn get_status(headers: &[(String, String)]) -> Option<u16> {
    get_pseudo_header(headers, ":status").and_then(|s| s.parse().ok())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut encoder = HeaderEncoder::with_default_size();
        let mut decoder = HeaderDecoder::with_default_size();

        let headers = vec![
            (":method", "GET"),
            (":path", "/"),
            (":scheme", "https"),
            (":authority", "example.com"),
            ("user-agent", "test/1.0"),
        ];

        let encoded = encoder.encode(headers);
        let decoded = decoder.decode(&encoded).unwrap();

        assert_eq!(decoded.len(), 5);
        assert_eq!(decoded[0], (":method".to_string(), "GET".to_string()));
        assert_eq!(decoded[1], (":path".to_string(), "/".to_string()));
    }

    #[test]
    fn test_extract_pseudo_headers() {
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/".to_string()),
            ("content-type".to_string(), "text/html".to_string()),
        ];
        let (pseudo, regular) = extract_pseudo_headers(&headers);
        assert_eq!(pseudo.len(), 2);
        assert_eq!(regular.len(), 1);
        assert_eq!(regular[0].0, "content-type");
    }

    #[test]
    fn test_get_pseudo_headers() {
        let headers = vec![
            (":method".to_string(), "POST".to_string()),
            (":path".to_string(), "/api".to_string()),
            (":status".to_string(), "200".to_string()),
        ];
        assert_eq!(get_method(&headers), Some("POST"));
        assert_eq!(get_path(&headers), Some("/api"));
        assert_eq!(get_status(&headers), Some(200));
        assert_eq!(get_authority(&headers), None);
    }

    #[test]
    fn decode_does_not_panic_on_malformed_input() {
        // Adversarial HPACK blocks of the kind that historically tripped HPACK
        // decoders (cf. RUSTSEC-2023-0085 against the unmaintained `hpack`
        // crate). Decoding untrusted server headers must never panic / abort the
        // process — at worst it returns an error and the connection is dropped.
        let malformed: &[&[u8]] = &[
            &[0x80],                               // indexed field, index 0 (illegal)
            &[0xbf],                               // indexed field, index past the table
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // index varint overflow
            &[0x00, 0x8f, 0xff, 0xff, 0xff, 0xff], // literal, huffman name length overflow
            &[0x40, 0x82, 0xff, 0xff],             // huffman name, invalid/truncated
            &[0x20, 0xff, 0xff, 0xff, 0xff, 0xff], // dynamic table size update overflow
        ];
        let mut rejected = 0;
        for block in malformed {
            let mut decoder = HeaderDecoder::with_default_size();
            // Ok or Err are both acceptable; the guarantee under test is "no panic".
            if decoder.decode(block).is_err() {
                rejected += 1;
            }
        }
        // Reaching this line proves none of the blocks panicked the decoder, and
        // clearly-illegal blocks (e.g. an out-of-range index) must be rejected.
        assert!(
            rejected > 0,
            "expected at least one malformed HPACK block to be rejected, got none"
        );
    }
}
