//! HPACK encoder with Huffman support and policy-driven encoding.
//!
//! This replaces the `hpack 0.3` crate's encoder, which lacks Huffman
//! encoding and has a fixed indexing strategy.  The implementation follows
//! RFC 7541 and is modelled after the `h2` crate's HPACK encoder.

mod huffman;
mod table;

use crate::policy::HpackEncodePolicy;
use table::{find_header, DynamicTable, TableMatch};

/// HPACK encoder with Huffman support and configurable encoding policy.
pub struct Encoder {
    dynamic: DynamicTable,
    /// RFC 7541 §6.3: pending Dynamic Table Size Update to emit at the start
    /// of the next header block.
    pending_table_size_update: Option<usize>,
}

impl std::fmt::Debug for Encoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("hpack_enc::Encoder").finish()
    }
}

impl Encoder {
    pub fn new(max_table_size: usize) -> Self {
        Self {
            dynamic: DynamicTable::new(max_table_size),
            pending_table_size_update: None,
        }
    }

    pub fn with_default_size() -> Self {
        Self::new(4096)
    }

    /// Encode headers using a given `HpackEncodePolicy`.
    ///
    /// Each header is encoded according to the policy's decision:
    /// - `Indexed` → try full indexed, else incremental with Huffman
    /// - `IncrementalIndexing` → literal with incremental indexing
    /// - `WithoutIndexing` → literal without indexing
    /// - `NeverIndexed` → literal never indexed (sensitive)
    pub fn encode_with_policy<N: AsRef<str>, V: AsRef<str>>(
        &mut self,
        headers: &[(N, V)],
        policy: &dyn HpackEncodePolicy,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(headers.len() * 32);
        self.emit_pending_table_size_update(&mut buf);
        for (name, value) in headers {
            let (n, v) = (name.as_ref(), value.as_ref());
            let encoding = policy.encoding_for(n, v);
            self.encode_header(n.as_bytes(), v.as_bytes(), encoding, &mut buf);
        }
        buf
    }

    /// Encode headers with Chrome-like defaults (indexed + Huffman).
    pub fn encode_owned<N: AsRef<str>, V: AsRef<str>>(&mut self, headers: &[(N, V)]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(headers.len() * 32);
        self.emit_pending_table_size_update(&mut buf);
        for (name, value) in headers {
            self.encode_header_default(
                name.as_ref().as_bytes(),
                value.as_ref().as_bytes(),
                &mut buf,
            );
        }
        buf
    }

    /// Encode a `(&str, &str)` iterator with Chrome-like defaults.
    pub fn encode<'a, I>(&mut self, headers: I) -> Vec<u8>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut buf = Vec::with_capacity(128);
        self.emit_pending_table_size_update(&mut buf);
        for (name, value) in headers {
            self.encode_header_default(name.as_bytes(), value.as_bytes(), &mut buf);
        }
        buf
    }

    pub fn set_max_table_size(&mut self, size: usize) {
        self.dynamic.set_max_size(size);
        self.pending_table_size_update = Some(size);
    }

    // ─── Internal ────────────────────────────────────────────────────

    /// RFC 7541 §6.3: emit a Dynamic Table Size Update instruction at the
    /// start of a header block if the table size has changed.
    fn emit_pending_table_size_update(&mut self, buf: &mut Vec<u8>) {
        if let Some(new_size) = self.pending_table_size_update.take() {
            encode_integer(new_size, 5, 0x20, buf);
        }
    }

    fn encode_header_default(&mut self, name: &[u8], value: &[u8], buf: &mut Vec<u8>) {
        use crate::policy::HpackFieldEncoding;

        let encoding = if name.starts_with(b":") {
            HpackFieldEncoding::Indexed
        } else {
            HpackFieldEncoding::IncrementalIndexing {
                huffman_value: true,
            }
        };
        self.encode_header(name, value, encoding, buf);
    }

    fn encode_header(
        &mut self,
        name: &[u8],
        value: &[u8],
        encoding: crate::policy::HpackFieldEncoding,
        buf: &mut Vec<u8>,
    ) {
        use crate::policy::HpackFieldEncoding;

        let table_match = find_header(name, value, &self.dynamic);

        match encoding {
            HpackFieldEncoding::Indexed => match table_match {
                Some(TableMatch::Full(idx)) => {
                    encode_indexed(idx, buf);
                }
                Some(TableMatch::NameOnly(idx)) => {
                    encode_literal_indexed_name(idx, value, true, buf);
                    self.dynamic.insert(name.to_vec(), value.to_vec());
                }
                None => {
                    encode_literal_new_name(name, value, true, buf);
                    self.dynamic.insert(name.to_vec(), value.to_vec());
                }
            },
            HpackFieldEncoding::IncrementalIndexing { huffman_value } => match table_match {
                Some(TableMatch::Full(idx)) => {
                    encode_indexed(idx, buf);
                }
                Some(TableMatch::NameOnly(idx)) => {
                    encode_literal_indexed_name(idx, value, huffman_value, buf);
                    self.dynamic.insert(name.to_vec(), value.to_vec());
                }
                None => {
                    encode_literal_new_name(name, value, huffman_value, buf);
                    self.dynamic.insert(name.to_vec(), value.to_vec());
                }
            },
            HpackFieldEncoding::WithoutIndexing { huffman_value } => match table_match {
                Some(TableMatch::Full(idx)) | Some(TableMatch::NameOnly(idx)) => {
                    encode_literal_without_indexing_indexed_name(idx, value, huffman_value, buf);
                }
                None => {
                    encode_literal_without_indexing_new_name(name, value, huffman_value, buf);
                }
            },
            HpackFieldEncoding::NeverIndexed { huffman_value } => match table_match {
                Some(TableMatch::Full(idx)) | Some(TableMatch::NameOnly(idx)) => {
                    encode_literal_never_indexed_indexed_name(idx, value, huffman_value, buf);
                }
                None => {
                    encode_literal_never_indexed_new_name(name, value, huffman_value, buf);
                }
            },
        }
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::with_default_size()
    }
}

// ─── Wire-level encoding helpers ─────────────────────────────────────────────

/// RFC 7541 §6.1 — Indexed Header Field Representation
///   0   1   2   3   4   5   6   7
/// +---+---+---+---+---+---+---+---+
/// | 1 |        Index (7+)         |
/// +---+---------------------------+
fn encode_indexed(index: usize, buf: &mut Vec<u8>) {
    encode_integer(index, 7, 0x80, buf);
}

/// RFC 7541 §6.2.1 — Literal with Incremental Indexing, Indexed Name
///   0   1   2   3   4   5   6   7
/// +---+---+---+---+---+---+---+---+
/// | 0 | 1 |      Index (6+)       |
/// +---+---+-----------------------+
/// |   Value String (Length/Data)   |
/// +-------------------------------+
fn encode_literal_indexed_name(
    name_index: usize,
    value: &[u8],
    huffman_value: bool,
    buf: &mut Vec<u8>,
) {
    encode_integer(name_index, 6, 0x40, buf);
    encode_string(value, huffman_value, buf);
}

/// RFC 7541 §6.2.1 — Literal with Incremental Indexing, New Name
fn encode_literal_new_name(name: &[u8], value: &[u8], huffman_value: bool, buf: &mut Vec<u8>) {
    buf.push(0x40);
    encode_string(name, true, buf); // name always Huffman
    encode_string(value, huffman_value, buf);
}

/// RFC 7541 §6.2.2 — Without Indexing, Indexed Name
fn encode_literal_without_indexing_indexed_name(
    name_index: usize,
    value: &[u8],
    huffman_value: bool,
    buf: &mut Vec<u8>,
) {
    encode_integer(name_index, 4, 0x00, buf);
    encode_string(value, huffman_value, buf);
}

/// RFC 7541 §6.2.2 — Without Indexing, New Name
fn encode_literal_without_indexing_new_name(
    name: &[u8],
    value: &[u8],
    huffman_value: bool,
    buf: &mut Vec<u8>,
) {
    buf.push(0x00);
    encode_string(name, true, buf);
    encode_string(value, huffman_value, buf);
}

/// RFC 7541 §6.2.3 — Never Indexed, Indexed Name
fn encode_literal_never_indexed_indexed_name(
    name_index: usize,
    value: &[u8],
    huffman_value: bool,
    buf: &mut Vec<u8>,
) {
    encode_integer(name_index, 4, 0x10, buf);
    encode_string(value, huffman_value, buf);
}

/// RFC 7541 §6.2.3 — Never Indexed, New Name
fn encode_literal_never_indexed_new_name(
    name: &[u8],
    value: &[u8],
    huffman_value: bool,
    buf: &mut Vec<u8>,
) {
    buf.push(0x10);
    encode_string(name, true, buf);
    encode_string(value, huffman_value, buf);
}

/// Encode a string literal, optionally Huffman-encoded (RFC 7541 §5.2).
///
///   0   1   2   3   4   5   6   7
/// +---+---+---+---+---+---+---+---+
/// | H |    String Length (7+)      |
/// +---+---------------------------+
/// |  String Data (Length octets)   |
/// +-------------------------------+
fn encode_string(src: &[u8], use_huffman: bool, buf: &mut Vec<u8>) {
    if use_huffman {
        let huff_len = huffman::encoded_len(src);
        if huff_len <= src.len() {
            encode_integer(huff_len, 7, 0x80, buf);
            huffman::encode(src, buf);
            return;
        }
    }
    // Raw literal (Huffman wouldn't help or is disabled)
    encode_integer(src.len(), 7, 0x00, buf);
    buf.extend_from_slice(src);
}

/// RFC 7541 §5.1 — Integer Representation
fn encode_integer(mut value: usize, prefix_bits: u8, leading: u8, buf: &mut Vec<u8>) {
    let mask = (1usize << prefix_bits) - 1;
    let leading = leading & !(mask as u8);

    if value < mask {
        buf.push(leading | value as u8);
        return;
    }

    buf.push(leading | mask as u8);
    value -= mask;
    while value >= 128 {
        buf.push((value % 128 + 128) as u8);
        value /= 128;
    }
    buf.push(value as u8);
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_integer_small() {
        let mut buf = Vec::new();
        encode_integer(10, 5, 0, &mut buf);
        assert_eq!(buf, vec![10]);
    }

    #[test]
    fn test_encode_integer_large() {
        let mut buf = Vec::new();
        encode_integer(1337, 5, 0, &mut buf);
        assert_eq!(buf, vec![31, 154, 10]);
    }

    #[test]
    fn test_encode_indexed_method_get() {
        let mut encoder = Encoder::with_default_size();
        let headers = vec![(":method".to_string(), "GET".to_string())];
        let encoded = encoder.encode_owned(&headers);
        // :method GET is static table index 2 → 0x82
        assert_eq!(encoded, vec![0x82]);
    }

    #[test]
    fn test_encode_indexed_path_root() {
        let mut encoder = Encoder::with_default_size();
        let headers = vec![(":path".to_string(), "/".to_string())];
        let encoded = encoder.encode_owned(&headers);
        // :path / is static table index 4 → 0x84
        assert_eq!(encoded, vec![0x84]);
    }

    #[test]
    fn test_encode_scheme_https() {
        let mut encoder = Encoder::with_default_size();
        let headers = vec![(":scheme".to_string(), "https".to_string())];
        let encoded = encoder.encode_owned(&headers);
        // :scheme https is static table index 7 → 0x87
        assert_eq!(encoded, vec![0x87]);
    }

    #[test]
    fn test_encode_authority_uses_huffman() {
        let mut encoder = Encoder::with_default_size();
        let headers = vec![(":authority".to_string(), "www.example.com".to_string())];
        let encoded = encoder.encode_owned(&headers);
        // :authority name-only match at index 1 → 0x41 prefix
        assert_eq!(encoded[0], 0x41);
        // Second byte should have H bit set (0x80) for Huffman value
        assert_ne!(encoded[1] & 0x80, 0, "value should be Huffman-encoded");
        // Total should be shorter than raw (15 bytes for "www.example.com")
        assert!(encoded.len() < 2 + 15);
    }

    #[test]
    fn test_encode_custom_header_huffman() {
        let mut encoder = Encoder::with_default_size();
        let headers = vec![("user-agent".to_string(), "Mozilla/5.0 test".to_string())];
        let encoded = encoder.encode_owned(&headers);
        // user-agent is in static table at index 58 → indexed name
        // But with IncrementalIndexing (default for non-pseudo)
        // First byte should be 0x40 | 58 = 0x7a? No, 6-bit prefix:
        // 58 < 63 → single byte 0x40 | 58 = 0x7a
        assert_eq!(encoded[0], 0x40 | 58);
        // Value should be Huffman-encoded (H bit set)
        assert_ne!(encoded[1] & 0x80, 0, "value should be Huffman-encoded");
    }

    #[test]
    fn test_second_encode_uses_dynamic_table() {
        let mut encoder = Encoder::with_default_size();
        let headers = vec![("x-custom".to_string(), "myvalue".to_string())];

        let _first = encoder.encode_owned(&headers);
        let second = encoder.encode_owned(&headers);
        // Second time should be a single indexed byte (full match in dynamic table)
        assert_eq!(second.len(), 1);
        assert_ne!(second[0] & 0x80, 0, "should use indexed representation");
    }

    #[test]
    fn test_roundtrip_with_hpack_decoder() {
        let mut encoder = Encoder::with_default_size();
        let mut decoder = fluke_hpack::Decoder::new();

        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
            ("user-agent".to_string(), "test/1.0".to_string()),
        ];

        let encoded = encoder.encode_owned(&headers);
        let decoded = decoder.decode(&encoded).unwrap();

        let decoded_strings: Vec<(String, String)> = decoded
            .into_iter()
            .map(|(n, v)| (String::from_utf8(n).unwrap(), String::from_utf8(v).unwrap()))
            .collect();
        assert_eq!(decoded_strings, headers);
    }

    #[test]
    fn test_encode_with_chrome_policy() {
        use crate::policy::ChromeHpackPolicy;

        let mut encoder = Encoder::with_default_size();
        let policy = ChromeHpackPolicy;

        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
            ("user-agent".to_string(), "Chrome/145".to_string()),
        ];

        let encoded = encoder.encode_with_policy(&headers, &policy);

        // Verify with hpack decoder
        let mut decoder = fluke_hpack::Decoder::new();
        let decoded = decoder.decode(&encoded).unwrap();
        let decoded_strings: Vec<(String, String)> = decoded
            .into_iter()
            .map(|(n, v)| (String::from_utf8(n).unwrap(), String::from_utf8(v).unwrap()))
            .collect();
        assert_eq!(decoded_strings, headers);
    }

    #[test]
    fn test_chrome145_full_headers_length() {
        use crate::policy::ChromeHpackPolicy;

        let mut encoder = Encoder::with_default_size();
        let policy = ChromeHpackPolicy;

        let headers: Vec<(&str, &str)> = vec![
            (":method", "GET"),
            (":authority", "tls.browserleaks.com"),
            (":scheme", "https"),
            (":path", "/"),
            ("cache-control", "max-age=0"),
            ("sec-ch-ua", r#""Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145""#),
            ("sec-ch-ua-mobile", "?0"),
            ("sec-ch-ua-platform", r#""Windows""#),
            ("upgrade-insecure-requests", "1"),
            ("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"),
            ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
            ("sec-fetch-site", "none"),
            ("sec-fetch-mode", "navigate"),
            ("sec-fetch-user", "?1"),
            ("sec-fetch-dest", "document"),
            ("accept-encoding", "gzip, deflate, br, zstd"),
            ("accept-language", "zh-CN,zh;q=0.9"),
            ("priority", "u=0, i"),
        ];

        let encoded = encoder.encode_with_policy(&headers, &policy);

        // Print per-header breakdown for analysis
        let mut encoder2 = Encoder::with_default_size();
        let mut total = 0usize;
        for &(name, value) in &headers {
            let single = vec![(name, value)];
            let before = total;
            let single_encoded = encoder2.encode_with_policy(&single, &policy);
            let len = single_encoded.len();
            total += len;
            eprintln!("{name}: {value} → {len} bytes (running total: {total})");
            let _ = before;
        }

        eprintln!("\nTotal header block length: {} bytes", encoded.len());
        eprintln!("Sum of individual: {} bytes", total);

        // Verify roundtrip
        let mut decoder = fluke_hpack::Decoder::new();
        let decoded = decoder.decode(&encoded).unwrap();
        assert_eq!(decoded.len(), headers.len());

        // Chrome's HEADERS frame length = 468 (from browserleaks), i.e. the
        // payload priority(5) + header_block(463). Our encoded header block must
        // match that captured size exactly; a change here is a fingerprint
        // regression (e.g. an altered sec-ch-ua GREASE brand string).
        let chrome_header_block = 468 - 5; // priority 5 bytes
        assert_eq!(
            encoded.len(),
            chrome_header_block,
            "encoded header block must match Chrome 145's captured length"
        );
    }
}
