//! Application-Layer Protocol Negotiation (ALPN) extension — type 0x0010.
//!
//! Encoding for ClientHello and decoding of server-selected ALPN from
//! ServerHello / EncryptedExtensions.

use super::Extension;

/// ALPN extension listing the protocols the client supports (e.g. `h2`, `http/1.1`).
pub struct Alpn {
    /// Protocol identifier strings.
    pub protocols: Vec<String>,
}

impl Extension for Alpn {
    fn extension_type(&self) -> u16 {
        0x0010
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        // Calculate total ALPN list length
        let list_len: usize = self.protocols.iter().map(|p| 1 + p.len()).sum();

        // ALPN extension list length (2 bytes)
        buf.extend_from_slice(&(list_len as u16).to_be_bytes());

        for proto in &self.protocols {
            buf.push(proto.len() as u8);
            buf.extend_from_slice(proto.as_bytes());
        }
    }
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Parse the server-selected ALPN protocol from the extension payload.
///
/// The server ALPN extension contains a single selected protocol in the
/// format: `protocol_name_list_length(2) + protocol_name_length(1) + name`.
pub fn parse_server_alpn(data: &[u8]) -> Option<String> {
    if data.len() < 4 {
        return None;
    }
    // protocol_name_list_length (2 bytes) — we skip it, just use inner length
    let name_len = data[2] as usize;
    if 3 + name_len > data.len() {
        return None;
    }
    std::str::from_utf8(&data[3..3 + name_len])
        .ok()
        .map(|s| s.to_string())
}

/// Parse all ALPN protocols from a client or server extension payload.
///
/// The payload format is: `list_length(2) + (name_length(1) + name)*`.
pub fn parse_alpn_list(data: &[u8]) -> Option<Vec<String>> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if 2 + list_len > data.len() {
        return None;
    }

    let mut protocols = Vec::new();
    let mut pos = 2;
    let end = 2 + list_len;
    while pos < end {
        let name_len = data[pos] as usize;
        pos += 1;
        if pos + name_len > end {
            return None;
        }
        if let Ok(name) = std::str::from_utf8(&data[pos..pos + name_len]) {
            protocols.push(name.to_string());
        }
        pos += name_len;
    }
    Some(protocols)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_alpn() {
        let ext = Alpn {
            protocols: vec!["h2".to_string(), "http/1.1".to_string()],
        };
        let mut buf = Vec::new();
        ext.encode(&mut buf);
        // type(2) + len(2) + list_len(2) + "h2"(1+2) + "http/1.1"(1+8) = 4+2+3+9 = 18
        assert_eq!(buf[0..2], [0x00, 0x10]); // type
        let payload_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        assert_eq!(payload_len, 2 + 3 + 9); // 14
    }

    #[test]
    fn test_parse_server_alpn() {
        // Server selects "h2": list_len=3, name_len=2, "h2"
        let data = [0x00, 0x03, 0x02, b'h', b'2'];
        assert_eq!(parse_server_alpn(&data), Some("h2".to_string()));
    }

    #[test]
    fn test_parse_server_alpn_http11() {
        let data = [
            0x00, 0x09, 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
        ];
        assert_eq!(parse_server_alpn(&data), Some("http/1.1".to_string()));
    }

    #[test]
    fn test_parse_server_alpn_too_short() {
        assert_eq!(parse_server_alpn(&[0x00, 0x03, 0x02]), None);
        assert_eq!(parse_server_alpn(&[0x00]), None);
    }

    #[test]
    fn test_parse_alpn_list() {
        // "h2" + "http/1.1"
        let data = [
            0x00, 0x0c, // list_len=12
            0x02, b'h', b'2', // h2
            0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1', // http/1.1
        ];
        let protos = parse_alpn_list(&data).unwrap();
        assert_eq!(protos, vec!["h2", "http/1.1"]);
    }
}
