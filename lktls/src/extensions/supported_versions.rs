//! Supported Versions extension — type 0x002b.
//!
//! Encoding for ClientHello (list of supported versions) and decoding
//! of the server-selected version from ServerHello.

use super::Extension;

/// Lists the TLS versions the client is willing to negotiate.
pub struct SupportedVersions {
    /// Ordered list of version code-points (e.g. `[0x0304, 0x0303]`).
    pub versions: Vec<u16>,
}

impl Extension for SupportedVersions {
    fn extension_type(&self) -> u16 {
        0x002b
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        // Length of versions list in bytes
        let list_len = (self.versions.len() * 2) as u8;
        buf.push(list_len);
        for &v in &self.versions {
            buf.extend_from_slice(&v.to_be_bytes());
        }
    }
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Parse the server-selected version from the `supported_versions` extension
/// payload in a ServerHello.
///
/// The payload is exactly 2 bytes: the selected ProtocolVersion.
pub fn parse_server_version(data: &[u8]) -> Option<u16> {
    if data.len() >= 2 {
        Some(u16::from_be_bytes([data[0], data[1]]))
    } else {
        None
    }
}

/// Parse the client version list from a ClientHello `supported_versions`
/// extension payload.
///
/// The payload format is: `list_length(1) + version(2)*`.
pub fn parse_client_versions(data: &[u8]) -> Option<Vec<u16>> {
    if data.is_empty() {
        return None;
    }
    let list_len = data[0] as usize;
    if 1 + list_len > data.len() || !list_len.is_multiple_of(2) {
        return None;
    }
    let mut versions = Vec::with_capacity(list_len / 2);
    let mut pos = 1;
    while pos + 1 < 1 + list_len {
        versions.push(u16::from_be_bytes([data[pos], data[pos + 1]]));
        pos += 2;
    }
    Some(versions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_supported_versions() {
        let ext = SupportedVersions {
            versions: vec![0x0304, 0x0303],
        };
        let mut buf = Vec::new();
        ext.encode(&mut buf);
        assert_eq!(
            buf,
            [
                0x00, 0x2b, // type
                0x00, 0x05, // extension length = 5
                0x04, // list length = 4 bytes
                0x03, 0x04, // TLS 1.3
                0x03, 0x03, // TLS 1.2
            ]
        );
    }

    #[test]
    fn test_parse_server_version() {
        assert_eq!(parse_server_version(&[0x03, 0x04]), Some(0x0304));
        assert_eq!(parse_server_version(&[0x03, 0x03]), Some(0x0303));
        assert_eq!(parse_server_version(&[0x03]), None);
        assert_eq!(parse_server_version(&[]), None);
    }

    #[test]
    fn test_parse_client_versions() {
        let data = [0x04, 0x03, 0x04, 0x03, 0x03]; // 4 bytes = 2 versions
        let versions = parse_client_versions(&data).unwrap();
        assert_eq!(versions, vec![0x0304, 0x0303]);
    }

    #[test]
    fn test_parse_client_versions_invalid() {
        assert_eq!(parse_client_versions(&[]), None);
        assert_eq!(parse_client_versions(&[0x03, 0x03, 0x04]), None); // odd list_len
    }
}
