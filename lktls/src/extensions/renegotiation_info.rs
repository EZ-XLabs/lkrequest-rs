//! Renegotiation Info extension — type 0xff01.
//!
//! Indicates support for secure renegotiation (RFC 5746).
//! In the initial ClientHello, the `renegotiated_connection` field is empty
//! (a single 0x00 length byte).

use super::Extension;

/// Renegotiation Info extension.
pub struct RenegotiationInfo {
    /// The `renegotiated_connection` opaque data.
    /// Empty (`Vec::new()`) for the initial handshake.
    pub renegotiated_connection: Vec<u8>,
}

impl RenegotiationInfo {
    /// Create a renegotiation info extension for the initial handshake
    /// (empty renegotiated_connection).
    pub fn initial() -> Self {
        Self {
            renegotiated_connection: Vec::new(),
        }
    }
}

impl Extension for RenegotiationInfo {
    fn extension_type(&self) -> u16 {
        0xff01
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        buf.push(self.renegotiated_connection.len() as u8);
        buf.extend_from_slice(&self.renegotiated_connection);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_initial() {
        let ext = RenegotiationInfo::initial();
        let mut buf = Vec::new();
        ext.encode(&mut buf);
        // type(2) + length(2) + renegotiated_connection_length(1) = 0x00
        assert_eq!(buf, [0xff, 0x01, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn test_encode_with_data() {
        let ext = RenegotiationInfo {
            renegotiated_connection: vec![0x11, 0x22],
        };
        let mut buf = Vec::new();
        ext.encode(&mut buf);
        assert_eq!(buf, [0xff, 0x01, 0x00, 0x03, 0x02, 0x11, 0x22]);
    }
}
