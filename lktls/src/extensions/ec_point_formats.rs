//! EC Point Formats extension — type 0x000b.
//!
//! Indicates the set of point formats that the client can parse for
//! elliptic curve points (typically just `uncompressed` = 0x00).

use super::Extension;

/// EC Point Formats extension.
pub struct EcPointFormats {
    /// List of supported point format codes (e.g. `[0x00]` for uncompressed).
    pub formats: Vec<u8>,
}

impl Extension for EcPointFormats {
    fn extension_type(&self) -> u16 {
        0x000b
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        buf.push(self.formats.len() as u8);
        buf.extend_from_slice(&self.formats);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_uncompressed_only() {
        let ext = EcPointFormats {
            formats: vec![0x00],
        };
        let mut buf = Vec::new();
        ext.encode(&mut buf);
        // type(2) + length(2) + payload(1 len byte + 1 format byte)
        assert_eq!(buf, [0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_encode_multiple_formats() {
        let ext = EcPointFormats {
            formats: vec![0x00, 0x01, 0x02],
        };
        let mut buf = Vec::new();
        ext.encode(&mut buf);
        assert_eq!(buf, [0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02]);
    }
}
