//! Application-Layer Protocol Settings (ALPS) extension.
//!
//! This is a Chrome-specific extension used in conjunction with ALPN.
//! Chrome <= 131 uses type 0x4469, Chrome 132+ uses type 0x44CD.

use super::Extension;

/// ALPS extension listing supported application protocols.
pub struct Alps {
    /// The extension type code to use (0x4469 or 0x44CD).
    pub extension_type: u16,
    /// Protocol identifier strings (typically `["h2"]`).
    pub protocols: Vec<String>,
}

impl Extension for Alps {
    fn extension_type(&self) -> u16 {
        self.extension_type
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        // Total length of protocol list
        let list_len: usize = self.protocols.iter().map(|p| 1 + p.len()).sum();
        buf.extend_from_slice(&(list_len as u16).to_be_bytes());
        for proto in &self.protocols {
            buf.push(proto.len() as u8);
            buf.extend_from_slice(proto.as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_type_chrome_old() {
        let ext = Alps {
            extension_type: 0x4469,
            protocols: vec!["h2".into()],
        };
        assert_eq!(ext.extension_type(), 0x4469);
    }

    #[test]
    fn extension_type_chrome_new() {
        let ext = Alps {
            extension_type: 0x44CD,
            protocols: vec!["h2".into()],
        };
        assert_eq!(ext.extension_type(), 0x44CD);
    }

    #[test]
    fn encode_single_protocol_h2() {
        let ext = Alps {
            extension_type: 0x4469,
            protocols: vec!["h2".into()],
        };
        let mut buf = Vec::new();
        ext.encode_payload(&mut buf);

        // list_len = 1 (len byte) + 2 (h2) = 3
        assert_eq!(&buf[0..2], &0x0003u16.to_be_bytes());
        // protocol length
        assert_eq!(buf[2], 0x02);
        // protocol name
        assert_eq!(&buf[3..5], b"h2");
        assert_eq!(buf.len(), 5);
    }

    #[test]
    fn encode_multiple_protocols() {
        let ext = Alps {
            extension_type: 0x4469,
            protocols: vec!["h2".into(), "http/1.1".into()],
        };
        let mut buf = Vec::new();
        ext.encode_payload(&mut buf);

        // list_len = (1+2) + (1+8) = 12
        assert_eq!(&buf[0..2], &0x000cu16.to_be_bytes());
        // first proto
        assert_eq!(buf[2], 2);
        assert_eq!(&buf[3..5], b"h2");
        // second proto
        assert_eq!(buf[5], 8);
        assert_eq!(&buf[6..14], b"http/1.1");
    }

    #[test]
    fn encode_empty_protocols() {
        let ext = Alps {
            extension_type: 0x4469,
            protocols: vec![],
        };
        let mut buf = Vec::new();
        ext.encode_payload(&mut buf);

        // list_len = 0
        assert_eq!(&buf[0..2], &0x0000u16.to_be_bytes());
        assert_eq!(buf.len(), 2);
    }
}
