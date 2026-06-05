//! Server Name Indication (SNI) extension — type 0x0000.

use super::Extension;

/// SNI extension carrying the target hostname.
pub struct Sni {
    /// The hostname to include in the SNI extension.
    pub hostname: String,
}

impl Extension for Sni {
    fn extension_type(&self) -> u16 {
        0x0000
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        let name_bytes = self.hostname.as_bytes();
        let name_len = name_bytes.len() as u16;
        // Server Name List length = 1 (type) + 2 (length) + name_len
        let list_len = 3 + name_len;

        // Server Name List length (2 bytes)
        buf.extend_from_slice(&list_len.to_be_bytes());
        // Host Name type (1 byte) = 0x00
        buf.push(0x00);
        // Host Name length (2 bytes)
        buf.extend_from_slice(&name_len.to_be_bytes());
        // Host Name
        buf.extend_from_slice(name_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_extension_type() {
        let sni = Sni {
            hostname: "example.com".into(),
        };
        assert_eq!(sni.extension_type(), 0x0000);
    }

    #[test]
    fn sni_encode_payload_basic() {
        let sni = Sni {
            hostname: "example.com".into(),
        };
        let mut buf = Vec::new();
        sni.encode_payload(&mut buf);

        let name = b"example.com";
        let name_len = name.len() as u16;
        let list_len = 3 + name_len;

        // Server Name List length (2 bytes)
        assert_eq!(&buf[0..2], &list_len.to_be_bytes());
        // Host Name type = 0x00
        assert_eq!(buf[2], 0x00);
        // Host Name length (2 bytes)
        assert_eq!(&buf[3..5], &name_len.to_be_bytes());
        // Host Name
        assert_eq!(&buf[5..], name);
    }

    #[test]
    fn sni_encode_full_extension() {
        let sni = Sni {
            hostname: "a.io".into(),
        };
        let mut buf = Vec::new();
        sni.encode(&mut buf);

        // Type = 0x0000
        assert_eq!(&buf[0..2], &[0x00, 0x00]);
        // Payload length
        let payload_len = buf.len() - 4;
        assert_eq!(&buf[2..4], &(payload_len as u16).to_be_bytes());
    }

    #[test]
    fn sni_empty_hostname() {
        let sni = Sni {
            hostname: String::new(),
        };
        let mut buf = Vec::new();
        sni.encode_payload(&mut buf);

        // list_len = 3 + 0 = 3
        assert_eq!(&buf[0..2], &0x0003u16.to_be_bytes());
        // type = 0x00
        assert_eq!(buf[2], 0x00);
        // name_len = 0
        assert_eq!(&buf[3..5], &[0x00, 0x00]);
        // no more bytes
        assert_eq!(buf.len(), 5);
    }

    #[test]
    fn sni_unicode_hostname_encoded_as_utf8() {
        let sni = Sni {
            hostname: "münchen.de".into(),
        };
        let mut buf = Vec::new();
        sni.encode_payload(&mut buf);

        let name_bytes = "münchen.de".as_bytes();
        let name_len = name_bytes.len() as u16;
        assert_eq!(&buf[3..5], &name_len.to_be_bytes());
        assert_eq!(&buf[5..], name_bytes);
    }
}
