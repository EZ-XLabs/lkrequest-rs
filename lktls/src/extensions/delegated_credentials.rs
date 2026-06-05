//! Delegated Credentials extension — type 0x0022.
//!
//! Indicates support for delegated credentials (draft-ietf-tls-subcerts).
//! Used primarily by Firefox.  The ClientHello payload contains a list of
//! signature algorithms that the client supports for delegated credentials.

use super::Extension;

/// Delegated Credentials extension.
pub struct DelegatedCredentials {
    /// Signature algorithms supported for delegated credentials.
    pub signature_algorithms: Vec<u16>,
}

impl Extension for DelegatedCredentials {
    fn extension_type(&self) -> u16 {
        0x0022
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        let list_len = (self.signature_algorithms.len() * 2) as u16;
        buf.extend_from_slice(&list_len.to_be_bytes());
        for &alg in &self.signature_algorithms {
            buf.extend_from_slice(&alg.to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_delegated_credentials() {
        let ext = DelegatedCredentials {
            signature_algorithms: vec![0x0403, 0x0503], // ECDSA-P256-SHA256, ECDSA-P384-SHA384
        };
        let mut buf = Vec::new();
        ext.encode(&mut buf);
        assert_eq!(
            buf,
            [
                0x00, 0x22, // type
                0x00, 0x06, // extension length = 6
                0x00, 0x04, // list length = 4
                0x04, 0x03, // ECDSA-P256-SHA256
                0x05, 0x03, // ECDSA-P384-SHA384
            ]
        );
    }

    #[test]
    fn test_encode_empty_algorithms() {
        let ext = DelegatedCredentials {
            signature_algorithms: vec![],
        };
        let mut buf = Vec::new();
        ext.encode(&mut buf);
        assert_eq!(
            buf,
            [
                0x00, 0x22, // type
                0x00, 0x02, // extension length = 2
                0x00, 0x00, // list length = 0
            ]
        );
    }
}
