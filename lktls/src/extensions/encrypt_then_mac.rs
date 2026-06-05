//! Encrypt-Then-MAC extension — type 0x0016.
//!
//! Indicates support for the Encrypt-then-MAC mechanism (RFC 7366).
//! Sent with an empty payload in the ClientHello.  Relevant only for
//! TLS 1.2 CBC cipher suites.

use super::Extension;

/// Encrypt-Then-MAC extension.
pub struct EncryptThenMac;

impl Extension for EncryptThenMac {
    fn extension_type(&self) -> u16 {
        0x0016
    }

    fn encode_payload(&self, _buf: &mut Vec<u8>) {
        // Empty payload.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_encrypt_then_mac() {
        let ext = EncryptThenMac;
        let mut buf = Vec::new();
        ext.encode(&mut buf);
        // type(2) + length(2) with zero-length payload
        assert_eq!(buf, [0x00, 0x16, 0x00, 0x00]);
    }
}
