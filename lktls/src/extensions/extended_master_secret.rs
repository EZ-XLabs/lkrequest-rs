//! Extended Master Secret extension — type 0x0017.
//!
//! Indicates support for the Extended Master Secret computation (RFC 7627).
//! Sent with an empty payload in both ClientHello and ServerHello.

use super::Extension;

/// Extended Master Secret extension.
///
/// When present, the master secret is derived using the session hash
/// (transcript of handshake messages) instead of just the client/server
/// random values, providing stronger protection against man-in-the-middle
/// attacks.
pub struct ExtendedMasterSecret;

impl Extension for ExtendedMasterSecret {
    fn extension_type(&self) -> u16 {
        0x0017
    }

    fn encode_payload(&self, _buf: &mut Vec<u8>) {
        // Empty payload.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_extended_master_secret() {
        let ext = ExtendedMasterSecret;
        let mut buf = Vec::new();
        ext.encode(&mut buf);
        // type(2) + length(2) with zero-length payload
        assert_eq!(buf, [0x00, 0x17, 0x00, 0x00]);
    }
}
