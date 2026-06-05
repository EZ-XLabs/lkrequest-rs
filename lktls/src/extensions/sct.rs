//! Signed Certificate Timestamp (SCT) extension — type 0x0012.
//!
//! In the ClientHello, this extension is sent with an empty payload to
//! indicate that the client supports receiving SCTs (RFC 6962).

use super::Extension;

/// Signed Certificate Timestamp extension.
///
/// Sent with an empty payload in the ClientHello to request that the
/// server include SCTs in the TLS handshake.
pub struct SignedCertificateTimestamp;

impl Extension for SignedCertificateTimestamp {
    fn extension_type(&self) -> u16 {
        0x0012
    }

    fn encode_payload(&self, _buf: &mut Vec<u8>) {
        // Empty payload in ClientHello.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_sct() {
        let ext = SignedCertificateTimestamp;
        let mut buf = Vec::new();
        ext.encode(&mut buf);
        // type(2) + length(2) with zero-length payload
        assert_eq!(buf, [0x00, 0x12, 0x00, 0x00]);
    }
}
