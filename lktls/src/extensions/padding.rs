//! Padding extension — type 0x0015.
//!
//! Used to pad the ClientHello to a target length (e.g. 512 bytes for Chrome)
//! to avoid TLS fingerprinting based on ClientHello size.

use super::Extension;

/// Padding extension that pads the ClientHello to a target total length.
///
/// The actual padding length is computed by the ClientHello builder after
/// all other extensions have been encoded.  This struct carries the
/// pre-computed number of zero-bytes to include.
pub struct Padding {
    /// Number of zero-bytes to include as the padding payload.
    pub padding_len: u16,
}

impl Extension for Padding {
    fn extension_type(&self) -> u16 {
        0x0015
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        buf.extend(std::iter::repeat_n(0u8, self.padding_len as usize));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_type_is_0015() {
        let ext = Padding { padding_len: 10 };
        assert_eq!(ext.extension_type(), 0x0015);
    }

    #[test]
    fn encode_padding_correct_length() {
        let ext = Padding { padding_len: 128 };
        let mut buf = Vec::new();
        ext.encode_payload(&mut buf);

        assert_eq!(buf.len(), 128);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn encode_zero_padding() {
        let ext = Padding { padding_len: 0 };
        let mut buf = Vec::new();
        ext.encode_payload(&mut buf);

        assert!(buf.is_empty());
    }

    #[test]
    fn full_encode_includes_header() {
        let ext = Padding { padding_len: 5 };
        let mut buf = Vec::new();
        ext.encode(&mut buf);

        // type = 0x0015
        assert_eq!(&buf[0..2], &[0x00, 0x15]);
        // length = 5
        assert_eq!(&buf[2..4], &[0x00, 0x05]);
        // 5 zero bytes
        assert_eq!(&buf[4..9], &[0x00; 5]);
        assert_eq!(buf.len(), 9);
    }

    #[test]
    fn encode_large_padding() {
        let ext = Padding { padding_len: 512 };
        let mut buf = Vec::new();
        ext.encode_payload(&mut buf);

        assert_eq!(buf.len(), 512);
        assert!(buf.iter().all(|&b| b == 0));
    }
}
