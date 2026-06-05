//! Compress Certificate extension — type 0x001b.
//!
//! Used by Chrome and Safari to signal support for compressed server
//! certificates (brotli = 0x0002, zlib = 0x0001).

use super::Extension;

/// Compress Certificate extension.
pub struct CompressCertificate {
    /// Algorithm IDs (e.g. `[0x0002]` for brotli).
    pub algorithms: Vec<u16>,
}

impl Extension for CompressCertificate {
    fn extension_type(&self) -> u16 {
        0x001b
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        let list_len = (self.algorithms.len() * 2) as u8;
        buf.push(list_len);
        for &alg in &self.algorithms {
            buf.extend_from_slice(&alg.to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_type_is_001b() {
        let ext = CompressCertificate {
            algorithms: vec![0x0002],
        };
        assert_eq!(ext.extension_type(), 0x001b);
    }

    #[test]
    fn encode_brotli_only() {
        let ext = CompressCertificate {
            algorithms: vec![0x0002], // brotli
        };
        let mut buf = Vec::new();
        ext.encode_payload(&mut buf);

        // list_len = 2 (1 algorithm * 2 bytes)
        assert_eq!(buf[0], 0x02);
        assert_eq!(&buf[1..3], &0x0002u16.to_be_bytes());
        assert_eq!(buf.len(), 3);
    }

    #[test]
    fn encode_multiple_algorithms() {
        let ext = CompressCertificate {
            algorithms: vec![0x0001, 0x0002, 0x0003], // zlib, brotli, zstd
        };
        let mut buf = Vec::new();
        ext.encode_payload(&mut buf);

        assert_eq!(buf[0], 0x06); // 3 * 2 = 6
        assert_eq!(&buf[1..3], &0x0001u16.to_be_bytes());
        assert_eq!(&buf[3..5], &0x0002u16.to_be_bytes());
        assert_eq!(&buf[5..7], &0x0003u16.to_be_bytes());
    }

    #[test]
    fn encode_empty_algorithms() {
        let ext = CompressCertificate { algorithms: vec![] };
        let mut buf = Vec::new();
        ext.encode_payload(&mut buf);

        assert_eq!(buf[0], 0x00);
        assert_eq!(buf.len(), 1);
    }
}
