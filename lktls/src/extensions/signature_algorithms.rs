//! Signature Algorithms extension — type 0x000d.

use super::Extension;

/// Lists the signature algorithms the client supports.
pub struct SignatureAlgorithms {
    /// Ordered list of SignatureScheme code-points.
    pub algorithms: Vec<u16>,
}

impl Extension for SignatureAlgorithms {
    fn extension_type(&self) -> u16 {
        0x000d
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        let list_len = (self.algorithms.len() * 2) as u16;
        buf.extend_from_slice(&list_len.to_be_bytes());
        for &alg in &self.algorithms {
            buf.extend_from_slice(&alg.to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_type_is_000d() {
        let ext = SignatureAlgorithms {
            algorithms: vec![0x0403],
        };
        assert_eq!(ext.extension_type(), 0x000d);
    }

    #[test]
    fn encode_single_algorithm() {
        let ext = SignatureAlgorithms {
            algorithms: vec![0x0403], // ecdsa_secp256r1_sha256
        };
        let mut buf = Vec::new();
        ext.encode_payload(&mut buf);

        assert_eq!(&buf[0..2], &0x0002u16.to_be_bytes());
        assert_eq!(&buf[2..4], &0x0403u16.to_be_bytes());
    }

    #[test]
    fn encode_chrome_signature_algorithms() {
        let algs = vec![
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let ext = SignatureAlgorithms {
            algorithms: algs.clone(),
        };
        let mut buf = Vec::new();
        ext.encode_payload(&mut buf);

        let list_len = (algs.len() * 2) as u16;
        assert_eq!(&buf[0..2], &list_len.to_be_bytes());
        for (i, &alg) in algs.iter().enumerate() {
            let offset = 2 + i * 2;
            assert_eq!(&buf[offset..offset + 2], &alg.to_be_bytes());
        }
    }

    #[test]
    fn encode_empty_algorithms() {
        let ext = SignatureAlgorithms { algorithms: vec![] };
        let mut buf = Vec::new();
        ext.encode_payload(&mut buf);

        assert_eq!(&buf[0..2], &0x0000u16.to_be_bytes());
        assert_eq!(buf.len(), 2);
    }
}
