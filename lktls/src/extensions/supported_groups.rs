//! Supported Groups (Named Curves) extension — type 0x000a.

use super::Extension;

/// Lists the elliptic curves / DH groups the client supports.
pub struct SupportedGroups {
    /// Ordered list of NamedGroup code-points.
    pub groups: Vec<u16>,
}

impl Extension for SupportedGroups {
    fn extension_type(&self) -> u16 {
        0x000a
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        let list_len = (self.groups.len() * 2) as u16;
        buf.extend_from_slice(&list_len.to_be_bytes());
        for &g in &self.groups {
            buf.extend_from_slice(&g.to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_type_is_000a() {
        let ext = SupportedGroups {
            groups: vec![0x001d],
        };
        assert_eq!(ext.extension_type(), 0x000a);
    }

    #[test]
    fn encode_single_group() {
        let ext = SupportedGroups {
            groups: vec![0x001d], // x25519
        };
        let mut buf = Vec::new();
        ext.encode_payload(&mut buf);

        // list_len = 2
        assert_eq!(&buf[0..2], &0x0002u16.to_be_bytes());
        // group code
        assert_eq!(&buf[2..4], &0x001du16.to_be_bytes());
        assert_eq!(buf.len(), 4);
    }

    #[test]
    fn encode_multiple_groups_preserves_order() {
        let groups = vec![0x001d, 0x0017, 0x0018]; // x25519, secp256r1, secp384r1
        let ext = SupportedGroups {
            groups: groups.clone(),
        };
        let mut buf = Vec::new();
        ext.encode_payload(&mut buf);

        let list_len = (groups.len() * 2) as u16;
        assert_eq!(&buf[0..2], &list_len.to_be_bytes());
        for (i, &g) in groups.iter().enumerate() {
            let offset = 2 + i * 2;
            assert_eq!(&buf[offset..offset + 2], &g.to_be_bytes());
        }
    }

    #[test]
    fn encode_empty_groups() {
        let ext = SupportedGroups { groups: vec![] };
        let mut buf = Vec::new();
        ext.encode_payload(&mut buf);

        assert_eq!(&buf[0..2], &0x0000u16.to_be_bytes());
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn full_encode_includes_header() {
        let ext = SupportedGroups {
            groups: vec![0x001d],
        };
        let mut buf = Vec::new();
        ext.encode(&mut buf);

        // type = 0x000a
        assert_eq!(&buf[0..2], &[0x00, 0x0a]);
        // payload length = 4 (2 list_len + 2 group)
        assert_eq!(&buf[2..4], &0x0004u16.to_be_bytes());
    }
}
