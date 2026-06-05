//! Record Size Limit extension — type 0x001c.
//!
//! Indicates the maximum record size the endpoint is willing to receive
//! (RFC 8449).  Used primarily by Firefox.

use super::Extension;

/// Record Size Limit extension.
pub struct RecordSizeLimit {
    /// The maximum record size in bytes (big-endian u16 on the wire).
    pub limit: u16,
}

impl Extension for RecordSizeLimit {
    fn extension_type(&self) -> u16 {
        0x001c
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.limit.to_be_bytes());
    }
}

/// Parse a Record Size Limit value from extension payload bytes.
pub fn parse_record_size_limit(data: &[u8]) -> Option<u16> {
    if data.len() >= 2 {
        Some(u16::from_be_bytes([data[0], data[1]]))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_record_size_limit() {
        let ext = RecordSizeLimit { limit: 16385 };
        let mut buf = Vec::new();
        ext.encode(&mut buf);
        assert_eq!(
            buf,
            [
                0x00, 0x1c, // type
                0x00, 0x02, // extension length = 2
                0x40, 0x01, // 16385 in big-endian
            ]
        );
    }

    #[test]
    fn test_parse_record_size_limit() {
        assert_eq!(parse_record_size_limit(&[0x40, 0x01]), Some(16385));
        assert_eq!(parse_record_size_limit(&[0x00]), None);
        assert_eq!(parse_record_size_limit(&[]), None);
    }
}
