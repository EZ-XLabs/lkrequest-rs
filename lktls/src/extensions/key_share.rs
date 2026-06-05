//! Key Share extension — type 0x0033.
//!
//! In the ClientHello, this extension carries one or more (group, key) pairs.
//! The actual key generation is handled by the crypto layer; this module
//! is responsible for encoding and decoding the wire format.

use super::Extension;

/// A single key share entry.
pub struct KeyShareEntry {
    /// Named group code-point (e.g. 0x001d for X25519).
    pub group: u16,
    /// The public key bytes.
    pub key_data: Vec<u8>,
}

/// Key Share extension carrying client key shares.
pub struct KeyShare {
    pub entries: Vec<KeyShareEntry>,
}

impl Extension for KeyShare {
    fn extension_type(&self) -> u16 {
        0x0033
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        // Calculate total length of all entries
        let entries_len: usize = self
            .entries
            .iter()
            .map(|e| 2 /* group */ + 2 /* key_len */ + e.key_data.len())
            .sum();

        // Client key share length (2 bytes)
        buf.extend_from_slice(&(entries_len as u16).to_be_bytes());

        for entry in &self.entries {
            buf.extend_from_slice(&entry.group.to_be_bytes());
            buf.extend_from_slice(&(entry.key_data.len() as u16).to_be_bytes());
            buf.extend_from_slice(&entry.key_data);
        }
    }
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Parse the server's key share from a ServerHello `key_share` extension payload.
///
/// The payload format is: `group(2) + key_length(2) + key_exchange(key_length)`.
/// Returns `(named_group, public_key_bytes)`.
pub fn parse_server_key_share(data: &[u8]) -> Option<(u16, Vec<u8>)> {
    if data.len() < 4 {
        return None;
    }
    let group = u16::from_be_bytes([data[0], data[1]]);
    let key_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if 4 + key_len > data.len() {
        return None;
    }
    Some((group, data[4..4 + key_len].to_vec()))
}

/// Parse the selected group from a HelloRetryRequest `key_share` extension.
///
/// In HRR, the key_share extension contains only the selected group (2 bytes).
pub fn parse_hrr_selected_group(data: &[u8]) -> Option<u16> {
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
    fn test_encode_key_share() {
        let ext = KeyShare {
            entries: vec![KeyShareEntry {
                group: 0x001d, // X25519
                key_data: vec![0xAA; 32],
            }],
        };
        let mut buf = Vec::new();
        ext.encode(&mut buf);
        // type(2) + ext_len(2) + entries_len(2) + group(2) + key_len(2) + key(32) = 42
        assert_eq!(buf[0..2], [0x00, 0x33]); // type
        assert_eq!(buf.len(), 42);
    }

    #[test]
    fn test_parse_server_key_share() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x001du16.to_be_bytes()); // X25519
        data.extend_from_slice(&32u16.to_be_bytes()); // key_len = 32
        data.extend_from_slice(&[0x55; 32]); // key bytes

        let (group, key) = parse_server_key_share(&data).unwrap();
        assert_eq!(group, 0x001d);
        assert_eq!(key, vec![0x55; 32]);
    }

    #[test]
    fn test_parse_server_key_share_too_short() {
        assert!(parse_server_key_share(&[0x00, 0x1d, 0x00]).is_none());
        assert!(parse_server_key_share(&[0x00, 0x1d, 0x00, 0x20]).is_none()); // claims 32 but no data
    }

    #[test]
    fn test_parse_hrr_selected_group() {
        assert_eq!(parse_hrr_selected_group(&[0x00, 0x17]), Some(0x0017)); // P-256
        assert_eq!(parse_hrr_selected_group(&[0x00, 0x1d]), Some(0x001d)); // X25519
        assert_eq!(parse_hrr_selected_group(&[0x00]), None);
    }
}
