//! PSK Key Exchange Modes extension — type 0x002d.
//!
//! Indicates the PSK key exchange modes the client supports (RFC 8446 §4.2.9).
//! Typically `[psk_dhe_ke(1)]` for TLS 1.3 clients.

use super::Extension;

/// Well-known PSK key exchange mode values.
pub mod mode {
    /// PSK-only key establishment.
    pub const PSK_KE: u8 = 0x00;
    /// PSK with (EC)DHE key establishment.
    pub const PSK_DHE_KE: u8 = 0x01;
}

/// PSK Key Exchange Modes extension.
pub struct PskKeyExchangeModes {
    /// List of supported PSK key exchange mode codes.
    pub modes: Vec<u8>,
}

impl Extension for PskKeyExchangeModes {
    fn extension_type(&self) -> u16 {
        0x002d
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        buf.push(self.modes.len() as u8);
        buf.extend_from_slice(&self.modes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_psk_dhe_ke() {
        let ext = PskKeyExchangeModes {
            modes: vec![mode::PSK_DHE_KE],
        };
        let mut buf = Vec::new();
        ext.encode(&mut buf);
        // type(2) + length(2) + modes_count(1) + mode(1)
        assert_eq!(buf, [0x00, 0x2d, 0x00, 0x02, 0x01, 0x01]);
    }

    #[test]
    fn test_encode_both_modes() {
        let ext = PskKeyExchangeModes {
            modes: vec![mode::PSK_KE, mode::PSK_DHE_KE],
        };
        let mut buf = Vec::new();
        ext.encode(&mut buf);
        assert_eq!(buf, [0x00, 0x2d, 0x00, 0x03, 0x02, 0x00, 0x01]);
    }
}
