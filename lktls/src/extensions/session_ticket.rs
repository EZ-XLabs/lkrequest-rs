//! Session Ticket extension — type 0x0023.
//!
//! In the initial ClientHello (no resumption), this extension is sent with
//! an empty payload to indicate support.  When resuming, the payload
//! contains the previously received session ticket.

use super::Extension;

/// Session Ticket extension.
pub struct SessionTicket {
    /// Ticket data.  Empty for initial ClientHello (indicating support),
    /// or the opaque ticket bytes for resumption.
    pub data: Vec<u8>,
}

impl SessionTicket {
    /// Create an empty session ticket extension (initial ClientHello).
    pub fn empty() -> Self {
        Self { data: Vec::new() }
    }
}

impl Extension for SessionTicket {
    fn extension_type(&self) -> u16 {
        0x0023
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_empty_ticket() {
        let ext = SessionTicket::empty();
        let mut buf = Vec::new();
        ext.encode(&mut buf);
        // type(2) + length(2) with zero-length payload
        assert_eq!(buf, [0x00, 0x23, 0x00, 0x00]);
    }

    #[test]
    fn test_encode_with_ticket_data() {
        let ext = SessionTicket {
            data: vec![0xAA, 0xBB, 0xCC],
        };
        let mut buf = Vec::new();
        ext.encode(&mut buf);
        assert_eq!(buf, [0x00, 0x23, 0x00, 0x03, 0xAA, 0xBB, 0xCC]);
    }
}
