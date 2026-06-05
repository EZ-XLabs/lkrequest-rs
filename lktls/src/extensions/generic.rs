//! Generic / opaque extension encoder.
//!
//! Used for extensions that are included with fixed raw bytes (e.g.
//! `extended_master_secret`, `renegotiation_info`, `session_ticket`,
//! `ec_point_formats`, `status_request`, `signed_certificate_timestamp`,
//! `psk_key_exchange_modes`, `delegated_credentials`, `record_size_limit`,
//! or any unknown / future extension).

use super::Extension;

/// A generic extension carrying an opaque byte payload.
///
/// This can represent any TLS extension by its type code and raw bytes.
pub struct GenericExtension {
    /// Extension type code-point.
    pub ext_type: u16,
    /// Raw payload bytes (without the type/length header).
    pub payload: Vec<u8>,
}

impl GenericExtension {
    /// Create a new generic extension.
    pub fn new(ext_type: u16, payload: Vec<u8>) -> Self {
        Self { ext_type, payload }
    }

    /// Create an extension with an empty payload.
    ///
    /// Useful for extensions like `extended_master_secret` (0x0017) and
    /// `session_ticket` (0x0023) that are sent with zero-length data in
    /// the ClientHello.
    pub fn empty(ext_type: u16) -> Self {
        Self {
            ext_type,
            payload: Vec::new(),
        }
    }
}

impl Extension for GenericExtension {
    fn extension_type(&self) -> u16 {
        self.ext_type
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.payload);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_extension_type() {
        let ext = GenericExtension::new(0x0017, vec![]);
        assert_eq!(ext.extension_type(), 0x0017);
    }

    #[test]
    fn generic_with_payload() {
        let payload = vec![0x01, 0x02, 0x03];
        let ext = GenericExtension::new(0x00FF, payload.clone());
        let mut buf = Vec::new();
        ext.encode_payload(&mut buf);

        assert_eq!(buf, payload);
    }

    #[test]
    fn generic_empty_payload() {
        let ext = GenericExtension::empty(0x0017);
        let mut buf = Vec::new();
        ext.encode_payload(&mut buf);

        assert!(buf.is_empty());
    }

    #[test]
    fn generic_full_encode_empty() {
        let ext = GenericExtension::empty(0x0017);
        let mut buf = Vec::new();
        ext.encode(&mut buf);

        // type = 0x0017
        assert_eq!(&buf[0..2], &[0x00, 0x17]);
        // length = 0
        assert_eq!(&buf[2..4], &[0x00, 0x00]);
        assert_eq!(buf.len(), 4);
    }

    #[test]
    fn generic_full_encode_with_data() {
        let ext = GenericExtension::new(0x0023, vec![0xAA, 0xBB]);
        let mut buf = Vec::new();
        ext.encode(&mut buf);

        // type = 0x0023
        assert_eq!(&buf[0..2], &[0x00, 0x23]);
        // length = 2
        assert_eq!(&buf[2..4], &[0x00, 0x02]);
        // payload
        assert_eq!(&buf[4..6], &[0xAA, 0xBB]);
    }
}
