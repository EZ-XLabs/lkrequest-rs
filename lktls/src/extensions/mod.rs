//! TLS extension encoding and decoding.
//!
//! Each extension implements the [`Extension`] trait, which provides a uniform
//! interface for the ClientHello builder to emit extension bytes in the exact
//! order specified by the fingerprint profile.
//!
//! ## Supported Extensions
//!
//! | Extension | Module | Type Code |
//! |-----------|--------|-----------|
//! | Server Name Indication (SNI) | [`sni`] | 0x0000 |
//! | Status Request (OCSP) | [`status_request`] | 0x0005 |
//! | Supported Groups | [`supported_groups`] | 0x000A |
//! | EC Point Formats | [`ec_point_formats`] | 0x000B |
//! | Signature Algorithms | [`signature_algorithms`] | 0x000D |
//! | ALPN | [`alpn`] | 0x0010 |
//! | SCT (Signed Certificate Timestamp) | [`sct`] | 0x0012 |
//! | Padding | [`padding`] | 0x0015 |
//! | Encrypt-Then-MAC | [`encrypt_then_mac`] | 0x0016 |
//! | Extended Master Secret | [`extended_master_secret`] | 0x0017 |
//! | Compress Certificate | [`compress_certificate`] | 0x001B |
//! | Record Size Limit | [`record_size_limit`] | 0x001C |
//! | Delegated Credentials | [`delegated_credentials`] | 0x0022 |
//! | Session Ticket | [`session_ticket`] | 0x0023 |
//! | Pre-Shared Key | [`pre_shared_key`] | 0x0029 |
//! | Supported Versions | [`supported_versions`] | 0x002B |
//! | PSK Key Exchange Modes | [`psk_key_exchange_modes`] | 0x002D |
//! | Key Share | [`key_share`] | 0x0033 |
//! | ALPS | [`alps`] | 0x4469 / 0x44CD |
//! | Renegotiation Info | [`renegotiation_info`] | 0xFF01 |
//! | ECH (Encrypted Client Hello) | [`ech`] | 0xFE0D |
//! | GREASE | [`grease`] | 0x?A?A |
//! | Generic (raw bytes) | [`generic`] | any |

pub mod alpn;
pub mod alps;
pub mod compress_certificate;
pub mod delegated_credentials;
pub mod ec_point_formats;
pub mod ech;
pub mod encrypt_then_mac;
pub mod extended_master_secret;
pub mod generic;
pub mod grease;
pub mod key_share;
pub mod padding;
pub mod pre_shared_key;
pub mod psk_key_exchange_modes;
pub mod quic_transport_params;
pub mod record_size_limit;
pub mod renegotiation_info;
pub mod sct;
pub mod session_ticket;
pub mod signature_algorithms;
pub mod sni;
pub mod status_request;
pub mod supported_groups;
pub mod supported_versions;

/// Trait that all TLS extension encoders must implement.
///
/// The ClientHello builder iterates over the profile's extension list and
/// calls `encode` for each one, emitting the 4-byte extension header
/// (type + length) followed by the payload.
pub trait Extension {
    /// The 2-byte extension type code-point (e.g. `0x0000` for SNI).
    fn extension_type(&self) -> u16;

    /// Encode the extension **payload** (without the type/length header)
    /// into `buf`.  The caller is responsible for prepending the header.
    fn encode_payload(&self, buf: &mut Vec<u8>);

    /// Convenience: encode the full extension (type + length + payload).
    fn encode(&self, buf: &mut Vec<u8>) {
        let type_code = self.extension_type();
        // Reserve space for type (2) + length (2)
        let header_pos = buf.len();
        buf.extend_from_slice(&[0u8; 4]);

        let payload_start = buf.len();
        self.encode_payload(buf);
        let payload_len = buf.len() - payload_start;

        // Fill in header
        buf[header_pos..header_pos + 2].copy_from_slice(&type_code.to_be_bytes());
        buf[header_pos + 2..header_pos + 4].copy_from_slice(&(payload_len as u16).to_be_bytes());
    }
}
