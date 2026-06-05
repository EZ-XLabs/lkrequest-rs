//! GREASE (Generate Random Extensions And Sustain Extensibility) helpers.
//!
//! GREASE values follow the pattern `0x?a?a` where `?` is the same nibble,
//! e.g. 0x0a0a, 0x1a1a, 0x2a2a, ... 0xfafa.

use super::Extension;

/// Generates a random GREASE value.
///
/// GREASE values follow the pattern `0x?a?a` where `?` is the same hex digit:
/// `0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa`.
pub fn random_grease_value() -> u16 {
    seed_to_grease(rand_u8())
}

/// Convert a seed byte to a GREASE value using BoringSSL's high-nibble rule.
fn seed_to_grease(seed: u8) -> u16 {
    let byte = ((seed & 0xf0) | 0x0a) as u16;
    byte | (byte << 8)
}

/// Simple non-cryptographic random byte (sufficient for GREASE).
fn rand_u8() -> u8 {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut buf = [0u8; 1];
    rng.fill(&mut buf).expect("system RNG failed");
    buf[0]
}

/// Per-connection GREASE seeds, mirroring BoringSSL's `ssl_grease_index_t`.
///
/// Each GREASE position (cipher, group, extension1, extension2, version,
/// ticket_extension, ech_config_id) gets its own independent random value,
/// generated once per connection and reused across HelloRetryRequest retries.
#[derive(Debug, Clone)]
pub struct GreaseValues {
    seeds: [u8; 7],
}

#[repr(usize)]
#[derive(Clone, Copy)]
pub enum GreaseIndex {
    Cipher = 0,
    Group = 1,
    Extension1 = 2,
    Extension2 = 3,
    Version = 4,
    TicketExtension = 5,
    EchConfigId = 6,
}

impl Default for GreaseValues {
    fn default() -> Self {
        Self::new()
    }
}

impl GreaseValues {
    /// Generate a fresh set of GREASE seeds for a new connection.
    pub fn new() -> Self {
        use aws_lc_rs::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut seeds = [0u8; 7];
        rng.fill(&mut seeds).expect("system RNG failed");
        Self { seeds }
    }

    /// Get the GREASE value for a specific position.
    pub fn get(&self, index: GreaseIndex) -> u16 {
        let mut value = seed_to_grease(self.seeds[index as usize]);
        if matches!(index, GreaseIndex::Extension2)
            && value == seed_to_grease(self.seeds[GreaseIndex::Extension1 as usize])
        {
            value ^= 0x1010;
        }
        value
    }

    /// Get the raw seed byte for a specific position.
    ///
    /// Used for ECH GREASE `config_id`, which needs the raw byte
    /// rather than a converted GREASE value (matching BoringSSL's
    /// `hs->grease_seed[ssl_grease_ech_config_id]`).
    pub fn raw_seed(&self, index: GreaseIndex) -> u8 {
        self.seeds[index as usize]
    }
}

/// A GREASE extension with a random type and configurable payload length.
///
/// BoringSSL uses two GREASE extensions as "bookends" around the real
/// extensions.  They differ in payload size:
///
/// - **Extension1** (first bookend): **empty** payload (0 bytes)
/// - **Extension2** (last bookend): **1 byte** payload (`0x00`)
pub struct GreaseExtension {
    /// The GREASE type value (e.g. 0x0a0a).
    pub grease_value: u16,
    /// Payload length in bytes (0 = empty, 1 = single zero byte).
    payload_len: usize,
}

impl GreaseExtension {
    /// Create a new GREASE extension with a fresh random value and 1-byte payload.
    pub fn new() -> Self {
        Self {
            grease_value: random_grease_value(),
            payload_len: 1,
        }
    }

    /// Create a GREASE extension with a specific value and 1-byte payload.
    pub fn with_value(value: u16) -> Self {
        Self {
            grease_value: value,
            payload_len: 1,
        }
    }

    /// Create a GREASE extension with a specific value and payload length.
    ///
    /// Mirrors BoringSSL's `add_padding_extension(cbb, grease_value, len)`.
    pub fn with_value_and_len(value: u16, payload_len: usize) -> Self {
        Self {
            grease_value: value,
            payload_len,
        }
    }
}

impl Default for GreaseExtension {
    fn default() -> Self {
        Self::new()
    }
}

impl Extension for GreaseExtension {
    fn extension_type(&self) -> u16 {
        self.grease_value
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        for _ in 0..self.payload_len {
            buf.push(0x00);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify a value matches the 0x?A?A pattern where ? is the same nibble.
    fn is_valid_grease(v: u16) -> bool {
        let hi = (v >> 8) as u8;
        let lo = (v & 0xFF) as u8;
        // Low nibble of each byte must be 0xA
        if (hi & 0x0F) != 0x0A || (lo & 0x0F) != 0x0A {
            return false;
        }
        // High nibble of each byte must be the same
        (hi >> 4) == (lo >> 4)
    }

    #[test]
    fn random_grease_value_matches_pattern() {
        for _ in 0..100 {
            let v = random_grease_value();
            assert!(
                is_valid_grease(v),
                "GREASE value 0x{:04x} does not match 0x?A?A pattern",
                v
            );
        }
    }

    #[test]
    fn seed_to_grease_uses_boringssl_high_nibble() {
        assert_eq!(seed_to_grease(0x00), 0x0a0a);
        assert_eq!(seed_to_grease(0x0f), 0x0a0a);
        assert_eq!(seed_to_grease(0x10), 0x1a1a);
        assert_eq!(seed_to_grease(0xf0), 0xfafa);
    }

    #[test]
    fn extension2_grease_is_xored_when_it_matches_extension1() {
        let grease = GreaseValues {
            seeds: [0, 0, 0x20, 0x2f, 0, 0, 0],
        };
        assert_eq!(grease.get(GreaseIndex::Extension1), 0x2a2a);
        assert_eq!(grease.get(GreaseIndex::Extension2), 0x3a3a);
    }

    #[test]
    fn known_grease_values() {
        let known = [
            0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa,
            0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
        ];
        for &v in &known {
            assert!(is_valid_grease(v), "0x{:04x} should be valid GREASE", v);
        }
    }

    #[test]
    fn grease_extension_with_value() {
        let ext = GreaseExtension::with_value(0x2a2a);
        assert_eq!(ext.extension_type(), 0x2a2a);
    }

    #[test]
    fn grease_extension_new_is_valid() {
        let ext = GreaseExtension::new();
        assert!(
            is_valid_grease(ext.grease_value),
            "GreaseExtension::new() produced invalid value 0x{:04x}",
            ext.grease_value
        );
    }

    #[test]
    fn grease_encode_payload_is_single_zero() {
        let ext = GreaseExtension::with_value(0x0a0a);
        let mut buf = Vec::new();
        ext.encode_payload(&mut buf);

        assert_eq!(buf, vec![0x00]);
    }

    #[test]
    fn grease_extension1_empty_payload() {
        let ext = GreaseExtension::with_value_and_len(0x2a2a, 0);
        let mut buf = Vec::new();
        ext.encode(&mut buf);

        // type = 0x2a2a
        assert_eq!(&buf[0..2], &[0x2a, 0x2a]);
        // length = 0
        assert_eq!(&buf[2..4], &[0x00, 0x00]);
        assert_eq!(buf.len(), 4);
    }

    #[test]
    fn grease_extension2_one_byte_payload() {
        let ext = GreaseExtension::with_value_and_len(0x3a3a, 1);
        let mut buf = Vec::new();
        ext.encode(&mut buf);

        // type = 0x3a3a
        assert_eq!(&buf[0..2], &[0x3a, 0x3a]);
        // length = 1
        assert_eq!(&buf[2..4], &[0x00, 0x01]);
        // payload = 0x00
        assert_eq!(buf[4], 0x00);
        assert_eq!(buf.len(), 5);
    }

    #[test]
    fn grease_default_is_valid() {
        let ext = GreaseExtension::default();
        assert!(is_valid_grease(ext.grease_value));
    }
}
