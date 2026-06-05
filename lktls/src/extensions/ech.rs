//! Encrypted Client Hello (ECH) extension encoding.
//!
//! Supports three extension variants:
//!
//! - **GREASE** ([`EchGreaseExtension`]) — generates a random-looking ECH outer
//!   extension when no real ECHConfig is available.
//!
//! - **Real outer** ([`EchRealOuterExtension`]) — carries the HPKE-encrypted
//!   inner ClientHello in the outer ClientHello.
//!
//! - **Inner** ([`EchInnerExtension`]) — the `type = inner` marker placed in
//!   the ClientHelloInner's extension list (empty payload).
//!
//! ## Wire format (draft-ietf-tls-esni-24)
//!
//! ```text
//! struct {
//!     ECHClientHelloType type;     // 1 byte: 0x00 = outer, 0x01 = inner
//!     select (type) {
//!         case outer:
//!             HpkeSymmetricCipherSuite cipher_suite;  // 4 bytes: kdf_id(2) + aead_id(2)
//!             uint8 config_id;                        // 1 byte
//!             opaque enc<0..2^16-1>;                  // 2-byte length + enc data
//!             opaque payload<1..2^16-1>;              // 2-byte length + payload data
//!         case inner:
//!             Empty;
//!     };
//! } ECHClientHello;
//! ```

use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use super::Extension;
use crate::profile::types::EchGreaseConfig;

/// ECH extension type code-point (0xFE0D = 65037).
const ECH_EXTENSION_TYPE: u16 = 0xFE0D;

/// ECH GREASE extension — generates a random-looking ECH outer payload
/// on each call so that every connection has a unique ECH extension.
pub struct EchGreaseExtension {
    /// KDF algorithm ID (e.g. 0x0001 = HKDF-SHA256).
    kdf_id: u16,
    /// AEAD algorithm ID (e.g. 0x0001 = AES-128-GCM, 0x0003 = ChaCha20Poly1305).
    aead_id: u16,
    /// Length of the `enc` field (typically 32 for X25519).
    enc_length: u16,
    /// Per-connection config_id from the GREASE seed, matching BoringSSL's
    /// `hs->grease_seed[ssl_grease_ech_config_id]`.
    config_id: u8,
    /// Target payload length, randomly chosen per connection.
    payload_length: u16,
}

impl EchGreaseExtension {
    /// Create a new ECH GREASE extension.
    ///
    /// `config_id` should come from `GreaseValues::raw_seed(EchConfigId)` to
    /// match BoringSSL's per-connection GREASE seed behavior.
    pub fn new(config: &EchGreaseConfig, hostname: &str, config_id: u8) -> Self {
        let payload_length = compute_grease_payload_length(config, hostname);
        Self {
            kdf_id: config.kdf_id,
            aead_id: config.aead_id,
            enc_length: config.enc_length,
            config_id,
            payload_length,
        }
    }
}

impl Extension for EchGreaseExtension {
    fn extension_type(&self) -> u16 {
        ECH_EXTENSION_TYPE
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        let rng = SystemRandom::new();

        // type = 0x00 (outer)
        buf.push(0x00);

        // cipher_suite: kdf_id (2 bytes) + aead_id (2 bytes)
        buf.extend_from_slice(&self.kdf_id.to_be_bytes());
        buf.extend_from_slice(&self.aead_id.to_be_bytes());

        // config_id: from per-connection GREASE seed
        buf.push(self.config_id);

        // enc: length (2 bytes) + random bytes
        buf.extend_from_slice(&self.enc_length.to_be_bytes());
        let enc_start = buf.len();
        buf.resize(enc_start + self.enc_length as usize, 0);
        rng.fill(&mut buf[enc_start..]).expect("system RNG failed");

        // payload: length (2 bytes) + random bytes
        buf.extend_from_slice(&self.payload_length.to_be_bytes());
        let payload_start = buf.len();
        buf.resize(payload_start + self.payload_length as usize, 0);
        rng.fill(&mut buf[payload_start..])
            .expect("system RNG failed");
    }
}

/// Compute a randomized GREASE payload length, matching BoringSSL's
/// `setup_ech_grease()`.
///
/// BoringSSL picks a random multiple of 32 in `[min, max]` (inclusive),
/// then adds the AEAD overhead (16 bytes for AES-128-GCM / ChaCha20Poly1305).
///
/// ```text
/// payload_len = 32 * random_size(min/32, max/32) + aead_overhead
/// ```
///
/// For Chrome with `min=128, max=224` this produces one of four discrete
/// values per connection: **{144, 176, 208, 240}**.
fn compute_grease_payload_length(config: &EchGreaseConfig, _hostname: &str) -> u16 {
    let aead_tag_len: u16 = 16;
    let min = config.payload_length_min.unwrap_or(128) as u32;
    let max = config.payload_length_max.unwrap_or(224) as u32;

    let min_units = min / 32;
    let max_units = max / 32;
    let range = max_units - min_units + 1; // e.g. 7 - 4 + 1 = 4

    let rng = SystemRandom::new();
    let mut buf = [0u8; 4];
    rng.fill(&mut buf).expect("system RNG failed");
    let random_unit = min_units + (u32::from_le_bytes(buf) % range);

    (random_unit * 32) as u16 + aead_tag_len
}

/// ECH Real outer extension — carries the HPKE-encrypted inner ClientHello.
///
/// Used when a real ECHConfig is available and the client performs actual
/// ECH encryption.  The wire format is identical to GREASE (type = outer),
/// but `config_id`, `enc`, and `payload` contain real cryptographic data
/// instead of random bytes.
pub struct EchRealOuterExtension {
    /// KDF algorithm ID from the selected cipher suite.
    pub kdf_id: u16,
    /// AEAD algorithm ID from the selected cipher suite.
    pub aead_id: u16,
    /// Config ID from the chosen ECHConfig.
    pub config_id: u8,
    /// HPKE encapsulated key (32 bytes for X25519).
    pub enc: Vec<u8>,
    /// HPKE ciphertext (encrypted EncodedClientHelloInner).
    pub payload: Vec<u8>,
}

impl Extension for EchRealOuterExtension {
    fn extension_type(&self) -> u16 {
        ECH_EXTENSION_TYPE
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        // type = 0x00 (outer) — same as GREASE
        buf.push(0x00);

        // cipher_suite: kdf_id (2 bytes) + aead_id (2 bytes)
        buf.extend_from_slice(&self.kdf_id.to_be_bytes());
        buf.extend_from_slice(&self.aead_id.to_be_bytes());

        // config_id: from ECHConfig
        buf.push(self.config_id);

        // enc: length (2 bytes) + HPKE encapsulated key
        buf.extend_from_slice(&(self.enc.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.enc);

        // payload: length (2 bytes) + HPKE ciphertext
        buf.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload);
    }
}

/// ECH inner extension — the `type = inner` marker in ClientHelloInner.
///
/// This is an empty extension (just 1 byte of payload: 0x01) that is placed
/// in the ClientHelloInner's extension list.  It signals to the server that
/// this is an inner ClientHello.
pub struct EchInnerExtension;

impl Extension for EchInnerExtension {
    fn extension_type(&self) -> u16 {
        ECH_EXTENSION_TYPE
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        // type = 0x01 (inner)
        buf.push(0x01);
    }
}

/// `ech_outer_extensions` extension (type 0xFD00).
///
/// Used in EncodedClientHelloInner to reference extensions from the outer
/// ClientHello, avoiding duplication of large extensions like `key_share`.
///
/// Wire format:
/// ```text
/// ExtensionType OuterExtensions<2..254>;
/// ```
pub struct EchOuterExtensionsExtension {
    /// The extension type codes to reference from the outer ClientHello.
    pub extension_types: Vec<u16>,
}

/// Extension type for `ech_outer_extensions`.
pub const ECH_OUTER_EXTENSIONS_TYPE: u16 = 0xFD00;

impl Extension for EchOuterExtensionsExtension {
    fn extension_type(&self) -> u16 {
        ECH_OUTER_EXTENSIONS_TYPE
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        // Length-prefixed list of extension types (1-byte length prefix).
        let list_len = (self.extension_types.len() * 2) as u8;
        buf.push(list_len);
        for &ext_type in &self.extension_types {
            buf.extend_from_slice(&ext_type.to_be_bytes());
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn chrome_grease_config() -> EchGreaseConfig {
        EchGreaseConfig {
            kdf_id: 0x0001,  // HKDF-SHA256
            aead_id: 0x0001, // AES-128-GCM
            enc_length: 32,
            payload_length_min: Some(128),
            payload_length_max: Some(224),
        }
    }

    fn firefox_grease_config() -> EchGreaseConfig {
        EchGreaseConfig {
            kdf_id: 0x0001,  // HKDF-SHA256
            aead_id: 0x0003, // ChaCha20Poly1305
            enc_length: 32,
            payload_length_min: Some(128),
            payload_length_max: Some(240),
        }
    }

    #[test]
    fn test_ech_grease_encodes_valid_structure() {
        let config = chrome_grease_config();
        let ext = EchGreaseExtension::new(&config, "example.com", 0x42);

        let mut buf = Vec::new();
        ext.encode(&mut buf);

        // Minimum size: header(4) + type(1) + cipher_suite(4) + config_id(1)
        //             + enc_len(2) + enc(32) + payload_len(2) + payload(>=128+16)
        assert!(buf.len() > 4 + 1 + 4 + 1 + 2 + 32 + 2 + 128);

        // Extension type should be 0xFE0D
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 0xFE0D);

        // After the 4-byte header: type should be 0x00 (outer)
        assert_eq!(buf[4], 0x00);

        // kdf_id = 0x0001
        assert_eq!(u16::from_be_bytes([buf[5], buf[6]]), 0x0001);
        // aead_id = 0x0001
        assert_eq!(u16::from_be_bytes([buf[7], buf[8]]), 0x0001);

        // enc length should be 32
        let enc_len = u16::from_be_bytes([buf[10], buf[11]]);
        assert_eq!(enc_len, 32);
    }

    #[test]
    fn test_ech_grease_produces_different_bytes_each_call() {
        let config = chrome_grease_config();

        let mut buf1 = Vec::new();
        EchGreaseExtension::new(&config, "example.com", 0x01).encode(&mut buf1);

        let mut buf2 = Vec::new();
        // Same config_id as buf1 so any difference can only come from the
        // randomized GREASE fields (enc / payload / payload length), not the
        // 1-byte config_id.
        EchGreaseExtension::new(&config, "example.com", 0x01).encode(&mut buf2);

        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_ech_grease_firefox_config() {
        let config = firefox_grease_config();
        let ext = EchGreaseExtension::new(&config, "example.com", 0x7F);

        let mut buf = Vec::new();
        ext.encode(&mut buf);

        // aead_id = 0x0003 (ChaCha20Poly1305)
        assert_eq!(u16::from_be_bytes([buf[7], buf[8]]), 0x0003);
    }

    #[test]
    fn test_payload_length_is_valid_discrete_value() {
        let config = chrome_grease_config();
        let valid_lengths: Vec<u16> = vec![144, 176, 208, 240];

        for _ in 0..100 {
            let len = compute_grease_payload_length(&config, "example.com");
            assert!(
                valid_lengths.contains(&len),
                "payload length {} is not one of {:?}",
                len,
                valid_lengths
            );
        }
    }

    #[test]
    fn test_payload_length_is_random() {
        let config = chrome_grease_config();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            seen.insert(compute_grease_payload_length(&config, "example.com"));
        }
        assert!(
            seen.len() > 1,
            "payload length should vary across calls, got only {:?}",
            seen
        );
    }

    #[test]
    fn test_ech_real_outer_extension_wire_format() {
        let ext = EchRealOuterExtension {
            kdf_id: 0x0001,
            aead_id: 0x0001,
            config_id: 42,
            enc: vec![0xAA; 32],
            payload: vec![0xBB; 128],
        };

        let mut buf = Vec::new();
        ext.encode(&mut buf);

        // Extension type = 0xFE0D
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 0xFE0D);

        // type = 0x00 (outer)
        assert_eq!(buf[4], 0x00);

        // kdf_id
        assert_eq!(u16::from_be_bytes([buf[5], buf[6]]), 0x0001);
        // aead_id
        assert_eq!(u16::from_be_bytes([buf[7], buf[8]]), 0x0001);

        // config_id
        assert_eq!(buf[9], 42);

        // enc length
        assert_eq!(u16::from_be_bytes([buf[10], buf[11]]), 32);
        // enc data
        assert_eq!(&buf[12..44], &[0xAA; 32]);

        // payload length
        assert_eq!(u16::from_be_bytes([buf[44], buf[45]]), 128);
        // payload data
        assert_eq!(&buf[46..174], &[0xBB; 128]);
    }

    #[test]
    fn test_ech_inner_extension_wire_format() {
        let ext = EchInnerExtension;
        let mut buf = Vec::new();
        ext.encode(&mut buf);

        // Extension type = 0xFE0D
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 0xFE0D);
        // Extension length = 1
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 1);
        // type = 0x01 (inner)
        assert_eq!(buf[4], 0x01);
        assert_eq!(buf.len(), 5);
    }

    #[test]
    fn test_ech_outer_extensions_extension_wire_format() {
        let ext = EchOuterExtensionsExtension {
            extension_types: vec![51, 10, 13], // key_share, groups, sig_algs
        };
        let mut buf = Vec::new();
        ext.encode(&mut buf);

        // Extension type = 0xFD00
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 0xFD00);
        // Payload starts at offset 4
        // First byte: list length = 6 (3 * 2)
        assert_eq!(buf[4], 6);
        // Extension types
        assert_eq!(u16::from_be_bytes([buf[5], buf[6]]), 51);
        assert_eq!(u16::from_be_bytes([buf[7], buf[8]]), 10);
        assert_eq!(u16::from_be_bytes([buf[9], buf[10]]), 13);
    }

    #[test]
    fn test_real_outer_same_wire_format_as_grease() {
        // Verify that a real ECH outer extension has the SAME wire format
        // structure as a GREASE extension (F1 — fingerprint indistinguishability).
        let grease_config = chrome_grease_config();
        let grease_ext = EchGreaseExtension::new(&grease_config, "example.com", 7);
        let mut grease_buf = Vec::new();
        grease_ext.encode(&mut grease_buf);

        let real_ext = EchRealOuterExtension {
            kdf_id: 0x0001,
            aead_id: 0x0001,
            config_id: 7,
            enc: vec![0x42; 32],
            payload: vec![0x42; 160],
        };
        let mut real_buf = Vec::new();
        real_ext.encode(&mut real_buf);

        // Both should have the same structure:
        // [0..2] = extension type 0xFE0D
        assert_eq!(grease_buf[0..2], real_buf[0..2]);
        // [4] = type 0x00 (outer)
        assert_eq!(grease_buf[4], 0x00);
        assert_eq!(real_buf[4], 0x00);
        // [5..7] = kdf_id
        assert_eq!(grease_buf[5..7], real_buf[5..7]);
        // [7..9] = aead_id
        assert_eq!(grease_buf[7..9], real_buf[7..9]);
        // Both have enc_length = 32 at [10..12]
        assert_eq!(u16::from_be_bytes([grease_buf[10], grease_buf[11]]), 32);
        assert_eq!(u16::from_be_bytes([real_buf[10], real_buf[11]]), 32);
    }
}
