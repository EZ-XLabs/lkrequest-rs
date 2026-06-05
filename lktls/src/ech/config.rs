//! ECHConfigList binary parser (draft-ietf-tls-esni-24 Section 4).
//!
//! Parses the wire-format ECHConfigList (obtained from DNS HTTPS records,
//! `ech_retry_configs`, or manual configuration) into structured [`EchConfig`]
//! values that drive the HPKE encryption in [`super::hpke`].

use crate::error::{Result, TlsError};

/// KEM identifier for DHKEM(X25519, HKDF-SHA256) — the only KEM we support.
pub const KEM_X25519_HKDF_SHA256: u16 = 0x0020;

/// ECH version code-point (same as the extension type).
pub const ECH_CONFIG_VERSION: u16 = 0xFE0D;

/// An HPKE symmetric cipher suite (KDF + AEAD).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HpkeSymmetricCipherSuite {
    pub kdf_id: u16,
    pub aead_id: u16,
}

/// A parsed ECHConfig structure.
#[derive(Debug, Clone)]
pub struct EchConfig {
    /// ECH version (must be 0xFE0D for the current draft).
    pub version: u16,
    /// Config identifier — used in the outer ECH extension.
    pub config_id: u8,
    /// HPKE KEM algorithm identifier.
    pub kem_id: u16,
    /// HPKE public key (32 bytes for X25519).
    pub public_key: Vec<u8>,
    /// List of supported HPKE cipher suites (KDF + AEAD pairs).
    pub cipher_suites: Vec<HpkeSymmetricCipherSuite>,
    /// Maximum backend server name length (for padding computation).
    pub maximum_name_length: u8,
    /// The DNS name of the client-facing server (used as outer SNI).
    pub public_name: String,
    /// The raw bytes of this single ECHConfig (version + length + contents).
    /// Used to construct the HPKE `info` parameter.
    pub raw_config: Vec<u8>,
}

/// Parse an ECHConfigList (wire-format) into a list of [`EchConfig`] values.
///
/// The wire format is:
/// ```text
/// ECHConfig ECHConfigList<4..2^16-1>;
///
/// struct {
///     uint16 version;
///     uint16 length;
///     select (version) {
///         case 0xfe0d: ECHConfigContents contents;
///     }
/// } ECHConfig;
/// ```
pub fn parse_ech_config_list(data: &[u8]) -> Result<Vec<EchConfig>> {
    if data.len() < 2 {
        return Err(TlsError::HandshakeFailure(
            "ECHConfigList too short".to_string(),
        ));
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return Err(TlsError::HandshakeFailure(format!(
            "ECHConfigList length mismatch: declared {list_len}, available {}",
            data.len() - 2
        )));
    }

    let mut configs = Vec::new();
    let mut pos = 2; // skip the outer length prefix
    let end = 2 + list_len;

    while pos < end {
        if pos + 4 > end {
            return Err(TlsError::HandshakeFailure(
                "ECHConfig truncated (header)".to_string(),
            ));
        }

        let version = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let config_data_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let config_end = pos + 4 + config_data_len;

        if config_end > end {
            return Err(TlsError::HandshakeFailure(
                "ECHConfig length exceeds list boundary".to_string(),
            ));
        }

        // Save the raw bytes for this single ECHConfig (version + length + contents).
        let raw_config = data[pos..config_end].to_vec();

        if version != ECH_CONFIG_VERSION {
            // Unknown version — skip per spec.
            tracing::debug!("Skipping ECHConfig with unsupported version 0x{version:04x}");
            pos = config_end;
            continue;
        }

        // Parse ECHConfigContents from data[pos+4 .. config_end].
        match parse_ech_config_contents(&data[pos + 4..config_end], raw_config) {
            Ok(Some(config)) => configs.push(config),
            Ok(None) => {
                tracing::debug!("Skipping unsupported ECHConfig");
            }
            Err(e) => {
                tracing::warn!("Failed to parse ECHConfig: {e}");
            }
        }

        pos = config_end;
    }

    Ok(configs)
}

/// Select the best ECHConfig from a parsed list.
///
/// Picks the first config that uses a KEM and cipher suite we support:
/// - KEM: DHKEM(X25519, HKDF-SHA256) = 0x0020
/// - KDF: HKDF-SHA256 = 0x0001
/// - AEAD: AES-128-GCM (0x0001) or ChaCha20Poly1305 (0x0003)
///
/// When `preferred_aead` is provided, configs offering that AEAD are
/// preferred (for fingerprint consistency with the browser profile).
pub fn select_ech_config(
    configs: &[EchConfig],
    preferred_aead: Option<u16>,
) -> Option<(&EchConfig, HpkeSymmetricCipherSuite)> {
    // First pass: try to find a config with the preferred AEAD.
    if let Some(pref) = preferred_aead {
        for config in configs {
            if config.kem_id != KEM_X25519_HKDF_SHA256 {
                continue;
            }
            for cs in &config.cipher_suites {
                if cs.kdf_id == 0x0001 && cs.aead_id == pref {
                    return Some((config, *cs));
                }
            }
        }
    }

    // Second pass: any supported cipher suite.
    for config in configs {
        if config.kem_id != KEM_X25519_HKDF_SHA256 {
            continue;
        }
        for cs in &config.cipher_suites {
            if cs.kdf_id == 0x0001 && is_supported_aead(cs.aead_id) {
                return Some((config, *cs));
            }
        }
    }

    None
}

fn is_supported_aead(aead_id: u16) -> bool {
    // 0x0001 = AES-128-GCM, 0x0003 = ChaCha20Poly1305
    // 0x0002 (AES-256-GCM) is excluded — not implemented in our HPKE backend
    // and not used by Chrome/BoringSSL.
    matches!(aead_id, 0x0001 | 0x0003)
}

/// Parse ECHConfigContents from the content bytes (after version + length).
///
/// Returns `Ok(None)` if the config has unsupported mandatory extensions.
fn parse_ech_config_contents(data: &[u8], raw_config: Vec<u8>) -> Result<Option<EchConfig>> {
    let mut pos = 0;
    let len = data.len();

    // config_id: uint8
    if pos >= len {
        return Err(parse_err("config_id missing"));
    }
    let config_id = data[pos];
    pos += 1;

    // kem_id: uint16
    if pos + 2 > len {
        return Err(parse_err("kem_id truncated"));
    }
    let kem_id = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // public_key: opaque<1..2^16-1>
    if pos + 2 > len {
        return Err(parse_err("public_key length truncated"));
    }
    let pk_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pk_len == 0 || pos + pk_len > len {
        return Err(parse_err("public_key data truncated"));
    }
    let public_key = data[pos..pos + pk_len].to_vec();
    pos += pk_len;

    // cipher_suites: HpkeSymmetricCipherSuite<4..2^16-4>
    if pos + 2 > len {
        return Err(parse_err("cipher_suites length truncated"));
    }
    let cs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if cs_len == 0 || !cs_len.is_multiple_of(4) || pos + cs_len > len {
        return Err(parse_err("cipher_suites data invalid"));
    }
    let mut cipher_suites = Vec::with_capacity(cs_len / 4);
    let cs_end = pos + cs_len;
    while pos < cs_end {
        let kdf_id = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let aead_id = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        cipher_suites.push(HpkeSymmetricCipherSuite { kdf_id, aead_id });
        pos += 4;
    }

    // maximum_name_length: uint8
    if pos >= len {
        return Err(parse_err("maximum_name_length missing"));
    }
    let maximum_name_length = data[pos];
    pos += 1;

    // public_name: opaque<1..255>
    if pos >= len {
        return Err(parse_err("public_name length missing"));
    }
    let pn_len = data[pos] as usize;
    pos += 1;
    if pn_len == 0 || pos + pn_len > len {
        return Err(parse_err("public_name data truncated"));
    }
    let public_name = String::from_utf8_lossy(&data[pos..pos + pn_len]).to_string();
    pos += pn_len;

    // extensions: ECHConfigExtension<0..2^16-1>
    if pos + 2 > len {
        return Err(parse_err("extensions length truncated"));
    }
    let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pos + ext_len > len {
        return Err(parse_err("extensions data truncated"));
    }

    // Check for unsupported mandatory extensions (high bit set).
    let ext_end = pos + ext_len;
    let mut ext_pos = pos;
    while ext_pos < ext_end {
        if ext_pos + 4 > ext_end {
            return Err(parse_err("extension header truncated"));
        }
        let ext_type = u16::from_be_bytes([data[ext_pos], data[ext_pos + 1]]);
        let ext_data_len = u16::from_be_bytes([data[ext_pos + 2], data[ext_pos + 3]]) as usize;
        ext_pos += 4;
        if ext_pos + ext_data_len > ext_end {
            return Err(parse_err("extension data truncated"));
        }
        if ext_type & 0x8000 != 0 {
            // Mandatory extension we don't understand — skip this config.
            tracing::debug!("ECHConfig has unsupported mandatory extension 0x{ext_type:04x}");
            return Ok(None);
        }
        ext_pos += ext_data_len;
    }

    Ok(Some(EchConfig {
        version: ECH_CONFIG_VERSION,
        config_id,
        kem_id,
        public_key,
        cipher_suites,
        maximum_name_length,
        public_name,
        raw_config,
    }))
}

fn parse_err(msg: &str) -> TlsError {
    TlsError::HandshakeFailure(format!("ECHConfig parse error: {msg}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal ECHConfigList with one config for testing.
    fn build_test_ech_config_list(config_id: u8, public_name: &str, max_name_len: u8) -> Vec<u8> {
        // Public key: 32 random bytes (fake X25519 key)
        let public_key = [0x42u8; 32];
        // Cipher suites: HKDF-SHA256 + AES-128-GCM
        let cipher_suites: &[(u16, u16)] = &[(0x0001, 0x0001)];

        let mut contents = Vec::new();
        // config_id
        contents.push(config_id);
        // kem_id
        contents.extend_from_slice(&KEM_X25519_HKDF_SHA256.to_be_bytes());
        // public_key length + data
        contents.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
        contents.extend_from_slice(&public_key);
        // cipher_suites length + data
        let cs_len = (cipher_suites.len() * 4) as u16;
        contents.extend_from_slice(&cs_len.to_be_bytes());
        for (kdf, aead) in cipher_suites {
            contents.extend_from_slice(&kdf.to_be_bytes());
            contents.extend_from_slice(&aead.to_be_bytes());
        }
        // maximum_name_length
        contents.push(max_name_len);
        // public_name
        let pn_bytes = public_name.as_bytes();
        contents.push(pn_bytes.len() as u8);
        contents.extend_from_slice(pn_bytes);
        // extensions (empty)
        contents.extend_from_slice(&0u16.to_be_bytes());

        // ECHConfig = version(2) + length(2) + contents
        let mut config = Vec::new();
        config.extend_from_slice(&ECH_CONFIG_VERSION.to_be_bytes());
        config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        config.extend_from_slice(&contents);

        // ECHConfigList = list_length(2) + configs
        let mut list = Vec::new();
        list.extend_from_slice(&(config.len() as u16).to_be_bytes());
        list.extend_from_slice(&config);

        list
    }

    #[test]
    fn test_parse_minimal_ech_config_list() {
        let data = build_test_ech_config_list(42, "cloudflare-ech.com", 0);
        let configs = parse_ech_config_list(&data).unwrap();

        assert_eq!(configs.len(), 1);
        let c = &configs[0];
        assert_eq!(c.version, ECH_CONFIG_VERSION);
        assert_eq!(c.config_id, 42);
        assert_eq!(c.kem_id, KEM_X25519_HKDF_SHA256);
        assert_eq!(c.public_key.len(), 32);
        assert_eq!(c.cipher_suites.len(), 1);
        assert_eq!(c.cipher_suites[0].kdf_id, 0x0001);
        assert_eq!(c.cipher_suites[0].aead_id, 0x0001);
        assert_eq!(c.maximum_name_length, 0);
        assert_eq!(c.public_name, "cloudflare-ech.com");
    }

    #[test]
    fn test_select_ech_config_preferred_aead() {
        // Build a config with two cipher suites: AES-128-GCM and ChaCha20Poly1305.
        let public_key = [0x42u8; 32];
        let mut contents = Vec::new();
        contents.push(7); // config_id
        contents.extend_from_slice(&KEM_X25519_HKDF_SHA256.to_be_bytes());
        contents.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
        contents.extend_from_slice(&public_key);
        // 2 cipher suites = 8 bytes
        contents.extend_from_slice(&8u16.to_be_bytes());
        contents.extend_from_slice(&0x0001u16.to_be_bytes()); // HKDF-SHA256
        contents.extend_from_slice(&0x0001u16.to_be_bytes()); // AES-128-GCM
        contents.extend_from_slice(&0x0001u16.to_be_bytes()); // HKDF-SHA256
        contents.extend_from_slice(&0x0003u16.to_be_bytes()); // ChaCha20Poly1305
        contents.push(32); // max_name_length
        let pn = b"example.com";
        contents.push(pn.len() as u8);
        contents.extend_from_slice(pn);
        contents.extend_from_slice(&0u16.to_be_bytes()); // no extensions

        let mut config_bytes = Vec::new();
        config_bytes.extend_from_slice(&ECH_CONFIG_VERSION.to_be_bytes());
        config_bytes.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        config_bytes.extend_from_slice(&contents);

        let mut list = Vec::new();
        list.extend_from_slice(&(config_bytes.len() as u16).to_be_bytes());
        list.extend_from_slice(&config_bytes);

        let configs = parse_ech_config_list(&list).unwrap();
        assert_eq!(configs.len(), 1);

        // Prefer ChaCha20Poly1305 (Firefox style)
        let (_, cs) = select_ech_config(&configs, Some(0x0003)).unwrap();
        assert_eq!(cs.aead_id, 0x0003);

        // Prefer AES-128-GCM (Chrome style)
        let (_, cs) = select_ech_config(&configs, Some(0x0001)).unwrap();
        assert_eq!(cs.aead_id, 0x0001);

        // No preference — pick first supported
        let (_, cs) = select_ech_config(&configs, None).unwrap();
        assert_eq!(cs.aead_id, 0x0001);
    }

    #[test]
    fn test_skip_unsupported_version() {
        let mut data = Vec::new();
        // One config with unknown version 0xFFFF
        let fake_contents = [0u8; 10];
        let mut config = Vec::new();
        config.extend_from_slice(&0xFFFFu16.to_be_bytes());
        config.extend_from_slice(&(fake_contents.len() as u16).to_be_bytes());
        config.extend_from_slice(&fake_contents);

        data.extend_from_slice(&(config.len() as u16).to_be_bytes());
        data.extend_from_slice(&config);

        let configs = parse_ech_config_list(&data).unwrap();
        assert!(configs.is_empty());
    }

    #[test]
    fn test_raw_config_preserved() {
        let data = build_test_ech_config_list(1, "test.example", 16);
        let configs = parse_ech_config_list(&data).unwrap();
        assert_eq!(configs.len(), 1);

        // raw_config should start with version bytes
        let raw = &configs[0].raw_config;
        assert_eq!(raw[0], 0xFE);
        assert_eq!(raw[1], 0x0D);
        // It should be the full ECHConfig (not the list wrapper)
        assert!(raw.len() > 4);
    }
}
