//! TLS ClientHello parser — extract fingerprint data from raw ClientHello bytes.
//!
//! Parses raw TLS record / handshake bytes into a structured [`ParsedClientHello`],
//! then builds a [`TlsProfile`] from the parsed data.

use crate::error::ParseError;
use lktls::profile::types::{
    DelegatedCredentialConfig, EchGreaseConfig, EchMode, ExtensionSource, ExtensionSpec,
    GreaseConfig, PaddingStrategy, TlsClientHelloStyle, TlsProfile, TlsVersion,
};

// ─────────────────────────────────────────────────────────────────────────────
// Parsed types
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed TLS ClientHello message.
#[derive(Debug, Clone)]
pub struct ParsedClientHello {
    /// Protocol version from the ClientHello header (typically 0x0303).
    pub protocol_version: u16,
    /// Length of the session ID field.
    pub session_id_length: u8,
    /// Ordered list of cipher suite code-points.
    pub cipher_suites: Vec<u16>,
    /// Compression methods (typically `[0x00]`).
    pub compression_methods: Vec<u8>,
    /// Ordered list of TLS extensions.
    pub extensions: Vec<ParsedExtension>,
}

/// A single TLS extension from a ClientHello.
#[derive(Debug, Clone)]
pub struct ParsedExtension {
    /// Extension type code-point.
    pub extension_type: u16,
    /// Raw extension payload bytes.
    pub data: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// GREASE helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if `v` is a GREASE value (RFC 8701).
pub fn is_grease_value(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a
}

fn tls_version_from_u16(v: u16) -> TlsVersion {
    match v {
        0x0301 => TlsVersion::Tls10,
        0x0302 => TlsVersion::Tls11,
        0x0303 => TlsVersion::Tls12,
        0x0304 => TlsVersion::Tls13,
        _ => TlsVersion::Tls12,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ClientHello parser
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a TLS ClientHello from raw bytes.
///
/// Accepts either a bare handshake message or a full TLS record (starting with
/// the 5-byte record header `0x16 ...`). The parser auto-detects the format.
///
/// # Errors
///
/// Returns [`ParseError`] if the data is truncated or malformed.
pub fn parse_client_hello(data: &[u8]) -> Result<ParsedClientHello, ParseError> {
    let mut pos = 0;

    // Skip TLS record header if present (0x16 = Handshake)
    if data.len() >= 6 && data[0] == 0x16 {
        pos = 5;
    }

    if pos + 4 > data.len() {
        return Err(ParseError::DataTooShort(
            "data too short for handshake header".into(),
        ));
    }
    if data[pos] != 0x01 {
        return Err(ParseError::UnexpectedValue(format!(
            "expected ClientHello type (0x01), got 0x{:02x}",
            data[pos]
        )));
    }
    pos += 4; // skip HandshakeType(1) + Length(3)

    // Protocol version (2 bytes)
    if pos + 2 > data.len() {
        return Err(ParseError::DataTooShort(
            "data too short for protocol version".into(),
        ));
    }
    let protocol_version = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // Random (32 bytes)
    if pos + 32 > data.len() {
        return Err(ParseError::DataTooShort("data too short for random".into()));
    }
    pos += 32;

    // Session ID
    if pos + 1 > data.len() {
        return Err(ParseError::DataTooShort(
            "data too short for session ID length".into(),
        ));
    }
    let session_id_length = data[pos];
    pos += 1 + session_id_length as usize;

    // Cipher suites
    if pos + 2 > data.len() {
        return Err(ParseError::DataTooShort(
            "data too short for cipher suites length".into(),
        ));
    }
    let cs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pos + cs_len > data.len() {
        return Err(ParseError::DataTooShort(
            "data too short for cipher suites".into(),
        ));
    }
    let mut cipher_suites = Vec::new();
    let cs_end = pos + cs_len;
    while pos + 2 <= cs_end {
        cipher_suites.push(u16::from_be_bytes([data[pos], data[pos + 1]]));
        pos += 2;
    }

    // Compression methods
    if pos + 1 > data.len() {
        return Err(ParseError::DataTooShort(
            "data too short for compression methods".into(),
        ));
    }
    let comp_len = data[pos] as usize;
    pos += 1;
    if pos + comp_len > data.len() {
        return Err(ParseError::DataTooShort(
            "data too short for compression methods data".into(),
        ));
    }
    let compression_methods = data[pos..pos + comp_len].to_vec();
    pos += comp_len;

    // Extensions
    let mut extensions = Vec::new();
    if pos + 2 <= data.len() {
        let ext_total = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let ext_end = pos + ext_total;

        while pos + 4 <= ext_end && pos + 4 <= data.len() {
            let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ext_data_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;

            let ext_data = if ext_data_len > 0 && pos + ext_data_len <= data.len() {
                let d = data[pos..pos + ext_data_len].to_vec();
                pos += ext_data_len;
                d
            } else {
                pos += ext_data_len;
                Vec::new()
            };

            extensions.push(ParsedExtension {
                extension_type: ext_type,
                data: ext_data,
            });
        }
    }

    Ok(ParsedClientHello {
        protocol_version,
        session_id_length,
        cipher_suites,
        compression_methods,
        extensions,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Extension data extractors
// ─────────────────────────────────────────────────────────────────────────────

/// Extract supported groups (named curves) from extension data (0x000a).
pub fn extract_supported_groups(data: &[u8]) -> Vec<u16> {
    if data.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut groups = Vec::new();
    let mut pos = 2;
    while pos + 2 <= 2 + list_len && pos + 2 <= data.len() {
        groups.push(u16::from_be_bytes([data[pos], data[pos + 1]]));
        pos += 2;
    }
    groups
}

/// Extract signature algorithms from extension data (0x000d).
pub fn extract_signature_algorithms(data: &[u8]) -> Vec<u16> {
    if data.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut algs = Vec::new();
    let mut pos = 2;
    while pos + 2 <= 2 + list_len && pos + 2 <= data.len() {
        algs.push(u16::from_be_bytes([data[pos], data[pos + 1]]));
        pos += 2;
    }
    algs
}

/// Extract EC point formats from extension data (0x000b).
pub fn extract_ec_point_formats(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let len = data[0] as usize;
    data[1..1 + len.min(data.len() - 1)].to_vec()
}

/// Extract ALPN protocol list from extension data (0x0010).
pub fn extract_alpn_protocols(data: &[u8]) -> Vec<String> {
    if data.len() < 2 {
        return Vec::new();
    }
    let mut protocols = Vec::new();
    let mut pos = 2;
    while pos < data.len() {
        let plen = data[pos] as usize;
        pos += 1;
        if pos + plen <= data.len() {
            if let Ok(s) = std::str::from_utf8(&data[pos..pos + plen]) {
                protocols.push(s.to_string());
            }
        }
        pos += plen;
    }
    protocols
}

/// Infer ECH GREASE `payload_length_min` / `payload_length_max` from a single
/// observed `payload_len`.
///
/// BoringSSL computes: `payload_len = 32 * random_in(min/32, max/32) + 16`.
/// Chrome uses `min=128, max=224`, producing discrete values {144, 176, 208, 240}.
/// From one observation we strip the AEAD tag and round to the nearest 32-aligned
/// block boundaries.
fn infer_ech_payload_range(payload_len: u16) -> (Option<u16>, Option<u16>) {
    if payload_len < 16 {
        return (None, None);
    }
    let block = payload_len - 16; // strip AEAD tag
                                  // Round down to nearest multiple of 32 for the block value
    let block_aligned = (block / 32) * 32;
    if block_aligned == 0 {
        return (None, None);
    }

    // For Chrome: the observed block is one of {128, 160, 192, 224}.
    // The true range is min=128, max=224.  We can recognize this pattern
    // if the block falls within [128, 224] at a 32-byte boundary.
    if (128..=224).contains(&block_aligned) {
        (Some(128), Some(224))
    } else {
        // Unknown browser: use the observed value as both min and max
        (Some(block_aligned), Some(block_aligned))
    }
}

/// Extract key share curves from extension data (0x0033).
pub fn extract_key_share_curves(data: &[u8]) -> Vec<u16> {
    if data.len() < 2 {
        return Vec::new();
    }
    let mut curves = Vec::new();
    let mut pos = 2;
    while pos + 4 <= data.len() {
        let group = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let key_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        curves.push(group);
        pos += 4 + key_len;
    }
    curves
}

/// Extract supported versions from extension data (0x002b).
pub fn extract_supported_versions(data: &[u8]) -> Vec<u16> {
    if data.is_empty() {
        return Vec::new();
    }
    let list_len = data[0] as usize;
    let mut versions = Vec::new();
    let mut pos = 1;
    while pos + 2 <= 1 + list_len && pos + 2 <= data.len() {
        versions.push(u16::from_be_bytes([data[pos], data[pos + 1]]));
        pos += 2;
    }
    versions
}

/// Extract compress_certificate algorithm IDs from extension data (0x001b).
pub fn extract_compress_cert_algorithms(data: &[u8]) -> Vec<u16> {
    if data.is_empty() {
        return Vec::new();
    }
    let len = data[0] as usize;
    let mut algs = Vec::new();
    let mut pos = 1;
    while pos + 2 <= 1 + len && pos + 2 <= data.len() {
        algs.push(u16::from_be_bytes([data[pos], data[pos + 1]]));
        pos += 2;
    }
    algs
}

/// Extract record_size_limit from extension data (0x001c).
pub fn extract_record_size_limit(data: &[u8]) -> Option<u16> {
    if data.len() >= 2 {
        Some(u16::from_be_bytes([data[0], data[1]]))
    } else {
        None
    }
}

/// Extract delegated credential config from extension data (0x0022).
pub fn extract_delegated_credentials(data: &[u8]) -> Option<DelegatedCredentialConfig> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut algs = Vec::new();
    let mut pos = 2;
    while pos + 2 <= 2 + list_len && pos + 2 <= data.len() {
        algs.push(u16::from_be_bytes([data[pos], data[pos + 1]]));
        pos += 2;
    }
    Some(DelegatedCredentialConfig {
        signature_algorithms: algs,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// TlsProfile builder
// ─────────────────────────────────────────────────────────────────────────────

/// Build a [`TlsProfile`] from a parsed ClientHello.
///
/// This examines the ClientHello's extensions and cipher suites to construct
/// a complete profile that can be used with `lkrequest::TlsConnector`.
///
/// # Arguments
///
/// * `name` — Human-readable profile name (e.g. "Chrome 131").
/// * `ch` — Parsed ClientHello data.
pub fn build_tls_profile(name: &str, ch: &ParsedClientHello) -> TlsProfile {
    let mut supported_groups = Vec::new();
    let mut signature_algorithms = Vec::new();
    let mut ec_point_formats = vec![0x00u8];
    let mut alpn_protocols = Vec::new();
    let mut key_share_curves = Vec::new();
    let mut supported_versions = Vec::new();
    let mut compress_cert_algorithms = None;
    let mut record_size_limit = None;
    let mut delegated_credentials = None;
    let mut alps_protocols = None;
    let mut has_padding = false;
    let mut ech_mode: Option<EchMode> = None;

    let has_grease_cs = ch.cipher_suites.iter().any(|s| is_grease_value(*s));
    let mut has_grease_ext = false;
    let mut has_grease_groups = false;
    let mut has_grease_versions = false;
    let mut has_grease_sigalgs = false;
    let mut has_grease_key_share = false;

    for ext in &ch.extensions {
        if is_grease_value(ext.extension_type) {
            has_grease_ext = true;
            continue;
        }
        match ext.extension_type {
            0x000a => {
                supported_groups = extract_supported_groups(&ext.data);
                has_grease_groups = supported_groups.iter().any(|g| is_grease_value(*g));
                supported_groups.retain(|g| !is_grease_value(*g));
            }
            0x000b => ec_point_formats = extract_ec_point_formats(&ext.data),
            0x000d => {
                signature_algorithms = extract_signature_algorithms(&ext.data);
                has_grease_sigalgs = signature_algorithms.iter().any(|a| is_grease_value(*a));
                signature_algorithms.retain(|a| !is_grease_value(*a));
            }
            0x0010 => alpn_protocols = extract_alpn_protocols(&ext.data),
            0x0015 => has_padding = true,
            0x001b => compress_cert_algorithms = Some(extract_compress_cert_algorithms(&ext.data)),
            0x001c => record_size_limit = extract_record_size_limit(&ext.data),
            0x0022 => delegated_credentials = extract_delegated_credentials(&ext.data),
            0x002b => {
                supported_versions = extract_supported_versions(&ext.data);
                has_grease_versions = supported_versions.iter().any(|v| is_grease_value(*v));
            }
            0x0033 => {
                key_share_curves = extract_key_share_curves(&ext.data);
                has_grease_key_share = key_share_curves.iter().any(|c| is_grease_value(*c));
                key_share_curves.retain(|c| !is_grease_value(*c));
            }
            0x4469 | 0x44cd => alps_protocols = Some(extract_alpn_protocols(&ext.data)),
            0xFE0D
                // ECH extension — extract GREASE parameters.
                // Outer ECH payload: type(1) + kdf_id(2) + aead_id(2) + config_id(1)
                //   + enc_len(2) + enc(N) + payload_len(2) + payload(M)
                if ext.data.len() >= 8 && ext.data[0] == 0x00 => {
                    let kdf_id = u16::from_be_bytes([ext.data[1], ext.data[2]]);
                    let aead_id = u16::from_be_bytes([ext.data[3], ext.data[4]]);
                    let enc_length = u16::from_be_bytes([ext.data[6], ext.data[7]]);

                    // Infer payload_length_min/max from observed payload length.
                    // BoringSSL: payload_len = 32 * rand_in(min/32, max/32) + aead_tag(16).
                    // From a single observation we recover the plaintext block size
                    // and assume the standard Chrome range (128..=224).
                    let payload_offset = 8 + enc_length as usize;
                    let (pl_min, pl_max) = if payload_offset + 2 <= ext.data.len() {
                        let payload_len = u16::from_be_bytes([
                            ext.data[payload_offset],
                            ext.data[payload_offset + 1],
                        ]);
                        infer_ech_payload_range(payload_len)
                    } else {
                        (None, None)
                    };

                    ech_mode = Some(EchMode::Grease(EchGreaseConfig {
                        kdf_id,
                        aead_id,
                        enc_length,
                        payload_length_min: pl_min,
                        payload_length_max: pl_max,
                    }));
                }
            _ => {}
        }
    }

    // Determine TLS version range
    let (tls_min, tls_max) = if !supported_versions.is_empty() {
        let real_versions: Vec<u16> = supported_versions
            .iter()
            .filter(|v| !is_grease_value(**v))
            .copied()
            .collect();
        let min_v = real_versions.iter().min().copied().unwrap_or(0x0303);
        let max_v = real_versions.iter().max().copied().unwrap_or(0x0303);
        (tls_version_from_u16(min_v), tls_version_from_u16(max_v))
    } else {
        (
            tls_version_from_u16(ch.protocol_version),
            tls_version_from_u16(ch.protocol_version),
        )
    };

    // Build extension specs
    let extension_specs: Vec<ExtensionSpec> = ch
        .extensions
        .iter()
        .map(|e| {
            if is_grease_value(e.extension_type) {
                ExtensionSpec {
                    extension_type: e.extension_type,
                    source: ExtensionSource::Grease,
                }
            } else {
                let source = match e.extension_type {
                    // Well-known extensions that lktls auto-generates at runtime.
                    // These MUST be Auto so the profile fields (not RawBytes) drive generation.
                    0x0000 // SNI
                    | 0x0005 // status_request (OCSP stapling)
                    | 0x000a // supported_groups
                    | 0x000b // ec_point_formats
                    | 0x000d // signature_algorithms
                    | 0x0010 // ALPN
                    | 0x0012 // signed_certificate_timestamp
                    | 0x0015 // padding
                    | 0x0016 // encrypt_then_mac
                    | 0x0017 // extended_master_secret
                    | 0x001b // compress_certificate
                    | 0x001c // record_size_limit
                    | 0x0022 // delegated_credentials
                    | 0x0023 // session_ticket
                    | 0x002b // supported_versions
                    | 0x002d // psk_key_exchange_modes
                    | 0x0033 // key_share
                    | 0x4469 | 0x44cd // ALPS (application_settings)
                    | 0xFE0D // encrypted_client_hello (ECH)
                    | 0xff01 // renegotiation_info
                    => ExtensionSource::Auto,
                    _ => {
                        if e.data.is_empty() {
                            ExtensionSource::Auto
                        } else {
                            ExtensionSource::RawBytes {
                                data: hex::encode(&e.data),
                            }
                        }
                    }
                };
                ExtensionSpec {
                    extension_type: e.extension_type,
                    source,
                }
            }
        })
        .collect();

    // Filter GREASE cipher suites
    let cipher_suites: Vec<u16> = ch
        .cipher_suites
        .iter()
        .filter(|s| !is_grease_value(**s))
        .copied()
        .collect();

    let padding = if has_padding {
        PaddingStrategy::BlockAlign {
            min_length: 256,
            block_size: 512,
        }
    } else {
        PaddingStrategy::None
    };

    TlsProfile {
        name: name.to_string(),
        tls_client_hello_style: TlsClientHelloStyle::Generic,
        tls_min_version: tls_min,
        tls_max_version: tls_max,
        cipher_suites,
        extensions: extension_specs,
        supported_groups,
        signature_algorithms,
        ec_point_formats,
        compression_methods: ch.compression_methods.clone(),
        grease: GreaseConfig {
            cipher_suite: has_grease_cs,
            extensions: has_grease_ext,
            supported_groups: has_grease_groups,
            supported_versions: has_grease_versions,
            signature_algorithms: has_grease_sigalgs,
            key_share: has_grease_key_share,
        },
        padding,
        alps_protocols,
        compress_cert_algorithms,
        key_share_curves,
        record_size_limit,
        delegated_credentials,
        session_id_length: ch.session_id_length,
        alpn_protocols,
        randomization: None,
        ech: ech_mode.clone(),
        // Auto-populate ech_outer_extensions with the BoringSSL default list
        // when ECH is active. This list is shared across Chrome versions and
        // cannot be passively captured (the inner CH is encrypted).
        ech_outer_extensions: if ech_mode.is_some() {
            Some(vec![51, 10, 13, 5, 18, 16, 45, 27, 17613])
        } else {
            None
        },
        session_resumption: Default::default(),
    }
}

/// Round-trip fidelity tests for the ClientHello mirror.
///
/// For each browser preset we treat the preset's *encoded* ClientHello as a
/// stand-in for a real captured one, mirror it (`parse_client_hello` →
/// `build_tls_profile`), re-encode the mirror, and compare TLS fingerprints. A
/// faithful mirror must reproduce the same JA3 / JA3N / JA4. This is the test
/// the audit flagged as missing — it empirically measures whether the
/// "semantic re-synthesis" (Generic style + Auto-regenerated extensions)
/// preserves the fingerprint, including for non-Chrome families.
#[cfg(test)]
mod mirror_roundtrip {
    use super::{build_tls_profile, parse_client_hello};
    use crate::fingerprint::{collect_tls_fingerprint, TlsFingerprintCollection};
    use lktls::handshake::client_hello::ClientHelloBuilder;
    use lktls::profile::types::TlsProfile;

    fn encode_and_fingerprint(profile: &TlsProfile) -> TlsFingerprintCollection {
        let out = ClientHelloBuilder::new(profile, "example.com")
            .build()
            .expect("encode ClientHello");
        // `out.message` is the handshake message (no record header);
        // `parse_client_hello` accepts that directly.
        let parsed = parse_client_hello(&out.message).expect("parse encoded ClientHello");
        collect_tls_fingerprint(&parsed)
    }

    /// Returns `Err(diagnostic)` if the mirror round-trip changed the fingerprint;
    /// the caller asserts so each `#[test]` carries an explicit assertion.
    fn mirror_fingerprint_diff(name: &str, profile: TlsProfile) -> Result<(), String> {
        // 1. Encode the preset as a stand-in for a captured real ClientHello.
        let out = ClientHelloBuilder::new(&profile, "example.com")
            .build()
            .expect("encode original ClientHello");
        let parsed_orig = parse_client_hello(&out.message).expect("parse original");
        let fp_orig = collect_tls_fingerprint(&parsed_orig);

        // 2. Mirror it, then re-encode + fingerprint the mirror.
        let mirror = build_tls_profile("mirror", &parsed_orig);
        let fp_mirror = encode_and_fingerprint(&mirror);

        // JA3N (normalized: extensions sorted) — proves the mirror preserved the
        // cipher list, extension SET, groups and ec-point formats.
        if fp_orig.ja3n_hash != fp_mirror.ja3n_hash {
            return Err(format!(
                "[{name}] JA3N differs (semantic loss):\n  orig:   {}\n  mirror: {}",
                fp_orig.ja3n_text, fp_mirror.ja3n_text
            ));
        }
        // JA4 prefix (version, cipher/ext counts, ALPN).
        if fp_orig.ja4_prefix != fp_mirror.ja4_prefix {
            return Err(format!("[{name}] JA4 prefix differs"));
        }
        // JA3 (order-sensitive) — the mirror keeps the captured extension order
        // (randomization disabled), so a mismatch here pinpoints an extension
        // ORDER or per-extension byte-encoding discrepancy under the mirror's
        // Generic style / Auto-regeneration.
        if fp_orig.ja3_hash != fp_mirror.ja3_hash {
            return Err(format!(
                "[{name}] JA3 differs (order / byte-encoding):\n  orig:   {}\n  mirror: {}",
                fp_orig.ja3_text, fp_mirror.ja3_text
            ));
        }
        Ok(())
    }

    #[test]
    fn mirror_preserves_chrome_144() {
        let result = mirror_fingerprint_diff("chrome_144", lktls::profile::presets::chrome_144());
        assert!(result.is_ok(), "{}", result.unwrap_err());
    }

    #[test]
    fn mirror_preserves_firefox_147() {
        let result = mirror_fingerprint_diff("firefox_147", lktls::profile::presets::firefox_147());
        assert!(result.is_ok(), "{}", result.unwrap_err());
    }

    #[test]
    fn mirror_preserves_safari_26() {
        let result = mirror_fingerprint_diff("safari_26", lktls::profile::presets::safari_26());
        assert!(result.is_ok(), "{}", result.unwrap_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_client_hello() -> Vec<u8> {
        let mut ch = Vec::new();
        // TLS record header
        ch.push(0x16);
        ch.extend_from_slice(&[0x03, 0x01]);
        let record_len_pos = ch.len();
        ch.extend_from_slice(&[0x00, 0x00]); // placeholder
        let hs_start = ch.len();
        // Handshake header
        ch.push(0x01); // ClientHello
        let hs_len_pos = ch.len();
        ch.extend_from_slice(&[0x00, 0x00, 0x00]); // placeholder
        let ch_start = ch.len();
        // Protocol version
        ch.extend_from_slice(&[0x03, 0x03]);
        // Random
        ch.extend_from_slice(&[0xAA; 32]);
        // Session ID
        ch.push(32);
        ch.extend_from_slice(&[0xBB; 32]);
        // Cipher suites
        ch.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);
        // Compression methods
        ch.extend_from_slice(&[0x01, 0x00]);
        // Extensions
        let ext_start = ch.len();
        ch.extend_from_slice(&[0x00, 0x00]); // placeholder
        let ext_data_start = ch.len();
        // supported_versions extension
        ch.extend_from_slice(&[0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03]);
        let ext_total_len = ch.len() - ext_data_start;
        ch[ext_start] = ((ext_total_len >> 8) & 0xff) as u8;
        ch[ext_start + 1] = (ext_total_len & 0xff) as u8;
        // Fix lengths
        let hs_len = ch.len() - ch_start;
        ch[hs_len_pos + 1] = ((hs_len >> 8) & 0xff) as u8;
        ch[hs_len_pos + 2] = (hs_len & 0xff) as u8;
        let record_len = ch.len() - hs_start;
        ch[record_len_pos] = ((record_len >> 8) & 0xff) as u8;
        ch[record_len_pos + 1] = (record_len & 0xff) as u8;
        ch
    }

    #[test]
    fn test_parse_sample() {
        let data = sample_client_hello();
        let ch = parse_client_hello(&data).expect("should parse");
        assert_eq!(ch.protocol_version, 0x0303);
        assert_eq!(ch.session_id_length, 32);
        assert_eq!(ch.cipher_suites, vec![0x1301, 0x1302]);
        assert_eq!(ch.extensions.len(), 1);
    }

    #[test]
    fn test_build_tls_profile() {
        let data = sample_client_hello();
        let ch = parse_client_hello(&data).expect("should parse");
        let profile = build_tls_profile("Test", &ch);
        assert_eq!(profile.cipher_suites, vec![0x1301, 0x1302]);
        assert_eq!(profile.tls_max_version, TlsVersion::Tls13);
        assert_eq!(profile.name, "Test");
    }

    #[test]
    fn test_grease_detection() {
        assert!(is_grease_value(0x0a0a));
        assert!(is_grease_value(0x1a1a));
        assert!(is_grease_value(0xfafa));
        assert!(!is_grease_value(0x1301));
    }

    /// Build a sample ClientHello that contains an ECH GREASE extension.
    fn sample_client_hello_with_ech() -> Vec<u8> {
        let mut ch = Vec::new();
        // TLS record header
        ch.push(0x16);
        ch.extend_from_slice(&[0x03, 0x01]);
        let record_len_pos = ch.len();
        ch.extend_from_slice(&[0x00, 0x00]); // placeholder
        let hs_start = ch.len();
        // Handshake header
        ch.push(0x01); // ClientHello
        let hs_len_pos = ch.len();
        ch.extend_from_slice(&[0x00, 0x00, 0x00]); // placeholder
        let ch_start = ch.len();
        // Protocol version
        ch.extend_from_slice(&[0x03, 0x03]);
        // Random
        ch.extend_from_slice(&[0xAA; 32]);
        // Session ID
        ch.push(32);
        ch.extend_from_slice(&[0xBB; 32]);
        // Cipher suites
        ch.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);
        // Compression methods
        ch.extend_from_slice(&[0x01, 0x00]);
        // Extensions
        let ext_start = ch.len();
        ch.extend_from_slice(&[0x00, 0x00]); // placeholder
        let ext_data_start = ch.len();

        // supported_versions extension
        ch.extend_from_slice(&[0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03]);

        // ECH extension (0xFE0D) — GREASE-like outer structure
        // type(1=outer) + kdf_id(2) + aead_id(2) + config_id(1)
        // + enc_len(2) + enc(32) + payload_len(2) + payload(128)
        let ech_type: u16 = 0xFE0D;
        let mut ech_payload = Vec::new();
        ech_payload.push(0x00); // type = outer
        ech_payload.extend_from_slice(&0x0001u16.to_be_bytes()); // kdf_id = HKDF-SHA256
        ech_payload.extend_from_slice(&0x0003u16.to_be_bytes()); // aead_id = ChaCha20
        ech_payload.push(0x42); // config_id
        ech_payload.extend_from_slice(&32u16.to_be_bytes()); // enc_len
        ech_payload.extend_from_slice(&[0xCC; 32]); // enc
        ech_payload.extend_from_slice(&128u16.to_be_bytes()); // payload_len
        ech_payload.extend_from_slice(&[0xDD; 128]); // payload

        ch.extend_from_slice(&ech_type.to_be_bytes());
        ch.extend_from_slice(&(ech_payload.len() as u16).to_be_bytes());
        ch.extend_from_slice(&ech_payload);

        let ext_total_len = ch.len() - ext_data_start;
        ch[ext_start] = ((ext_total_len >> 8) & 0xff) as u8;
        ch[ext_start + 1] = (ext_total_len & 0xff) as u8;
        // Fix lengths
        let hs_len = ch.len() - ch_start;
        ch[hs_len_pos + 1] = ((hs_len >> 8) & 0xff) as u8;
        ch[hs_len_pos + 2] = (hs_len & 0xff) as u8;
        let record_len = ch.len() - hs_start;
        ch[record_len_pos] = ((record_len >> 8) & 0xff) as u8;
        ch[record_len_pos + 1] = (record_len & 0xff) as u8;
        ch
    }

    #[test]
    fn test_build_tls_profile_extracts_ech_grease() {
        let data = sample_client_hello_with_ech();
        let ch = parse_client_hello(&data).expect("should parse");
        let profile = build_tls_profile("ECH Test", &ch);

        // ECH should be extracted as Grease mode
        assert!(profile.ech.is_some(), "ech field should be populated");
        match profile.ech.as_ref().unwrap() {
            EchMode::Grease(config) => {
                assert_eq!(config.kdf_id, 0x0001, "kdf_id should be HKDF-SHA256");
                assert_eq!(config.aead_id, 0x0003, "aead_id should be ChaCha20Poly1305");
                assert_eq!(config.enc_length, 32, "enc_length should be 32 (X25519)");
            }
            other => panic!("expected EchMode::Grease, got: {other:?}"),
        }
    }

    #[test]
    fn test_build_tls_profile_ech_extension_is_auto() {
        let data = sample_client_hello_with_ech();
        let ch = parse_client_hello(&data).expect("should parse");
        let profile = build_tls_profile("ECH Test", &ch);

        // The ECH extension (0xFE0D) should be marked as Auto, not RawBytes
        let ech_ext = profile
            .extensions
            .iter()
            .find(|e| e.extension_type == 0xFE0D);
        assert!(ech_ext.is_some(), "0xFE0D should be in extension list");
        assert!(
            matches!(ech_ext.unwrap().source, ExtensionSource::Auto),
            "ECH extension source should be Auto"
        );
    }

    #[test]
    fn test_build_tls_profile_no_ech_returns_none() {
        // The original sample_client_hello() has no ECH extension
        let data = sample_client_hello();
        let ch = parse_client_hello(&data).expect("should parse");
        let profile = build_tls_profile("NoECH", &ch);
        assert!(
            profile.ech.is_none(),
            "profile without ECH should have ech=None"
        );
    }
}
