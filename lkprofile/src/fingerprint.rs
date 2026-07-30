use md5::Md5;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::client_hello::{
    extract_alpn_protocols, extract_ec_point_formats, extract_signature_algorithms,
    extract_supported_groups, is_grease_value, parse_client_hello, ParsedClientHello,
};
use crate::error::ParseError;
use crate::h2::H2Fingerprint;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsFingerprintCollection {
    pub ja3_text: String,
    pub ja3_hash: String,
    pub ja3n_text: String,
    pub ja3n_hash: String,
    pub ja4_prefix: String,
    pub alpn_protocols: Vec<String>,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuicFingerprintCollection {
    pub transport_parameters: Vec<(String, u64)>,
    pub send_min_ack_delay: bool,
    pub send_reserved_transport_parameter: bool,
    pub extra_transport_parameters: Vec<(u64, String)>,
    pub transport_parameter_order: Vec<u64>,
    pub transport_fingerprint: String,
    pub transport_hash: String,
    pub packetization: QuicPacketizationFingerprint,
    pub packetization_fingerprint: String,
    pub packetization_hash: String,
    pub h3_settings: Vec<(u64, u64)>,
    pub h3_settings_fingerprint: String,
    pub h3_settings_hash: String,
    pub pseudo_header_order: Vec<String>,
    pub pseudo_header_order_token: String,
    pub connection_id_length: usize,
    pub initial_destination_connection_id_length: Option<usize>,
    pub grease_settings: bool,
    pub grease_transport_params: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct H3FingerprintInput {
    pub settings: Vec<(u64, u64)>,
    pub pseudo_header_order: Vec<String>,
    pub pseudo_header_order_token: String,
    pub grease_settings: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuicPacketizationFingerprint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_mtu: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_datagram_size: Option<u16>,
    #[serde(default)]
    pub disable_mtu_discovery: bool,
    #[serde(default = "default_true")]
    pub enable_segmentation_offload: bool,
    #[serde(default = "default_true")]
    pub enable_ecn: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_frame_layout: Option<String>,
}

impl Default for QuicPacketizationFingerprint {
    fn default() -> Self {
        Self {
            initial_mtu: None,
            initial_datagram_size: None,
            disable_mtu_discovery: false,
            enable_segmentation_offload: true,
            enable_ecn: true,
            initial_frame_layout: None,
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuicFingerprintInput {
    pub transport_parameters: Vec<(String, u64)>,
    pub h3: H3FingerprintInput,
    pub connection_id_length: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_destination_connection_id_length: Option<usize>,
    pub grease_transport_params: bool,
    #[serde(default = "default_true")]
    pub send_min_ack_delay: bool,
    #[serde(default = "default_true")]
    pub send_reserved_transport_parameter: bool,
    #[serde(default)]
    pub extra_transport_parameters: Vec<(u64, String)>,
    #[serde(default)]
    pub transport_parameter_order: Vec<u64>,
    #[serde(default)]
    pub packetization: QuicPacketizationFingerprint,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CollectedFingerprint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsFingerprintCollection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h2: Option<H2Fingerprint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic: Option<QuicFingerprintCollection>,
}

impl CollectedFingerprint {
    pub fn with_tls(mut self, tls: TlsFingerprintCollection) -> Self {
        self.tls = Some(tls);
        self
    }

    pub fn with_h2(mut self, h2: H2Fingerprint) -> Self {
        self.h2 = Some(h2);
        self
    }

    pub fn with_quic(mut self, quic: QuicFingerprintCollection) -> Self {
        self.quic = Some(quic);
        self
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FingerprintFieldStatus {
    Match,
    Mismatch,
    MissingLeft,
    MissingRight,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintFieldComparison {
    pub field: String,
    pub status: FingerprintFieldStatus,
    pub left: Option<String>,
    pub right: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FingerprintComparison {
    pub matches: usize,
    pub mismatches: usize,
    pub fields: Vec<FingerprintFieldComparison>,
}

impl FingerprintComparison {
    pub fn is_match(&self) -> bool {
        self.mismatches == 0
    }
}

pub fn collect_tls_fingerprint(ch: &ParsedClientHello) -> TlsFingerprintCollection {
    let cipher_suites: Vec<u16> = ch
        .cipher_suites
        .iter()
        .copied()
        .filter(|value| !is_grease_value(*value))
        .collect();
    let extensions: Vec<u16> = ch
        .extensions
        .iter()
        .map(|ext| ext.extension_type)
        .filter(|value| !is_grease_value(*value))
        .collect();

    let supported_groups = ch
        .extensions
        .iter()
        .find(|ext| ext.extension_type == 0x000a)
        .map(|ext| {
            extract_supported_groups(&ext.data)
                .into_iter()
                .filter(|value| !is_grease_value(*value))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let ec_point_formats = ch
        .extensions
        .iter()
        .find(|ext| ext.extension_type == 0x000b)
        .map(|ext| extract_ec_point_formats(&ext.data))
        .unwrap_or_default();

    let signature_algorithms = ch
        .extensions
        .iter()
        .find(|ext| ext.extension_type == 0x000d)
        .map(|ext| extract_signature_algorithms(&ext.data))
        .unwrap_or_default();

    let alpn_protocols = ch
        .extensions
        .iter()
        .find(|ext| ext.extension_type == 0x0010)
        .map(|ext| extract_alpn_protocols(&ext.data))
        .unwrap_or_default();

    let ja3_text = format!(
        "{},{},{},{},{}",
        ch.protocol_version,
        join_u16(&cipher_suites),
        join_u16(&extensions),
        join_u16(&supported_groups),
        join_u8(&ec_point_formats),
    );

    let mut ja3n_extensions = extensions.clone();
    ja3n_extensions.sort_unstable();
    let ja3n_text = format!(
        "{},{},{},{},{}",
        ch.protocol_version,
        join_u16(&cipher_suites),
        join_u16(&ja3n_extensions),
        join_u16(&supported_groups),
        join_u8(&ec_point_formats),
    );

    TlsFingerprintCollection {
        ja3_hash: md5_hex(&ja3_text),
        ja3_text,
        ja3n_hash: md5_hex(&ja3n_text),
        ja3n_text,
        ja4_prefix: compute_ja4_prefix(ch, &cipher_suites, &extensions, &alpn_protocols),
        alpn_protocols,
        cipher_suites,
        extensions,
        supported_groups,
        ec_point_formats,
        signature_algorithms,
    }
}

pub fn collect_tls_fingerprint_from_bytes(
    data: &[u8],
) -> Result<TlsFingerprintCollection, ParseError> {
    let parsed = parse_client_hello(data)?;
    Ok(collect_tls_fingerprint(&parsed))
}

pub fn collect_quic_fingerprint(input: &QuicFingerprintInput) -> QuicFingerprintCollection {
    let transport_parameters = input.transport_parameters.clone();
    let mut transport_parts = transport_parameters
        .iter()
        .map(|(name, value)| format!("{name}:{value}"))
        .collect::<Vec<_>>();
    transport_parts.push(format!("send_min_ack_delay:{}", input.send_min_ack_delay));
    transport_parts.push(format!(
        "send_reserved_transport_parameter:{}",
        input.send_reserved_transport_parameter
    ));
    transport_parts.extend(
        input
            .extra_transport_parameters
            .iter()
            .map(|(id, value)| format!("extra:{id:#x}:{value}")),
    );
    transport_parts.extend(
        input
            .transport_parameter_order
            .iter()
            .map(|id| format!("order:{id:#x}")),
    );
    let transport_fingerprint = transport_parts.join(";");

    let h3_settings_fingerprint = input
        .h3
        .settings
        .iter()
        .map(|(id, value)| format!("{id}:{value}"))
        .collect::<Vec<_>>()
        .join(";");
    let packetization_fingerprint = packetization_fingerprint(&input.packetization);

    QuicFingerprintCollection {
        transport_hash: sha256_hex(&transport_fingerprint),
        transport_fingerprint,
        transport_parameters,
        send_min_ack_delay: input.send_min_ack_delay,
        send_reserved_transport_parameter: input.send_reserved_transport_parameter,
        extra_transport_parameters: input.extra_transport_parameters.clone(),
        transport_parameter_order: input.transport_parameter_order.clone(),
        packetization: input.packetization.clone(),
        packetization_hash: sha256_hex(&packetization_fingerprint),
        packetization_fingerprint,
        h3_settings: input.h3.settings.clone(),
        h3_settings_hash: sha256_hex(&h3_settings_fingerprint),
        h3_settings_fingerprint,
        pseudo_header_order: input.h3.pseudo_header_order.clone(),
        pseudo_header_order_token: input.h3.pseudo_header_order_token.clone(),
        connection_id_length: input.connection_id_length,
        initial_destination_connection_id_length: input.initial_destination_connection_id_length,
        grease_settings: input.h3.grease_settings,
        grease_transport_params: input.grease_transport_params,
    }
}

pub fn compare_collected_fingerprints(
    left: &CollectedFingerprint,
    right: &CollectedFingerprint,
) -> FingerprintComparison {
    let mut comparison = FingerprintComparison::default();

    compare_optional_field(
        &mut comparison,
        "tls.ja3_hash",
        left.tls.as_ref().map(|tls| tls.ja3_hash.clone()),
        right.tls.as_ref().map(|tls| tls.ja3_hash.clone()),
    );
    compare_optional_field(
        &mut comparison,
        "tls.ja3n_hash",
        left.tls.as_ref().map(|tls| tls.ja3n_hash.clone()),
        right.tls.as_ref().map(|tls| tls.ja3n_hash.clone()),
    );
    compare_optional_field(
        &mut comparison,
        "tls.ja4_prefix",
        left.tls.as_ref().map(|tls| tls.ja4_prefix.clone()),
        right.tls.as_ref().map(|tls| tls.ja4_prefix.clone()),
    );
    compare_optional_field(
        &mut comparison,
        "tls.alpn_protocols",
        left.tls.as_ref().map(|tls| tls.alpn_protocols.join(",")),
        right.tls.as_ref().map(|tls| tls.alpn_protocols.join(",")),
    );
    compare_optional_field(
        &mut comparison,
        "h2.akamai_hash",
        left.h2.as_ref().map(|h2| h2.akamai_hash.clone()),
        right.h2.as_ref().map(|h2| h2.akamai_hash.clone()),
    );
    compare_optional_field(
        &mut comparison,
        "h2.akamai_fingerprint",
        left.h2.as_ref().map(|h2| h2.akamai_fingerprint.clone()),
        right.h2.as_ref().map(|h2| h2.akamai_fingerprint.clone()),
    );
    compare_optional_field(
        &mut comparison,
        "quic.transport_hash",
        left.quic.as_ref().map(|quic| quic.transport_hash.clone()),
        right.quic.as_ref().map(|quic| quic.transport_hash.clone()),
    );
    compare_optional_field(
        &mut comparison,
        "quic.h3_settings_hash",
        left.quic.as_ref().map(|quic| quic.h3_settings_hash.clone()),
        right
            .quic
            .as_ref()
            .map(|quic| quic.h3_settings_hash.clone()),
    );
    compare_optional_field(
        &mut comparison,
        "quic.packetization_hash",
        left.quic
            .as_ref()
            .map(|quic| quic.packetization_hash.clone()),
        right
            .quic
            .as_ref()
            .map(|quic| quic.packetization_hash.clone()),
    );
    compare_optional_field(
        &mut comparison,
        "quic.pseudo_header_order_token",
        left.quic
            .as_ref()
            .map(|quic| quic.pseudo_header_order_token.clone()),
        right
            .quic
            .as_ref()
            .map(|quic| quic.pseudo_header_order_token.clone()),
    );
    compare_optional_field(
        &mut comparison,
        "quic.connection_id_length",
        left.quic
            .as_ref()
            .map(|quic| quic.connection_id_length.to_string()),
        right
            .quic
            .as_ref()
            .map(|quic| quic.connection_id_length.to_string()),
    );
    compare_optional_field(
        &mut comparison,
        "quic.initial_destination_connection_id_length",
        left.quic.as_ref().map(|quic| {
            quic.initial_destination_connection_id_length
                .map(|len| len.to_string())
                .unwrap_or_else(|| "none".to_string())
        }),
        right.quic.as_ref().map(|quic| {
            quic.initial_destination_connection_id_length
                .map(|len| len.to_string())
                .unwrap_or_else(|| "none".to_string())
        }),
    );
    compare_optional_field(
        &mut comparison,
        "quic.grease_settings",
        left.quic
            .as_ref()
            .map(|quic| quic.grease_settings.to_string()),
        right
            .quic
            .as_ref()
            .map(|quic| quic.grease_settings.to_string()),
    );
    compare_optional_field(
        &mut comparison,
        "quic.grease_transport_params",
        left.quic
            .as_ref()
            .map(|quic| quic.grease_transport_params.to_string()),
        right
            .quic
            .as_ref()
            .map(|quic| quic.grease_transport_params.to_string()),
    );
    compare_optional_field(
        &mut comparison,
        "quic.send_min_ack_delay",
        left.quic
            .as_ref()
            .map(|quic| quic.send_min_ack_delay.to_string()),
        right
            .quic
            .as_ref()
            .map(|quic| quic.send_min_ack_delay.to_string()),
    );
    compare_optional_field(
        &mut comparison,
        "quic.send_reserved_transport_parameter",
        left.quic
            .as_ref()
            .map(|quic| quic.send_reserved_transport_parameter.to_string()),
        right
            .quic
            .as_ref()
            .map(|quic| quic.send_reserved_transport_parameter.to_string()),
    );
    compare_optional_field(
        &mut comparison,
        "quic.extra_transport_parameters",
        left.quic
            .as_ref()
            .map(|quic| format_extra_transport_parameters(&quic.extra_transport_parameters)),
        right
            .quic
            .as_ref()
            .map(|quic| format_extra_transport_parameters(&quic.extra_transport_parameters)),
    );
    compare_optional_field(
        &mut comparison,
        "quic.transport_parameter_order",
        left.quic
            .as_ref()
            .map(|quic| format_transport_parameter_order(&quic.transport_parameter_order)),
        right
            .quic
            .as_ref()
            .map(|quic| format_transport_parameter_order(&quic.transport_parameter_order)),
    );

    comparison
}

fn format_extra_transport_parameters(parameters: &[(u64, String)]) -> String {
    parameters
        .iter()
        .map(|(id, value)| format!("{id:#x}:{value}"))
        .collect::<Vec<_>>()
        .join(";")
}

fn format_transport_parameter_order(order: &[u64]) -> String {
    order
        .iter()
        .map(|id| format!("{id:#x}"))
        .collect::<Vec<_>>()
        .join(";")
}

fn packetization_fingerprint(packetization: &QuicPacketizationFingerprint) -> String {
    [
        format!(
            "initial_mtu:{}",
            packetization
                .initial_mtu
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_string())
        ),
        format!(
            "initial_datagram_size:{}",
            packetization
                .initial_datagram_size
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_string())
        ),
        format!(
            "disable_mtu_discovery:{}",
            packetization.disable_mtu_discovery
        ),
        format!(
            "enable_segmentation_offload:{}",
            packetization.enable_segmentation_offload
        ),
        format!("enable_ecn:{}", packetization.enable_ecn),
        format!(
            "initial_frame_layout:{}",
            packetization
                .initial_frame_layout
                .as_deref()
                .unwrap_or("none")
        ),
    ]
    .join(";")
}

fn compare_optional_field(
    comparison: &mut FingerprintComparison,
    field: &str,
    left: Option<String>,
    right: Option<String>,
) {
    let status = match (&left, &right) {
        (Some(left), Some(right)) if left == right => {
            comparison.matches += 1;
            FingerprintFieldStatus::Match
        }
        (Some(_), Some(_)) => {
            comparison.mismatches += 1;
            FingerprintFieldStatus::Mismatch
        }
        (Some(_), None) => {
            comparison.mismatches += 1;
            FingerprintFieldStatus::MissingRight
        }
        (None, Some(_)) => {
            comparison.mismatches += 1;
            FingerprintFieldStatus::MissingLeft
        }
        (None, None) => return,
    };

    comparison.fields.push(FingerprintFieldComparison {
        field: field.to_string(),
        status,
        left,
        right,
    });
}

fn compute_ja4_prefix(
    ch: &ParsedClientHello,
    cipher_suites: &[u16],
    extensions: &[u16],
    alpn_protocols: &[String],
) -> String {
    let version = extract_supported_versions_token(ch)
        .unwrap_or_else(|| tls_version_token(ch.protocol_version));
    let sni = if ch.extensions.iter().any(|ext| ext.extension_type == 0x0000) {
        'd'
    } else {
        'i'
    };
    let alpn = alpn_token(alpn_protocols.first().map(String::as_str));
    format!(
        "t{version}{sni}{:02}{:02}{alpn}",
        cipher_suites.len().min(99),
        extensions.len().min(99),
    )
}

fn extract_supported_versions_token(ch: &ParsedClientHello) -> Option<String> {
    let ext = ch
        .extensions
        .iter()
        .find(|ext| ext.extension_type == 0x002b)?;
    if ext.data.is_empty() {
        return None;
    }

    let versions = if ext.data.len() >= 3 && ext.data[0] as usize + 1 == ext.data.len() {
        ext.data[1..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| u16::from_be_bytes(*chunk))
            .collect::<Vec<_>>()
    } else if ext.data.len() == 2 {
        vec![u16::from_be_bytes([ext.data[0], ext.data[1]])]
    } else {
        Vec::new()
    };

    versions
        .into_iter()
        .filter(|value| !is_grease_value(*value))
        .max()
        .map(tls_version_token)
}

fn tls_version_token(version: u16) -> String {
    match version {
        0x0304 => "13".to_string(),
        0x0303 => "12".to_string(),
        0x0302 => "11".to_string(),
        0x0301 => "10".to_string(),
        _ => "00".to_string(),
    }
}

fn alpn_token(alpn: Option<&str>) -> String {
    match alpn {
        Some("h2") => "h2".to_string(),
        Some("http/1.1") => "h1".to_string(),
        Some(value) => {
            let mut token = value
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric())
                .map(|ch| ch.to_ascii_lowercase())
                .take(2)
                .collect::<String>();
            while token.len() < 2 {
                token.push('0');
            }
            token
        }
        None => "00".to_string(),
    }
}

fn join_u16(values: &[u16]) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("-")
}

fn join_u8(values: &[u8]) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("-")
}

fn md5_hex(input: &str) -> String {
    use md5::Digest;
    hex::encode(Md5::digest(input.as_bytes()))
}

fn sha256_hex(input: &str) -> String {
    use sha2::Digest;
    hex::encode(Sha256::digest(input.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h2::{
        H2Fingerprint, H2HeadersPriority, H2ProfileData, H2PseudoHeaderId, H2Setting, H2SettingId,
    };

    fn chrome_quic_input() -> QuicFingerprintInput {
        QuicFingerprintInput {
            transport_parameters: vec![
                ("max_idle_timeout".into(), 30_000),
                ("max_udp_payload_size".into(), 1_472),
                ("initial_max_data".into(), 15_728_640),
                ("initial_max_stream_data_bidi_local".into(), 6_291_456),
                ("initial_max_stream_data_bidi_remote".into(), 6_291_456),
                ("initial_max_stream_data_uni".into(), 6_291_456),
                ("initial_max_streams_bidi".into(), 100),
                ("initial_max_streams_uni".into(), 100),
                ("active_connection_id_limit".into(), 8),
            ],
            h3: H3FingerprintInput {
                settings: vec![(1, 65_536), (6, 262_144), (7, 100), (0x33, 1)],
                pseudo_header_order: vec![
                    ":method".into(),
                    ":authority".into(),
                    ":scheme".into(),
                    ":path".into(),
                ],
                pseudo_header_order_token: "masp".into(),
                grease_settings: true,
            },
            connection_id_length: 8,
            grease_transport_params: false,
            send_min_ack_delay: false,
            send_reserved_transport_parameter: false,
            extra_transport_parameters: vec![
                (0x11, "000000019a9aca7a00000001".to_string()),
                (0x17af394a4ef8da0a, String::new()),
                (0x3127, "8009df94".to_string()),
            ],
            transport_parameter_order: vec![
                0x03,
                0x11,
                0x09,
                0x08,
                0x20,
                0x01,
                0x06,
                0x0f,
                0x04,
                0x17af394a4ef8da0a,
                0x3127,
                0x07,
                0x05,
            ],
            initial_destination_connection_id_length: Some(8),
            packetization: QuicPacketizationFingerprint {
                initial_mtu: Some(1250),
                initial_datagram_size: Some(1250),
                disable_mtu_discovery: false,
                enable_segmentation_offload: true,
                enable_ecn: true,
                initial_frame_layout: Some(
                    "target=1250;pn=0:crypto@1099+16,pad+21,ping".to_string(),
                ),
            },
        }
    }

    fn sample_client_hello() -> Vec<u8> {
        let mut ch = Vec::new();
        ch.push(0x16);
        ch.extend_from_slice(&[0x03, 0x01]);
        let record_len_pos = ch.len();
        ch.extend_from_slice(&[0x00, 0x00]);
        let hs_start = ch.len();
        ch.push(0x01);
        let hs_len_pos = ch.len();
        ch.extend_from_slice(&[0x00, 0x00, 0x00]);
        let ch_start = ch.len();
        ch.extend_from_slice(&[0x03, 0x03]);
        ch.extend_from_slice(&[0x11; 32]);
        ch.push(32);
        ch.extend_from_slice(&[0x22; 32]);
        ch.extend_from_slice(&[0x00, 0x08, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0x0a, 0x0a]);
        ch.extend_from_slice(&[0x01, 0x00]);
        let ext_len_pos = ch.len();
        ch.extend_from_slice(&[0x00, 0x00]);
        let ext_start = ch.len();

        ch.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b, b'e', b'x', b'a', b'm', b'p',
            b'l', b'e', b'.', b'c', b'o', b'm',
        ]);
        ch.extend_from_slice(&[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);
        ch.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
        ch.extend_from_slice(&[0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x04]);
        ch.extend_from_slice(&[0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'2']);
        ch.extend_from_slice(&[0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03]);

        let ext_len = ch.len() - ext_start;
        ch[ext_len_pos] = ((ext_len >> 8) & 0xff) as u8;
        ch[ext_len_pos + 1] = (ext_len & 0xff) as u8;
        let hs_len = ch.len() - ch_start;
        ch[hs_len_pos + 1] = ((hs_len >> 8) & 0xff) as u8;
        ch[hs_len_pos + 2] = (hs_len & 0xff) as u8;
        let record_len = ch.len() - hs_start;
        ch[record_len_pos] = ((record_len >> 8) & 0xff) as u8;
        ch[record_len_pos + 1] = (record_len & 0xff) as u8;
        ch
    }

    #[test]
    fn collect_tls_fingerprint_computes_hashes_and_prefix() {
        let fingerprint = collect_tls_fingerprint_from_bytes(&sample_client_hello()).unwrap();

        assert!(fingerprint.ja3_text.starts_with("771,4865-4866-4867"));
        assert_eq!(fingerprint.alpn_protocols, vec!["h2".to_string()]);
        assert_eq!(fingerprint.supported_groups, vec![29, 23]);
        assert_eq!(fingerprint.ec_point_formats, vec![0]);
        assert_eq!(fingerprint.signature_algorithms, vec![0x0403, 0x0804]);
        assert_eq!(fingerprint.ja4_prefix, "t13d0306h2");
        assert_eq!(fingerprint.ja3_hash.len(), 32);
        assert_eq!(fingerprint.ja3n_hash.len(), 32);
    }

    #[test]
    fn collect_quic_fingerprint_from_chrome_profile_is_stable() {
        let fingerprint = collect_quic_fingerprint(&chrome_quic_input());

        assert!(fingerprint
            .transport_fingerprint
            .contains("max_idle_timeout:30000"));
        assert!(fingerprint
            .transport_fingerprint
            .contains("send_min_ack_delay:false"));
        assert!(fingerprint
            .transport_fingerprint
            .contains("send_reserved_transport_parameter:false"));
        assert!(fingerprint
            .transport_fingerprint
            .contains("extra:0x17af394a4ef8da0a:"));
        assert!(fingerprint
            .transport_fingerprint
            .contains("extra:0x3127:8009df94"));
        assert!(fingerprint
            .transport_fingerprint
            .contains("order:0x17af394a4ef8da0a"));
        assert!(fingerprint.h3_settings_fingerprint.contains("1:65536"));
        assert_eq!(fingerprint.pseudo_header_order_token, "masp");
        assert_eq!(fingerprint.connection_id_length, 8);
        assert_eq!(
            fingerprint.initial_destination_connection_id_length,
            Some(8)
        );
        assert!(!fingerprint.send_min_ack_delay);
        assert!(!fingerprint.send_reserved_transport_parameter);
        assert_eq!(
            fingerprint.extra_transport_parameters,
            vec![
                (0x11, "000000019a9aca7a00000001".to_string()),
                (0x17af394a4ef8da0a, String::new()),
                (0x3127, "8009df94".to_string())
            ]
        );
        assert_eq!(
            fingerprint.transport_parameter_order,
            vec![
                0x03,
                0x11,
                0x09,
                0x08,
                0x20,
                0x01,
                0x06,
                0x0f,
                0x04,
                0x17af394a4ef8da0a,
                0x3127,
                0x07,
                0x05,
            ]
        );
        assert_eq!(fingerprint.packetization.initial_mtu, Some(1250));
        assert_eq!(fingerprint.packetization.initial_datagram_size, Some(1250));
        assert!(fingerprint
            .packetization_fingerprint
            .contains("initial_mtu:1250"));
        assert!(fingerprint
            .packetization_fingerprint
            .contains("initial_datagram_size:1250"));
        assert!(fingerprint
            .packetization_fingerprint
            .contains("initial_frame_layout:target=1250"));
        assert_eq!(fingerprint.transport_hash.len(), 64);
        assert_eq!(fingerprint.packetization_hash.len(), 64);
        assert_eq!(fingerprint.h3_settings_hash.len(), 64);
    }

    #[test]
    fn compare_collected_fingerprints_reports_tls_and_quic_differences() {
        let left = CollectedFingerprint::default()
            .with_tls(collect_tls_fingerprint_from_bytes(&sample_client_hello()).unwrap())
            .with_h2(H2Fingerprint {
                profile: H2ProfileData {
                    settings: vec![H2Setting {
                        id: H2SettingId::HeaderTableSize,
                        value: 65_536,
                    }],
                    window_update: 15_663_105,
                    pseudo_header_order: vec![
                        H2PseudoHeaderId::Method,
                        H2PseudoHeaderId::Authority,
                        H2PseudoHeaderId::Scheme,
                        H2PseudoHeaderId::Path,
                    ],
                    headers_priority: Some(H2HeadersPriority {
                        stream_dependency: 0,
                        weight: 255,
                        exclusive: false,
                    }),
                    priority_frames: Vec::new(),
                    priority_config: None,
                },
                akamai_fingerprint: "1:65536|15663105|0|m,a,s,p".to_string(),
                akamai_hash: "left".to_string(),
                akamai_hash_sha256: "left-sha".to_string(),
            })
            .with_quic(collect_quic_fingerprint(&chrome_quic_input()));

        let mut modified = chrome_quic_input();
        modified.connection_id_length = 12;
        modified.initial_destination_connection_id_length = Some(20);
        modified.h3.pseudo_header_order.swap(0, 1);
        modified.h3.pseudo_header_order_token = "amsp".into();
        modified.h3.grease_settings = false;
        modified.packetization.initial_mtu = Some(1200);
        modified.packetization.initial_datagram_size = Some(1200);
        modified.send_min_ack_delay = true;
        modified.send_reserved_transport_parameter = true;
        modified.extra_transport_parameters.clear();
        modified.transport_parameter_order.clear();

        let right = CollectedFingerprint::default()
            .with_tls(TlsFingerprintCollection {
                ja3_hash: "different".to_string(),
                ..collect_tls_fingerprint_from_bytes(&sample_client_hello()).unwrap()
            })
            .with_h2(H2Fingerprint {
                akamai_hash: "right".to_string(),
                ..left.h2.clone().unwrap()
            })
            .with_quic(collect_quic_fingerprint(&modified));

        let comparison = compare_collected_fingerprints(&left, &right);

        assert!(!comparison.is_match());
        assert!(comparison.mismatches >= 3);
        assert!(comparison
            .fields
            .iter()
            .any(|field| field.field == "tls.ja3_hash"
                && field.status == FingerprintFieldStatus::Mismatch));
        assert!(comparison.fields.iter().any(|field| {
            field.field == "quic.connection_id_length"
                && field.status == FingerprintFieldStatus::Mismatch
        }));
        assert!(comparison.fields.iter().any(|field| {
            field.field == "quic.initial_destination_connection_id_length"
                && field.status == FingerprintFieldStatus::Mismatch
        }));
        assert!(comparison.fields.iter().any(|field| {
            field.field == "quic.grease_settings"
                && field.status == FingerprintFieldStatus::Mismatch
        }));
        assert!(comparison.fields.iter().any(|field| {
            field.field == "quic.packetization_hash"
                && field.status == FingerprintFieldStatus::Mismatch
        }));
        assert!(comparison.fields.iter().any(|field| {
            field.field == "quic.send_min_ack_delay"
                && field.status == FingerprintFieldStatus::Mismatch
        }));
        assert!(comparison.fields.iter().any(|field| {
            field.field == "quic.send_reserved_transport_parameter"
                && field.status == FingerprintFieldStatus::Mismatch
        }));
        assert!(comparison.fields.iter().any(|field| {
            field.field == "quic.extra_transport_parameters"
                && field.status == FingerprintFieldStatus::Mismatch
        }));
        assert!(comparison.fields.iter().any(|field| {
            field.field == "quic.transport_parameter_order"
                && field.status == FingerprintFieldStatus::Mismatch
        }));
    }
}
