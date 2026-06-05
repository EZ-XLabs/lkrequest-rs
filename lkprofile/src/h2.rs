//! HTTP/2 frame parser — extract H2 fingerprint from raw frame bytes.
//!
//! Parses a sequence of HTTP/2 frames (the decrypted application data from a
//! TLS connection) and builds an [`H2Fingerprint`] containing all fingerprint
//! dimensions: SETTINGS, WINDOW_UPDATE, PRIORITY frames, pseudo-header order,
//! and the Akamai fingerprint hash.
//!
//! # H2 Profile Compatibility
//!
//! The [`H2ProfileData`] sub-struct uses serde attributes identical to
//! `lkrequest::h2::H2Profile`, so it can be converted via:
//!
//! ```text
//! let fp = lkprofile::h2_fingerprint_from_frames(&data)?;
//! let h2_profile: lkrequest::h2::H2Profile =
//!     serde_json::from_value(serde_json::to_value(&fp.profile)?)?;
//! ```

use crate::error::ParseError;
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};

// ─────────────────────────────────────────────────────────────────────────────
// H2 constants
// ─────────────────────────────────────────────────────────────────────────────

/// HTTP/2 connection preface (24 bytes).
const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// Frame types
const H2_HEADERS: u8 = 0x01;
const H2_PRIORITY: u8 = 0x02;
const H2_SETTINGS: u8 = 0x04;
const H2_WINDOW_UPDATE: u8 = 0x08;

// ─────────────────────────────────────────────────────────────────────────────
// Output types (serde-compatible with lkrequest::h2::H2Profile)
// ─────────────────────────────────────────────────────────────────────────────

/// Complete HTTP/2 fingerprint, including profile data and Akamai fingerprint metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H2Fingerprint {
    /// H2 profile data — compatible with `lkrequest::h2::H2Profile` via serde.
    #[serde(flatten)]
    pub profile: H2ProfileData,

    /// Raw Akamai fingerprint string: `"S|WU|P|PS"`.
    pub akamai_fingerprint: String,
    /// MD5 hash of the Akamai fingerprint string.
    pub akamai_hash: String,
    /// SHA-256 hash of the Akamai fingerprint string.
    pub akamai_hash_sha256: String,
}

/// H2 profile data, schema-compatible with `lkrequest::h2::H2Profile`.
///
/// All fields use matching serde attributes so that:
/// ```text
/// serde_json::to_value(&h2_profile_data)
/// ```
/// produces JSON that `lkrequest::h2::H2Profile` can deserialize from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H2ProfileData {
    /// Ordered SETTINGS parameters.
    pub settings: Vec<H2Setting>,
    /// Connection-level WINDOW_UPDATE increment.
    pub window_update: u32,
    /// Pseudo-header order from the first HEADERS frame.
    pub pseudo_header_order: Vec<H2PseudoHeaderId>,
    /// HEADERS frame priority (if PRIORITY flag was set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers_priority: Option<H2HeadersPriority>,
    /// Standalone PRIORITY frames sent before the first HEADERS.
    #[serde(default)]
    pub priority_frames: Vec<H2PriorityFrame>,
    /// Per-browser priority strategy — maps RFC 9218 urgency to H2
    /// wire-level weight, stream dependency policy, and HTTP priority header.
    ///
    /// Populated by browser presets or inferred from captured data.
    /// When `None`, the profile uses default priority behaviour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority_config: Option<H2PriorityConfig>,
}

/// Per-browser priority strategy, schema-compatible with
/// `lkrequest::h2::PriorityConfig`.
///
/// Controls how `RequestPriority` (RFC 9218 urgency) maps to H2 wire-level
/// weight, stream dependencies, and HTTP headers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H2PriorityConfig {
    /// Maps urgency levels 0–7 to H2 wire weight (0–255).
    ///
    /// When `Some`, the engine uses `urgency_weights[urgency]` as the
    /// HEADERS frame weight (Chrome-style).
    /// When `None`, the engine uses the fixed `headers_priority.weight`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urgency_weights: Option<[u8; 8]>,

    /// Whether the exclusive bit is set on HEADERS priority.
    #[serde(default)]
    pub exclusive: bool,

    /// How concurrent stream dependencies are formed.
    #[serde(default)]
    pub stream_dep_policy: H2StreamDepPolicy,

    /// Whether to auto-inject the RFC 9218 `priority` HTTP header.
    #[serde(default)]
    pub auto_priority_header: bool,

    /// Default urgency when the caller does not specify one (0–7).
    #[serde(default = "default_urgency")]
    pub default_urgency: u8,

    /// Default incremental flag.
    #[serde(default)]
    pub default_incremental: bool,
}

fn default_urgency() -> u8 {
    3
}

/// How concurrent H2 stream dependencies are formed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum H2StreamDepPolicy {
    /// All streams depend on stream 0 (Firefox / Safari style).
    #[default]
    Flat,
    /// Each new stream depends on the previous client stream (Chrome style).
    Chain,
}

/// A single HTTP/2 SETTINGS parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H2Setting {
    /// Setting ID (serde-compatible with `lkrequest::h2::H2SettingId`).
    pub id: H2SettingId,
    /// Setting value.
    pub value: u32,
}

/// HTTP/2 SETTINGS parameter identifier.
///
/// Known IDs use `snake_case` serde names matching `lkrequest::h2::H2SettingId`.
/// Unknown IDs are preserved as raw u16 values for lossless capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum H2SettingId {
    HeaderTableSize,
    EnablePush,
    MaxConcurrentStreams,
    InitialWindowSize,
    MaxFrameSize,
    MaxHeaderListSize,
    /// SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08, RFC 8441).
    EnableConnectProtocol,
    NoRfc7540Priorities,
    /// Unknown/non-standard SETTINGS ID — preserved for lossless fingerprinting.
    #[serde(untagged)]
    Unknown(u16),
}

impl H2SettingId {
    /// Convert from wire ID (u16) to enum variant.
    /// Never returns `None` — unknown IDs become `Unknown(id)`.
    pub fn from_wire(id: u16) -> Self {
        match id {
            0x01 => Self::HeaderTableSize,
            0x02 => Self::EnablePush,
            0x03 => Self::MaxConcurrentStreams,
            0x04 => Self::InitialWindowSize,
            0x05 => Self::MaxFrameSize,
            0x06 => Self::MaxHeaderListSize,
            0x08 => Self::EnableConnectProtocol,
            0x09 => Self::NoRfc7540Priorities,
            other => Self::Unknown(other),
        }
    }

    /// Convert to wire ID (u16).
    pub fn to_wire(self) -> u16 {
        match self {
            Self::HeaderTableSize => 0x01,
            Self::EnablePush => 0x02,
            Self::MaxConcurrentStreams => 0x03,
            Self::InitialWindowSize => 0x04,
            Self::MaxFrameSize => 0x05,
            Self::MaxHeaderListSize => 0x06,
            Self::EnableConnectProtocol => 0x08,
            Self::NoRfc7540Priorities => 0x09,
            Self::Unknown(id) => id,
        }
    }
}

/// Pseudo-header identifier for HEADERS frame ordering.
///
/// Uses `snake_case` serde names matching `lkrequest::h2::PseudoHeaderId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum H2PseudoHeaderId {
    Method,
    Authority,
    Scheme,
    Path,
}

/// Stream dependency embedded in HEADERS frames (priority info).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H2HeadersPriority {
    #[serde(default)]
    pub stream_dependency: u32,
    #[serde(default)]
    pub weight: u8,
    #[serde(default)]
    pub exclusive: bool,
}

/// A standalone PRIORITY frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H2PriorityFrame {
    pub stream_id: u32,
    pub dependency: u32,
    pub weight: u8,
    #[serde(default)]
    pub exclusive: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Frame parsing
// ─────────────────────────────────────────────────────────────────────────────

/// A raw HTTP/2 frame.
struct RawH2Frame {
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

/// Read a single H2 frame from a reader.
fn read_h2_frame(reader: &mut dyn Read) -> Result<RawH2Frame, ParseError> {
    let mut header = [0u8; 9];
    reader.read_exact(&mut header)?;

    let length = ((header[0] as u32) << 16) | ((header[1] as u32) << 8) | (header[2] as u32);
    let frame_type = header[3];
    let flags = header[4];
    let stream_id = u32::from_be_bytes([header[5] & 0x7f, header[6], header[7], header[8]]);

    if length > 16384 * 2 {
        return Err(ParseError::UnexpectedValue(format!(
            "H2 frame too large: {length}"
        )));
    }

    let mut payload = vec![0u8; length as usize];
    if length > 0 {
        reader.read_exact(&mut payload)?;
    }

    Ok(RawH2Frame {
        frame_type,
        flags,
        stream_id,
        payload,
    })
}

/// Parse SETTINGS frame payload into typed settings.
/// All settings are preserved, including unknown IDs (as `H2SettingId::Unknown`).
fn parse_settings(payload: &[u8]) -> Vec<H2Setting> {
    let mut settings = Vec::new();
    let mut pos = 0;
    while pos + 6 <= payload.len() {
        let raw_id = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let value = u32::from_be_bytes([
            payload[pos + 2],
            payload[pos + 3],
            payload[pos + 4],
            payload[pos + 5],
        ]);
        let id = H2SettingId::from_wire(raw_id);
        settings.push(H2Setting { id, value });
        pos += 6;
    }
    settings
}

/// Parse WINDOW_UPDATE frame payload.
fn parse_window_update(payload: &[u8]) -> u32 {
    if payload.len() >= 4 {
        u32::from_be_bytes([payload[0] & 0x7f, payload[1], payload[2], payload[3]])
    } else {
        0
    }
}

/// Parse PRIORITY frame payload.
fn parse_priority_payload(stream_id: u32, payload: &[u8]) -> Option<H2PriorityFrame> {
    if payload.len() < 5 {
        return None;
    }
    let exclusive = payload[0] & 0x80 != 0;
    let depends_on = u32::from_be_bytes([payload[0] & 0x7f, payload[1], payload[2], payload[3]]);
    let weight = payload[4];
    Some(H2PriorityFrame {
        stream_id,
        exclusive,
        dependency: depends_on,
        weight,
    })
}

/// Extract priority data from HEADERS frame payload (if PRIORITY flag is set).
fn extract_headers_priority(payload: &[u8], flags: u8) -> Option<H2HeadersPriority> {
    let mut pos = 0;
    // PADDED flag (0x08) — skip pad length byte
    if flags & 0x08 != 0 && !payload.is_empty() {
        pos = 1;
    }
    // PRIORITY flag (0x20)
    if flags & 0x20 != 0 && pos + 5 <= payload.len() {
        let exclusive = payload[pos] & 0x80 != 0;
        let dep = u32::from_be_bytes([
            payload[pos] & 0x7f,
            payload[pos + 1],
            payload[pos + 2],
            payload[pos + 3],
        ]);
        let weight = payload[pos + 4];
        Some(H2HeadersPriority {
            stream_dependency: dep,
            weight,
            exclusive,
        })
    } else {
        None
    }
}

/// Extract the HPACK block from a HEADERS frame payload, stripping PADDED/PRIORITY.
fn extract_hpack_block(payload: &[u8], flags: u8) -> &[u8] {
    let mut pos = 0;
    let mut end = payload.len();

    // PADDED flag (0x08)
    if flags & 0x08 != 0 && !payload.is_empty() {
        let pad_length = payload[0] as usize;
        pos = 1;
        end = end.saturating_sub(pad_length);
    }

    // PRIORITY flag (0x20)
    if flags & 0x20 != 0 && pos + 5 <= payload.len() {
        pos += 5;
    }

    if pos <= end && end <= payload.len() {
        &payload[pos..end]
    } else {
        &[]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HPACK pseudo-header extraction
// ─────────────────────────────────────────────────────────────────────────────

/// HPACK static table: index → pseudo-header name.
fn hpack_static_pseudo_header(index: usize) -> Option<&'static str> {
    match index {
        1 => Some(":authority"),
        2 | 3 => Some(":method"),
        4 | 5 => Some(":path"),
        6 | 7 => Some(":scheme"),
        8..=14 => Some(":status"), // server-only
        _ => None,
    }
}

/// Decode an HPACK integer with the given prefix bit width.
fn decode_hpack_integer(data: &[u8], prefix_bits: u8) -> (usize, usize) {
    if data.is_empty() {
        return (0, 0);
    }
    let mask = (1u16 << prefix_bits) - 1;
    let value = (data[0] & mask as u8) as usize;
    if value < mask as usize {
        return (value, 1);
    }
    let mut result = mask as usize;
    let mut shift = 0usize;
    let mut i = 1;
    while i < data.len() {
        let b = data[i];
        result += ((b & 0x7f) as usize) << shift;
        shift += 7;
        i += 1;
        if b & 0x80 == 0 {
            break;
        }
    }
    (result, i)
}

/// Skip over an HPACK string (Huffman or raw).
fn skip_hpack_string(data: &[u8]) -> usize {
    if data.is_empty() {
        return 0;
    }
    let (length, header_bytes) = decode_hpack_integer(data, 7);
    header_bytes + length
}

/// Extract pseudo-header order from HPACK-encoded header block data.
fn extract_pseudo_header_order(hpack_data: &[u8]) -> Vec<H2PseudoHeaderId> {
    let mut result = Vec::new();
    let mut pos = 0;

    while pos < hpack_data.len() {
        let byte = hpack_data[pos];

        if byte & 0x80 != 0 {
            // Indexed header field (1xxxxxxx)
            let (index, consumed) = decode_hpack_integer(&hpack_data[pos..], 7);
            pos += consumed;
            if let Some(name) = hpack_static_pseudo_header(index) {
                if let Some(id) = pseudo_header_name_to_id(name) {
                    result.push(id);
                }
            } else {
                break;
            }
        } else if byte & 0xc0 == 0x40 {
            // Literal with incremental indexing (01xxxxxx)
            let (name_index, consumed) = decode_hpack_integer(&hpack_data[pos..], 6);
            pos += consumed;
            if name_index > 0 {
                if let Some(name) = hpack_static_pseudo_header(name_index) {
                    if let Some(id) = pseudo_header_name_to_id(name) {
                        result.push(id);
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            } else {
                // Literal name — peek to check if it's a pseudo-header
                if pos < hpack_data.len() {
                    let (str_len, str_header) = decode_hpack_integer(&hpack_data[pos..], 7);
                    let is_huffman = hpack_data[pos] & 0x80 != 0;
                    let name_start = pos + str_header;
                    if !is_huffman && name_start + str_len <= hpack_data.len() {
                        if let Ok(name) =
                            std::str::from_utf8(&hpack_data[name_start..name_start + str_len])
                        {
                            if let Some(id) = pseudo_header_name_to_id(name) {
                                result.push(id);
                            } else {
                                break;
                            }
                        }
                    }
                }
                let name_consumed = skip_hpack_string(&hpack_data[pos..]);
                pos += name_consumed;
            }
            // Skip value string
            pos += skip_hpack_string(&hpack_data[pos..]);
        } else if byte & 0xe0 == 0x20 {
            // Dynamic table size update (001xxxxx)
            let (_, consumed) = decode_hpack_integer(&hpack_data[pos..], 5);
            pos += consumed;
        } else {
            // Literal without indexing (0000xxxx) or never indexed (0001xxxx)
            let (name_index, consumed) = decode_hpack_integer(&hpack_data[pos..], 4);
            pos += consumed;
            if name_index > 0 {
                if let Some(name) = hpack_static_pseudo_header(name_index) {
                    if let Some(id) = pseudo_header_name_to_id(name) {
                        result.push(id);
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
            pos += skip_hpack_string(&hpack_data[pos..]);
        }
    }

    result
}

fn pseudo_header_name_to_id(name: &str) -> Option<H2PseudoHeaderId> {
    match name {
        ":method" => Some(H2PseudoHeaderId::Method),
        ":authority" => Some(H2PseudoHeaderId::Authority),
        ":scheme" => Some(H2PseudoHeaderId::Scheme),
        ":path" => Some(H2PseudoHeaderId::Path),
        _ => None, // :status and unknown
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Priority config inference
// ─────────────────────────────────────────────────────────────────────────────

/// Check if an HPACK block contains a `priority` HTTP header.
///
/// Does a best-effort scan for the literal header name "priority" in the
/// HPACK data. This catches both indexed and literal representations.
fn hpack_block_contains_priority_header(hpack_data: &[u8]) -> bool {
    // Fast path: look for the raw bytes "priority" in the HPACK data.
    // This works for literal representations (non-Huffman).
    // For a more robust check we'd need full HPACK decoding, but this
    // is sufficient for the common case.
    let needle = b"priority";
    hpack_data.windows(needle.len()).any(|w| w == needle)
}

/// Infer `H2PriorityConfig` from captured HEADERS frame data.
///
/// Returns `Some` when enough information is available to make a
/// useful inference, `None` otherwise.
fn infer_priority_config(
    first_headers_priority: &Option<H2HeadersPriority>,
    all_headers_deps: &[(u32, u32, u8, bool)], // (stream_id, dep, weight, exclusive)
    has_priority_header: bool,
    observed_weights: &[u8],
) -> Option<H2PriorityConfig> {
    // No HEADERS priority at all → might be Safari 26 (NO_RFC7540_PRIORITIES)
    // Still useful to record auto_priority_header.
    if first_headers_priority.is_none() && !has_priority_header {
        return None;
    }

    let exclusive = first_headers_priority
        .as_ref()
        .map(|hp| hp.exclusive)
        .unwrap_or(false);

    // Infer stream dependency policy from multiple HEADERS frames.
    // Chain: stream 3 depends on 1, stream 5 depends on 3, etc.
    // Flat: all streams depend on 0.
    let stream_dep_policy = if all_headers_deps.len() >= 2 {
        let is_chain = all_headers_deps.windows(2).all(|pair| {
            let (prev_stream, _, _, _) = pair[0];
            let (_, dep, _, _) = pair[1];
            dep == prev_stream
        });
        if is_chain {
            H2StreamDepPolicy::Chain
        } else {
            H2StreamDepPolicy::Flat
        }
    } else {
        H2StreamDepPolicy::Flat
    };

    // Try to infer urgency_weights from observed weight values.
    // Chrome uses a known mapping: [255, 219, 146, 110, 73, 36, 0, 0].
    // If we see these characteristic values, we can identify Chrome.
    let chrome_weights: [u8; 8] = [255, 219, 146, 110, 73, 36, 0, 0];
    let urgency_weights = if observed_weights.len() >= 2 {
        let all_chrome = observed_weights.iter().all(|w| chrome_weights.contains(w));
        if all_chrome && observed_weights.iter().any(|w| *w != observed_weights[0]) {
            Some(chrome_weights)
        } else {
            None
        }
    } else {
        None
    };

    Some(H2PriorityConfig {
        urgency_weights,
        exclusive,
        stream_dep_policy,
        auto_priority_header: has_priority_header,
        default_urgency: 3,
        default_incremental: false,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Akamai fingerprint computation
// ─────────────────────────────────────────────────────────────────────────────

fn pseudo_header_id_to_short(id: &H2PseudoHeaderId) -> &'static str {
    match id {
        H2PseudoHeaderId::Method => "m",
        H2PseudoHeaderId::Authority => "a",
        H2PseudoHeaderId::Scheme => "s",
        H2PseudoHeaderId::Path => "p",
    }
}

fn compute_akamai_fingerprint(profile: &H2ProfileData) -> String {
    let settings_str: String = profile
        .settings
        .iter()
        .map(|s| format!("{}:{}", s.id.to_wire(), s.value))
        .collect::<Vec<_>>()
        .join(";");

    let wu_str = profile.window_update.to_string();

    let priority_str = if profile.priority_frames.is_empty() {
        "0".to_string()
    } else {
        profile
            .priority_frames
            .iter()
            .map(|p| {
                format!(
                    "{}:{}:{}:{}",
                    p.stream_id,
                    if p.exclusive { 1 } else { 0 },
                    p.dependency,
                    p.weight
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    };

    let ps_str: String = profile
        .pseudo_header_order
        .iter()
        .map(pseudo_header_id_to_short)
        .collect::<Vec<_>>()
        .join(",");

    format!("{settings_str}|{wu_str}|{priority_str}|{ps_str}")
}

fn md5_hex(input: &str) -> String {
    use md5::Digest;
    let hash = md5::Md5::digest(input.as_bytes());
    hex::encode(hash)
}

fn sha256_hex(input: &str) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(input.as_bytes());
    hex::encode(hash)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Parse HTTP/2 frames from raw bytes and build an [`H2Fingerprint`].
///
/// The input `data` should be the decrypted application-layer bytes from a
/// TLS connection, starting from the HTTP/2 connection preface
/// (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`).
///
/// The parser reads frames until it encounters a HEADERS frame (which provides
/// pseudo-header order), then stops.
///
/// # Errors
///
/// Returns [`ParseError`] if the data is truncated, the H2 preface is invalid,
/// or frames are malformed.
pub fn h2_fingerprint_from_frames(data: &[u8]) -> Result<H2Fingerprint, ParseError> {
    let mut cursor = Cursor::new(data);

    // Read and validate H2 preface
    let mut preface = [0u8; 24];
    cursor.read_exact(&mut preface)?;
    if &preface != H2_PREFACE {
        return Err(ParseError::UnexpectedValue(format!(
            "invalid H2 preface: {:?}",
            String::from_utf8_lossy(&preface)
        )));
    }

    let mut settings = Vec::new();
    let mut window_update: u32 = 0;
    let mut priority_frames = Vec::new();
    let mut pseudo_header_order = Vec::new();
    let mut headers_priority = None;
    let mut first_headers_seen = false;

    // Extended capture: collect priority info from multiple HEADERS frames
    // to infer PriorityConfig fields.
    let mut headers_stream_deps: Vec<(u32, u32, u8, bool)> = Vec::new(); // (stream_id, dep, weight, exclusive)
    let mut has_priority_header = false;
    let mut observed_weights: Vec<u8> = Vec::new();

    for _ in 0..100 {
        let frame = match read_h2_frame(&mut cursor) {
            Ok(f) => f,
            Err(_) => break,
        };

        match frame.frame_type {
            H2_SETTINGS => {
                if frame.flags & 0x01 != 0 {
                    continue; // ACK
                }
                if !first_headers_seen {
                    settings = parse_settings(&frame.payload);
                }
            }
            H2_WINDOW_UPDATE if frame.stream_id == 0 && !first_headers_seen => {
                window_update = parse_window_update(&frame.payload);
            }
            H2_PRIORITY if !first_headers_seen => {
                if let Some(p) = parse_priority_payload(frame.stream_id, &frame.payload) {
                    priority_frames.push(p);
                }
            }
            H2_HEADERS => {
                let hp = extract_headers_priority(&frame.payload, frame.flags);
                let hpack_block = extract_hpack_block(&frame.payload, frame.flags);

                if !first_headers_seen {
                    headers_priority = hp.clone();
                    pseudo_header_order = extract_pseudo_header_order(hpack_block);
                    first_headers_seen = true;
                }

                if let Some(ref hp) = hp {
                    headers_stream_deps.push((
                        frame.stream_id,
                        hp.stream_dependency,
                        hp.weight,
                        hp.exclusive,
                    ));
                    observed_weights.push(hp.weight);
                }

                if !has_priority_header {
                    has_priority_header = hpack_block_contains_priority_header(hpack_block);
                }
            }
            _ => {}
        }
    }

    let priority_config = infer_priority_config(
        &headers_priority,
        &headers_stream_deps,
        has_priority_header,
        &observed_weights,
    );

    let profile = H2ProfileData {
        settings,
        window_update,
        pseudo_header_order,
        headers_priority,
        priority_frames,
        priority_config,
    };

    let akamai_fingerprint = compute_akamai_fingerprint(&profile);
    let akamai_hash = md5_hex(&akamai_fingerprint);
    let akamai_hash_sha256 = sha256_hex(&akamai_fingerprint);

    Ok(H2Fingerprint {
        profile,
        akamai_fingerprint,
        akamai_hash,
        akamai_hash_sha256,
    })
}

/// Parse HTTP/2 frames from raw bytes **without** the connection preface.
///
/// Use this when the H2 preface has already been consumed (e.g. by a proxy
/// or capture tool that strips it). The input should start directly with
/// H2 frame data.
pub fn h2_fingerprint_from_frames_no_preface(data: &[u8]) -> Result<H2Fingerprint, ParseError> {
    let mut with_preface = Vec::with_capacity(H2_PREFACE.len() + data.len());
    with_preface.extend_from_slice(H2_PREFACE);
    with_preface.extend_from_slice(data);
    h2_fingerprint_from_frames(&with_preface)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h2_settings_parsing() {
        let payload = [
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // id=1 value=65536
            0x00, 0x03, 0x00, 0x00, 0x03, 0xe8, // id=3 value=1000
        ];
        let settings = parse_settings(&payload);
        assert_eq!(settings.len(), 2);
        assert_eq!(settings[0].id, H2SettingId::HeaderTableSize);
        assert_eq!(settings[0].value, 65536);
        assert_eq!(settings[1].id, H2SettingId::MaxConcurrentStreams);
        assert_eq!(settings[1].value, 1000);
    }

    #[test]
    fn test_h2_window_update_parsing() {
        let payload = [0x00, 0xef, 0x00, 0x01];
        let increment = parse_window_update(&payload);
        assert_eq!(increment, 0x00ef0001);
    }

    #[test]
    fn test_akamai_fingerprint_computation() {
        let profile = H2ProfileData {
            settings: vec![
                H2Setting {
                    id: H2SettingId::HeaderTableSize,
                    value: 65536,
                },
                H2Setting {
                    id: H2SettingId::MaxConcurrentStreams,
                    value: 1000,
                },
                H2Setting {
                    id: H2SettingId::InitialWindowSize,
                    value: 6291456,
                },
                H2Setting {
                    id: H2SettingId::MaxHeaderListSize,
                    value: 262144,
                },
            ],
            window_update: 15663105,
            pseudo_header_order: vec![
                H2PseudoHeaderId::Method,
                H2PseudoHeaderId::Authority,
                H2PseudoHeaderId::Scheme,
                H2PseudoHeaderId::Path,
            ],
            headers_priority: None,
            priority_frames: vec![],
            priority_config: None,
        };
        let fp = compute_akamai_fingerprint(&profile);
        assert_eq!(fp, "1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p");
    }

    #[test]
    fn test_hpack_pseudo_header_extraction_indexed() {
        let mut data = Vec::new();
        data.push(0x82); // :method GET
        data.push(0x41); // :authority (literal incremental, index 1)
        data.push(0x09); // value length
        data.extend_from_slice(b"localhost");
        data.push(0x87); // :scheme https
        data.push(0x84); // :path /
                         // non-pseudo header
        data.push(0x40); // literal incremental: index 0 = literal name
        data.push(0x0a);
        data.extend_from_slice(b"user-agent");
        data.push(0x05);
        data.extend_from_slice(b"test/");

        let order = extract_pseudo_header_order(&data);
        assert_eq!(
            order,
            vec![
                H2PseudoHeaderId::Method,
                H2PseudoHeaderId::Authority,
                H2PseudoHeaderId::Scheme,
                H2PseudoHeaderId::Path,
            ]
        );
    }

    #[test]
    #[allow(clippy::vec_init_then_push)]
    fn test_hpack_pseudo_header_firefox_order() {
        let mut data = Vec::new();
        data.push(0x82); // :method GET
        data.push(0x84); // :path /
        data.push(0x41); // :authority
        data.push(0x09);
        data.extend_from_slice(b"localhost");
        data.push(0x87); // :scheme https

        let order = extract_pseudo_header_order(&data);
        assert_eq!(
            order,
            vec![
                H2PseudoHeaderId::Method,
                H2PseudoHeaderId::Path,
                H2PseudoHeaderId::Authority,
                H2PseudoHeaderId::Scheme,
            ]
        );
    }

    #[test]
    fn test_hpack_integer_decode() {
        assert_eq!(decode_hpack_integer(&[0x82], 7), (2, 1));
        assert_eq!(decode_hpack_integer(&[0x41], 6), (1, 1));
        assert_eq!(decode_hpack_integer(&[0xff, 0x00], 7), (127, 2));
    }

    #[test]
    fn test_extract_hpack_block_with_padding() {
        let payload = [
            0x03, // pad_length = 3
            0x82, 0x84, // HPACK data
            0x00, 0x00, 0x00, // padding
        ];
        let block = extract_hpack_block(&payload, 0x08);
        assert_eq!(block, &[0x82, 0x84]);
    }

    #[test]
    fn test_extract_hpack_block_with_priority() {
        let payload = [
            0x80, 0x00, 0x00, 0x00, 0x0f, // priority
            0x82, 0x84, // HPACK data
        ];
        let block = extract_hpack_block(&payload, 0x20);
        assert_eq!(block, &[0x82, 0x84]);
    }

    #[test]
    fn test_headers_priority_extraction() {
        let payload = [
            0x80, 0x00, 0x00, 0x00, // exclusive=1, dep=0
            0x00, // weight=0
            0x82, 0x84, // HPACK data
        ];
        let hp = extract_headers_priority(&payload, 0x20).unwrap();
        assert!(hp.exclusive);
        assert_eq!(hp.stream_dependency, 0);
        assert_eq!(hp.weight, 0);
    }

    #[test]
    fn test_md5_hex() {
        let hash = md5_hex("test");
        assert_eq!(hash, "098f6bcd4621d373cade4e832627b4f6");
    }

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex("test");
        assert_eq!(
            hash,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn test_full_h2_frame_parsing() {
        let mut data = Vec::new();
        // H2 preface
        data.extend_from_slice(H2_PREFACE);
        // SETTINGS frame: HEADER_TABLE_SIZE=65536
        data.extend_from_slice(&[
            0x00, 0x00, 0x06, // length=6
            0x04, // type=SETTINGS
            0x00, // flags=0
            0x00, 0x00, 0x00, 0x00, // stream=0
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // id=1 value=65536
        ]);
        // WINDOW_UPDATE frame: increment=15663105
        data.extend_from_slice(&[
            0x00, 0x00, 0x04, // length=4
            0x08, // type=WINDOW_UPDATE
            0x00, // flags=0
            0x00, 0x00, 0x00, 0x00, // stream=0
            0x00, 0xef, 0x00, 0x01, // increment=0x00EF0001
        ]);
        // HEADERS frame (with PRIORITY flag): :method GET, :path /
        let hpack_block = vec![0x82, 0x84]; // :method GET, :path /
        let priority_data = vec![0x80, 0x00, 0x00, 0x00, 0x00]; // exclusive=1, dep=0, weight=0
        let payload_len = priority_data.len() + hpack_block.len();
        data.push(((payload_len >> 16) & 0xff) as u8);
        data.push(((payload_len >> 8) & 0xff) as u8);
        data.push((payload_len & 0xff) as u8);
        data.push(0x01); // type=HEADERS
        data.push(0x25); // flags=END_STREAM|END_HEADERS|PRIORITY
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // stream=1
        data.extend_from_slice(&priority_data);
        data.extend_from_slice(&hpack_block);

        let fp = h2_fingerprint_from_frames(&data).unwrap();
        assert_eq!(fp.profile.settings.len(), 1);
        assert_eq!(fp.profile.settings[0].id, H2SettingId::HeaderTableSize);
        assert_eq!(fp.profile.settings[0].value, 65536);
        assert_eq!(fp.profile.window_update, 0x00ef0001);
        assert_eq!(
            fp.profile.pseudo_header_order,
            vec![H2PseudoHeaderId::Method, H2PseudoHeaderId::Path]
        );
        let hp = fp.profile.headers_priority.as_ref().unwrap();
        assert!(hp.exclusive);
        assert_eq!(hp.stream_dependency, 0);
        assert_eq!(hp.weight, 0);

        // priority_config should be inferred from the single HEADERS frame
        let pc = fp.profile.priority_config.as_ref().unwrap();
        assert!(pc.exclusive);
        assert_eq!(pc.stream_dep_policy, H2StreamDepPolicy::Flat);
    }

    #[test]
    fn test_priority_config_infer_chain_dep() {
        // Two HEADERS frames: stream 1 dep=0, stream 3 dep=1 → Chain
        let deps = vec![(1, 0, 255, true), (3, 1, 219, true)];
        let config = super::infer_priority_config(
            &Some(H2HeadersPriority {
                stream_dependency: 0,
                weight: 255,
                exclusive: true,
            }),
            &deps,
            true,
            &[255, 219],
        );
        let pc = config.unwrap();
        assert_eq!(pc.stream_dep_policy, H2StreamDepPolicy::Chain);
        assert!(pc.exclusive);
        assert!(pc.auto_priority_header);
        // Both 255 and 219 are Chrome weights → should detect Chrome weights
        assert!(pc.urgency_weights.is_some());
    }

    #[test]
    fn test_priority_config_infer_flat_dep() {
        // Three HEADERS frames all depending on 0 → Flat (Firefox-style)
        let deps = vec![(1, 0, 42, false), (3, 0, 42, false), (5, 0, 42, false)];
        let config = super::infer_priority_config(
            &Some(H2HeadersPriority {
                stream_dependency: 0,
                weight: 42,
                exclusive: false,
            }),
            &deps,
            true,
            &[42, 42, 42],
        );
        let pc = config.unwrap();
        assert_eq!(pc.stream_dep_policy, H2StreamDepPolicy::Flat);
        assert!(!pc.exclusive);
        assert!(pc.auto_priority_header);
        // All same weight, not Chrome values → no urgency_weights
        assert!(pc.urgency_weights.is_none());
    }

    #[test]
    fn test_priority_config_none_when_no_priority() {
        let config = super::infer_priority_config(&None, &[], false, &[]);
        assert!(config.is_none());
    }

    #[test]
    fn test_hpack_block_contains_priority_header() {
        let with = b"\x82\x84\x00\x08priorityu=1, i";
        assert!(super::hpack_block_contains_priority_header(with));

        let without = b"\x82\x84\x00\x0auser-agenttest";
        assert!(!super::hpack_block_contains_priority_header(without));
    }
}
