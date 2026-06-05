//! HTTP/2 fingerprint profile — controls H2-level fingerprint dimensions.
//!
//! The `H2Profile` data structure describes the HTTP/2 connection parameters
//! that affect the Akamai H2 fingerprint:
//!
//! - SETTINGS frame parameters and their order
//! - Connection-level WINDOW_UPDATE value
//! - Pseudo-header order (`:method`, `:authority`, `:scheme`, `:path`)
//! - HEADERS frame priority (stream dependency embedded in HEADERS frames)
//! - Optional initial PRIORITY frames sent after connection setup
//!
//! These are applied through lkh2's native HTTP/2 engine, which provides
//! fine-grained frame and HPACK control.

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::policy::H2Behavior;

/// Complete HTTP/2 fingerprint configuration.
///
/// Contains two layers of information:
///
/// - **Identity** (serialisable): SETTINGS, WINDOW_UPDATE, pseudo-header
///   order, HEADERS priority — the Akamai fingerprint dimensions.
/// - **Behaviour** (runtime): how frames are grouped into
///   TLS records, when WINDOW_UPDATE is sent, HPACK encoding choices.
///
/// Built-in presets (`chrome_144_h2()`, etc.) populate both layers.
/// Profiles loaded from JSON get `None` for `behavior` and will use
/// the baseline behaviour unless explicitly overridden via
/// `with_behavior()`.
///
/// # Example (Chrome 144)
///
/// ```text
/// SETTINGS:       1:65536;2:0;4:6291456;6:262144
/// WINDOW_UPDATE:  15663105
/// Pseudo order:   :method, :authority, :scheme, :path  (m,a,s,p)
/// Akamai hash:    52d84b11737d980aef856699f885ca86
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H2Profile {
    /// Ordered list of SETTINGS parameters.
    ///
    /// The order matters for the Akamai fingerprint. Each entry specifies
    /// the setting ID and its value.
    pub settings: Vec<H2Setting>,

    /// Connection-level WINDOW_UPDATE increment.
    ///
    /// Sent immediately after the SETTINGS frame. For Chrome 144 this is
    /// 15663105 (meaning initial_connection_window = 65535 + 15663105 = 15728640).
    pub window_update: u32,

    /// Pseudo-header order for HEADERS frames.
    ///
    /// Controls the order of `:method`, `:authority`, `:scheme`, `:path`
    /// in the HEADERS frame. Chrome uses `[Method, Authority, Scheme, Path]`.
    pub pseudo_header_order: Vec<PseudoHeaderId>,

    /// Optional stream dependency to embed in every outgoing HEADERS frame.
    ///
    /// When set, the HEADERS frame will include the PRIORITY flag (0x20)
    /// and carry 5 extra bytes specifying stream dependency, weight, and
    /// the exclusive bit.
    ///
    /// # Browser behaviour
    ///
    /// - **Chrome 144**: `{ dependency: 0, weight: 0, exclusive: true }`
    ///   → `flags_raw = 0x25` (END_STREAM | END_HEADERS | PRIORITY)
    /// - **Firefox 147**: `{ dependency: 0, weight: 42, exclusive: false }`
    ///   → `flags_raw = 0x25`
    /// - **Safari 26**: `None` (sends `NO_RFC7540_PRIORITIES=1`, no PRIORITY flag)
    #[serde(default)]
    pub headers_priority: Option<HeadersPriority>,

    /// Optional initial PRIORITY frames to send after connection setup.
    ///
    /// These standalone PRIORITY frames are sent right after the SETTINGS +
    /// WINDOW_UPDATE exchange, before the first request HEADERS frame.
    /// Modern Chrome (≥ 100) does **not** send any; older Chrome and some
    /// other clients may send several to pre-build the dependency tree.
    #[serde(default)]
    pub priority_frames: Vec<ProfilePriorityFrame>,

    /// Per-browser priority strategy controlling how `RequestPriority`
    /// maps to H2 wire-level weight, stream dependencies, and HTTP headers.
    ///
    /// Built-in presets populate this automatically (e.g. `PriorityConfig::chrome()`).
    /// JSON-loaded profiles get the `Default` (no dynamic mapping).
    #[serde(default)]
    pub priority_config: PriorityConfig,

    /// Behaviour strategies for the native engine (frame grouping,
    /// flow control, HPACK encoding).
    ///
    /// - Built-in presets populate this automatically.
    /// - JSON-loaded profiles get `None` → baseline behaviour.
    /// - Override with `with_behavior()`.
    ///
    /// Skipped during serialisation.
    #[serde(skip)]
    pub behavior: Option<H2Behavior>,
}

/// A single HTTP/2 SETTINGS parameter (id + value).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H2Setting {
    /// The SETTINGS parameter identifier.
    pub id: H2SettingId,
    /// The value for this setting.
    pub value: u32,
}

/// Well-known HTTP/2 SETTINGS parameter identifiers.
///
/// Variants are kept in sync with `lkprofile::H2SettingId` so that profiles
/// captured by `lkprofile` can be deserialized into this type without errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum H2SettingId {
    /// SETTINGS_HEADER_TABLE_SIZE (0x1)
    HeaderTableSize,
    /// SETTINGS_ENABLE_PUSH (0x2)
    EnablePush,
    /// SETTINGS_MAX_CONCURRENT_STREAMS (0x3)
    MaxConcurrentStreams,
    /// SETTINGS_INITIAL_WINDOW_SIZE (0x4)
    InitialWindowSize,
    /// SETTINGS_MAX_FRAME_SIZE (0x5)
    MaxFrameSize,
    /// SETTINGS_MAX_HEADER_LIST_SIZE (0x6)
    MaxHeaderListSize,
    /// SETTINGS_ENABLE_CONNECT_PROTOCOL (0x8, RFC 8441)
    EnableConnectProtocol,
    /// SETTINGS_NO_RFC7540_PRIORITIES (0x9)
    /// Used by Safari 26+ to indicate RFC 9218 extensible priorities.
    NoRfc7540Priorities,
    /// Unknown/non-standard SETTINGS ID — preserved for lossless fingerprinting.
    #[serde(untagged)]
    Unknown(u16),
}

/// Pseudo-header identifier for controlling HEADERS frame pseudo-header order.
///
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PseudoHeaderId {
    /// `:method`
    Method,
    /// `:authority`
    Authority,
    /// `:scheme`
    Scheme,
    /// `:path`
    Path,
}

/// Stream dependency to embed in HEADERS frames (adds PRIORITY flag).
///
/// When applied, each outgoing HEADERS frame carries an extra 5-byte
/// priority payload: `[E | Stream Dependency (31 bits)] [Weight (8 bits)]`.
/// This sets the PRIORITY flag (0x20) on the frame.
///
/// The wire format matches RFC 7540 §6.2 (HEADERS frame with PRIORITY).
///
/// # Weight semantics
///
/// The `weight` field uses the **wire-level** range `0..=255`, which the
/// HTTP/2 spec maps to `1..=256`.  A wire value of `0` means weight 1
/// (lowest priority).  This matches what Chrome sends (`weight: 0`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadersPriority {
    /// The stream ID this stream depends on (0 = root of the dependency tree).
    #[serde(default)]
    pub stream_dependency: u32,
    /// The weight for the stream (wire range 0–255, representing 1–256).
    #[serde(default)]
    pub weight: u8,
    /// Whether the dependency is exclusive.
    #[serde(default)]
    pub exclusive: bool,
}

/// An HTTP/2 PRIORITY frame configuration for connection setup.
///
/// Distinct from `frame::PriorityFrame` which is the wire-level representation.
/// This struct is used for JSON profile deserialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilePriorityFrame {
    /// The stream ID this priority applies to.
    pub stream_id: u32,
    /// The stream dependency.
    pub dependency: u32,
    /// The weight (1-256).
    pub weight: u8,
    /// Whether the dependency is exclusive.
    #[serde(default)]
    pub exclusive: bool,
}

// ---------------------------------------------------------------------------
// Request-level priority (RFC 9218)
// ---------------------------------------------------------------------------

/// RFC 9218 request priority — the common source from which both the HTTP
/// `priority` header and the H2 HEADERS frame weight are derived.
///
/// In a real browser the resource type (navigation, XHR, image, …)
/// determines an urgency level; the browser then uses that single value
/// to produce both the HTTP `priority` header and the H2 frame weight.
///
/// # Examples
///
/// ```
/// use lkh2::profile::RequestPriority;
///
/// let p = RequestPriority::fetch();   // u=1, incremental=true
/// assert_eq!(p.urgency, 1);
///
/// let p = RequestPriority::image();   // u=2, incremental=true (Chrome 148)
/// assert_eq!(p.urgency, 2);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestPriority {
    /// Urgency level 0–7 (RFC 9218 §4.1).
    /// Lower values indicate higher priority.
    pub urgency: u8,
    /// Whether the response can be processed incrementally (RFC 9218 §4.2).
    pub incremental: bool,
}

impl RequestPriority {
    /// Navigation / top-level document request.
    ///
    /// Captured from real Chrome 148: `u=0, i`.
    pub fn navigation() -> Self {
        Self {
            urgency: 0,
            incremental: true,
        }
    }

    /// XHR / fetch request. Captured from real Chrome 148: `u=1, i`.
    pub fn fetch() -> Self {
        Self {
            urgency: 1,
            incremental: true,
        }
    }

    /// Render-blocking stylesheet (`<link rel=stylesheet>`).
    ///
    /// Captured from real Chrome 148: `u=0` (not incremental).
    pub fn css() -> Self {
        Self {
            urgency: 0,
            incremental: false,
        }
    }

    /// Parser-inserted script (`<script src>`).
    ///
    /// Captured from real Chrome 148: `u=1` (not incremental).
    pub fn script() -> Self {
        Self {
            urgency: 1,
            incremental: false,
        }
    }

    /// Image resource (`<img>`). Captured from real Chrome 148: `u=2, i`.
    pub fn image() -> Self {
        Self {
            urgency: 2,
            incremental: true,
        }
    }

    /// Background / low-priority resource (u=3).
    pub fn background() -> Self {
        Self {
            urgency: 3,
            incremental: false,
        }
    }

    /// Custom urgency and incremental flag.
    pub fn custom(urgency: u8, incremental: bool) -> Self {
        Self {
            urgency: urgency.min(7),
            incremental,
        }
    }

    /// Derive the priority from a `Sec-Fetch-Dest` fetch-destination value,
    /// mirroring Chrome's resource-type → priority mapping (captured from real
    /// Chrome 148). Returns `None` for destinations without a captured mapping,
    /// so the caller falls back to its default.
    pub fn from_sec_fetch_dest(dest: &str) -> Option<Self> {
        Some(match dest {
            "document" | "iframe" | "frame" => Self::navigation(), // u=0, i
            "style" => Self::css(),                                // u=0
            "script" => Self::script(),                            // u=1
            "image" => Self::image(),                              // u=2, i
            "empty" => Self::fetch(),                              // u=1, i (fetch/XHR)
            _ => return None,
        })
    }

    /// Format as the RFC 9218 `priority` HTTP header value.
    ///
    /// Produces `"u=N, i"` when incremental is true, `"u=N"` otherwise.
    pub fn to_header_value(&self) -> String {
        if self.incremental {
            format!("u={}, i", self.urgency)
        } else {
            format!("u={}", self.urgency)
        }
    }

    /// Parse from an RFC 9218 `priority` header value.
    ///
    /// Accepts formats like `"u=1, i"`, `"u=2"`, `"u=1,i"`.
    /// Returns `None` if the value cannot be parsed.
    pub fn from_header_value(value: &str) -> Option<Self> {
        let mut urgency: Option<u8> = None;
        let mut incremental = false;

        for part in value.split(',') {
            let part = part.trim();
            if let Some(rest) = part.strip_prefix("u=") {
                urgency = rest.trim().parse::<u8>().ok().map(|v| v.min(7));
            } else if part == "i" {
                incremental = true;
            } else if let Some(rest) = part.strip_prefix("i=") {
                let rest = rest.trim();
                incremental = rest == "?1" || rest == "1";
            }
        }

        urgency.map(|u| Self {
            urgency: u,
            incremental,
        })
    }
}

impl Default for RequestPriority {
    /// Default: u=3 (RFC 9218 default urgency), not incremental.
    fn default() -> Self {
        Self {
            urgency: 3,
            incremental: false,
        }
    }
}

/// Per-browser priority strategy — controls how `RequestPriority` maps
/// to H2 wire-level priority and HTTP headers.
///
/// Embedded in `H2Profile` and populated by browser presets.
/// Users normally do not need to configure this directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityConfig {
    /// Maps urgency levels 0–7 to H2 wire weight (0–255).
    ///
    /// When `Some`, the engine uses `urgency_weights[urgency]` as the
    /// HEADERS frame weight instead of the static `headers_priority.weight`.
    ///
    /// When `None`, the engine falls back to the fixed
    /// `headers_priority.weight` for all requests (Firefox-style).
    #[serde(default)]
    pub urgency_weights: Option<[u8; 8]>,

    /// Whether the exclusive bit is set on HEADERS priority.
    /// Only used when `urgency_weights` is `Some`.
    #[serde(default)]
    pub exclusive: bool,

    /// How concurrent stream dependencies are formed.
    #[serde(default)]
    pub stream_dep_policy: StreamDepPolicy,

    /// Whether to auto-inject the RFC 9218 `priority` HTTP header.
    ///
    /// When `true`, if the request does not already contain a `priority`
    /// header, one is generated from the active `RequestPriority`.
    #[serde(default)]
    pub auto_priority_header: bool,

    /// Default urgency when the caller does not specify one (0–7).
    #[serde(default = "default_urgency")]
    pub default_urgency: u8,

    /// Default incremental flag when the caller does not specify one.
    #[serde(default)]
    pub default_incremental: bool,
}

fn default_urgency() -> u8 {
    3
}

impl Default for PriorityConfig {
    fn default() -> Self {
        Self {
            urgency_weights: None,
            exclusive: false,
            stream_dep_policy: StreamDepPolicy::Flat,
            auto_priority_header: false,
            default_urgency: 3,
            default_incremental: false,
        }
    }
}

impl PriorityConfig {
    /// Chrome-like priority configuration.
    ///
    /// Urgency→weight mapping matches Chromium's `Urgency2Weight()`:
    /// u=0→255, u=1→219, u=2→146, u=3→110, u=4→73, u=5→36, u=6→0, u=7→0.
    pub fn chrome() -> Self {
        Self {
            urgency_weights: Some([255, 219, 146, 110, 73, 36, 0, 0]),
            exclusive: true,
            stream_dep_policy: StreamDepPolicy::Chain,
            auto_priority_header: true,
            default_urgency: 1,
            default_incremental: true,
        }
    }

    /// Firefox-like priority configuration.
    ///
    /// Firefox uses a fixed weight (42) for all requests regardless of
    /// urgency, so `urgency_weights` is `None` and the engine falls back
    /// to `headers_priority.weight`.
    pub fn firefox() -> Self {
        Self {
            urgency_weights: None,
            exclusive: false,
            stream_dep_policy: StreamDepPolicy::Flat,
            auto_priority_header: true,
            default_urgency: 3,
            default_incremental: false,
        }
    }

    /// Safari 18 priority configuration (RFC 7540 priorities, no HTTP header).
    pub fn safari18() -> Self {
        Self {
            urgency_weights: None,
            exclusive: true,
            stream_dep_policy: StreamDepPolicy::Flat,
            auto_priority_header: false,
            default_urgency: 3,
            default_incremental: false,
        }
    }

    /// Safari 26 priority configuration (RFC 9218 only, no H2 frame priority).
    pub fn safari26() -> Self {
        Self {
            urgency_weights: None,
            exclusive: false,
            stream_dep_policy: StreamDepPolicy::Flat,
            auto_priority_header: true,
            default_urgency: 3,
            default_incremental: false,
        }
    }

    /// Resolve the effective `RequestPriority`, filling in defaults.
    pub fn effective_priority(&self, explicit: Option<RequestPriority>) -> RequestPriority {
        explicit.unwrap_or(RequestPriority {
            urgency: self.default_urgency,
            incremental: self.default_incremental,
        })
    }

    /// Look up the H2 wire weight for a given urgency.
    ///
    /// Returns `None` if `urgency_weights` is not configured (use
    /// `headers_priority.weight` instead).
    pub fn weight_for_urgency(&self, urgency: u8) -> Option<u8> {
        self.urgency_weights.map(|w| w[urgency.min(7) as usize])
    }
}

/// Controls how concurrent H2 stream dependencies are formed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamDepPolicy {
    /// All streams depend on stream 0 (Firefox / Safari style).
    #[default]
    Flat,
    /// Each new stream depends on the previous client stream (Chrome style).
    ///
    /// Stream 1 → dep=0, stream 3 → dep=1, stream 5 → dep=3, etc.
    Chain,
}

// ---------------------------------------------------------------------------
// Built-in presets
// ---------------------------------------------------------------------------

/// Returns the Chrome 144 H2 fingerprint profile.
///
/// Akamai fingerprint: `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`
/// Akamai hash: `52d84b11737d980aef856699f885ca86`
///
/// HEADERS frame priority: `exclusive=1, dependency=0, weight=255`
/// (`flags_raw = 0x25`: END_STREAM | END_HEADERS | PRIORITY)
///
/// Chrome internally uses RFC 7540 semantic weight 256 (highest) for
/// navigation requests, serialized as `weight - 1 = 255` on the wire.
/// See Chromium `Spdy3PriorityToHttp2Weight(0) = 256` and
/// `spdy_framer.cc: builder.WriteUInt8(weight - 1)`.
pub fn chrome_144_h2() -> H2Profile {
    H2Profile {
        settings: vec![
            H2Setting {
                id: H2SettingId::HeaderTableSize,
                value: 65536,
            },
            H2Setting {
                id: H2SettingId::EnablePush,
                value: 0,
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
            PseudoHeaderId::Method,
            PseudoHeaderId::Authority,
            PseudoHeaderId::Scheme,
            PseudoHeaderId::Path,
        ],
        headers_priority: Some(HeadersPriority {
            stream_dependency: 0,
            weight: 255,
            exclusive: true,
        }),
        priority_frames: vec![],
        priority_config: PriorityConfig::chrome(),
        behavior: Some(H2Behavior::chrome()),
    }
}

/// Returns the Chrome 145 H2 fingerprint profile.
///
/// The capture-time build carried an experimental/Finch-gated GREASE SETTINGS
/// parameter (`6746:…`), but that is field-trial-variable and absent from
/// stable Chrome 148; the presets are kept consistent at the experiment-OFF
/// (default) state, so it is not emitted here.
/// Akamai: `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`
pub fn chrome_145_h2() -> H2Profile {
    H2Profile {
        settings: vec![
            H2Setting {
                id: H2SettingId::HeaderTableSize,
                value: 65536,
            },
            H2Setting {
                id: H2SettingId::EnablePush,
                value: 0,
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
            PseudoHeaderId::Method,
            PseudoHeaderId::Authority,
            PseudoHeaderId::Scheme,
            PseudoHeaderId::Path,
        ],
        headers_priority: Some(HeadersPriority {
            stream_dependency: 0,
            weight: 255,
            exclusive: true,
        }),
        priority_frames: vec![],
        priority_config: PriorityConfig::chrome(),
        behavior: Some(H2Behavior::chrome()),
    }
}

/// Returns the Chrome 146 H2 fingerprint profile.
///
/// Same H2 parameters as Chrome 144 (H2 fingerprint hasn't changed).
/// Akamai fingerprint: `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`
/// Akamai hash: `52d84b11737d980aef856699f885ca86`
pub fn chrome_146_h2() -> H2Profile {
    chrome_144_h2()
}

/// Returns the Chrome 147 H2 fingerprint profile.
///
/// Same as Chrome 144/146 per capture (`1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`).
pub fn chrome_147_h2() -> H2Profile {
    chrome_144_h2()
}

/// Returns the Chrome 148 H2 fingerprint profile.
///
/// Same as Chrome 144/146/147 per capture.
/// Akamai fingerprint: `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`
/// Akamai hash: `52d84b11737d980aef856699f885ca86`
pub fn chrome_148_h2() -> H2Profile {
    chrome_144_h2()
}

/// Returns the Chrome 149 H2 fingerprint profile.
///
/// Verified identical to Chrome 148 by capturing real Chrome 149.0.7827.54.
/// Akamai fingerprint: `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`
/// Akamai hash: `52d84b11737d980aef856699f885ca86`
pub fn chrome_149_h2() -> H2Profile {
    chrome_144_h2()
}

/// Returns the Chrome 131 H2 fingerprint profile.
///
/// Same H2 parameters as Chrome 144 (H2 fingerprint hasn't changed).
pub fn chrome_131_h2() -> H2Profile {
    chrome_144_h2()
}

/// Encode H2 SETTINGS as raw bytes for ALPS (Application-Layer Protocol Settings).
///
/// ALPS carries the H2 SETTINGS payload (without the HTTP/2 frame header)
/// inside the TLS ClientHello. Each setting is 6 bytes: id(2) + value(4).
///
/// This matches what Chrome sends in the ALPS extension during the TLS handshake.
pub fn encode_alps_h2_settings(profile: &H2Profile) -> Vec<u8> {
    let mut buf = Vec::with_capacity(profile.settings.len() * 6);
    for setting in &profile.settings {
        buf.extend_from_slice(&setting.id.as_u16().to_be_bytes());
        buf.extend_from_slice(&setting.value.to_be_bytes());
    }
    buf
}

/// Encode H2 SETTINGS as base64url (no padding) for the `HTTP2-Settings` header.
///
/// RFC 7540 §3.2.1: The content of the HTTP2-Settings header field is the
/// SETTINGS payload (Section 6.5.1), encoded as a base64url string (RFC 4648 §5)
/// with trailing padding omitted.
pub fn encode_h2_settings_base64url(profile: &H2Profile) -> String {
    let raw = encode_alps_h2_settings(profile);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

/// Returns the Firefox 133 H2 fingerprint profile.
///
/// Firefox uses different SETTINGS order and values, and different pseudo-header order:
/// `:method`, `:path`, `:authority`, `:scheme` (m,p,a,s)
///
/// Akamai fingerprint: `1:65536;4:131072;5:16384|12517377|0|m,p,a,s`
///
/// HEADERS frame priority: `exclusive=0, dependency=0, weight=42`
/// (same as Firefox 147 — H2 priority behaviour unchanged)
pub fn firefox_133_h2() -> H2Profile {
    H2Profile {
        settings: vec![
            H2Setting {
                id: H2SettingId::HeaderTableSize,
                value: 65536,
            },
            H2Setting {
                id: H2SettingId::InitialWindowSize,
                value: 131072,
            },
            H2Setting {
                id: H2SettingId::MaxFrameSize,
                value: 16384,
            },
        ],
        window_update: 12517377,
        pseudo_header_order: vec![
            PseudoHeaderId::Method,
            PseudoHeaderId::Path,
            PseudoHeaderId::Authority,
            PseudoHeaderId::Scheme,
        ],
        headers_priority: Some(HeadersPriority {
            stream_dependency: 0,
            weight: 42,
            exclusive: false,
        }),
        priority_frames: vec![],
        priority_config: PriorityConfig::firefox(),
        behavior: Some(H2Behavior::firefox()),
    }
}

/// Returns the Firefox 147 H2 fingerprint profile.
///
/// Calibrated from `tlsleak/firefox147.0.3_tlsleak.json`.
/// Firefox 147 adds SETTINGS_ENABLE_PUSH(2:0) compared to Firefox 133.
///
/// Akamai fingerprint: `1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s`
///
/// HEADERS frame priority: `exclusive=0, dependency=0, weight=42`
/// (`flags_raw = 0x25`: END_STREAM | END_HEADERS | PRIORITY)
pub fn firefox_147_h2() -> H2Profile {
    H2Profile {
        settings: vec![
            H2Setting {
                id: H2SettingId::HeaderTableSize,
                value: 65536,
            },
            H2Setting {
                id: H2SettingId::EnablePush,
                value: 0,
            },
            H2Setting {
                id: H2SettingId::InitialWindowSize,
                value: 131072,
            },
            H2Setting {
                id: H2SettingId::MaxFrameSize,
                value: 16384,
            },
        ],
        window_update: 12517377,
        pseudo_header_order: vec![
            PseudoHeaderId::Method,
            PseudoHeaderId::Path,
            PseudoHeaderId::Authority,
            PseudoHeaderId::Scheme,
        ],
        headers_priority: Some(HeadersPriority {
            stream_dependency: 0,
            weight: 42,
            exclusive: false,
        }),
        priority_frames: vec![],
        priority_config: PriorityConfig::firefox(),
        behavior: Some(H2Behavior::firefox()),
    }
}

/// Returns the Safari 18 H2 fingerprint profile.
///
/// Safari uses a unique pseudo-header order:
/// `:method`, `:scheme`, `:path`, `:authority` (m,s,p,a)
///
/// Akamai fingerprint: `4:4194304;3:100|10485760|0|m,s,p,a`
///
/// HEADERS frame priority: Safari 18 still uses RFC 7540 priorities
/// (does not send `NO_RFC7540_PRIORITIES`), so it includes PRIORITY
/// on HEADERS frames. Calibrated value: `exclusive=1, dependency=0, weight=255`.
pub fn safari_18_h2() -> H2Profile {
    H2Profile {
        settings: vec![
            H2Setting {
                id: H2SettingId::InitialWindowSize,
                value: 4194304,
            },
            H2Setting {
                id: H2SettingId::MaxConcurrentStreams,
                value: 100,
            },
        ],
        window_update: 10485760,
        pseudo_header_order: vec![
            PseudoHeaderId::Method,
            PseudoHeaderId::Scheme,
            PseudoHeaderId::Path,
            PseudoHeaderId::Authority,
        ],
        headers_priority: Some(HeadersPriority {
            stream_dependency: 0,
            weight: 255,
            exclusive: true,
        }),
        priority_frames: vec![],
        priority_config: PriorityConfig::safari18(),
        behavior: Some(H2Behavior::safari()),
    }
}

/// Returns the Safari 26.2 H2 fingerprint profile.
///
/// Calibrated from `tlsleak/safari26.2_tlsleak.json`.
/// Safari 26.2 uses updated SETTINGS (adds NO_RFC7540_PRIORITIES), different
/// INITIAL_WINDOW_SIZE, and corrected pseudo-header order (m,s,a,p not m,s,p,a).
///
/// Akamai fingerprint: `2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p`
///
/// HEADERS frame priority: `None` — Safari 26 sends `NO_RFC7540_PRIORITIES=1`
/// (opts in to RFC 9218 extensible priorities), so no PRIORITY flag on HEADERS.
/// (`flags_raw = 0x05`: END_STREAM | END_HEADERS only)
pub fn safari_26_h2() -> H2Profile {
    H2Profile {
        settings: vec![
            H2Setting {
                id: H2SettingId::EnablePush,
                value: 0,
            },
            H2Setting {
                id: H2SettingId::MaxConcurrentStreams,
                value: 100,
            },
            H2Setting {
                id: H2SettingId::InitialWindowSize,
                value: 2097152,
            },
            H2Setting {
                id: H2SettingId::NoRfc7540Priorities,
                value: 1,
            },
        ],
        window_update: 10420225,
        pseudo_header_order: vec![
            PseudoHeaderId::Method,
            PseudoHeaderId::Scheme,
            PseudoHeaderId::Authority,
            PseudoHeaderId::Path,
        ],
        headers_priority: None,
        priority_frames: vec![],
        priority_config: PriorityConfig::safari26(),
        behavior: Some(H2Behavior::safari()),
    }
}

impl H2Profile {
    /// Set (or replace) the behaviour for this profile.
    pub fn with_behavior(mut self, behavior: H2Behavior) -> Self {
        self.behavior = Some(behavior);
        self
    }

    /// Returns the behaviour for this profile.
    ///
    /// If none was set (e.g. JSON-loaded profile), returns the baseline.
    pub fn behavior(&self) -> H2Behavior {
        self.behavior
            .clone()
            .unwrap_or_else(H2Behavior::default_behavior)
    }
}

// ---------------------------------------------------------------------------
// H2Profile → native frame conversion
// ---------------------------------------------------------------------------

impl H2Profile {
    /// Convert SETTINGS list to a native `SettingsFrame` (preserving order).
    pub fn to_settings_frame(&self) -> crate::frame::SettingsFrame {
        let settings = self
            .settings
            .iter()
            .map(|s| crate::frame::SettingsParameter {
                id: s.id.as_u16(),
                value: s.value,
            })
            .collect();
        crate::frame::SettingsFrame {
            ack: false,
            settings,
        }
    }

    /// Convert `window_update` to a connection-level `WindowUpdateFrame`.
    ///
    /// Returns `None` if `window_update == 0` (no WINDOW_UPDATE needed).
    pub fn to_window_update_frame(&self) -> Option<crate::frame::WindowUpdateFrame> {
        if self.window_update == 0 {
            return None;
        }
        Some(crate::frame::WindowUpdateFrame {
            stream_id: 0,
            increment: self.window_update,
        })
    }

    /// Convert `headers_priority` to a native `PrioritySpec` for embedding in
    /// HEADERS frames.
    pub fn to_headers_priority_spec(&self) -> Option<crate::frame::PrioritySpec> {
        self.headers_priority
            .as_ref()
            .map(|hp| crate::frame::PrioritySpec {
                exclusive: hp.exclusive,
                stream_dependency: hp.stream_dependency,
                weight: hp.weight,
            })
    }

    /// Convert `priority_frames` to a `Vec<frame::PriorityFrame>`.
    pub fn to_native_priority_frames(&self) -> Vec<crate::frame::PriorityFrame> {
        self.priority_frames
            .iter()
            .map(|pf| crate::frame::PriorityFrame {
                stream_id: pf.stream_id,
                priority: crate::frame::PrioritySpec {
                    exclusive: pf.exclusive,
                    stream_dependency: pf.dependency,
                    weight: pf.weight,
                },
            })
            .collect()
    }

    /// Build the complete "connection preface" frames in wire order:
    ///   1. SETTINGS frame
    ///   2. Connection-level WINDOW_UPDATE (if non-zero)
    ///   3. Standalone PRIORITY frames (if any)
    ///
    /// Returns a `Vec<H2Frame>` ready to be encoded by `H2Codec`.
    pub fn to_preface_frames(&self) -> Vec<crate::frame::H2Frame> {
        let mut frames = Vec::with_capacity(2 + self.priority_frames.len());

        frames.push(crate::frame::H2Frame::Settings(self.to_settings_frame()));

        if let Some(wu) = self.to_window_update_frame() {
            frames.push(crate::frame::H2Frame::WindowUpdate(wu));
        }

        for pf in self.to_native_priority_frames() {
            frames.push(crate::frame::H2Frame::Priority(pf));
        }

        frames
    }
}

impl H2SettingId {
    /// Returns the numeric SETTINGS parameter ID.
    pub fn as_u16(&self) -> u16 {
        match self {
            Self::HeaderTableSize => 0x01,
            Self::EnablePush => 0x02,
            Self::MaxConcurrentStreams => 0x03,
            Self::InitialWindowSize => 0x04,
            Self::MaxFrameSize => 0x05,
            Self::MaxHeaderListSize => 0x06,
            Self::EnableConnectProtocol => 0x08,
            Self::NoRfc7540Priorities => 0x09,
            Self::Unknown(raw) => *raw,
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP header order presets
// ---------------------------------------------------------------------------

/// Returns the Chrome 144 HTTP header sending order (navigation only).
///
/// For a broader template that covers XHR/fetch/script loads, use
/// [`chrome_full_header_order()`] instead.
pub fn chrome_144_header_order() -> Vec<String> {
    vec![
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "upgrade-insecure-requests",
        "user-agent",
        "accept",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-user",
        "sec-fetch-dest",
        "accept-encoding",
        "accept-language",
        "priority",
        "cookie",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

/// Returns a comprehensive Chrome header sending order template.
///
/// Covers navigation, XHR/fetch, script loads, and CORS requests.
/// Headers not present in a specific request are simply skipped;
/// the relative order of those that ARE present is preserved.
///
/// Derived from real Chrome 146 traffic across multiple request types
/// (document navigation, fetch/cors, script no-cors, etc.).
pub fn chrome_full_header_order() -> Vec<String> {
    vec![
        "content-length",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "upgrade-insecure-requests",
        "user-agent",
        "accept",
        "content-type",
        "origin",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-user",
        "sec-fetch-dest",
        "sec-fetch-storage-access",
        "referer",
        "accept-encoding",
        "accept-language",
        "priority",
        "cookie",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

/// Returns the Chrome 145 HTTP header sending order.
///
/// Same as Chrome 144 (navigation header order unchanged in this channel).
pub fn chrome_145_header_order() -> Vec<String> {
    chrome_144_header_order()
}

/// Returns the Chrome 146 HTTP header sending order.
///
/// Same as Chrome 144 (header order hasn't changed).
pub fn chrome_146_header_order() -> Vec<String> {
    chrome_144_header_order()
}

/// Returns the Chrome 147 HTTP header sending order.
///
/// Same as Chrome 144/146 (header order unchanged vs capture).
pub fn chrome_147_header_order() -> Vec<String> {
    chrome_144_header_order()
}

/// Returns the Chrome 148 HTTP header sending order.
///
/// Same as Chrome 144/146/147 (header order unchanged vs capture).
pub fn chrome_148_header_order() -> Vec<String> {
    chrome_144_header_order()
}

/// Returns the Chrome 149 HTTP header sending order.
///
/// Same as Chrome 148 (verified unchanged vs the Chrome 149 capture).
pub fn chrome_149_header_order() -> Vec<String> {
    chrome_144_header_order()
}

/// Returns the Chrome 131 HTTP header sending order.
///
/// Same as Chrome 144 (header order hasn't changed).
pub fn chrome_131_header_order() -> Vec<String> {
    chrome_144_header_order()
}

/// Returns the Firefox 147 HTTP header sending order.
///
/// Derived from `tlsleak/firefox147.0.3_tlsleak.json`. Firefox puts
/// `user-agent` and `accept` first, then `sec-fetch-*` headers.
pub fn firefox_147_header_order() -> Vec<String> {
    vec![
        "user-agent",
        "accept",
        "accept-language",
        "accept-encoding",
        "upgrade-insecure-requests",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "priority",
        "te",
        "cookie",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

/// Returns the Firefox 133 HTTP header sending order.
///
/// Same as Firefox 147 (header order hasn't changed).
pub fn firefox_133_header_order() -> Vec<String> {
    firefox_147_header_order()
}

/// Returns the Safari 26.2 HTTP header sending order.
///
/// Derived from `tlsleak/safari26.2_tlsleak.json`. Safari puts
/// `sec-fetch-dest` first, then `user-agent`, `accept`, etc.
pub fn safari_26_header_order() -> Vec<String> {
    vec![
        "sec-fetch-dest",
        "user-agent",
        "accept",
        "sec-fetch-site",
        "sec-fetch-mode",
        "accept-language",
        "priority",
        "accept-encoding",
        "cookie",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

/// Returns the Safari 18 HTTP header sending order.
///
/// Similar to Safari 26, with minor differences.
pub fn safari_18_header_order() -> Vec<String> {
    safari_26_header_order()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chrome_144_h2_preset() {
        let p = chrome_144_h2();
        assert_eq!(p.settings.len(), 4);
        assert_eq!(p.settings[0].id, H2SettingId::HeaderTableSize);
        assert_eq!(p.settings[0].value, 65536);
        assert_eq!(p.window_update, 15663105);
        assert_eq!(p.pseudo_header_order.len(), 4);
        assert_eq!(p.pseudo_header_order[0], PseudoHeaderId::Method);
        assert_eq!(p.pseudo_header_order[1], PseudoHeaderId::Authority);
        // Chrome 144: HEADERS carries PRIORITY flag (exclusive=1, dep=0, weight=255)
        let hp = p
            .headers_priority
            .expect("Chrome 144 should have headers_priority");
        assert!(hp.exclusive);
        assert_eq!(hp.stream_dependency, 0);
        assert_eq!(hp.weight, 255);
        assert!(p.priority_frames.is_empty());
    }

    #[test]
    fn test_chrome_148_h2_preset_matches_captured_akamai_fingerprint() {
        let p = chrome_148_h2();
        let settings = p
            .settings
            .iter()
            .map(|setting| format!("{}:{}", setting.id.as_u16(), setting.value))
            .collect::<Vec<_>>()
            .join(";");
        let pseudo = p
            .pseudo_header_order
            .iter()
            .map(|header| match header {
                PseudoHeaderId::Method => "m",
                PseudoHeaderId::Authority => "a",
                PseudoHeaderId::Scheme => "s",
                PseudoHeaderId::Path => "p",
            })
            .collect::<Vec<_>>()
            .join(",");
        let akamai = format!("{settings}|{}|0|{pseudo}", p.window_update);

        assert_eq!(akamai, "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p");
        assert_eq!(p.window_update, 15_663_105);
        assert_eq!(
            p.headers_priority.as_ref().expect("Chrome priority").weight,
            255
        );
        assert!(p.priority_frames.is_empty());
    }

    #[test]
    fn test_firefox_147_h2_preset() {
        let p = firefox_147_h2();
        assert_eq!(p.settings.len(), 4);
        assert_eq!(p.window_update, 12517377);
        // Firefox 147: HEADERS carries PRIORITY flag (exclusive=0, dep=0, weight=42)
        let hp = p
            .headers_priority
            .expect("Firefox 147 should have headers_priority");
        assert!(!hp.exclusive);
        assert_eq!(hp.stream_dependency, 0);
        assert_eq!(hp.weight, 42);
    }

    #[test]
    fn test_safari_26_h2_preset_no_priority() {
        let p = safari_26_h2();
        // Safari 26 sends NO_RFC7540_PRIORITIES=1, so no PRIORITY flag on HEADERS
        assert!(p.headers_priority.is_none());
    }

    #[test]
    fn test_safari_18_h2_preset_has_priority() {
        let p = safari_18_h2();
        // Safari 18 still uses RFC 7540 priorities
        let hp = p
            .headers_priority
            .expect("Safari 18 should have headers_priority");
        assert!(hp.exclusive);
        assert_eq!(hp.stream_dependency, 0);
        assert_eq!(hp.weight, 255);
    }

    #[test]
    fn test_chrome_144_header_order_preset() {
        let order = chrome_144_header_order();
        assert!(!order.is_empty());
        // Chrome puts sec-ch-ua first, user-agent in middle, cookie last
        assert_eq!(order[0], "sec-ch-ua");
        assert!(order.contains(&"user-agent".to_string()));
        assert_eq!(*order.last().unwrap(), "cookie");
    }

    #[test]
    fn test_firefox_147_header_order_preset() {
        let order = firefox_147_header_order();
        assert!(!order.is_empty());
        // Firefox puts user-agent first
        assert_eq!(order[0], "user-agent");
        assert!(order.contains(&"accept".to_string()));
        assert_eq!(*order.last().unwrap(), "cookie");
    }

    #[test]
    fn test_safari_26_header_order_preset() {
        let order = safari_26_header_order();
        assert!(!order.is_empty());
        // Safari puts sec-fetch-dest first
        assert_eq!(order[0], "sec-fetch-dest");
        assert!(order.contains(&"user-agent".to_string()));
    }

    #[test]
    fn test_h2_profile_json_deserialization() {
        let json = r#"{
            "settings": [
                { "id": "header_table_size", "value": 65536 },
                { "id": "enable_push", "value": 0 },
                { "id": "initial_window_size", "value": 6291456 },
                { "id": "max_header_list_size", "value": 262144 }
            ],
            "window_update": 15663105,
            "pseudo_header_order": ["method", "authority", "scheme", "path"],
            "priority_frames": []
        }"#;
        let profile: H2Profile = serde_json::from_str(json).unwrap();
        assert_eq!(profile.settings.len(), 4);
        assert_eq!(profile.window_update, 15663105);
        assert_eq!(profile.pseudo_header_order[0], PseudoHeaderId::Method);
        // headers_priority not specified → defaults to None
        assert!(profile.headers_priority.is_none());
    }

    #[test]
    fn test_h2_profile_json_with_headers_priority() {
        let json = r#"{
            "settings": [
                { "id": "header_table_size", "value": 65536 }
            ],
            "window_update": 15663105,
            "pseudo_header_order": ["method", "authority", "scheme", "path"],
            "headers_priority": {
                "stream_dependency": 0,
                "weight": 0,
                "exclusive": true
            }
        }"#;
        let profile: H2Profile = serde_json::from_str(json).unwrap();
        let hp = profile
            .headers_priority
            .expect("should deserialize headers_priority");
        assert_eq!(hp.stream_dependency, 0);
        assert_eq!(hp.weight, 0);
        assert!(hp.exclusive);
    }

    #[test]
    fn test_to_settings_frame() {
        let p = chrome_144_h2();
        let sf = p.to_settings_frame();
        assert!(!sf.ack);
        assert_eq!(sf.settings.len(), 4);
        assert_eq!(sf.settings[0].id, 0x01);
        assert_eq!(sf.settings[0].value, 65536);
        assert_eq!(sf.settings[1].id, 0x02);
        assert_eq!(sf.settings[1].value, 0);
    }

    #[test]
    fn test_to_window_update_frame() {
        let p = chrome_144_h2();
        let wu = p
            .to_window_update_frame()
            .expect("Chrome should have window_update");
        assert_eq!(wu.stream_id, 0);
        assert_eq!(wu.increment, 15663105);
    }

    #[test]
    fn test_to_headers_priority_spec() {
        let p = chrome_144_h2();
        let ps = p.to_headers_priority_spec().unwrap();
        assert!(ps.exclusive);
        assert_eq!(ps.stream_dependency, 0);
        assert_eq!(ps.weight, 255);

        let s = safari_26_h2();
        assert!(s.to_headers_priority_spec().is_none());
    }

    #[test]
    fn test_to_preface_frames() {
        let p = chrome_144_h2();
        let frames = p.to_preface_frames();
        assert_eq!(frames.len(), 2); // SETTINGS + WINDOW_UPDATE, no PRIORITY frames
        assert!(matches!(frames[0], crate::frame::H2Frame::Settings(_)));
        assert!(matches!(frames[1], crate::frame::H2Frame::WindowUpdate(_)));
    }

    #[test]
    fn test_to_preface_frames_with_priority() {
        use crate::frame::H2Frame;
        let mut p = chrome_144_h2();
        p.priority_frames = vec![
            ProfilePriorityFrame {
                stream_id: 3,
                dependency: 0,
                weight: 201,
                exclusive: false,
            },
            ProfilePriorityFrame {
                stream_id: 5,
                dependency: 3,
                weight: 101,
                exclusive: true,
            },
        ];
        let frames = p.to_preface_frames();
        assert_eq!(frames.len(), 4); // SETTINGS + WU + 2 PRIORITY
        assert!(matches!(frames[2], H2Frame::Priority(_)));
        assert!(matches!(frames[3], H2Frame::Priority(_)));
    }

    #[test]
    fn test_to_preface_frames_codec_roundtrip() {
        use crate::codec::{DecodeResult, H2Codec};
        use bytes::BytesMut;

        let p = chrome_144_h2();
        let frames = p.to_preface_frames();
        let codec = H2Codec::new();
        let mut buf = BytesMut::new();
        for f in &frames {
            codec.encode(f, &mut buf);
        }
        let mut decoder = H2Codec::new();
        let mut decoded_count = 0;
        loop {
            match decoder.decode(&mut buf) {
                DecodeResult::Frame(_) => decoded_count += 1,
                DecodeResult::NeedMoreData { .. } => break,
                DecodeResult::Error(e) => panic!("decode error: {e}"),
            }
        }
        assert_eq!(decoded_count, frames.len());
    }

    #[test]
    fn test_h2_profile_json_with_priority_frames() {
        let json = r#"{
            "settings": [],
            "window_update": 0,
            "pseudo_header_order": ["method", "path", "authority", "scheme"],
            "priority_frames": [
                { "stream_id": 3, "dependency": 0, "weight": 201, "exclusive": false },
                { "stream_id": 5, "dependency": 3, "weight": 101, "exclusive": true }
            ]
        }"#;
        let profile: H2Profile = serde_json::from_str(json).unwrap();
        assert_eq!(profile.priority_frames.len(), 2);
        assert_eq!(profile.priority_frames[0].stream_id, 3);
        assert_eq!(profile.priority_frames[0].weight, 201);
        assert!(!profile.priority_frames[0].exclusive);
        assert_eq!(profile.priority_frames[1].stream_id, 5);
        assert_eq!(profile.priority_frames[1].dependency, 3);
        assert!(profile.priority_frames[1].exclusive);
    }

    // ── RequestPriority tests ─────────────────────────────────────────

    #[test]
    fn test_request_priority_to_header_value() {
        // Values captured from real Chrome 148 (see chrome-h3-priority capture).
        assert_eq!(RequestPriority::navigation().to_header_value(), "u=0, i");
        assert_eq!(RequestPriority::css().to_header_value(), "u=0");
        assert_eq!(RequestPriority::script().to_header_value(), "u=1");
        assert_eq!(RequestPriority::fetch().to_header_value(), "u=1, i");
        assert_eq!(RequestPriority::image().to_header_value(), "u=2, i");
        assert_eq!(RequestPriority::custom(5, true).to_header_value(), "u=5, i");
    }

    #[test]
    fn test_request_priority_from_sec_fetch_dest() {
        let d = RequestPriority::from_sec_fetch_dest;
        assert_eq!(d("document"), Some(RequestPriority::navigation())); // u=0, i
        assert_eq!(d("iframe"), Some(RequestPriority::navigation()));
        assert_eq!(d("style"), Some(RequestPriority::css())); // u=0
        assert_eq!(d("script"), Some(RequestPriority::script())); // u=1
        assert_eq!(d("image"), Some(RequestPriority::image())); // u=2, i
        assert_eq!(d("empty"), Some(RequestPriority::fetch())); // u=1, i
                                                                // Uncaptured destinations fall back to the caller's default.
        assert_eq!(d("font"), None);
        assert_eq!(d("audio"), None);
        assert_eq!(d(""), None);
    }

    #[test]
    fn test_request_priority_from_header_value() {
        let p = RequestPriority::from_header_value("u=1, i").unwrap();
        assert_eq!(p.urgency, 1);
        assert!(p.incremental);

        let p = RequestPriority::from_header_value("u=2").unwrap();
        assert_eq!(p.urgency, 2);
        assert!(!p.incremental);

        let p = RequestPriority::from_header_value("u=0").unwrap();
        assert_eq!(p.urgency, 0);
        assert!(!p.incremental);

        // compact form
        let p = RequestPriority::from_header_value("u=1,i").unwrap();
        assert_eq!(p.urgency, 1);
        assert!(p.incremental);

        // bad input
        assert!(RequestPriority::from_header_value("garbage").is_none());
    }

    #[test]
    fn test_request_priority_roundtrip() {
        for rp in [
            RequestPriority::navigation(),
            RequestPriority::fetch(),
            RequestPriority::image(),
            RequestPriority::background(),
        ] {
            let hv = rp.to_header_value();
            let parsed = RequestPriority::from_header_value(&hv).unwrap();
            assert_eq!(rp, parsed);
        }
    }

    // ── PriorityConfig tests ──────────────────────────────────────────

    #[test]
    fn test_chrome_priority_config_weights() {
        let cfg = PriorityConfig::chrome();
        assert_eq!(cfg.weight_for_urgency(0), Some(255)); // navigation
        assert_eq!(cfg.weight_for_urgency(1), Some(219)); // fetch/XHR
        assert_eq!(cfg.weight_for_urgency(2), Some(146)); // image
        assert_eq!(cfg.weight_for_urgency(3), Some(110));
        assert_eq!(cfg.weight_for_urgency(7), Some(0));
    }

    #[test]
    fn test_firefox_priority_config_no_weights() {
        let cfg = PriorityConfig::firefox();
        assert!(cfg.urgency_weights.is_none());
        assert_eq!(cfg.weight_for_urgency(1), None);
    }

    #[test]
    fn test_effective_priority_with_explicit() {
        let cfg = PriorityConfig::chrome();
        let rp = cfg.effective_priority(Some(RequestPriority::image()));
        assert_eq!(rp.urgency, 2);
        assert!(rp.incremental); // Chrome 148: image is u=2, i
    }

    #[test]
    fn test_effective_priority_default() {
        let cfg = PriorityConfig::chrome();
        let rp = cfg.effective_priority(None);
        assert_eq!(rp.urgency, 1); // Chrome default
        assert!(rp.incremental);
    }

    #[test]
    fn test_chrome_h2_preset_has_priority_config() {
        let p = chrome_144_h2();
        assert!(p.priority_config.urgency_weights.is_some());
        assert!(p.priority_config.exclusive);
        assert_eq!(p.priority_config.stream_dep_policy, StreamDepPolicy::Chain);
        assert!(p.priority_config.auto_priority_header);
        assert_eq!(p.priority_config.default_urgency, 1);
    }

    #[test]
    fn test_firefox_h2_preset_has_priority_config() {
        let p = firefox_147_h2();
        assert!(p.priority_config.urgency_weights.is_none());
        assert!(!p.priority_config.exclusive);
        assert_eq!(p.priority_config.stream_dep_policy, StreamDepPolicy::Flat);
        assert!(p.priority_config.auto_priority_header);
    }

    #[test]
    fn test_safari_26_h2_preset_has_priority_config() {
        let p = safari_26_h2();
        assert!(p.headers_priority.is_none());
        assert!(p.priority_config.auto_priority_header);
    }
}
