//! Core data structures that define a TLS fingerprint profile.
//!
//! A `TlsProfile` fully describes the ClientHello characteristics of a specific
//! client (e.g. Chrome 131, Firefox 133, Safari 18, OkHttp3).
//! The entire TLS engine is driven by these data structures — adding a new
//! client fingerprint only requires creating a new profile, no code changes.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Top-level profile
// ---------------------------------------------------------------------------

/// Complete description of a client's TLS fingerprint.
///
/// This struct is intentionally data-only: it carries no behaviour and can be
/// loaded from JSON or constructed programmatically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsProfile {
    /// Human-readable name, e.g. "Chrome 131".
    pub name: String,

    /// TLS ClientHello stack style used for browser-family-specific encoding
    /// rules that cannot be represented as simple ordered lists.
    ///
    /// This is intentionally scoped to TLS only. HTTP/2, HTTP/3, and header
    /// ordering stay in their own profile layers.
    #[serde(default)]
    pub tls_client_hello_style: TlsClientHelloStyle,

    /// Minimum TLS version to advertise.
    pub tls_min_version: TlsVersion,

    /// Maximum TLS version to advertise.
    pub tls_max_version: TlsVersion,

    /// Ordered list of cipher suite code-points to include in ClientHello.
    /// The order matters — it is part of the fingerprint.
    pub cipher_suites: Vec<u16>,

    /// Ordered list of TLS extensions.  Each entry specifies the extension
    /// type and how its payload should be produced.
    pub extensions: Vec<ExtensionSpec>,

    /// Ordered list of supported groups (named curves) code-points.
    pub supported_groups: Vec<u16>,

    /// Ordered list of signature algorithm code-points.
    pub signature_algorithms: Vec<u16>,

    /// EC point formats (typically `[0]` = uncompressed).
    #[serde(default = "default_ec_point_formats")]
    pub ec_point_formats: Vec<u8>,

    /// Compression methods (typically `[0]` = null).
    #[serde(default = "default_compression_methods")]
    pub compression_methods: Vec<u8>,

    /// GREASE configuration.
    #[serde(default)]
    pub grease: GreaseConfig,

    /// Padding strategy — controls how the ClientHello is padded.
    #[serde(default)]
    pub padding: PaddingStrategy,

    /// ALPS (Application-Layer Protocol Settings) protocol list.
    /// Chrome-specific; `None` for browsers that don't use ALPS.
    #[serde(default)]
    pub alps_protocols: Option<Vec<String>>,

    /// Certificate compression algorithm IDs (e.g. brotli = 2, zlib = 1).
    /// `None` if the client doesn't send `compress_certificate`.
    #[serde(default)]
    pub compress_cert_algorithms: Option<Vec<u16>>,

    /// Which curves to include a key share for in the initial ClientHello.
    /// Typically `[0x001d]` (X25519) or `[0x001d, 0x0017]` (X25519 + P-256).
    pub key_share_curves: Vec<u16>,

    /// `record_size_limit` extension value (Firefox-specific).
    #[serde(default)]
    pub record_size_limit: Option<u16>,

    /// Delegated credentials configuration (Firefox-specific).
    #[serde(default)]
    pub delegated_credentials: Option<DelegatedCredentialConfig>,

    /// Length of the session ID field in ClientHello.
    /// Typically 32 for TLS 1.2 compat; some clients send 0.
    #[serde(default = "default_session_id_length")]
    pub session_id_length: u8,

    /// ALPN protocol list, e.g. `["h2", "http/1.1"]`.
    #[serde(default)]
    pub alpn_protocols: Vec<String>,

    /// Fingerprint randomization configuration.
    /// When set, certain dimensions of the ClientHello are slightly randomized
    /// on each connection to avoid all requests having identical fingerprints.
    #[serde(default)]
    pub randomization: Option<RandomizationConfig>,

    /// ECH (Encrypted Client Hello) configuration.
    ///
    /// Controls whether and how the ECH extension (0xFE0D) is generated.
    /// `None` means no ECH extension is sent (unless provided via `raw_bytes`
    /// in the extension list).
    #[serde(default)]
    pub ech: Option<EchMode>,

    /// Extensions to compress via `ech_outer_extensions` (0xFD00) in the
    /// inner ClientHello when real ECH is active.
    ///
    /// Listed as extension type code-points.  These extensions will appear
    /// normally in the outer CH but be replaced by a single
    /// `ech_outer_extensions` reference in the inner CH.
    ///
    /// Browser-specific:
    /// - Chrome: typically `[51, 10, 13, 43, 45, 27]`
    /// - Firefox: typically `[51, 10, 13, 43, 45, 28, 27]`
    ///
    /// If `None`, defaults to compressing `key_share` (51) only.
    #[serde(default)]
    pub ech_outer_extensions: Option<Vec<u16>>,

    /// Session resumption configuration.
    ///
    /// Controls whether and how TLS session tickets / PSK are used for
    /// resumption.  Different browsers have different resumption behaviour:
    /// - Chrome: always attempts TLS 1.3 PSK and TLS 1.2 ticket resumption
    /// - Firefox: similar to Chrome
    /// - Safari: may disable certain resumption modes
    ///
    /// When `None`, defaults to all resumption modes enabled.
    #[serde(default)]
    pub session_resumption: SessionResumptionConfig,
}

/// TLS stack style for ClientHello construction.
///
/// The style captures browser-family behavior such as GREASE placement,
/// extension permutation boundaries, and other ClientHello encoding details.
/// Profiles that do not need stack-specific behavior should use `Generic`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsClientHelloStyle {
    /// Emit ClientHello from the explicit profile fields without additional
    /// family-specific rules.
    #[default]
    Generic,

    /// Chromium-family clients backed by BoringSSL, e.g. Chrome, Edge, Brave,
    /// Electron, and many CEF clients.
    ChromiumBoringssl,

    /// Firefox-family clients backed by NSS.
    FirefoxNss,

    /// Safari / Apple platform clients backed by CFNetwork/Secure Transport.
    SafariCfnetwork,

    /// Java clients backed by JSSE, including `java.net.http.HttpClient`.
    JavaJsse,
}

// ---------------------------------------------------------------------------
// Extension spec
// ---------------------------------------------------------------------------

/// Describes a single TLS extension to include in ClientHello.
///
/// The extension list in a `TlsProfile` is **ordered** — the builder emits
/// extensions in exactly this order, which is a key fingerprint dimension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionSpec {
    /// TLS extension type code-point (e.g. 0x0000 for SNI).
    pub extension_type: u16,

    /// How the extension payload is produced.
    #[serde(default)]
    pub source: ExtensionSource,
}

/// Determines where an extension's payload bytes come from.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExtensionSource {
    /// Payload is derived automatically at runtime.
    /// For example, SNI is filled from the connection target hostname,
    /// `key_share` is generated from the profile's `key_share_curves`, etc.
    #[default]
    Auto,

    /// Use a fixed, pre-defined byte sequence as the extension payload.
    /// Useful for opaque or exotic extensions.
    RawBytes {
        /// Hex-encoded payload bytes.
        data: String,
    },

    /// Insert a GREASE value as extension type and/or payload.
    Grease,
}

// ---------------------------------------------------------------------------
// Sub-configs
// ---------------------------------------------------------------------------

/// GREASE (Generate Random Extensions And Sustain Extensibility) configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GreaseConfig {
    /// Whether to insert GREASE values in cipher suites.
    pub cipher_suite: bool,
    /// Whether to insert GREASE values in extensions.
    pub extensions: bool,
    /// Whether to insert GREASE values in supported groups.
    pub supported_groups: bool,
    /// Whether to insert GREASE values in supported versions.
    pub supported_versions: bool,
    /// Whether to insert GREASE values in signature algorithms.
    pub signature_algorithms: bool,
    /// Whether to insert a GREASE entry in the key_share extension.
    /// Chrome 124+ includes a 1-byte GREASE key_share entry before the real entries.
    #[serde(default)]
    pub key_share: bool,
}

/// Padding strategy — different browsers use different padding logic.
///
/// Chrome uses `BlockAlign`, which pads the ClientHello body to the next
/// `block_size` boundary when the body length exceeds `min_length`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PaddingStrategy {
    /// Chrome-style: pad the ClientHello body to the next `block_size` boundary
    /// when the body length exceeds `min_length`.
    ///
    /// Example: `BlockAlign { min_length: 256, block_size: 512 }`:
    /// - body 200 → no padding (≤ min_length)
    /// - body 300 → pad to 512 (> min_length, < block_size)
    /// - body 600 → no padding (≥ block_size)
    BlockAlign {
        /// Pad only when the ClientHello body exceeds this many bytes.
        min_length: u16,
        /// Round the padded body up to a multiple of this many bytes.
        block_size: u16,
    },

    /// Pad the ClientHello body to an exact target length.
    FixedTarget {
        /// Exact target ClientHello body length in bytes.
        target_length: u16,
    },

    /// No padding extension.
    #[default]
    None,
}

/// Delegated credentials extension configuration (used by Firefox).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedCredentialConfig {
    /// Signature algorithms supported for delegated credentials.
    pub signature_algorithms: Vec<u16>,
}

/// ECH (Encrypted Client Hello) mode.
///
/// Determines how the ECH extension (type 0xFE0D) is generated in the
/// ClientHello.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EchMode {
    /// ECH GREASE — generate a random-looking ECH outer extension.
    ///
    /// Used when no real ECHConfig is available.  The extension looks like
    /// a genuine ECH attempt but uses a random `config_id` that will not
    /// match any server, causing the server to ignore it gracefully.
    /// This is what Chrome and Firefox do by default.
    Grease(EchGreaseConfig),

    /// Real ECH — encrypt the inner ClientHello using an ECHConfig.
    ///
    /// The `ech_config_list` field holds a base64-encoded ECHConfigList
    /// obtained from DNS HTTPS records or provided by the user.  At
    /// runtime, a raw ECHConfigList can also be injected via
    /// `TlsConnector::ech_config()` or `ClientBuilder::ech_config()`.
    Real {
        /// Base64-encoded ECHConfigList.
        ech_config_list: String,
    },

    /// ECH explicitly disabled — no ECH extension is sent.
    Disabled,
}

/// Configuration for ECH GREASE extension generation.
///
/// Controls the cryptographic parameters used in the GREASE outer extension.
/// Different browsers use different HPKE cipher suites:
/// - Chrome: HKDF-SHA256 (0x0001) + AES-128-GCM (0x0001)
/// - Firefox: HKDF-SHA256 (0x0001) + ChaCha20Poly1305 (0x0003)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EchGreaseConfig {
    /// HPKE KDF algorithm ID (e.g. 0x0001 = HKDF-SHA256).
    pub kdf_id: u16,

    /// HPKE AEAD algorithm ID (e.g. 0x0001 = AES-128-GCM, 0x0003 = ChaCha20Poly1305).
    pub aead_id: u16,

    /// Length of the `enc` field in bytes (typically 32 for X25519).
    #[serde(default = "default_enc_length")]
    pub enc_length: u16,

    /// Minimum payload length in bytes.
    /// If the computed payload (from hostname) is smaller, this value is used.
    #[serde(default)]
    pub payload_length_min: Option<u16>,

    /// Maximum payload length in bytes.
    /// The computed payload is clamped to this value.
    #[serde(default)]
    pub payload_length_max: Option<u16>,
}

fn default_enc_length() -> u16 {
    32
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsVersion {
    /// TLS 1.0 (0x0301) — for profile advertising only.
    Tls10,
    /// TLS 1.1 (0x0302) — for profile advertising only.
    Tls11,
    /// TLS 1.2 (0x0303).
    Tls12,
    /// TLS 1.3 (0x0304).
    Tls13,
}

impl TlsVersion {
    /// Returns the on-wire 2-byte representation.
    pub fn as_u16(self) -> u16 {
        match self {
            TlsVersion::Tls10 => 0x0301,
            TlsVersion::Tls11 => 0x0302,
            TlsVersion::Tls12 => 0x0303,
            TlsVersion::Tls13 => 0x0304,
        }
    }
}

// ---------------------------------------------------------------------------
// Well-known extension type constants
// ---------------------------------------------------------------------------

/// Well-known TLS extension type code-points.
pub mod ext_type {
    /// `server_name` / SNI — RFC 6066.
    pub const SNI: u16 = 0x0000;
    /// `ec_point_formats` — RFC 8422.
    pub const EC_POINT_FORMATS: u16 = 0x000b;
    /// `supported_groups` (named curves) — RFC 8422 / RFC 7919.
    pub const SUPPORTED_GROUPS: u16 = 0x000a;
    /// `session_ticket` — RFC 5077 (TLS 1.2 resumption).
    pub const SESSION_TICKET: u16 = 0x0023;
    /// `encrypt_then_mac` — RFC 7366.
    pub const ENCRYPT_THEN_MAC: u16 = 0x0016;
    /// `extended_master_secret` — RFC 7627.
    pub const EXTENDED_MASTER_SECRET: u16 = 0x0017;
    /// `signature_algorithms` — RFC 8446 §4.2.3.
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    /// `supported_versions` — RFC 8446 §4.2.1.
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    /// `psk_key_exchange_modes` — RFC 8446 §4.2.9.
    pub const PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
    /// `key_share` — RFC 8446 §4.2.8.
    pub const KEY_SHARE: u16 = 0x0033;
    /// `application_layer_protocol_negotiation` (ALPN) — RFC 7301.
    pub const ALPN: u16 = 0x0010;
    /// `status_request` (OCSP stapling) — RFC 6066.
    pub const STATUS_REQUEST: u16 = 0x0005;
    /// `signed_certificate_timestamp` — RFC 6962.
    pub const SIGNED_CERTIFICATE_TIMESTAMP: u16 = 0x0012;
    /// `compress_certificate` — RFC 8879.
    pub const COMPRESS_CERTIFICATE: u16 = 0x001b;
    /// ALPS extension (older draft, used by Chrome <=131)
    pub const APPLICATION_SETTINGS: u16 = 0x4469;
    /// ALPS extension (newer draft, used by Chrome 132+)
    pub const APPLICATION_SETTINGS_NEW: u16 = 0x44cd;
    /// `renegotiation_info` — RFC 5746.
    pub const RENEGOTIATION_INFO: u16 = 0xff01;
    /// `delegated_credentials` — RFC 9345.
    pub const DELEGATED_CREDENTIALS: u16 = 0x0022;
    /// `record_size_limit` — RFC 8449.
    pub const RECORD_SIZE_LIMIT: u16 = 0x001c;
    /// `padding` — RFC 7685.
    pub const PADDING: u16 = 0x0015;
    /// `cookie` — RFC 8446 §4.2.2.
    pub const COOKIE: u16 = 0x002c;
    /// `early_data` (0-RTT) — RFC 8446 §4.2.10.
    pub const EARLY_DATA: u16 = 0x002a;
    /// `pre_shared_key` — RFC 8446 §4.2.11 (must be the last extension).
    pub const PRE_SHARED_KEY: u16 = 0x0029;
    /// `quic_transport_parameters` — RFC 9001.
    pub const QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;
    /// Encrypted Client Hello (ECH) extension (draft-ietf-tls-esni).
    pub const ENCRYPTED_CLIENT_HELLO: u16 = 0xFE0D;
}

// ---------------------------------------------------------------------------
// Session resumption
// ---------------------------------------------------------------------------

/// Controls TLS session resumption behaviour.
///
/// Session resumption allows a client to skip the full handshake on
/// subsequent connections to the same server by reusing previously
/// negotiated keys.  This is a significant fingerprint dimension because
/// different browsers handle resumption differently.
///
/// # TLS 1.3
///
/// Uses PSK (Pre-Shared Key) derived from NewSessionTicket messages.
/// When enabled and a stored ticket is available, the ClientHello
/// includes the `pre_shared_key` extension (0x0029).
///
/// # TLS 1.2
///
/// Uses the Session Ticket extension (0x0023) to resume a session.
/// The ticket data is stored after a successful handshake and presented
/// in subsequent ClientHello messages.
///
/// # Example
///
/// ```text
/// // Disable all session resumption (each connection does a full handshake)
/// session_resumption: {
///     "tls13_psk": false,
///     "tls12_session_ticket": false
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResumptionConfig {
    /// Whether to attempt TLS 1.3 PSK resumption when a stored session
    /// ticket is available.
    ///
    /// When `true` (default), the ClientHello includes the `pre_shared_key`
    /// extension if a valid ticket exists for the target host.
    #[serde(default = "default_true")]
    pub tls13_psk: bool,

    /// Whether to attempt TLS 1.2 session ticket resumption.
    ///
    /// When `true` (default), stored TLS 1.2 tickets are presented in the
    /// `session_ticket` extension payload.
    #[serde(default = "default_true")]
    pub tls12_session_ticket: bool,

    /// Maximum number of session tickets to store per host.
    ///
    /// Real browsers typically store 1–2 tickets per host.
    /// `None` means no explicit limit (use the session store's default).
    #[serde(default)]
    pub max_tickets_per_host: Option<usize>,

    /// Whether to accept and store NewSessionTicket messages received
    /// after the handshake completes.
    ///
    /// When `false`, post-handshake NewSessionTicket messages are ignored
    /// and no session tickets are stored for future connections.
    #[serde(default = "default_true")]
    pub store_tickets: bool,
}

fn default_true() -> bool {
    true
}

impl Default for SessionResumptionConfig {
    fn default() -> Self {
        Self {
            tls13_psk: true,
            tls12_session_ticket: true,
            max_tickets_per_host: None,
            store_tickets: true,
        }
    }
}

impl SessionResumptionConfig {
    /// All resumption modes disabled — every connection does a full handshake.
    pub fn disabled() -> Self {
        Self {
            tls13_psk: false,
            tls12_session_ticket: false,
            max_tickets_per_host: None,
            store_tickets: false,
        }
    }

    /// Chrome-like resumption: all modes enabled.
    pub fn chrome() -> Self {
        Self::default()
    }

    /// Firefox-like resumption: all modes enabled.
    pub fn firefox() -> Self {
        Self::default()
    }

    /// Returns `true` if any form of session resumption is enabled.
    pub fn any_enabled(&self) -> bool {
        self.tls13_psk || self.tls12_session_ticket
    }
}

// ---------------------------------------------------------------------------
// Randomization
// ---------------------------------------------------------------------------

/// Configuration for fingerprint randomization.
///
/// Real browsers exhibit slight variations in their TLS fingerprint across
/// connections. This config allows controlled randomization to simulate
/// that behavior without breaking fingerprint validity.
///
/// Chrome/BoringSSL applies a Fisher-Yates permutation to its real extension
/// table. Ordinary GREASE extension bookends are handled by the TLS client
/// style, and `pre_shared_key` must remain last per RFC 8446 §4.2.11.
///
/// When `shuffle_extensions` is enabled, a full Fisher-Yates (Durstenfeld)
/// shuffle is applied to all extensions except the non-shuffleable extension
/// set (currently only `pre_shared_key`).
/// This matches BoringSSL's `ssl_setup_extension_permutation()`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RandomizationConfig {
    /// Apply a full Fisher-Yates permutation to extensions.
    /// Default: false. Chrome 108+ randomizes extension order per connection.
    #[serde(default)]
    pub shuffle_extensions: bool,
}

/// Extension types that must NOT be reordered.
///
/// In the generic shuffle pass, only `pre_shared_key` is excluded from
/// permutation because it must be the last extension per RFC 8446 §4.2.11.
/// ClientHello styles may apply additional boundaries before this helper is
/// called; for example Chromium/BoringSSL keeps ordinary GREASE bookends out
/// of the permuted real-extension list.
const NON_SHUFFLEABLE_EXTENSIONS: &[u16] = &[
    0x0029, // pre_shared_key — must be last (RFC 8446)
];

impl RandomizationConfig {
    /// Check if an extension type can be shuffled.
    pub fn is_shuffleable(ext_type: u16) -> bool {
        !NON_SHUFFLEABLE_EXTENSIONS.contains(&ext_type)
    }
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

fn default_ec_point_formats() -> Vec<u8> {
    vec![0x00] // uncompressed
}

fn default_compression_methods() -> Vec<u8> {
    vec![0x00] // null
}

fn default_session_id_length() -> u8 {
    32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_resumption_default_all_enabled() {
        let cfg = SessionResumptionConfig::default();
        assert!(cfg.tls13_psk);
        assert!(cfg.tls12_session_ticket);
        assert!(cfg.store_tickets);
        assert!(cfg.max_tickets_per_host.is_none());
        assert!(cfg.any_enabled());
    }

    #[test]
    fn session_resumption_disabled() {
        let cfg = SessionResumptionConfig::disabled();
        assert!(!cfg.tls13_psk);
        assert!(!cfg.tls12_session_ticket);
        assert!(!cfg.store_tickets);
        assert!(!cfg.any_enabled());
    }

    #[test]
    fn session_resumption_chrome_preset() {
        let cfg = SessionResumptionConfig::chrome();
        assert!(cfg.tls13_psk);
        assert!(cfg.tls12_session_ticket);
        assert!(cfg.store_tickets);
    }

    #[test]
    fn session_resumption_partial_disable() {
        let cfg = SessionResumptionConfig {
            tls13_psk: true,
            tls12_session_ticket: false,
            ..Default::default()
        };
        assert!(cfg.any_enabled());
        assert!(cfg.tls13_psk);
        assert!(!cfg.tls12_session_ticket);
    }

    #[test]
    fn session_resumption_json_roundtrip() {
        let cfg = SessionResumptionConfig {
            tls13_psk: true,
            tls12_session_ticket: false,
            max_tickets_per_host: Some(2),
            store_tickets: true,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: SessionResumptionConfig = serde_json::from_str(&json).unwrap();
        assert!(parsed.tls13_psk);
        assert!(!parsed.tls12_session_ticket);
        assert_eq!(parsed.max_tickets_per_host, Some(2));
        assert!(parsed.store_tickets);
    }

    #[test]
    fn session_resumption_json_defaults() {
        let json = "{}";
        let cfg: SessionResumptionConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.tls13_psk);
        assert!(cfg.tls12_session_ticket);
        assert!(cfg.store_tickets);
        assert!(cfg.max_tickets_per_host.is_none());
    }

    #[test]
    fn padding_strategy_default_is_none() {
        let ps: PaddingStrategy = Default::default();
        assert!(matches!(ps, PaddingStrategy::None));
    }

    #[test]
    fn tls_version_wire_values() {
        assert_eq!(TlsVersion::Tls10.as_u16(), 0x0301);
        assert_eq!(TlsVersion::Tls11.as_u16(), 0x0302);
        assert_eq!(TlsVersion::Tls12.as_u16(), 0x0303);
        assert_eq!(TlsVersion::Tls13.as_u16(), 0x0304);
    }
}
