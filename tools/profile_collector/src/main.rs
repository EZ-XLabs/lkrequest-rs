#![allow(linker_messages)]

//! # profile_collector — TLS + HTTP/2 Fingerprint Profile Extractor
//!
//! Extracts TLS and HTTP/2 fingerprint profile data from ClientHello hex dumps
//! or live browser captures. Outputs JSON compatible with lktls's `TlsProfile`.
//!
//! ## ECH Support
//!
//! Automatically detects ECH GREASE extensions (0xFE0D, type=outer) and:
//! - Extracts `kdf_id`, `aead_id`, `enc_length` from the wire format
//! - Infers `payload_length_min` / `payload_length_max` from the observed
//!   payload length using BoringSSL's formula (`32 * k + 16`)
//! - Auto-populates `ech_outer_extensions` with the BoringSSL default list
//!   `[51, 10, 13, 5, 18, 16, 45, 27, 17613]` (cannot be passively captured
//!   since the inner ClientHello is encrypted)
//!
//! ## Usage
//!
//! ```bash
//! # Extract profile from a hex dump file
//! profile-collector extract --input chrome_131.hex --name "Chrome 131" -o chrome_131.json
//!
//! # Show parsed ClientHello structure (human-readable)
//! profile-collector inspect --input chrome_131.hex
//!
//! # Capture live TLS + HTTP/2 fingerprint from browser
//! profile-collector capture --port 8443 --name "Chrome 131" -o chrome_131.json
//!
//! # Capture TLS fingerprint only (skip H2)
//! profile-collector capture --port 8443 --name "Chrome 131" --tls-only
//!
//! # Capture live QUIC + HTTP/3 fingerprint from browser
//! profile-collector capture-quic --port 8443 --name "Chrome 131"
//!
//! # Cross-platform headless Chrome capture
//! profile-collector capture-chrome --protocol h2 --browser /path/to/chrome -o chrome_148_h2.json
//! profile-collector capture-chrome --protocol h3 --browser /path/to/chrome -o chrome_148_h3.json
//!
//! # Export an lkrequest preset and diff at field level
//! profile-collector export-chrome-preset --version chrome_148 --protocol h2 -o preset.json
//! profile-collector compare-json --left chrome_148_h2.json --right preset.json --left-label chrome --right-label lkrequest
//! ```

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use bytes::BytesMut;
use clap::{Parser, Subcommand, ValueEnum};
use h3::qpack::{decode_stateless, encode_stateless, HeaderField};
use lkprofile::{
    collect_quic_fingerprint, extract_alpn_protocols, extract_compress_cert_algorithms,
    extract_delegated_credentials, extract_ec_point_formats, extract_key_share_curves,
    extract_record_size_limit, extract_signature_algorithms, extract_supported_groups,
    extract_supported_versions, is_grease_value, parse_client_hello, H3FingerprintInput,
    ParsedClientHello, QuicFingerprintCollection, QuicFingerprintInput,
    QuicPacketizationFingerprint,
};
use lktls::crypto::aead::{Aead, AeadAlgorithm};
use lktls::crypto::quic::{derive_initial_keys, Side as QuicKeySide};
use lktls::extensions::quic_transport_params::{
    decode_transport_params, decode_varint, encode_varint, param_id, QUIC_TRANSPORT_PARAMS_TYPE,
};
use md5::Md5;
use quinn::{AsyncUdpSocket, EndpointConfig, TokioRuntime, UdpPoller};
use quinn_udp::{RecvMeta, UdpSocketState};
use serde::Serialize;
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::future::Future;
use std::io::{self, Read, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::Interest;
use tokio::sync::mpsc;

// =============================================================================
// CLI
// =============================================================================

#[derive(Parser)]
#[command(
    name = "profile-collector",
    about = "Extract TLS + HTTP/2 + QUIC/HTTP3 fingerprint profiles from ClientHello hex dumps or live captures"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Extract a TlsProfile JSON from a ClientHello hex dump
    Extract {
        /// Input hex file path (or "-" for stdin)
        #[arg(short, long, default_value = "-")]
        input: String,

        /// Profile name (e.g. "Chrome 131")
        #[arg(short, long)]
        name: String,

        /// Output JSON file path (stdout if not specified)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Inspect a ClientHello and show parsed fields (human-readable)
    Inspect {
        /// Input hex file path (or "-" for stdin)
        #[arg(short, long, default_value = "-")]
        input: String,
    },

    /// Run a fingerprint capture server (persistent, handles multiple connections)
    ///
    /// Starts a TLS server with a self-signed certificate.
    /// Every browser that connects gets its TLS + HTTP/2 fingerprint
    /// captured and returned as a JSON response — like a local example.com.
    /// The server runs until you press Ctrl+C.
    Capture {
        /// HTTPS port to listen on
        #[arg(short, long, default_value = "8443")]
        port: u16,

        /// Default profile name in output JSON
        #[arg(short, long, default_value = "Browser")]
        name: String,

        /// Also save the latest capture to this JSON file
        #[arg(short, long)]
        output: Option<String>,

        /// Only capture TLS fingerprint, skip HTTP/2 handshake
        #[arg(long)]
        tls_only: bool,

        /// HTTP port for auto-redirect to HTTPS
        /// (e.g. --http-port 8080 redirects http://localhost:8080 → https://localhost:PORT)
        #[arg(long)]
        http_port: Option<u16>,

        /// PEM certificate chain to use instead of an ephemeral self-signed cert
        #[arg(long)]
        cert: Option<String>,

        /// PEM private key to use with --cert
        #[arg(long)]
        key: Option<String>,
    },

    /// Run a bootstrap HTTPS server plus QUIC/H3 capture server.
    ///
    /// Visit https://localhost:PORT in a browser. The TCP bootstrap response
    /// advertises Alt-Svc and retries automatically until a real H3 request is
    /// observed, then returns the captured fingerprint JSON.
    CaptureQuic {
        /// HTTPS / QUIC port to listen on (TCP and UDP share the same port)
        #[arg(short, long, default_value = "8443")]
        port: u16,

        /// Default profile name in output JSON
        #[arg(short, long, default_value = "Browser")]
        name: String,

        /// Also save the latest capture to this JSON file
        #[arg(short, long)]
        output: Option<String>,

        /// HTTP port for auto-redirect to HTTPS
        #[arg(long)]
        http_port: Option<u16>,

        /// PEM certificate chain to use instead of an ephemeral self-signed cert
        #[arg(long)]
        cert: Option<String>,

        /// PEM private key to use with --cert
        #[arg(long)]
        key: Option<String>,
    },

    /// Start Chrome/Chromium headless and capture its network-layer fingerprint.
    ///
    /// This wraps `capture` / `capture-quic` with a browser driver so the same
    /// flow works on Windows, macOS, and Linux. Pass a Chrome-for-Testing binary
    /// with `--browser` to collect specific Chrome milestones.
    CaptureChrome {
        /// Protocol stack to capture from Chrome.
        #[arg(long, value_enum, default_value = "h2")]
        protocol: ChromeCaptureProtocol,

        /// HTTPS / QUIC capture port.
        #[arg(short, long, default_value = "8443")]
        port: u16,

        /// HTTP redirect port. Useful because Chrome will follow an HTTP URL
        /// without requiring manual certificate-warning interaction.
        #[arg(long)]
        http_port: Option<u16>,

        /// Profile name in output JSON.
        #[arg(short, long, default_value = "Chrome")]
        name: String,

        /// Output JSON file path. Defaults to stdout.
        #[arg(short, long)]
        output: Option<String>,

        /// Chrome/Chromium executable path. If omitted, common install paths
        /// and PATH names are probed.
        #[arg(long)]
        browser: Option<String>,

        /// Use an existing Chrome user-data-dir instead of a temporary one.
        #[arg(long)]
        user_data_dir: Option<String>,

        /// Keep the generated temporary Chrome profile directory.
        #[arg(long)]
        keep_user_data_dir: bool,

        /// Additional argument passed through to Chrome. Repeatable.
        #[arg(long = "chrome-arg")]
        chrome_args: Vec<String>,

        /// Seconds to wait for the capture JSON.
        #[arg(long, default_value = "30")]
        timeout_secs: u64,

        /// PEM certificate chain to use instead of an ephemeral self-signed cert
        /// for QUIC/H3 capture.
        #[arg(long)]
        cert: Option<String>,

        /// PEM private key to use with --cert for QUIC/H3 capture.
        #[arg(long)]
        key: Option<String>,
    },

    /// Compare two profile-collector JSON outputs at field level.
    CompareJson {
        /// Left JSON file, typically the real Chrome capture.
        #[arg(long)]
        left: String,

        /// Right JSON file, typically lkrequest or another Chrome version.
        #[arg(long)]
        right: String,

        /// Optional label for the left side.
        #[arg(long, default_value = "left")]
        left_label: String,

        /// Optional label for the right side.
        #[arg(long, default_value = "right")]
        right_label: String,

        /// Emit JSON instead of text.
        #[arg(long)]
        json: bool,

        /// Output path for the comparison. Defaults to stdout.
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Export an lkrequest Chrome preset as comparable JSON.
    ExportChromePreset {
        /// Chrome preset version currently modelled by lkrequest.
        #[arg(long, value_enum)]
        version: ChromePresetVersion,

        /// Protocol stack to export.
        #[arg(long, value_enum, default_value = "h2")]
        protocol: ChromeCaptureProtocol,

        /// Output JSON file path. Defaults to stdout.
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ChromeCaptureProtocol {
    #[value(name = "h2")]
    H2,
    #[value(name = "h3")]
    H3,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ChromePresetVersion {
    #[value(name = "chrome_131")]
    Chrome131,
    #[value(name = "chrome_144")]
    Chrome144,
    #[value(name = "chrome_145")]
    Chrome145,
    #[value(name = "chrome_146")]
    Chrome146,
    #[value(name = "chrome_147")]
    Chrome147,
    #[value(name = "chrome_148")]
    Chrome148,
    #[value(name = "chrome_149")]
    Chrome149,
    #[value(name = "chrome_150")]
    Chrome150,
    #[value(name = "chrome_151")]
    Chrome151,
}

struct CaptureChromeOptions {
    protocol: ChromeCaptureProtocol,
    port: u16,
    http_port: Option<u16>,
    name: String,
    output: Option<String>,
    browser: Option<String>,
    user_data_dir: Option<String>,
    keep_user_data_dir: bool,
    chrome_args: Vec<String>,
    timeout_secs: u64,
    cert: Option<String>,
    key: Option<String>,
}

// =============================================================================
// Output Profile Types
// =============================================================================

#[derive(Debug, Serialize)]
struct OutputProfile {
    name: String,
    tls_min_version: String,
    tls_max_version: String,
    cipher_suites: Vec<u16>,
    extensions: Vec<OutputExtensionSpec>,
    supported_groups: Vec<u16>,
    signature_algorithms: Vec<u16>,
    ec_point_formats: Vec<u8>,
    compression_methods: Vec<u8>,
    grease: OutputGreaseConfig,
    padding: OutputPaddingStrategy,
    alps_protocols: Option<Vec<String>>,
    compress_cert_algorithms: Option<Vec<u16>>,
    key_share_curves: Vec<u16>,
    record_size_limit: Option<u16>,
    delegated_credentials: Option<OutputDelegatedCredentialConfig>,
    session_id_length: u8,
    alpn_protocols: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    ech: Option<OutputEchConfig>,

    /// Extensions compressed via `ech_outer_extensions` (0xFD00) in the inner
    /// ClientHello when real ECH is active.  Auto-populated with the BoringSSL
    /// default list when ECH GREASE is detected.
    #[serde(skip_serializing_if = "Option::is_none")]
    ech_outer_extensions: Option<Vec<u16>>,

    /// HTTP/2 fingerprint (present only when H2 was negotiated during capture)
    #[serde(skip_serializing_if = "Option::is_none")]
    h2_fingerprint: Option<H2Fingerprint>,

    /// QUIC + HTTP/3 fingerprint (present only in QUIC/H3 capture mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    quic_fingerprint: Option<QuicFingerprint>,
}

#[derive(Debug, Serialize)]
struct ChromeCaptureRun {
    protocol: String,
    requested_url: String,
    browser: String,
    user_data_dir: String,
    chrome_args: Vec<String>,
    output: String,
}

#[derive(Debug, Serialize)]
struct JsonFieldDiff {
    path: String,
    status: JsonFieldStatus,
    left: Option<serde_json::Value>,
    right: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum JsonFieldStatus {
    Match,
    Mismatch,
    MissingLeft,
    MissingRight,
}

#[derive(Debug, Serialize)]
struct JsonComparisonReport {
    left_label: String,
    right_label: String,
    matches: usize,
    mismatches: usize,
    fields: Vec<JsonFieldDiff>,
}

#[derive(Debug, Serialize)]
struct OutputExtensionSpec {
    extension_type: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<OutputExtensionSource>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(dead_code)]
enum OutputExtensionSource {
    Auto,
    RawBytes { data: String },
    Grease,
}

#[derive(Debug, Serialize)]
struct OutputGreaseConfig {
    cipher_suite: bool,
    extensions: bool,
    supported_groups: bool,
    supported_versions: bool,
    signature_algorithms: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    key_share: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(dead_code)]
enum OutputPaddingStrategy {
    BlockAlign { min_length: u16, block_size: u16 },
    FixedTarget { target_length: u16 },
    None,
}

#[derive(Debug, Serialize)]
struct OutputDelegatedCredentialConfig {
    signature_algorithms: Vec<u16>,
}

#[derive(Debug, Clone, Serialize)]
struct OutputEchConfig {
    #[serde(rename = "type")]
    ech_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kdf_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aead_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enc_length: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_length_min: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_length_max: Option<u16>,
}

// =============================================================================
// HTTP/2 Fingerprint Output Types
// =============================================================================

#[derive(Debug, Clone, Serialize)]
struct H2Fingerprint {
    /// SETTINGS parameters in the order they appeared in the frame.
    settings: Vec<H2Setting>,
    /// Connection-level WINDOW_UPDATE increment (0 if not sent).
    window_update: u32,
    /// PRIORITY frames sent before the first HEADERS.
    priority_frames: Vec<H2Priority>,
    /// Pseudo-header order from the first HEADERS frame.
    pseudo_header_order: Vec<String>,
    /// Raw Akamai fingerprint string: "S|WU|P|PS"
    akamai_fingerprint: String,
    /// MD5 hash of the Akamai fingerprint string (industry standard).
    akamai_hash: String,
    /// SHA-256 hash of the Akamai fingerprint string.
    akamai_hash_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct H2Setting {
    id: u16,
    value: u32,
}

#[derive(Debug, Clone, Serialize)]
struct H2Priority {
    stream_id: u32,
    exclusive: bool,
    depends_on: u32,
    weight: u8,
}

// =============================================================================
// QUIC / HTTP/3 Fingerprint Output Types
// =============================================================================

#[derive(Debug, Clone, Serialize)]
struct QuicFingerprint {
    transport_parameters: Vec<QuicTransportParameter>,
    transport_fingerprint: String,
    transport_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    packetization_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    packetization_hash: Option<String>,
    connection_id_length: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    initial_destination_connection_id_length: Option<usize>,
    grease_transport_params: bool,
    h3: H3Fingerprint,
}

#[derive(Debug, Clone, Serialize)]
struct QuicTransportParameter {
    name: String,
    value: u64,
}

#[derive(Debug, Clone, Serialize)]
struct H3Fingerprint {
    settings: Vec<H3Setting>,
    settings_fingerprint: String,
    settings_hash: String,
    pseudo_header_order: Vec<String>,
    pseudo_header_order_token: String,
    grease_settings: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    priority_updates: Vec<H3PriorityUpdate>,
}

#[derive(Debug, Clone, Serialize)]
struct H3Setting {
    id: u64,
    value: u64,
}

#[derive(Debug, Clone, Serialize)]
struct H3PriorityUpdate {
    element_id: u64,
    field_value: String,
}

// =============================================================================
// TLS Display Helpers
// =============================================================================

fn tls_version_string(v: u16) -> &'static str {
    match v {
        0x0301 => "tls10",
        0x0302 => "tls11",
        0x0303 => "tls12",
        0x0304 => "tls13",
        _ => "unknown",
    }
}

fn extension_name(ext_type: u16) -> &'static str {
    match ext_type {
        0x0000 => "server_name",
        0x0001 => "max_fragment_length",
        0x0005 => "status_request",
        0x000a => "supported_groups",
        0x000b => "ec_point_formats",
        0x000d => "signature_algorithms",
        0x0010 => "ALPN",
        0x0012 => "signed_certificate_timestamp",
        0x0015 => "padding",
        0x0016 => "encrypt_then_mac",
        0x0017 => "extended_master_secret",
        0x001b => "compress_certificate",
        0x001c => "record_size_limit",
        0x0022 => "delegated_credentials",
        0x0023 => "session_ticket",
        0x002b => "supported_versions",
        0x002d => "psk_key_exchange_modes",
        0x0033 => "key_share",
        0x0039 => "post_handshake_auth",
        0x4469 => "application_settings (ALPS legacy)",
        0x44cd => "application_settings (ALPS)",
        0xfe0d => "encrypted_client_hello (ECH)",
        0xff01 => "renegotiation_info",
        _ if is_grease_value(ext_type) => "GREASE",
        _ => "unknown",
    }
}

fn cipher_suite_name(suite: u16) -> &'static str {
    match suite {
        0x000a => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x003c => "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x003d => "TLS_RSA_WITH_AES_256_CBC_SHA256",
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x00ff => "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0xc008 => "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        0xc009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        0xc00a => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        0xc012 => "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        0xc013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0xc023 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        0xc024 => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        0xc027 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        0xc028 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        _ if is_grease_value(suite) => "GREASE",
        _ => "unknown",
    }
}

fn named_group_name(group: u16) -> &'static str {
    match group {
        0x0017 => "secp256r1 (P-256)",
        0x0018 => "secp384r1 (P-384)",
        0x0019 => "secp521r1 (P-521)",
        0x001d => "x25519",
        0x001e => "x448",
        0x0100 => "ffdhe2048",
        0x0101 => "ffdhe3072",
        0x11ec => "X25519MLKEM768",
        0x6399 => "X25519Kyber768Draft00",
        _ if is_grease_value(group) => "GREASE",
        _ => "unknown",
    }
}

fn sig_alg_name(alg: u16) -> &'static str {
    match alg {
        0x0401 => "rsa_pkcs1_sha256",
        0x0501 => "rsa_pkcs1_sha384",
        0x0601 => "rsa_pkcs1_sha512",
        0x0403 => "ecdsa_secp256r1_sha256",
        0x0503 => "ecdsa_secp384r1_sha384",
        0x0603 => "ecdsa_secp521r1_sha512",
        0x0804 => "rsa_pss_rsae_sha256",
        0x0805 => "rsa_pss_rsae_sha384",
        0x0806 => "rsa_pss_rsae_sha512",
        0x0807 => "ed25519",
        0x0808 => "ed448",
        _ => "unknown",
    }
}

/// Extract ECH GREASE config parameters from the ECH extension data.
///
/// ECH outer extension format:
///   client_hello_type(1) | kdf_id(2) | aead_id(2) | config_id(1) | enc_len(2) | enc(...) | payload_len(2) | payload(...)
///
/// Only processes `type == 0x00` (outer) payloads. Infers `payload_length_min`
/// and `payload_length_max` from the observed payload length using BoringSSL's
/// formula: `payload_len = 32 * rand_in(min/32, max/32) + aead_tag(16)`.
fn extract_ech_grease_config(data: &[u8]) -> Option<OutputEchConfig> {
    if data.len() < 8 || data[0] != 0x00 {
        return None;
    }

    let kdf_id = u16::from_be_bytes([data[1], data[2]]);
    let aead_id = u16::from_be_bytes([data[3], data[4]]);
    // data[5] = config_id (random per connection, skip)
    let enc_len = u16::from_be_bytes([data[6], data[7]]);

    let payload_offset = 8 + enc_len as usize;
    let (pl_min, pl_max) = if payload_offset + 2 <= data.len() {
        let payload_len = u16::from_be_bytes([data[payload_offset], data[payload_offset + 1]]);
        infer_ech_payload_range(payload_len)
    } else {
        (None, None)
    };

    Some(OutputEchConfig {
        ech_type: "grease".to_string(),
        kdf_id: Some(kdf_id),
        aead_id: Some(aead_id),
        enc_length: Some(enc_len),
        payload_length_min: pl_min,
        payload_length_max: pl_max,
    })
}

/// Infer ECH GREASE payload range from a single observed `payload_len`.
///
/// BoringSSL: `payload_len = 32 * random_in(min/32, max/32) + 16`.
/// Chrome uses `min=128, max=224` → discrete values {144, 176, 208, 240}.
fn infer_ech_payload_range(payload_len: u16) -> (Option<u16>, Option<u16>) {
    if payload_len < 16 {
        return (None, None);
    }
    let block = payload_len - 16;
    let block_aligned = (block / 32) * 32;
    if block_aligned == 0 {
        return (None, None);
    }
    if (128..=224).contains(&block_aligned) {
        (Some(128), Some(224))
    } else {
        (Some(block_aligned), Some(block_aligned))
    }
}

fn build_profile(name: &str, ch: &ParsedClientHello) -> OutputProfile {
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
    let mut has_ech = false;
    let mut ech_data: Option<Vec<u8>> = None;

    let has_grease_cs = ch.cipher_suites.iter().any(|s| is_grease_value(*s));
    let mut has_grease_ext = false;
    let mut has_grease_groups = false;
    let mut has_grease_versions = false;
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
            0x000d => signature_algorithms = extract_signature_algorithms(&ext.data),
            0x0010 => alpn_protocols = extract_alpn_protocols(&ext.data),
            0x0015 => has_padding = true,
            0x001b => compress_cert_algorithms = Some(extract_compress_cert_algorithms(&ext.data)),
            0x001c => record_size_limit = extract_record_size_limit(&ext.data),
            0x0022 => {
                delegated_credentials = extract_delegated_credentials(&ext.data).map(|dc| {
                    OutputDelegatedCredentialConfig {
                        signature_algorithms: dc.signature_algorithms,
                    }
                });
            }
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
            0xfe0d => {
                has_ech = true;
                ech_data = Some(ext.data.clone());
            }
            _ => {}
        }
    }

    let (tls_min, tls_max) = if !supported_versions.is_empty() {
        let real_versions: Vec<u16> = supported_versions
            .iter()
            .filter(|v| !is_grease_value(**v))
            .copied()
            .collect();
        let min_v = real_versions.iter().min().copied().unwrap_or(0x0303);
        let max_v = real_versions.iter().max().copied().unwrap_or(0x0303);
        (
            tls_version_string(min_v).to_string(),
            tls_version_string(max_v).to_string(),
        )
    } else {
        (
            tls_version_string(ch.protocol_version).to_string(),
            tls_version_string(ch.protocol_version).to_string(),
        )
    };

    let extension_specs: Vec<OutputExtensionSpec> = ch
        .extensions
        .iter()
        .map(|e| {
            if is_grease_value(e.extension_type) {
                OutputExtensionSpec {
                    extension_type: e.extension_type,
                    source: Some(OutputExtensionSource::Grease),
                }
            } else {
                let source = match e.extension_type {
                    // Well-known extensions that lktls auto-generates at runtime
                    0x0000 | 0x0005 | 0x000a | 0x000b | 0x000d | 0x0010 | 0x0012 | 0x0015
                    | 0x0016 | 0x0017 | 0x001b | 0x001c | 0x0022 | 0x0023 | 0x002b | 0x002d
                    | 0x0033 | 0x0039 | 0x4469 | 0x44cd | 0xfe0d | 0xff01 => None,
                    _ => {
                        if e.data.is_empty() {
                            None
                        } else {
                            Some(OutputExtensionSource::RawBytes {
                                data: hex::encode(&e.data),
                            })
                        }
                    }
                };
                OutputExtensionSpec {
                    extension_type: e.extension_type,
                    source,
                }
            }
        })
        .collect();

    let cipher_suites: Vec<u16> = ch
        .cipher_suites
        .iter()
        .filter(|s| !is_grease_value(**s))
        .copied()
        .collect();

    let padding = if has_padding {
        // RFC 7685: padding extension present → assume Chrome-style block alignment.
        // Modern browsers (Chrome 144+, Firefox 147+, Safari 26+) no longer use padding.
        OutputPaddingStrategy::BlockAlign {
            min_length: 256,
            block_size: 512,
        }
    } else {
        OutputPaddingStrategy::None
    };

    let ech_config = if has_ech {
        extract_ech_grease_config(ech_data.as_deref().unwrap_or(&[]))
    } else {
        None
    };

    // Auto-populate ech_outer_extensions with the BoringSSL default list when
    // ECH is detected.  This list cannot be passively captured (the inner CH
    // is encrypted) but is stable across Chrome versions.
    let ech_outer_extensions = if ech_config.is_some() {
        Some(vec![51, 10, 13, 5, 18, 16, 45, 27, 17613])
    } else {
        None
    };

    OutputProfile {
        name: name.to_string(),
        tls_min_version: tls_min,
        tls_max_version: tls_max,
        cipher_suites,
        extensions: extension_specs,
        supported_groups,
        signature_algorithms,
        ec_point_formats,
        compression_methods: ch.compression_methods.clone(),
        grease: OutputGreaseConfig {
            cipher_suite: has_grease_cs,
            extensions: has_grease_ext,
            supported_groups: has_grease_groups,
            supported_versions: has_grease_versions,
            signature_algorithms: false,
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
        ech: ech_config,
        ech_outer_extensions,
        h2_fingerprint: None,
        quic_fingerprint: None,
    }
}

fn tls_version_name(version: lktls::profile::types::TlsVersion) -> String {
    match version {
        lktls::profile::types::TlsVersion::Tls10 => "tls10",
        lktls::profile::types::TlsVersion::Tls11 => "tls11",
        lktls::profile::types::TlsVersion::Tls12 => "tls12",
        lktls::profile::types::TlsVersion::Tls13 => "tls13",
    }
    .into()
}

fn output_extension_source(
    source: &lktls::profile::types::ExtensionSource,
) -> Option<OutputExtensionSource> {
    match source {
        lktls::profile::types::ExtensionSource::Auto => Some(OutputExtensionSource::Auto),
        lktls::profile::types::ExtensionSource::RawBytes { data } => {
            Some(OutputExtensionSource::RawBytes { data: data.clone() })
        }
        lktls::profile::types::ExtensionSource::Grease => Some(OutputExtensionSource::Grease),
    }
}

fn output_ech_config(ech: &lktls::profile::types::EchMode) -> OutputEchConfig {
    match ech {
        lktls::profile::types::EchMode::Grease(config) => OutputEchConfig {
            ech_type: "grease".into(),
            kdf_id: Some(config.kdf_id),
            aead_id: Some(config.aead_id),
            enc_length: Some(config.enc_length),
            payload_length_min: config.payload_length_min,
            payload_length_max: config.payload_length_max,
        },
        lktls::profile::types::EchMode::Real { .. } => OutputEchConfig {
            ech_type: "real".into(),
            kdf_id: None,
            aead_id: None,
            enc_length: None,
            payload_length_min: None,
            payload_length_max: None,
        },
        lktls::profile::types::EchMode::Disabled => OutputEchConfig {
            ech_type: "disabled".into(),
            kdf_id: None,
            aead_id: None,
            enc_length: None,
            payload_length_min: None,
            payload_length_max: None,
        },
    }
}

fn output_profile_from_tls_profile(profile: &lktls::profile::types::TlsProfile) -> OutputProfile {
    OutputProfile {
        name: profile.name.clone(),
        tls_min_version: tls_version_name(profile.tls_min_version),
        tls_max_version: tls_version_name(profile.tls_max_version),
        cipher_suites: profile.cipher_suites.clone(),
        extensions: profile
            .extensions
            .iter()
            .map(|extension| OutputExtensionSpec {
                extension_type: extension.extension_type,
                source: output_extension_source(&extension.source),
            })
            .collect(),
        supported_groups: profile.supported_groups.clone(),
        signature_algorithms: profile.signature_algorithms.clone(),
        ec_point_formats: profile.ec_point_formats.clone(),
        compression_methods: profile.compression_methods.clone(),
        grease: OutputGreaseConfig {
            cipher_suite: profile.grease.cipher_suite,
            extensions: profile.grease.extensions,
            supported_groups: profile.grease.supported_groups,
            supported_versions: profile.grease.supported_versions,
            signature_algorithms: profile.grease.signature_algorithms,
            key_share: profile.grease.key_share,
        },
        padding: match profile.padding {
            lktls::profile::types::PaddingStrategy::BlockAlign {
                min_length,
                block_size,
            } => OutputPaddingStrategy::BlockAlign {
                min_length,
                block_size,
            },
            lktls::profile::types::PaddingStrategy::FixedTarget { target_length } => {
                OutputPaddingStrategy::FixedTarget { target_length }
            }
            lktls::profile::types::PaddingStrategy::None => OutputPaddingStrategy::None,
        },
        alps_protocols: profile.alps_protocols.clone(),
        compress_cert_algorithms: profile.compress_cert_algorithms.clone(),
        key_share_curves: profile.key_share_curves.clone(),
        record_size_limit: profile.record_size_limit,
        delegated_credentials: profile.delegated_credentials.as_ref().map(|config| {
            OutputDelegatedCredentialConfig {
                signature_algorithms: config.signature_algorithms.clone(),
            }
        }),
        session_id_length: profile.session_id_length,
        alpn_protocols: profile.alpn_protocols.clone(),
        ech: profile.ech.as_ref().map(output_ech_config),
        ech_outer_extensions: profile.ech_outer_extensions.clone(),
        h2_fingerprint: None,
        quic_fingerprint: None,
    }
}

// =============================================================================
// HTTP/2 Frame Parsing
// =============================================================================

const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// Frame types we care about
const H2_HEADERS: u8 = 0x01;
const H2_PRIORITY: u8 = 0x02;
const H2_SETTINGS: u8 = 0x04;
const H2_WINDOW_UPDATE: u8 = 0x08;

/// A parsed HTTP/2 frame header + payload.
struct H2Frame {
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

/// Read a single H2 frame from a reader.
fn read_h2_frame(reader: &mut dyn Read) -> Result<H2Frame, String> {
    let mut header = [0u8; 9];
    reader
        .read_exact(&mut header)
        .map_err(|e| format!("Failed to read H2 frame header: {e}"))?;

    let length = ((header[0] as u32) << 16) | ((header[1] as u32) << 8) | (header[2] as u32);
    let frame_type = header[3];
    let flags = header[4];
    let stream_id = u32::from_be_bytes([header[5] & 0x7f, header[6], header[7], header[8]]);

    if length > 16384 + 16384 {
        return Err(format!("H2 frame too large: {length}"));
    }

    let mut payload = vec![0u8; length as usize];
    if length > 0 {
        reader
            .read_exact(&mut payload)
            .map_err(|e| format!("Failed to read H2 frame payload ({length} bytes): {e}"))?;
    }

    Ok(H2Frame {
        frame_type,
        flags,
        stream_id,
        payload,
    })
}

/// Parse SETTINGS frame payload into a list of (id, value) pairs.
fn parse_h2_settings(payload: &[u8]) -> Vec<H2Setting> {
    let mut settings = Vec::new();
    let mut pos = 0;
    while pos + 6 <= payload.len() {
        let id = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let value = u32::from_be_bytes([
            payload[pos + 2],
            payload[pos + 3],
            payload[pos + 4],
            payload[pos + 5],
        ]);
        settings.push(H2Setting { id, value });
        pos += 6;
    }
    settings
}

/// Parse WINDOW_UPDATE frame payload.
fn parse_h2_window_update(payload: &[u8]) -> u32 {
    if payload.len() >= 4 {
        u32::from_be_bytes([payload[0] & 0x7f, payload[1], payload[2], payload[3]])
    } else {
        0
    }
}

/// Parse PRIORITY frame payload.
fn parse_h2_priority_payload(stream_id: u32, payload: &[u8]) -> Option<H2Priority> {
    if payload.len() < 5 {
        return None;
    }
    let exclusive = payload[0] & 0x80 != 0;
    let depends_on = u32::from_be_bytes([payload[0] & 0x7f, payload[1], payload[2], payload[3]]);
    let weight = payload[4];
    Some(H2Priority {
        stream_id,
        exclusive,
        depends_on,
        weight,
    })
}

/// H2 SETTINGS name for display.
fn h2_setting_name(id: u16) -> &'static str {
    match id {
        1 => "HEADER_TABLE_SIZE",
        2 => "ENABLE_PUSH",
        3 => "MAX_CONCURRENT_STREAMS",
        4 => "INITIAL_WINDOW_SIZE",
        5 => "MAX_FRAME_SIZE",
        6 => "MAX_HEADER_LIST_SIZE",
        8 => "ENABLE_CONNECT_PROTOCOL",
        _ => "UNKNOWN",
    }
}

// =============================================================================
// Minimal HPACK Decoder (pseudo-header order extraction only)
// =============================================================================

/// HPACK static table entries for pseudo-headers (index → header name).
fn hpack_static_pseudo_header(index: usize) -> Option<&'static str> {
    match index {
        1 => Some(":authority"),
        2 | 3 => Some(":method"),
        4 | 5 => Some(":path"),
        6 | 7 => Some(":scheme"),
        8..=14 => Some(":status"), // server-only, we'll filter
        _ => None,
    }
}

/// Decode an HPACK integer with the given prefix bit width.
/// Returns (value, bytes_consumed).
fn decode_hpack_integer(data: &[u8], prefix_bits: u8) -> (usize, usize) {
    if data.is_empty() {
        return (0, 0);
    }
    let mask = (1u16 << prefix_bits) - 1;
    let value = (data[0] & mask as u8) as usize;
    if value < mask as usize {
        return (value, 1);
    }
    // Multi-byte integer
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

/// Skip over an HPACK string (Huffman or raw). Returns bytes consumed.
fn skip_hpack_string(data: &[u8]) -> usize {
    if data.is_empty() {
        return 0;
    }
    let (length, header_bytes) = decode_hpack_integer(data, 7);
    header_bytes + length
}

/// Extract the pseudo-header order from HPACK-encoded header block data.
///
/// Only decodes enough to identify pseudo-headers (`:method`, `:authority`,
/// `:scheme`, `:path`) and their order. Stops at the first non-pseudo-header.
fn extract_pseudo_header_order(hpack_data: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    let mut pos = 0;

    while pos < hpack_data.len() {
        let byte = hpack_data[pos];

        if byte & 0x80 != 0 {
            // Indexed header field (1xxxxxxx)
            let (index, consumed) = decode_hpack_integer(&hpack_data[pos..], 7);
            pos += consumed;

            if let Some(name) = hpack_static_pseudo_header(index) {
                if name != ":status" {
                    result.push(name.to_string());
                }
            } else {
                // Non-pseudo-header or dynamic table entry — stop
                break;
            }
        } else if byte & 0xc0 == 0x40 {
            // Literal with incremental indexing (01xxxxxx)
            let (name_index, consumed) = decode_hpack_integer(&hpack_data[pos..], 6);
            pos += consumed;

            if name_index > 0 {
                if let Some(name) = hpack_static_pseudo_header(name_index) {
                    if name != ":status" {
                        result.push(name.to_string());
                    }
                } else {
                    break;
                }
            } else {
                // Literal name — skip name string, check if pseudo
                let name_len_consumed = skip_hpack_string(&hpack_data[pos..]);
                // Peek at the name to see if it's a pseudo-header
                if pos < hpack_data.len() {
                    let (str_len, str_header) = decode_hpack_integer(&hpack_data[pos..], 7);
                    let is_huffman = hpack_data[pos] & 0x80 != 0;
                    let name_start = pos + str_header;
                    if !is_huffman && name_start + str_len <= hpack_data.len() {
                        if let Ok(name) =
                            std::str::from_utf8(&hpack_data[name_start..name_start + str_len])
                        {
                            if name.starts_with(':') {
                                result.push(name.to_string());
                            } else {
                                break;
                            }
                        }
                    }
                }
                pos += name_len_consumed;
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
                    if name != ":status" {
                        result.push(name.to_string());
                    }
                } else {
                    break;
                }
            } else {
                // Literal name — stop (pseudo-headers always use indexed names)
                break;
            }
            pos += skip_hpack_string(&hpack_data[pos..]);
        }
    }

    result
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

// =============================================================================
// Akamai Fingerprint Computation
// =============================================================================

/// Build the Akamai fingerprint string from H2 capture data.
///
/// Format: `S[settings]|WU[window_update]|P[priority]|PS[pseudo_headers]`
fn compute_akamai_fingerprint(
    settings: &[H2Setting],
    window_update: u32,
    priorities: &[H2Priority],
    pseudo_header_order: &[String],
) -> String {
    // SETTINGS: "id:value;id:value;..."
    let settings_str: String = settings
        .iter()
        .map(|s| format!("{}:{}", s.id, s.value))
        .collect::<Vec<_>>()
        .join(";");

    // WINDOW_UPDATE
    let wu_str = window_update.to_string();

    // PRIORITY: "stream:exclusive:dep:weight,..." or "0"
    let priority_str = if priorities.is_empty() {
        "0".to_string()
    } else {
        priorities
            .iter()
            .map(|p| {
                format!(
                    "{}:{}:{}:{}",
                    p.stream_id,
                    if p.exclusive { 1 } else { 0 },
                    p.depends_on,
                    p.weight
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    };

    // Pseudo-header order: first char of each, comma-separated
    // :method → m, :authority → a, :scheme → s, :path → p
    let ps_str: String = pseudo_header_order
        .iter()
        .filter_map(|h| match h.as_str() {
            ":method" => Some("m"),
            ":authority" => Some("a"),
            ":scheme" => Some("s"),
            ":path" => Some("p"),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(",");

    format!("{settings_str}|{wu_str}|{priority_str}|{ps_str}")
}

fn h2_setting_id_value(id: lkh2::profile::H2SettingId) -> u16 {
    match id {
        lkh2::profile::H2SettingId::HeaderTableSize => 0x01,
        lkh2::profile::H2SettingId::EnablePush => 0x02,
        lkh2::profile::H2SettingId::MaxConcurrentStreams => 0x03,
        lkh2::profile::H2SettingId::InitialWindowSize => 0x04,
        lkh2::profile::H2SettingId::MaxFrameSize => 0x05,
        lkh2::profile::H2SettingId::MaxHeaderListSize => 0x06,
        lkh2::profile::H2SettingId::EnableConnectProtocol => 0x08,
        lkh2::profile::H2SettingId::NoRfc7540Priorities => 0x09,
        lkh2::profile::H2SettingId::Unknown(value) => value,
    }
}

fn pseudo_header_name(id: lkh2::profile::PseudoHeaderId) -> String {
    match id {
        lkh2::profile::PseudoHeaderId::Method => ":method",
        lkh2::profile::PseudoHeaderId::Authority => ":authority",
        lkh2::profile::PseudoHeaderId::Scheme => ":scheme",
        lkh2::profile::PseudoHeaderId::Path => ":path",
    }
    .into()
}

fn h2_fingerprint_from_profile(profile: &lkh2::profile::H2Profile) -> H2Fingerprint {
    let settings = profile
        .settings
        .iter()
        .map(|setting| H2Setting {
            id: h2_setting_id_value(setting.id),
            value: setting.value,
        })
        .collect::<Vec<_>>();
    let priority_frames = profile
        .priority_frames
        .iter()
        .map(|priority| H2Priority {
            stream_id: priority.stream_id,
            exclusive: priority.exclusive,
            depends_on: priority.dependency,
            weight: priority.weight,
        })
        .collect::<Vec<_>>();
    let pseudo_header_order = profile
        .pseudo_header_order
        .iter()
        .copied()
        .map(pseudo_header_name)
        .collect::<Vec<_>>();
    let akamai_fingerprint = compute_akamai_fingerprint(
        &settings,
        profile.window_update,
        &priority_frames,
        &pseudo_header_order,
    );
    H2Fingerprint {
        settings,
        window_update: profile.window_update,
        priority_frames,
        pseudo_header_order,
        akamai_hash: md5_hex(&akamai_fingerprint),
        akamai_hash_sha256: sha256_hex(&akamai_fingerprint),
        akamai_fingerprint,
    }
}

fn quic_packetization_fingerprint(
    packetization: &lkh3::QuicPacketizationProfile,
) -> QuicPacketizationFingerprint {
    QuicPacketizationFingerprint {
        initial_mtu: packetization.initial_mtu,
        initial_datagram_size: packetization.initial_datagram_size,
        disable_mtu_discovery: packetization.disable_mtu_discovery,
        enable_segmentation_offload: packetization.enable_segmentation_offload,
        enable_ecn: packetization.enable_ecn,
        initial_frame_layout: packetization.initial_frame_layout.as_ref().map(|layout| {
            layout
                .packets
                .iter()
                .map(|packet| {
                    let frames = packet
                        .frames
                        .iter()
                        .map(|frame| match frame {
                            lkh3::InitialFrameElement::Crypto { offset, length } => {
                                format!("crypto@{offset}+{length}")
                            }
                            lkh3::InitialFrameElement::Padding { length } => {
                                format!("padding+{length}")
                            }
                            lkh3::InitialFrameElement::Ping => "ping".to_string(),
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    format!("pn{}[{frames}]", packet.packet_number)
                })
                .collect::<Vec<_>>()
                .join("|")
        }),
    }
}

fn quic_fingerprint_from_profile(profile: &lkh3::QuicProfile) -> QuicFingerprint {
    let mut transport_parameters = vec![
        (
            "max_idle_timeout".to_string(),
            profile.transport_params.max_idle_timeout,
        ),
        (
            "initial_max_data".to_string(),
            profile.transport_params.initial_max_data,
        ),
        (
            "initial_max_stream_data_bidi_local".to_string(),
            profile.transport_params.initial_max_stream_data_bidi_local,
        ),
        (
            "initial_max_stream_data_bidi_remote".to_string(),
            profile.transport_params.initial_max_stream_data_bidi_remote,
        ),
        (
            "initial_max_stream_data_uni".to_string(),
            profile.transport_params.initial_max_stream_data_uni,
        ),
        (
            "initial_max_streams_bidi".to_string(),
            profile.transport_params.initial_max_streams_bidi,
        ),
        (
            "initial_max_streams_uni".to_string(),
            profile.transport_params.initial_max_streams_uni,
        ),
        (
            "active_connection_id_limit".to_string(),
            profile.transport_params.active_connection_id_limit,
        ),
    ];
    if let Some(value) = profile.transport_params.max_udp_payload_size {
        transport_parameters.push(("max_udp_payload_size".into(), value));
    }
    if let Some(value) = profile.transport_params.max_datagram_frame_size {
        transport_parameters.push(("max_datagram_frame_size".into(), value));
    }

    let pseudo_header_order = profile
        .h3
        .pseudo_header_order
        .iter()
        .map(|id| match id {
            lkh3::PseudoHeaderId::Method => ":method",
            lkh3::PseudoHeaderId::Authority => ":authority",
            lkh3::PseudoHeaderId::Scheme => ":scheme",
            lkh3::PseudoHeaderId::Path => ":path",
            lkh3::PseudoHeaderId::Protocol => ":protocol",
        })
        .map(str::to_string)
        .collect::<Vec<_>>();
    let quic_input = QuicFingerprintInput {
        transport_parameters,
        h3: H3FingerprintInput {
            settings: profile.h3.effective_settings(),
            pseudo_header_order,
            pseudo_header_order_token: profile.h3.pseudo_header_order_token(),
            grease_settings: profile.h3.grease_settings,
        },
        connection_id_length: profile.connection_id_length,
        initial_destination_connection_id_length: profile.initial_destination_connection_id_length,
        grease_transport_params: profile.transport_params.grease_transport_params,
        send_min_ack_delay: profile.transport_params.send_min_ack_delay,
        send_reserved_transport_parameter: profile
            .transport_params
            .send_reserved_transport_parameter,
        extra_transport_parameters: profile.transport_params.extra_transport_parameters.clone(),
        transport_parameter_order: profile.transport_params.transport_parameter_order.clone(),
        packetization: quic_packetization_fingerprint(&profile.packetization),
    };
    let mut fingerprint = convert_quic_fingerprint(collect_quic_fingerprint(&quic_input));
    fingerprint.h3.priority_updates = profile
        .h3
        .priority_updates
        .iter()
        .map(|(element_id, field_value)| H3PriorityUpdate {
            element_id: *element_id,
            field_value: field_value.clone(),
        })
        .collect();
    fingerprint
}

/// Compute MD5 hash of a string, returning hex-encoded digest.
fn md5_hex(input: &str) -> String {
    use md5::Digest;
    let hash = Md5::digest(input.as_bytes());
    hex::encode(hash)
}

/// Compute SHA-256 hash of a string, returning hex-encoded digest.
fn sha256_hex(input: &str) -> String {
    use sha2::Digest;
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(hash)
}

// =============================================================================
// TLS Server (for capture with H2)
// =============================================================================

fn generate_self_signed_identity(
) -> Result<(Vec<rustls::pki_types::CertificateDer<'static>>, Vec<u8>), String> {
    let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| format!("Certificate generation failed: {e}"))?;

    let certs = vec![certified_key.cert.der().clone()];
    let key_der = certified_key.signing_key.serialize_der();

    Ok((certs, key_der))
}

fn load_identity_from_files(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<rustls::pki_types::CertificateDer<'static>>, Vec<u8>), String> {
    let cert_pem =
        fs::read(cert_path).map_err(|e| format!("Failed to read certificate {cert_path}: {e}"))?;
    let key_pem =
        fs::read(key_path).map_err(|e| format!("Failed to read private key {key_path}: {e}"))?;

    let mut cert_reader = std::io::BufReader::new(cert_pem.as_slice());
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse certificate PEM {cert_path}: {e}"))?;
    if certs.is_empty() {
        return Err(format!("No certificates found in {cert_path}"));
    }

    let mut key_reader = std::io::BufReader::new(key_pem.as_slice());
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("Failed to parse private key PEM {key_path}: {e}"))?
        .ok_or_else(|| format!("No private key found in {key_path}"))?;

    let key_der = match key {
        rustls::pki_types::PrivateKeyDer::Pkcs8(key) => key.secret_pkcs8_der().to_vec(),
        rustls::pki_types::PrivateKeyDer::Pkcs1(key) => key.secret_pkcs1_der().to_vec(),
        rustls::pki_types::PrivateKeyDer::Sec1(key) => key.secret_sec1_der().to_vec(),
        _ => return Err(format!("Unsupported private key type in {key_path}")),
    };

    Ok((certs, key_der))
}

fn load_or_generate_identity(
    cert_path: Option<&str>,
    key_path: Option<&str>,
) -> Result<
    (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        Vec<u8>,
        &'static str,
    ),
    String,
> {
    match (cert_path, key_path) {
        (Some(cert), Some(key)) => {
            let (certs, key_der) = load_identity_from_files(cert, key)?;
            Ok((certs, key_der, "custom"))
        }
        (None, None) => {
            let (certs, key_der) = generate_self_signed_identity()?;
            Ok((certs, key_der, "self-signed"))
        }
        _ => Err("--cert and --key must be provided together".into()),
    }
}

fn make_tls_server_config_from_identity(
    certs: &[rustls::pki_types::CertificateDer<'static>],
    key_der: &[u8],
) -> Result<Arc<rustls::ServerConfig>, String> {
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(key_der.to_vec());

    let mut config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .map_err(|e| format!("TLS version configuration failed: {e}"))?
    .with_no_client_auth()
    .with_single_cert(certs.to_vec(), key.into())
    .map_err(|e| format!("TLS config error: {e}"))?;

    // Advertise h2 via ALPN so browsers negotiate HTTP/2.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

fn make_tls_server_config() -> Result<Arc<rustls::ServerConfig>, String> {
    let (certs, key_der) = generate_self_signed_identity()?;
    make_tls_server_config_from_identity(&certs, &key_der)
}

fn make_quic_server_config_from_identity(
    certs: &[rustls::pki_types::CertificateDer<'static>],
    key_der: &[u8],
) -> Result<quinn::ServerConfig, String> {
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(key_der.to_vec());

    let mut config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| format!("QUIC TLS version configuration failed: {e}"))?
    .with_no_client_auth()
    .with_single_cert(certs.to_vec(), key.into())
    .map_err(|e| format!("QUIC TLS config error: {e}"))?;
    config.alpn_protocols = vec![b"h3".to_vec()];
    config.max_early_data_size = u32::MAX;

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(config))
        .map_err(|e| format!("QUIC crypto config error: {e}"))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
}

/// Complete the TLS handshake using rustls, given the already-read ClientHello bytes.
///
/// Returns the ServerConnection ready for application data I/O.
fn complete_tls_handshake(
    config: &Arc<rustls::ServerConfig>,
    tcp: &mut TcpStream,
    client_hello_record: &[u8],
) -> Result<rustls::ServerConnection, String> {
    let mut conn = rustls::ServerConnection::new(Arc::clone(config))
        .map_err(|e| format!("ServerConnection creation failed: {e}"))?;

    // Feed the already-read ClientHello bytes
    let mut cursor = client_hello_record;
    conn.read_tls(&mut cursor)
        .map_err(|e| format!("Failed to feed ClientHello to rustls: {e}"))?;
    conn.process_new_packets()
        .map_err(|e| format!("TLS process error after ClientHello: {e}"))?;

    // Handshake loop
    for _ in 0..100 {
        // safety limit
        if !conn.is_handshaking() {
            break;
        }
        if conn.wants_write() {
            conn.write_tls(tcp)
                .map_err(|e| format!("TLS write error: {e}"))?;
            tcp.flush().map_err(|e| format!("TCP flush error: {e}"))?;
        }
        if conn.wants_read() {
            let n = conn
                .read_tls(tcp)
                .map_err(|e| format!("TLS read error: {e}"))?;
            if n == 0 {
                return Err("Connection closed during TLS handshake".to_string());
            }
            conn.process_new_packets()
                .map_err(|e| format!("TLS process error: {e}"))?;
        }
    }

    if conn.is_handshaking() {
        return Err("TLS handshake did not complete".to_string());
    }

    Ok(conn)
}

/// Capture HTTP/2 fingerprint after TLS handshake is complete.
///
/// Reads the H2 connection preface, SETTINGS, WINDOW_UPDATE, optional PRIORITY,
/// and the first HEADERS frame. Returns the parsed H2 fingerprint and the
/// stream ID of the request (needed to send back a response).
fn capture_h2_fingerprint(
    conn: &mut rustls::ServerConnection,
    tcp: &mut TcpStream,
) -> Result<(H2Fingerprint, u32), String> {
    // Use rustls::Stream for convenient Read+Write over TLS
    let mut tls = rustls::Stream::new(conn, tcp);

    // 1. Read H2 connection preface (24 bytes)
    let mut preface = [0u8; 24];
    tls.read_exact(&mut preface)
        .map_err(|e| format!("Failed to read H2 preface: {e}"))?;

    if &preface != H2_PREFACE {
        return Err(format!(
            "Invalid H2 preface: {:?}",
            String::from_utf8_lossy(&preface)
        ));
    }
    eprintln!("  H2 connection preface received");

    // 2. Send our server SETTINGS (empty = use defaults)
    let server_settings = [0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
    tls.write_all(&server_settings)
        .map_err(|e| format!("Failed to send server SETTINGS: {e}"))?;
    tls.flush().map_err(|e| format!("Flush error: {e}"))?;

    // 3. Read client frames until we get HEADERS (or timeout)
    let mut settings = Vec::new();
    let mut window_update: u32 = 0;
    let mut priority_frames = Vec::new();
    let mut pseudo_header_order = Vec::new();
    let mut got_headers = false;
    let mut sent_settings_ack = false;
    let mut request_stream_id: u32 = 1; // default to stream 1

    for frame_num in 0..50 {
        // safety limit
        let frame = match read_h2_frame(&mut tls) {
            Ok(f) => f,
            Err(e) => {
                if frame_num > 0 {
                    eprintln!("  (Stopped reading H2 frames: {e})");
                    break;
                }
                return Err(e);
            }
        };

        match frame.frame_type {
            H2_SETTINGS => {
                if frame.flags & 0x01 != 0 {
                    // ACK — ignore
                    eprintln!("  H2 SETTINGS ACK received");
                    continue;
                }
                settings = parse_h2_settings(&frame.payload);
                eprintln!("  H2 SETTINGS ({} params):", settings.len());
                for s in &settings {
                    eprintln!(
                        "    {} (0x{:02x}) = {}",
                        h2_setting_name(s.id),
                        s.id,
                        s.value
                    );
                }

                // Send SETTINGS ACK
                if !sent_settings_ack {
                    let ack = [0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00];
                    let _ = tls.write_all(&ack);
                    let _ = tls.flush();
                    sent_settings_ack = true;
                }
            }
            H2_WINDOW_UPDATE => {
                if frame.stream_id == 0 {
                    window_update = parse_h2_window_update(&frame.payload);
                    eprintln!("  H2 WINDOW_UPDATE (connection): {window_update}");
                }
            }
            H2_PRIORITY => {
                if let Some(p) = parse_h2_priority_payload(frame.stream_id, &frame.payload) {
                    eprintln!(
                        "  H2 PRIORITY stream={} exclusive={} dep={} weight={}",
                        p.stream_id, p.exclusive, p.depends_on, p.weight
                    );
                    priority_frames.push(p);
                }
            }
            H2_HEADERS => {
                eprintln!(
                    "  H2 HEADERS frame (stream={}, {} bytes)",
                    frame.stream_id,
                    frame.payload.len()
                );
                request_stream_id = frame.stream_id;
                let hpack_block = extract_hpack_block(&frame.payload, frame.flags);
                pseudo_header_order = extract_pseudo_header_order(hpack_block);
                eprintln!("  Pseudo-header order: {:?}", pseudo_header_order);
                got_headers = true;
                break;
            }
            _ => {
                eprintln!(
                    "  H2 frame type=0x{:02x} stream={} len={}",
                    frame.frame_type,
                    frame.stream_id,
                    frame.payload.len()
                );
            }
        }
    }

    if !got_headers {
        eprintln!("  Warning: did not receive HEADERS frame, pseudo-header order unavailable");
    }

    // Build Akamai fingerprint
    let akamai_fingerprint = compute_akamai_fingerprint(
        &settings,
        window_update,
        &priority_frames,
        &pseudo_header_order,
    );
    let akamai_hash = md5_hex(&akamai_fingerprint);
    let akamai_hash_sha256 = sha256_hex(&akamai_fingerprint);

    eprintln!("  Akamai fingerprint: {akamai_fingerprint}");
    eprintln!("  Akamai hash (MD5):  {akamai_hash}");

    let fp = H2Fingerprint {
        settings,
        window_update,
        priority_frames,
        pseudo_header_order,
        akamai_fingerprint,
        akamai_hash,
        akamai_hash_sha256,
    };

    Ok((fp, request_stream_id))
}

fn push_hpack_literal(block: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    assert!(
        name.len() < 128,
        "header name too long for simple HPACK encoder"
    );
    assert!(
        value.len() < 128,
        "header value too long for simple HPACK encoder"
    );
    block.push(0x00); // literal header field without indexing, new name
    block.push(name.len() as u8);
    block.extend_from_slice(name);
    block.push(value.len() as u8);
    block.extend_from_slice(value);
}

fn send_h2_response(
    conn: &mut rustls::ServerConnection,
    tcp: &mut TcpStream,
    stream_id: u32,
    content_type: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) {
    let mut tls = rustls::Stream::new(conn, tcp);

    // 1. HEADERS frame: :status 200 + literal headers
    let mut hpack = Vec::new();
    hpack.push(0x88); // :status 200 (indexed, static table entry 8)
    push_hpack_literal(&mut hpack, b"content-type", content_type.as_bytes());
    for (name, value) in extra_headers {
        push_hpack_literal(&mut hpack, name.as_bytes(), value.as_bytes());
    }

    let hpack_len = hpack.len() as u32;
    let mut headers_frame = Vec::with_capacity(9 + hpack.len());
    headers_frame.push((hpack_len >> 16) as u8);
    headers_frame.push((hpack_len >> 8) as u8);
    headers_frame.push(hpack_len as u8);
    headers_frame.push(0x01); // type = HEADERS
    headers_frame.push(0x04); // flags = END_HEADERS
    let sid_bytes = stream_id.to_be_bytes();
    headers_frame.push(sid_bytes[0] & 0x7f); // clear reserved bit
    headers_frame.push(sid_bytes[1]);
    headers_frame.push(sid_bytes[2]);
    headers_frame.push(sid_bytes[3]);
    headers_frame.extend_from_slice(&hpack);

    let _ = tls.write_all(&headers_frame);

    // 2. DATA frame(s): body (split into 16KB chunks if needed)
    let max_frame_size = 16384;
    let mut offset = 0;
    while offset < body.len() {
        let chunk_end = (offset + max_frame_size).min(body.len());
        let chunk = &body[offset..chunk_end];
        let is_last = chunk_end == body.len();
        let chunk_len = chunk.len() as u32;

        let mut data_frame = Vec::with_capacity(9 + chunk.len());
        data_frame.push((chunk_len >> 16) as u8);
        data_frame.push((chunk_len >> 8) as u8);
        data_frame.push(chunk_len as u8);
        data_frame.push(0x00); // type = DATA
        data_frame.push(if is_last { 0x01 } else { 0x00 }); // END_STREAM on last
        data_frame.push(sid_bytes[0] & 0x7f);
        data_frame.push(sid_bytes[1]);
        data_frame.push(sid_bytes[2]);
        data_frame.push(sid_bytes[3]);
        data_frame.extend_from_slice(chunk);

        let _ = tls.write_all(&data_frame);
        offset = chunk_end;
    }

    // 3. GOAWAY
    let goaway = [
        0x00, 0x00, 0x08, // length = 8
        0x07, // type = GOAWAY
        0x00, // flags
        0x00, 0x00, 0x00, 0x00, // stream_id = 0
        0x00, 0x00, 0x00, 0x01, // last_stream_id = 1
        0x00, 0x00, 0x00, 0x00, // error = NO_ERROR
    ];
    let _ = tls.write_all(&goaway);
    let _ = tls.flush();
}

/// Send an HTTP/2 response with JSON body back to the browser, then GOAWAY.
fn send_h2_json_response(
    conn: &mut rustls::ServerConnection,
    tcp: &mut TcpStream,
    stream_id: u32,
    json: &str,
) {
    send_h2_response(
        conn,
        tcp,
        stream_id,
        "application/json",
        json.as_bytes(),
        &[("access-control-allow-origin", "*")],
    );
}

fn send_h2_bootstrap_response(
    conn: &mut rustls::ServerConnection,
    tcp: &mut TcpStream,
    stream_id: u32,
    body: &str,
    port: u16,
) {
    let alt_svc = format!("h3=\":{port}\"; ma=86400");
    send_h2_response(
        conn,
        tcp,
        stream_id,
        "text/html; charset=utf-8",
        body.as_bytes(),
        &[("cache-control", "no-store"), ("alt-svc", &alt_svc)],
    );
}

// =============================================================================
// Hex I/O
// =============================================================================

fn read_hex(source: &str) -> Result<Vec<u8>, String> {
    let raw = if source == "-" {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("Failed to read stdin: {e}"))?;
        buf
    } else {
        fs::read_to_string(source).map_err(|e| format!("Failed to read {source}: {e}"))?
    };

    let cleaned: String = raw
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .flat_map(|line| line.chars())
        .filter(|c| c.is_ascii_hexdigit())
        .collect();

    if cleaned.is_empty() {
        return Err("No hex data found (file may be empty or contain only comments)".into());
    }

    hex::decode(&cleaned).map_err(|e| format!("Invalid hex: {e}"))
}

// =============================================================================
// Live Capture
// =============================================================================

#[derive(Debug)]
enum ConnectionData {
    TlsRecord(Vec<u8>),
    HttpRequest,
    Unknown(u8),
}

fn read_client_hello_from_stream(stream: &mut TcpStream) -> Result<ConnectionData, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("Failed to set read timeout: {e}"))?;

    let mut header = [0u8; 5];
    stream
        .read_exact(&mut header)
        .map_err(|e| format!("Failed to read TLS record header: {e}"))?;

    if header[0] != 0x16 {
        if header[0].is_ascii_alphabetic() {
            return Ok(ConnectionData::HttpRequest);
        }
        return Ok(ConnectionData::Unknown(header[0]));
    }

    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if record_len == 0 || record_len > 16384 + 2048 {
        return Err(format!("Invalid TLS record length: {record_len}"));
    }

    let mut body = vec![0u8; record_len];
    stream
        .read_exact(&mut body)
        .map_err(|e| format!("Failed to read TLS record body ({record_len} bytes): {e}"))?;

    let mut record = Vec::with_capacity(5 + record_len);
    record.extend_from_slice(&header);
    record.extend_from_slice(&body);
    Ok(ConnectionData::TlsRecord(record))
}

fn send_http_redirect(stream: &mut TcpStream, port: u16) {
    let location = format!("https://localhost:{port}/");
    let body_content = format!(
        "<html><body><h1>Redirecting...</h1>\
         <p>Please use <a href=\"{location}\">HTTPS</a>.</p></body></html>"
    );
    let response = format!(
        "HTTP/1.1 301 Moved Permanently\r\n\
         Location: {location}\r\n\
         Content-Type: text/html\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body_content}",
        body_content.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

enum CaptureResult {
    Success(String),
    HttpRedirected,
    Skipped(String),
    Error(String),
}

fn output_has_h2_fingerprint(json: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .and_then(|value| value.get("h2_fingerprint").cloned())
        .is_some_and(|value| !value.is_null())
}

fn handle_capture_connection(
    stream: &mut TcpStream,
    name: &str,
    addr: &std::net::SocketAddr,
    port: u16,
    tls_config: Option<&Arc<rustls::ServerConfig>>,
) -> CaptureResult {
    eprintln!("Connection from {addr}");

    let conn_data = match read_client_hello_from_stream(stream) {
        Ok(d) => d,
        Err(e) => return CaptureResult::Error(e),
    };

    match conn_data {
        ConnectionData::HttpRequest => {
            eprintln!(
                "  Received plain HTTP request (not TLS).\n  \
                 Sending redirect to https://localhost:{port}/ ..."
            );
            send_http_redirect(stream, port);
            CaptureResult::HttpRedirected
        }
        ConnectionData::Unknown(byte) => CaptureResult::Skipped(format!(
            "Unknown protocol: first byte = 0x{byte:02x} ('{}'). Skipping.",
            if byte.is_ascii_graphic() {
                byte as char
            } else {
                '.'
            }
        )),
        ConnectionData::TlsRecord(data) => {
            eprintln!(
                "  TLS record: {} bytes (version=0x{:02x}{:02x}, body={})",
                data.len(),
                data[1],
                data[2],
                data.len() - 5
            );

            // Parse ClientHello for TLS fingerprint
            let ch = match parse_client_hello(&data) {
                Ok(ch) => ch,
                Err(e) => return CaptureResult::Error(e.to_string()),
            };

            eprintln!("  Cipher suites: {}", ch.cipher_suites.len());
            eprintln!("  Extensions: {}", ch.extensions.len());
            eprintln!(
                "  GREASE: {}",
                if ch.cipher_suites.iter().any(|s| is_grease_value(*s))
                    || ch
                        .extensions
                        .iter()
                        .any(|e| is_grease_value(e.extension_type))
                {
                    "yes"
                } else {
                    "no"
                }
            );

            let mut profile = build_profile(name, &ch);

            // If TLS config is provided, complete the handshake and capture H2
            if let Some(config) = tls_config {
                eprintln!("  Completing TLS handshake...");

                // Increase read timeout for the handshake + H2 phase
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));

                match complete_tls_handshake(config, stream, &data) {
                    Ok(mut conn) => {
                        let alpn = conn
                            .alpn_protocol()
                            .map(|p| String::from_utf8_lossy(p).to_string());
                        eprintln!("  TLS handshake complete (ALPN: {:?})", alpn);

                        if alpn.as_deref() == Some("h2") {
                            eprintln!("  Capturing HTTP/2 fingerprint...");
                            match capture_h2_fingerprint(&mut conn, stream) {
                                Ok((h2fp, request_stream_id)) => {
                                    profile.h2_fingerprint = Some(h2fp);

                                    // Send the fingerprint JSON back as an H2 response
                                    let json = serde_json::to_string_pretty(&profile)
                                        .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
                                    eprintln!("  Sending fingerprint JSON as H2 response...");
                                    send_h2_json_response(
                                        &mut conn,
                                        stream,
                                        request_stream_id,
                                        &json,
                                    );
                                }
                                Err(e) => {
                                    eprintln!("  H2 capture error: {e}");
                                    eprintln!("  (TLS fingerprint was still captured)");
                                }
                            }
                        } else {
                            eprintln!("  ALPN is not h2, skipping H2 fingerprint");
                        }
                    }
                    Err(e) => {
                        eprintln!("  TLS handshake failed: {e}");
                        eprintln!("  (TLS fingerprint was still captured from ClientHello)");
                    }
                }
            }

            match serde_json::to_string_pretty(&profile) {
                Ok(json) => CaptureResult::Success(json),
                Err(e) => CaptureResult::Error(format!("JSON serialization error: {e}")),
            }
        }
    }
}

fn write_output(json: &str, output: &Option<String>) {
    match output {
        Some(path) => {
            fs::write(path, json).unwrap_or_else(|e| {
                eprintln!("Error writing {path}: {e}");
                std::process::exit(1);
            });
            eprintln!("Profile written to {path}");
        }
        None => {
            println!("{json}");
        }
    }
}

fn chrome_base_tls_profile(version: ChromePresetVersion) -> lktls::profile::types::TlsProfile {
    match version {
        ChromePresetVersion::Chrome131 => lktls::profile::presets::chrome_131(),
        ChromePresetVersion::Chrome144 => lktls::profile::presets::chrome_144(),
        ChromePresetVersion::Chrome145 => lktls::profile::presets::chrome_145(),
        ChromePresetVersion::Chrome146 => lktls::profile::presets::chrome_146(),
        ChromePresetVersion::Chrome147 => lktls::profile::presets::chrome_147(),
        ChromePresetVersion::Chrome148 => lktls::profile::presets::chrome_148(),
        ChromePresetVersion::Chrome149 => lktls::profile::presets::chrome_149(),
        ChromePresetVersion::Chrome150 => lktls::profile::presets::chrome_150(),
        ChromePresetVersion::Chrome151 => lktls::profile::presets::chrome_151(),
    }
}

fn chrome_quic_tls_profile(version: ChromePresetVersion) -> lktls::profile::types::TlsProfile {
    use lktls::profile::types::{ext_type, ExtensionSource, ExtensionSpec, TlsVersion};

    match version {
        ChromePresetVersion::Chrome146 => return lktls::profile::presets::chrome_146_quic(),
        ChromePresetVersion::Chrome150 => return lktls::profile::presets::chrome_150_quic(),
        ChromePresetVersion::Chrome151 => return lktls::profile::presets::chrome_151_quic(),
        _ => {}
    }

    let mut profile = chrome_base_tls_profile(version);
    let base_extension_types = profile
        .extensions
        .iter()
        .map(|extension| extension.extension_type)
        .collect::<std::collections::BTreeSet<_>>();
    let alps_extension_type = if matches!(version, ChromePresetVersion::Chrome131) {
        ext_type::APPLICATION_SETTINGS
    } else {
        ext_type::APPLICATION_SETTINGS_NEW
    };

    profile.name = format!("{} QUIC", profile.name);
    profile.tls_min_version = TlsVersion::Tls13;
    profile.tls_max_version = TlsVersion::Tls13;
    profile.session_id_length = 0;
    profile.alpn_protocols = vec!["h3".to_string()];
    profile.alps_protocols = Some(vec!["h3".to_string()]);
    profile.randomization = None;

    let mut extension_types = vec![
        ext_type::PSK_KEY_EXCHANGE_MODES,
        ext_type::SUPPORTED_GROUPS,
        ext_type::KEY_SHARE,
    ];
    if base_extension_types.contains(&ext_type::ENCRYPTED_CLIENT_HELLO) {
        extension_types.push(ext_type::ENCRYPTED_CLIENT_HELLO);
    }
    extension_types.extend([
        ext_type::ALPN,
        ext_type::SNI,
        ext_type::SIGNATURE_ALGORITHMS,
        ext_type::EARLY_DATA,
        ext_type::SUPPORTED_VERSIONS,
        ext_type::QUIC_TRANSPORT_PARAMETERS,
    ]);
    if profile.compress_cert_algorithms.is_some() {
        extension_types.insert(6, ext_type::COMPRESS_CERTIFICATE);
    }
    if profile.alps_protocols.is_some() {
        extension_types.push(alps_extension_type);
    }

    profile.extensions = extension_types
        .into_iter()
        .map(|extension_type| ExtensionSpec {
            extension_type,
            source: ExtensionSource::Auto,
        })
        .collect();
    profile
}

fn chrome_tls_profile(
    version: ChromePresetVersion,
    protocol: ChromeCaptureProtocol,
) -> lktls::profile::types::TlsProfile {
    match protocol {
        ChromeCaptureProtocol::H2 => chrome_base_tls_profile(version),
        ChromeCaptureProtocol::H3 => chrome_quic_tls_profile(version),
    }
}

fn chrome_h2_profile(version: ChromePresetVersion) -> lkh2::profile::H2Profile {
    match version {
        ChromePresetVersion::Chrome131 => lkh2::profile::chrome_131_h2(),
        ChromePresetVersion::Chrome144 => lkh2::profile::chrome_144_h2(),
        ChromePresetVersion::Chrome145 => lkh2::profile::chrome_145_h2(),
        ChromePresetVersion::Chrome146 => lkh2::profile::chrome_146_h2(),
        ChromePresetVersion::Chrome147 => lkh2::profile::chrome_147_h2(),
        ChromePresetVersion::Chrome148 => lkh2::profile::chrome_148_h2(),
        ChromePresetVersion::Chrome149 => lkh2::profile::chrome_149_h2(),
        ChromePresetVersion::Chrome150 => lkh2::profile::chrome_150_h2(),
        ChromePresetVersion::Chrome151 => lkh2::profile::chrome_151_h2(),
    }
}

fn chrome_quic_profile(version: ChromePresetVersion) -> lkh3::QuicProfile {
    match version {
        ChromePresetVersion::Chrome146 => lkh3::chrome_146_quic(),
        ChromePresetVersion::Chrome150 => lkh3::chrome_150_quic(),
        ChromePresetVersion::Chrome151 => lkh3::chrome_151_quic(),
        _ => lkh3::chrome_quic(),
    }
}

fn export_chrome_preset_profile(
    version: ChromePresetVersion,
    protocol: ChromeCaptureProtocol,
) -> OutputProfile {
    let tls = chrome_tls_profile(version, protocol);
    let mut profile = output_profile_from_tls_profile(&tls);
    match protocol {
        ChromeCaptureProtocol::H2 => {
            profile.h2_fingerprint = Some(h2_fingerprint_from_profile(&chrome_h2_profile(version)));
        }
        ChromeCaptureProtocol::H3 => {
            profile.quic_fingerprint =
                Some(quic_fingerprint_from_profile(&chrome_quic_profile(version)));
        }
    }
    profile
}

fn find_browser_executable(explicit: Option<&str>) -> Result<PathBuf, String> {
    if let Some(path) = explicit {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        return Err(format!("Chrome executable not found: {}", path.display()));
    }

    let mut candidates = Vec::new();
    if cfg!(target_os = "windows") {
        for env_name in ["PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"] {
            if let Some(root) = std::env::var_os(env_name) {
                candidates.push(
                    PathBuf::from(root)
                        .join("Google")
                        .join("Chrome")
                        .join("Application")
                        .join("chrome.exe"),
                );
            }
        }
        candidates.extend(
            ["chrome.exe", "chrome", "chromium.exe", "chromium"]
                .into_iter()
                .map(PathBuf::from),
        );
    } else if cfg!(target_os = "macos") {
        candidates.extend([
            PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            PathBuf::from("/Applications/Chromium.app/Contents/MacOS/Chromium"),
            PathBuf::from("google-chrome"),
            PathBuf::from("chrome"),
            PathBuf::from("chromium"),
        ]);
    } else {
        candidates.extend(
            [
                "google-chrome",
                "google-chrome-stable",
                "chrome",
                "chromium",
                "chromium-browser",
            ]
            .into_iter()
            .map(PathBuf::from),
        );
    }

    for candidate in candidates {
        if candidate.components().count() > 1 {
            if candidate.is_file() {
                return Ok(candidate);
            }
        } else if let Some(path) = find_on_path(&candidate) {
            return Ok(path);
        }
    }

    Err("Chrome/Chromium executable not found; pass --browser".into())
}

fn find_on_path(name: &Path) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var).find_map(|dir| {
        let candidate = dir.join(name);
        candidate.is_file().then_some(candidate)
    })
}

fn unique_temp_profile_dir() -> PathBuf {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    std::env::temp_dir().join(format!(
        "lkrequest-profile-collector-chrome-{millis}-{}",
        std::process::id()
    ))
}

fn unique_temp_capture_file() -> PathBuf {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    std::env::temp_dir().join(format!(
        "lkrequest-profile-collector-capture-{millis}-{}.json",
        std::process::id()
    ))
}

fn chrome_capture_url(
    protocol: ChromeCaptureProtocol,
    port: u16,
    http_port: Option<u16>,
) -> String {
    match (protocol, http_port) {
        (_, Some(http_port)) => format!("http://127.0.0.1:{http_port}/"),
        (ChromeCaptureProtocol::H2, None) | (ChromeCaptureProtocol::H3, None) => {
            format!("https://127.0.0.1:{port}/")
        }
    }
}

fn spawn_chrome(
    browser: &Path,
    url: &str,
    user_data_dir: &Path,
    chrome_args: &[String],
) -> Result<Child, String> {
    fs::create_dir_all(user_data_dir).map_err(|e| {
        format!(
            "failed to create Chrome user data dir {}: {e}",
            user_data_dir.display()
        )
    })?;

    let mut command = Command::new(browser);
    command
        .arg("--headless=new")
        .arg("--disable-gpu")
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--disable-background-networking")
        .arg("--disable-component-update")
        .arg("--disable-sync")
        .arg("--ignore-certificate-errors")
        .arg("--allow-insecure-localhost")
        .arg("--enable-quic")
        .arg(format!("--user-data-dir={}", user_data_dir.display()))
        .args(chrome_args)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    command
        .spawn()
        .map_err(|e| format!("failed to start Chrome {}: {e}", browser.display()))
}

fn wait_for_output_file(path: &Path, timeout: Duration) -> Result<String, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if path.is_file() {
            match fs::read_to_string(path) {
                Ok(content) if !content.trim().is_empty() => return Ok(content),
                Ok(_) => {}
                Err(error) => return Err(format!("failed to read {}: {error}", path.display())),
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for capture output {} after {timeout:?}",
                path.display()
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn flatten_json(
    path: &str,
    value: &serde_json::Value,
    out: &mut BTreeMap<String, serde_json::Value>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                let child = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                flatten_json(&child, value, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, value) in items.iter().enumerate() {
                flatten_json(&format!("{path}[{index}]"), value, out);
            }
            if items.is_empty() {
                out.insert(path.to_string(), serde_json::Value::Array(Vec::new()));
            }
        }
        _ => {
            out.insert(path.to_string(), value.clone());
        }
    }
}

fn compare_json_values(
    left_label: String,
    right_label: String,
    left: &serde_json::Value,
    right: &serde_json::Value,
) -> JsonComparisonReport {
    let mut left_fields = BTreeMap::new();
    let mut right_fields = BTreeMap::new();
    flatten_json("", left, &mut left_fields);
    flatten_json("", right, &mut right_fields);

    let keys = left_fields
        .keys()
        .chain(right_fields.keys())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let mut matches = 0usize;
    let mut mismatches = 0usize;
    let mut fields = Vec::new();

    for path in keys {
        let left = left_fields.get(&path).cloned();
        let right = right_fields.get(&path).cloned();
        let status = match (&left, &right) {
            (Some(left), Some(right)) if left == right => {
                matches += 1;
                JsonFieldStatus::Match
            }
            (Some(_), Some(_)) => {
                mismatches += 1;
                JsonFieldStatus::Mismatch
            }
            (Some(_), None) => {
                mismatches += 1;
                JsonFieldStatus::MissingRight
            }
            (None, Some(_)) => {
                mismatches += 1;
                JsonFieldStatus::MissingLeft
            }
            (None, None) => continue,
        };
        fields.push(JsonFieldDiff {
            path,
            status,
            left,
            right,
        });
    }

    JsonComparisonReport {
        left_label,
        right_label,
        matches,
        mismatches,
        fields,
    }
}

fn render_json_comparison_text(report: &JsonComparisonReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Field comparison: {} vs {}\n",
        report.left_label, report.right_label
    ));
    out.push_str(&format!(
        "matches: {}, mismatches: {}\n",
        report.matches, report.mismatches
    ));
    for field in &report.fields {
        if matches!(field.status, JsonFieldStatus::Match) {
            continue;
        }
        out.push_str(&format!(
            "\n{}: {:?}\n  {}: {}\n  {}: {}\n",
            field.path,
            field.status,
            report.left_label,
            field
                .left
                .as_ref()
                .map(serde_json::Value::to_string)
                .unwrap_or_else(|| "<missing>".into()),
            report.right_label,
            field
                .right
                .as_ref()
                .map(serde_json::Value::to_string)
                .unwrap_or_else(|| "<missing>".into()),
        ));
    }
    out
}

fn run_tls_capture_server_once(
    port: u16,
    name: String,
    output: Option<String>,
    http_port: Option<u16>,
    timeout: Duration,
) -> Result<(), String> {
    let tls_config = make_tls_server_config()?;

    if let Some(hp) = http_port {
        let http_bind = format!("0.0.0.0:{hp}");
        let http_listener = TcpListener::bind(&http_bind)
            .map_err(|e| format!("Failed to bind HTTP redirect port {hp}: {e}"))?;
        std::thread::spawn(move || {
            for mut stream in http_listener.incoming().flatten() {
                send_http_redirect(&mut stream, port);
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
        });
    }

    let bind_addr = format!("0.0.0.0:{port}");
    let listener =
        TcpListener::bind(&bind_addr).map_err(|e| format!("Failed to bind {bind_addr}: {e}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("Failed to set TLS listener nonblocking: {e}"))?;

    eprintln!("CaptureChrome H2 server listening on https://localhost:{port}");
    let deadline = Instant::now() + timeout + Duration::from_secs(2);
    loop {
        let (mut stream, addr) = match listener.accept() {
            Ok(conn) => conn,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "timed out waiting for Chrome H2 connection after {timeout:?}"
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(error) => return Err(format!("Failed to accept TLS capture connection: {error}")),
        };
        stream
            .set_nonblocking(false)
            .map_err(|e| format!("Failed to set TLS stream blocking mode: {e}"))?;

        match handle_capture_connection(&mut stream, &name, &addr, port, Some(&tls_config)) {
            CaptureResult::Success(json) => {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                if output_has_h2_fingerprint(&json) {
                    if let Some(path) = output {
                        fs::write(&path, &json)
                            .map_err(|e| format!("Error writing {path}: {e}"))?;
                    } else {
                        println!("{json}");
                    }
                    return Ok(());
                }
                eprintln!("  CaptureChrome H2 did not include an HTTP/2 fingerprint; waiting for another connection");
            }
            CaptureResult::HttpRedirected | CaptureResult::Skipped(_) => {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
            CaptureResult::Error(error) => {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                eprintln!("  CaptureChrome H2 connection error: {error}");
            }
        }
    }
}

async fn run_capture_chrome_command(options: CaptureChromeOptions) -> Result<(), String> {
    let browser = find_browser_executable(options.browser.as_deref())?;
    let generated_profile_dir = options.user_data_dir.is_none();
    let user_data_dir = options
        .user_data_dir
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(unique_temp_profile_dir);
    let output_path = options
        .output
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(unique_temp_capture_file);
    let server_output_path = if options.output.is_some() {
        unique_temp_capture_file()
    } else {
        output_path.clone()
    };
    let output_arg = Some(server_output_path.to_string_lossy().into_owned());

    let protocol = options.protocol;
    let port = options.port;
    let http_port = options.http_port;
    let name = options.name;
    let timeout = Duration::from_secs(options.timeout_secs);
    let mut chrome_args = options.chrome_args;
    if matches!(protocol, ChromeCaptureProtocol::H2)
        && !chrome_args.iter().any(|arg| arg == "--dump-dom")
    {
        chrome_args.push("--dump-dom".into());
    }
    if matches!(protocol, ChromeCaptureProtocol::H3)
        && !chrome_args
            .iter()
            .any(|arg| arg.starts_with("--origin-to-force-quic-on="))
    {
        chrome_args.push(format!("--origin-to-force-quic-on=127.0.0.1:{port}"));
    }

    let server = match protocol {
        ChromeCaptureProtocol::H2 => {
            let name = name.clone();
            let output_arg = output_arg.clone();
            tokio::task::spawn_blocking(move || {
                run_tls_capture_server_once(port, name, output_arg, http_port, timeout)
            })
        }
        ChromeCaptureProtocol::H3 => {
            let name = name.clone();
            let output_arg = output_arg.clone();
            let cert = options.cert.clone();
            let key = options.key.clone();
            tokio::spawn(async move {
                match tokio::time::timeout(
                    timeout + Duration::from_secs(2),
                    run_quic_capture_server_once(port, name, output_arg, http_port, cert, key),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err(format!(
                        "timed out waiting for Chrome H3 connection after {timeout:?}"
                    )),
                }
            })
        }
    };

    tokio::time::sleep(Duration::from_millis(350)).await;

    let url = chrome_capture_url(protocol, port, http_port);
    let run = ChromeCaptureRun {
        protocol: match protocol {
            ChromeCaptureProtocol::H2 => "h2",
            ChromeCaptureProtocol::H3 => "h3",
        }
        .into(),
        requested_url: url.clone(),
        browser: browser.display().to_string(),
        user_data_dir: user_data_dir.display().to_string(),
        chrome_args: chrome_args.clone(),
        output: output_path.display().to_string(),
    };
    eprintln!(
        "{}",
        serde_json::to_string_pretty(&run).map_err(|e| format!("run metadata JSON error: {e}"))?
    );

    let mut chrome = spawn_chrome(&browser, &url, &user_data_dir, &chrome_args)?;

    let wait_path = server_output_path.clone();
    let wait_result =
        tokio::task::spawn_blocking(move || wait_for_output_file(&wait_path, timeout))
            .await
            .map_err(|e| format!("capture wait task failed: {e}"))?;

    let _ = chrome.kill();
    let _ = chrome.wait();

    let server_result = tokio::time::timeout(Duration::from_secs(2), server).await;
    if let Ok(Ok(Err(error))) = server_result {
        return Err(error);
    }

    let json = wait_result.inspect_err(|_| {
        if generated_profile_dir && !options.keep_user_data_dir {
            let _ = fs::remove_dir_all(&user_data_dir);
        }
        let _ = fs::remove_file(&server_output_path);
    })?;
    if options.output.is_some() {
        fs::write(&output_path, &json)
            .map_err(|e| format!("failed to write {}: {e}", output_path.display()))?;
        let _ = fs::remove_file(&server_output_path);
    } else {
        println!("{json}");
        let _ = fs::remove_file(&output_path);
    }

    if generated_profile_dir && !options.keep_user_data_dir {
        let _ = fs::remove_dir_all(&user_data_dir);
    }

    Ok(())
}

fn read_json_file(path: &str) -> Result<serde_json::Value, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("Failed to read {path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("Failed to parse JSON {path}: {e}"))
}

// =============================================================================
// QUIC / HTTP/3 Capture
// =============================================================================

#[derive(Debug, Clone)]
struct ObservedInitialFingerprint {
    client_hello: ParsedClientHello,
    transport_parameters: Vec<(String, u64)>,
    transport_parameter_order: Vec<u64>,
    connection_id_length: usize,
    grease_transport_params: bool,
}

#[derive(Debug, Default)]
struct PartialInitialCapture {
    crypto_fragments: BTreeMap<u64, Vec<u8>>,
    next_expected_pn: u64,
    parsed: Option<ObservedInitialFingerprint>,
}

#[derive(Debug)]
struct H3RequestCapture {
    send: quinn::SendStream,
    pseudo_header_order: Vec<String>,
}

#[derive(Debug, Clone)]
struct H3UnidirectionalCapture {
    settings: Option<(Vec<(u64, u64)>, bool)>,
    priority_updates: Vec<H3PriorityUpdate>,
}

#[derive(Debug, Clone)]
struct DatagramObservation {
    addr: SocketAddr,
    data: Vec<u8>,
}

fn pseudo_header_token(name: &str) -> Option<char> {
    match name {
        ":method" => Some('m'),
        ":authority" => Some('a'),
        ":scheme" => Some('s'),
        ":path" => Some('p'),
        ":protocol" => Some('o'),
        _ => None,
    }
}

fn convert_quic_fingerprint(fp: QuicFingerprintCollection) -> QuicFingerprint {
    QuicFingerprint {
        transport_parameters: fp
            .transport_parameters
            .into_iter()
            .map(|(name, value)| QuicTransportParameter { name, value })
            .collect(),
        transport_fingerprint: fp.transport_fingerprint,
        transport_hash: fp.transport_hash,
        packetization_fingerprint: Some(fp.packetization_fingerprint),
        packetization_hash: Some(fp.packetization_hash),
        connection_id_length: fp.connection_id_length,
        initial_destination_connection_id_length: fp.initial_destination_connection_id_length,
        grease_transport_params: fp.grease_transport_params,
        h3: H3Fingerprint {
            settings: fp
                .h3_settings
                .into_iter()
                .map(|(id, value)| H3Setting { id, value })
                .collect(),
            settings_fingerprint: fp.h3_settings_fingerprint,
            settings_hash: fp.h3_settings_hash,
            pseudo_header_order: fp.pseudo_header_order,
            pseudo_header_order_token: fp.pseudo_header_order_token,
            grease_settings: fp.grease_settings,
            priority_updates: Vec::new(),
        },
    }
}

fn build_h3_observation_json(
    settings: &[(u64, u64)],
    grease_settings: bool,
    pseudo_header_order: &[String],
) -> serde_json::Value {
    let settings_fingerprint = settings
        .iter()
        .map(|(id, value)| format!("{id}:{value}"))
        .collect::<Vec<_>>()
        .join(";");
    let pseudo_header_order_token: String = pseudo_header_order
        .iter()
        .filter_map(|name| pseudo_header_token(name))
        .collect();

    serde_json::json!({
        "settings": settings
            .iter()
            .map(|(id, value)| serde_json::json!({ "id": id, "value": value }))
            .collect::<Vec<_>>(),
        "settings_fingerprint": settings_fingerprint,
        "settings_hash": sha256_hex(&settings_fingerprint),
        "pseudo_header_order": pseudo_header_order,
        "pseudo_header_order_token": pseudo_header_order_token,
        "grease_settings": grease_settings,
        "priority_updates": [],
    })
}

struct TokioWritablePoller {
    socket: Arc<tokio::net::UdpSocket>,
    fut: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>>,
}

impl std::fmt::Debug for TokioWritablePoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokioWritablePoller").finish()
    }
}

impl UdpPoller for TokioWritablePoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.fut.is_none() {
            let socket = Arc::clone(&this.socket);
            this.fut = Some(Box::pin(async move { socket.writable().await }));
        }

        let result = this
            .fut
            .as_mut()
            .expect("future is populated above")
            .as_mut()
            .poll(cx);
        if result.is_ready() {
            this.fut = None;
        }
        result
    }
}

struct SniffingUdpSocket {
    io: Arc<tokio::net::UdpSocket>,
    inner: UdpSocketState,
    tx: mpsc::UnboundedSender<DatagramObservation>,
}

impl std::fmt::Debug for SniffingUdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniffingUdpSocket")
            .field("local_addr", &self.io.local_addr())
            .finish()
    }
}

impl SniffingUdpSocket {
    fn capture_datagrams(&self, bufs: &[std::io::IoSliceMut<'_>], meta: &[RecvMeta], count: usize) {
        for idx in 0..count {
            let recvd = &meta[idx];
            if recvd.len == 0 || recvd.stride == 0 {
                continue;
            }

            let buffer = &bufs[idx][..recvd.len];
            let mut offset = 0usize;
            while offset < recvd.len {
                let next = (offset + recvd.stride).min(recvd.len);
                let packet = buffer[offset..next].to_vec();
                let _ = self.tx.send(DatagramObservation {
                    addr: recvd.addr,
                    data: packet,
                });
                offset = next;
            }
        }
    }
}

impl AsyncUdpSocket for SniffingUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(TokioWritablePoller {
            socket: Arc::clone(&self.io),
            fut: None,
        })
    }

    fn try_send(&self, transmit: &quinn_udp::Transmit) -> io::Result<()> {
        self.io.try_io(Interest::WRITABLE, || {
            self.inner.send((&*self.io).into(), transmit)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.io.poll_recv_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }

            let recv = self.io.try_io(Interest::READABLE, || {
                self.inner.recv((&*self.io).into(), bufs, meta)
            });
            match recv {
                Ok(count) => {
                    self.capture_datagrams(bufs, meta, count);
                    return Poll::Ready(Ok(count));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.gro_segments()
    }
}

struct InitialHeaderProtection {
    cipher: aes::Aes128,
}

impl InitialHeaderProtection {
    fn new(key: &[u8]) -> Result<Self, String> {
        Ok(Self {
            cipher: aes::Aes128::new_from_slice(key)
                .map_err(|_| "invalid QUIC initial HP key length".to_string())?,
        })
    }

    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) -> Result<(), String> {
        if packet.len() < pn_offset + 20 {
            return Err("packet too short for QUIC header protection sample".into());
        }

        let sample = &packet[pn_offset + 4..pn_offset + 20];
        let mut block = GenericArray::clone_from_slice(sample);
        self.cipher.encrypt_block(&mut block);

        let bits = if packet[0] & 0x80 != 0 { 0x0f } else { 0x1f };
        packet[0] ^= block[0] & bits;
        let pn_len = ((packet[0] & 0x03) + 1) as usize;
        for idx in 0..pn_len {
            packet[pn_offset + idx] ^= block[idx + 1];
        }
        Ok(())
    }
}

fn try_decode_prefix_varint(data: &[u8], pos: &mut usize) -> Result<Option<u64>, String> {
    if *pos >= data.len() {
        return Ok(None);
    }

    let first = data[*pos];
    let len = match first >> 6 {
        0 => 1usize,
        1 => 2usize,
        2 => 4usize,
        _ => 8usize,
    };
    if *pos + len > data.len() {
        return Ok(None);
    }

    let mut value = u64::from(first & 0x3f);
    for &byte in &data[*pos + 1..*pos + len] {
        value = (value << 8) | u64::from(byte);
    }
    *pos += len;
    Ok(Some(value))
}

fn decode_complete_varint(data: &[u8]) -> Result<u64, String> {
    let mut pos = 0usize;
    let value = decode_varint(data, &mut pos).map_err(|e| e.to_string())?;
    if pos != data.len() {
        return Err("varint payload contains trailing bytes".into());
    }
    Ok(value)
}

fn expand_packet_number(truncated: u64, pn_len: usize, expected: u64) -> u64 {
    let nbits = pn_len * 8;
    let win = 1u64 << nbits;
    let hwin = win / 2;
    let mask = win - 1;
    let candidate = (expected & !mask) | truncated;

    if expected.checked_sub(hwin).is_some_and(|x| candidate <= x) {
        candidate + win
    } else if candidate > expected + hwin && candidate > win {
        candidate - win
    } else {
        candidate
    }
}

fn skip_ack_frame(payload: &[u8], pos: &mut usize, has_ecn: bool) -> Result<(), String> {
    for _ in 0..4 {
        decode_varint(payload, pos).map_err(|e| e.to_string())?;
    }

    let range_count = decode_varint(payload, pos).map_err(|e| e.to_string())?;
    for _ in 0..range_count {
        decode_varint(payload, pos).map_err(|e| e.to_string())?;
        decode_varint(payload, pos).map_err(|e| e.to_string())?;
    }

    if has_ecn {
        for _ in 0..3 {
            decode_varint(payload, pos).map_err(|e| e.to_string())?;
        }
    }

    Ok(())
}

fn parse_initial_crypto_frames(payload: &[u8]) -> Result<Vec<(u64, Vec<u8>)>, String> {
    let mut pos = 0usize;
    let mut crypto = Vec::new();

    while pos < payload.len() {
        let frame_type = decode_varint(payload, &mut pos).map_err(|e| e.to_string())?;
        match frame_type {
            0x00 => {}
            0x01 => {}
            0x02 => skip_ack_frame(payload, &mut pos, false)?,
            0x03 => skip_ack_frame(payload, &mut pos, true)?,
            0x06 => {
                let offset = decode_varint(payload, &mut pos).map_err(|e| e.to_string())?;
                let len = decode_varint(payload, &mut pos).map_err(|e| e.to_string())? as usize;
                if pos + len > payload.len() {
                    return Err("CRYPTO frame exceeds decrypted payload".into());
                }
                crypto.push((offset, payload[pos..pos + len].to_vec()));
                pos += len;
            }
            0x1c | 0x1d => break,
            other => {
                return Err(format!(
                    "unsupported QUIC Initial frame type 0x{other:x} while extracting ClientHello"
                ));
            }
        }
    }

    Ok(crypto)
}

fn insert_crypto_fragment(fragments: &mut BTreeMap<u64, Vec<u8>>, offset: u64, data: Vec<u8>) {
    match fragments.get(&offset) {
        Some(existing) if existing.len() >= data.len() => {}
        _ => {
            fragments.insert(offset, data);
        }
    }
}

fn build_contiguous_crypto(fragments: &BTreeMap<u64, Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut expected = 0u64;

    for (offset, fragment) in fragments {
        if *offset > expected {
            break;
        }

        let start = expected.saturating_sub(*offset) as usize;
        if start < fragment.len() {
            out.extend_from_slice(&fragment[start..]);
            expected = out.len() as u64;
        }
    }

    out
}

fn parse_observed_initial_from_crypto(
    crypto: &[u8],
    connection_id_length: usize,
) -> Result<ObservedInitialFingerprint, String> {
    let client_hello = parse_client_hello(crypto).map_err(|e| e.to_string())?;
    let params_ext = client_hello
        .extensions
        .iter()
        .find(|ext| ext.extension_type == QUIC_TRANSPORT_PARAMS_TYPE)
        .ok_or_else(|| "ClientHello did not contain QUIC transport parameters".to_string())?;
    let params = decode_transport_params(&params_ext.data).map_err(|e| e.to_string())?;

    let mut transport_parameters = Vec::new();
    let mut transport_parameter_order = Vec::new();
    let mut grease_transport_params = false;

    for param in &params.parameters {
        transport_parameter_order.push(param.id);
        let value = match param.id {
            param_id::MAX_IDLE_TIMEOUT => {
                Some(("max_idle_timeout", decode_complete_varint(&param.value)?))
            }
            param_id::MAX_UDP_PAYLOAD_SIZE => Some((
                "max_udp_payload_size",
                decode_complete_varint(&param.value)?,
            )),
            param_id::INITIAL_MAX_DATA => {
                Some(("initial_max_data", decode_complete_varint(&param.value)?))
            }
            param_id::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => Some((
                "initial_max_stream_data_bidi_local",
                decode_complete_varint(&param.value)?,
            )),
            param_id::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => Some((
                "initial_max_stream_data_bidi_remote",
                decode_complete_varint(&param.value)?,
            )),
            param_id::INITIAL_MAX_STREAM_DATA_UNI => Some((
                "initial_max_stream_data_uni",
                decode_complete_varint(&param.value)?,
            )),
            param_id::INITIAL_MAX_STREAMS_BIDI => Some((
                "initial_max_streams_bidi",
                decode_complete_varint(&param.value)?,
            )),
            param_id::INITIAL_MAX_STREAMS_UNI => Some((
                "initial_max_streams_uni",
                decode_complete_varint(&param.value)?,
            )),
            param_id::ACTIVE_CONNECTION_ID_LIMIT => Some((
                "active_connection_id_limit",
                decode_complete_varint(&param.value)?,
            )),
            param_id::ORIGINAL_DESTINATION_CONNECTION_ID
            | param_id::STATELESS_RESET_TOKEN
            | param_id::INITIAL_SOURCE_CONNECTION_ID => None,
            _ => {
                grease_transport_params = true;
                None
            }
        };

        if let Some((name, value)) = value {
            transport_parameters.push((name.to_string(), value));
        }
    }

    Ok(ObservedInitialFingerprint {
        client_hello,
        transport_parameters,
        transport_parameter_order,
        connection_id_length,
        grease_transport_params,
    })
}

fn try_process_initial_packet(
    packet: &[u8],
    state: &mut PartialInitialCapture,
) -> Result<Option<usize>, String> {
    if packet.len() < 7 || packet[0] & 0x80 == 0 {
        return Ok(None);
    }

    let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
    let packet_type = (packet[0] >> 4) & 0x03;
    let mut pos = 5usize;

    let dcid_len = *packet
        .get(pos)
        .ok_or_else(|| "packet truncated before DCID length".to_string())?
        as usize;
    pos += 1;
    if pos + dcid_len > packet.len() {
        return Err("packet truncated in DCID".into());
    }
    let dcid = &packet[pos..pos + dcid_len];
    pos += dcid_len;

    let scid_len = *packet
        .get(pos)
        .ok_or_else(|| "packet truncated before SCID length".to_string())?
        as usize;
    pos += 1;
    if pos + scid_len > packet.len() {
        return Err("packet truncated in SCID".into());
    }
    pos += scid_len;

    if version != 1 {
        if packet_type == 0 {
            let token_len = try_decode_prefix_varint(packet, &mut pos)?
                .ok_or_else(|| "truncated Initial token length".to_string())?
                as usize;
            pos += token_len;
        }
        let payload_len = try_decode_prefix_varint(packet, &mut pos)?
            .ok_or_else(|| "truncated QUIC payload length".to_string())?
            as usize;
        return Ok(Some(pos + payload_len));
    }

    if packet_type != 0 {
        let payload_len = try_decode_prefix_varint(packet, &mut pos)?
            .ok_or_else(|| "truncated QUIC payload length".to_string())?
            as usize;
        return Ok(Some(pos + payload_len));
    }

    let token_len = try_decode_prefix_varint(packet, &mut pos)?
        .ok_or_else(|| "truncated Initial token length".to_string())? as usize;
    if pos + token_len > packet.len() {
        return Err("Initial token exceeds packet length".into());
    }
    pos += token_len;

    let payload_len = try_decode_prefix_varint(packet, &mut pos)?
        .ok_or_else(|| "truncated Initial payload length".to_string())?
        as usize;
    let packet_len = pos + payload_len;
    if packet_len > packet.len() {
        return Err("Initial packet length exceeds datagram payload".into());
    }

    let keys = derive_initial_keys(dcid, QuicKeySide::Server).map_err(|e| e.to_string())?;
    let hp = InitialHeaderProtection::new(&keys.remote.hp_key)?;

    let mut decrypted = packet[..packet_len].to_vec();
    hp.decrypt(pos, &mut decrypted)?;

    let pn_len = ((decrypted[0] & 0x03) + 1) as usize;
    if pos + pn_len > decrypted.len() {
        return Err("packet truncated in protected packet number".into());
    }

    let truncated = decrypted[pos..pos + pn_len]
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
    let packet_number = expand_packet_number(truncated, pn_len, state.next_expected_pn);

    let aead = Aead::new(AeadAlgorithm::Aes128Gcm, &keys.remote.key, &keys.remote.iv)
        .map_err(|e| e.to_string())?;
    let header = &decrypted[..pos + pn_len];
    let ciphertext = &decrypted[pos + pn_len..packet_len];
    let plaintext = aead
        .decrypt(packet_number, header, ciphertext)
        .map_err(|e| e.to_string())?;

    for (offset, fragment) in parse_initial_crypto_frames(&plaintext)? {
        insert_crypto_fragment(&mut state.crypto_fragments, offset, fragment);
    }
    state.next_expected_pn = packet_number + 1;

    if state.parsed.is_none() {
        let contiguous = build_contiguous_crypto(&state.crypto_fragments);
        if let Ok(parsed) = parse_observed_initial_from_crypto(&contiguous, scid_len) {
            state.parsed = Some(parsed);
        }
    }

    Ok(Some(packet_len))
}

fn process_observed_datagram(
    shared: &Arc<Mutex<HashMap<SocketAddr, PartialInitialCapture>>>,
    observation: DatagramObservation,
) {
    let mut guard = match shared.lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };

    let state = guard
        .entry(observation.addr)
        .or_insert_with(PartialInitialCapture::default);

    let mut offset = 0usize;
    while offset < observation.data.len() {
        let packet = &observation.data[offset..];
        match try_process_initial_packet(packet, state) {
            Ok(Some(consumed)) if consumed > 0 => offset += consumed,
            Ok(Some(_)) | Ok(None) => break,
            Err(_) => break,
        }
    }
}

fn try_parse_h3_frame(buf: &[u8]) -> Result<Option<(u64, usize, usize)>, String> {
    let mut pos = 0usize;
    let frame_type = match try_decode_prefix_varint(buf, &mut pos)? {
        Some(value) => value,
        None => return Ok(None),
    };
    let len = match try_decode_prefix_varint(buf, &mut pos)? {
        Some(value) => value as usize,
        None => return Ok(None),
    };
    if pos + len > buf.len() {
        return Ok(None);
    }
    Ok(Some((frame_type, pos, len)))
}

fn parse_h3_settings_payload(payload: &[u8]) -> Result<(Vec<(u64, u64)>, bool), String> {
    let mut pos = 0usize;
    let mut settings = Vec::new();
    let mut grease_settings = false;

    while pos < payload.len() {
        let id = decode_varint(payload, &mut pos).map_err(|e| e.to_string())?;
        let value = decode_varint(payload, &mut pos).map_err(|e| e.to_string())?;
        if !matches!(id, 0x01 | 0x06 | 0x07 | 0x33) {
            grease_settings = true;
        }
        settings.push((id, value));
    }

    Ok((settings, grease_settings))
}

fn decode_h3_pseudo_header_order(block: &[u8]) -> Result<Vec<String>, String> {
    let mut encoded = bytes::Bytes::copy_from_slice(block);
    let decoded = decode_stateless(&mut encoded, u64::MAX).map_err(|e| e.to_string())?;
    Ok(decoded
        .fields
        .into_iter()
        .map(|field| String::from_utf8_lossy(&field.name).to_string())
        .filter(|name| name.starts_with(':'))
        .collect())
}

fn encode_h3_frame(frame_type: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 16);
    encode_varint(frame_type, &mut out);
    encode_varint(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}

async fn read_stream_until<T, F>(
    recv: &mut quinn::RecvStream,
    size_limit: usize,
    mut parser: F,
) -> Result<T, String>
where
    F: FnMut(&[u8]) -> Result<Option<T>, String>,
{
    let mut buffer = Vec::new();

    loop {
        if let Some(value) = parser(&buffer)? {
            return Ok(value);
        }

        let chunk = recv
            .read_chunk(4096, true)
            .await
            .map_err(|e| e.to_string())?;
        let Some(chunk) = chunk else {
            return Err("stream ended before expected H3 data arrived".into());
        };
        buffer.extend_from_slice(&chunk.bytes);
        if buffer.len() > size_limit {
            return Err(format!(
                "stream exceeded {size_limit} bytes while waiting for H3 data"
            ));
        }
    }
}

fn parse_h3_priority_update_payload(payload: &[u8]) -> Result<H3PriorityUpdate, String> {
    let mut pos = 0usize;
    let element_id = decode_varint(payload, &mut pos).map_err(|e| e.to_string())?;
    let field_value = String::from_utf8(payload[pos..].to_vec())
        .map_err(|e| format!("invalid H3 PRIORITY_UPDATE field value: {e}"))?;
    Ok(H3PriorityUpdate {
        element_id,
        field_value,
    })
}

async fn capture_h3_control_stream(
    conn: quinn::Connection,
) -> Result<H3UnidirectionalCapture, String> {
    loop {
        let mut recv = tokio::time::timeout(Duration::from_secs(10), conn.accept_uni())
            .await
            .map_err(|_| "timed out waiting for H3 unidirectional stream".to_string())?
            .map_err(|e| e.to_string())?;

        let mut is_control_stream = false;
        let mut capture = H3UnidirectionalCapture {
            settings: None,
            priority_updates: Vec::new(),
        };
        let mut buffer = Vec::new();
        loop {
            let read_timeout = if capture.settings.is_some() {
                Duration::from_secs(1)
            } else {
                Duration::from_secs(10)
            };
            let chunk = match tokio::time::timeout(read_timeout, recv.read_chunk(4096, true)).await
            {
                Ok(Ok(Some(chunk))) => chunk,
                Ok(Ok(None)) => break,
                Ok(Err(error)) => return Err(error.to_string()),
                Err(_) if capture.settings.is_some() => return Ok(capture),
                Err(_) => return Err("timed out waiting for H3 control stream data".into()),
            };
            buffer.extend_from_slice(&chunk.bytes);
            if buffer.len() > 16 * 1024 {
                return Err("H3 control stream exceeded 16384 bytes".into());
            }

            if !is_control_stream {
                let mut pos = 0usize;
                let Some(stream_type) = try_decode_prefix_varint(&buffer, &mut pos)? else {
                    continue;
                };
                if stream_type != 0x00 {
                    break;
                }
                buffer.drain(..pos);
                is_control_stream = true;
            }

            let mut consumed = 0usize;
            while consumed < buffer.len() {
                let Some((frame_type, payload_offset, payload_len)) =
                    try_parse_h3_frame(&buffer[consumed..])?
                else {
                    break;
                };
                let payload_start = consumed + payload_offset;
                let payload_end = payload_start + payload_len;
                let payload = &buffer[payload_start..payload_end];
                match frame_type {
                    0x04 => capture.settings = Some(parse_h3_settings_payload(payload)?),
                    0x0f0700 => capture
                        .priority_updates
                        .push(parse_h3_priority_update_payload(payload)?),
                    _ => {}
                }
                consumed = payload_end;
            }
            if consumed > 0 {
                buffer.drain(..consumed);
            }

            if capture.settings.is_some() && !capture.priority_updates.is_empty() {
                return Ok(capture);
            }
        }

        if capture.settings.is_some() {
            return Ok(capture);
        }
    }
}

async fn capture_h3_request(conn: quinn::Connection) -> Result<H3RequestCapture, String> {
    let (send, mut recv) = tokio::time::timeout(Duration::from_secs(10), conn.accept_bi())
        .await
        .map_err(|_| "timed out waiting for H3 request stream".to_string())?
        .map_err(|e| e.to_string())?;

    let block = read_stream_until(&mut recv, 64 * 1024, |buffer| {
        let Some((frame_type, payload_offset, payload_len)) = try_parse_h3_frame(buffer)? else {
            return Ok(None);
        };
        if frame_type != 0x01 {
            return Err(format!(
                "expected HEADERS as first request frame, got frame type 0x{frame_type:x}"
            ));
        }
        Ok(Some(
            buffer[payload_offset..payload_offset + payload_len].to_vec(),
        ))
    })
    .await?;

    Ok(H3RequestCapture {
        send,
        pseudo_header_order: decode_h3_pseudo_header_order(&block)?,
    })
}

async fn send_h3_server_prelude(
    conn: &quinn::Connection,
) -> Result<(quinn::SendStream, quinn::SendStream, quinn::SendStream), String> {
    let mut control = conn.open_uni().await.map_err(|e| e.to_string())?;
    let mut encoder = conn.open_uni().await.map_err(|e| e.to_string())?;
    let mut decoder = conn.open_uni().await.map_err(|e| e.to_string())?;

    let mut control_bytes = Vec::new();
    encode_varint(0x00, &mut control_bytes);
    control_bytes.extend_from_slice(&encode_h3_frame(0x04, &[]));
    control
        .write_all(&control_bytes)
        .await
        .map_err(|e| e.to_string())?;

    let mut encoder_bytes = Vec::new();
    encode_varint(0x02, &mut encoder_bytes);
    encoder
        .write_all(&encoder_bytes)
        .await
        .map_err(|e| e.to_string())?;

    let mut decoder_bytes = Vec::new();
    encode_varint(0x03, &mut decoder_bytes);
    decoder
        .write_all(&decoder_bytes)
        .await
        .map_err(|e| e.to_string())?;

    Ok((control, encoder, decoder))
}

async fn send_h3_json_response(mut send: quinn::SendStream, json: &str) -> Result<(), String> {
    let mut header_block = BytesMut::new();
    let headers = vec![
        HeaderField::new(":status", "200"),
        HeaderField::new("content-type", "application/json"),
        HeaderField::new("cache-control", "no-store"),
        HeaderField::new("access-control-allow-origin", "*"),
    ];
    encode_stateless(&mut header_block, headers).map_err(|e| e.to_string())?;

    let headers_frame = encode_h3_frame(0x01, &header_block);
    let data_frame = encode_h3_frame(0x00, json.as_bytes());
    send.write_all(&headers_frame)
        .await
        .map_err(|e| e.to_string())?;
    send.write_all(&data_frame)
        .await
        .map_err(|e| e.to_string())?;
    send.finish().map_err(|e| e.to_string())?;
    Ok(())
}

// =============================================================================
// Inspect (human-readable output)
// =============================================================================

fn print_inspect(ch: &ParsedClientHello) {
    println!("=== ClientHello Inspection ===\n");
    println!(
        "Protocol Version: 0x{:04x} ({})",
        ch.protocol_version,
        tls_version_string(ch.protocol_version)
    );
    println!("Session ID Length: {}", ch.session_id_length);

    println!("\nCipher Suites ({}):", ch.cipher_suites.len());
    for (i, suite) in ch.cipher_suites.iter().enumerate() {
        println!("  [{i:2}] 0x{suite:04x} — {}", cipher_suite_name(*suite));
    }

    println!("\nCompression Methods: {:?}", ch.compression_methods);

    println!("\nExtensions ({}):", ch.extensions.len());
    for (i, ext) in ch.extensions.iter().enumerate() {
        println!(
            "  [{i:2}] 0x{:04x} — {} ({} bytes)",
            ext.extension_type,
            extension_name(ext.extension_type),
            ext.data.len()
        );
        match ext.extension_type {
            0x000a => {
                for (j, g) in extract_supported_groups(&ext.data).iter().enumerate() {
                    println!("        group[{j}]: 0x{g:04x} — {}", named_group_name(*g));
                }
            }
            0x000d => {
                for (j, a) in extract_signature_algorithms(&ext.data).iter().enumerate() {
                    println!("        alg[{j}]: 0x{a:04x} — {}", sig_alg_name(*a));
                }
            }
            0x0010 => {
                for p in &extract_alpn_protocols(&ext.data) {
                    println!("        protocol: {p}");
                }
            }
            0x002b => {
                for v in &extract_supported_versions(&ext.data) {
                    if is_grease_value(*v) {
                        println!("        version: 0x{v:04x} — GREASE");
                    } else {
                        println!("        version: 0x{v:04x} — {}", tls_version_string(*v));
                    }
                }
            }
            0x0033 => {
                for c in &extract_key_share_curves(&ext.data) {
                    println!(
                        "        key_share group: 0x{c:04x} — {}",
                        named_group_name(*c)
                    );
                }
            }
            0x001b => {
                for a in &extract_compress_cert_algorithms(&ext.data) {
                    let name = match *a {
                        1 => "zlib",
                        2 => "brotli",
                        3 => "zstd",
                        _ => "unknown",
                    };
                    println!("        algorithm: {a} — {name}");
                }
            }
            0x001c => {
                if let Some(limit) = extract_record_size_limit(&ext.data) {
                    println!("        limit: {limit}");
                }
            }
            0xfe0d if ext.data.len() >= 8 && ext.data[0] == 0x00 => {
                let kdf = u16::from_be_bytes([ext.data[1], ext.data[2]]);
                let aead = u16::from_be_bytes([ext.data[3], ext.data[4]]);
                let enc_len = u16::from_be_bytes([ext.data[6], ext.data[7]]);
                println!("        ECH type: GREASE (outer)");
                println!("        KDF: 0x{kdf:04x}, AEAD: 0x{aead:04x}, enc_length: {enc_len}");
                let payload_off = 8 + enc_len as usize;
                if payload_off + 2 <= ext.data.len() {
                    let pl = u16::from_be_bytes([ext.data[payload_off], ext.data[payload_off + 1]]);
                    let (min, max) = infer_ech_payload_range(pl);
                    println!("        payload_length: {pl}");
                    if let (Some(mn), Some(mx)) = (min, max) {
                        println!("        inferred range: payload_length_min={mn}, payload_length_max={mx}");
                    }
                }
                println!("        ech_outer_extensions: [51, 10, 13, 5, 18, 16, 45, 27, 17613] (BoringSSL default)");
            }
            _ => {}
        }
    }

    let has_grease = ch.cipher_suites.iter().any(|s| is_grease_value(*s))
        || ch
            .extensions
            .iter()
            .any(|e| is_grease_value(e.extension_type));
    println!(
        "\nGREASE detected: {}",
        if has_grease { "yes" } else { "no" }
    );
}

fn build_quic_bootstrap_html(port: u16) -> String {
    format!(
        r#"<!doctype html>
<meta charset="utf-8">
<title>QUIC / H3 Fingerprint Capture</title>
<style>
body {{ font-family: ui-monospace, Consolas, monospace; background: #111827; color: #e5e7eb; margin: 0; padding: 24px; }}
main {{ max-width: 900px; margin: 0 auto; }}
pre {{ white-space: pre-wrap; word-break: break-word; background: #0b1220; border: 1px solid #374151; border-radius: 12px; padding: 16px; }}
a {{ color: #93c5fd; }}
</style>
<main>
<h1>QUIC / HTTP/3 Fingerprint Capture</h1>
<p>Bootstrap page loaded over TCP. Alt-Svc has been advertised for <code>h3=":{port}"</code>.</p>
<p>The page will keep retrying until the browser switches to HTTP/3, then the captured JSON will appear below.</p>
<p>If it never switches, use a locally trusted certificate via <code>--cert</code>/<code>--key</code> or enable the browser's localhost insecure-cert override.</p>
<pre id="out">Waiting for HTTP/3...</pre>
</main>
<script>
const out = document.getElementById('out');
async function probe() {{
  try {{
    const res = await fetch(window.location.pathname + '?h3_probe=' + Date.now(), {{ cache: 'no-store' }});
    const text = await res.text();
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {{
      out.textContent = text;
      return;
    }}
    out.textContent = 'Alt-Svc cached. Retrying over HTTP/3...';
  }} catch (error) {{
    out.textContent = 'Retrying after network error: ' + error;
  }}
  setTimeout(probe, 1000);
}}
setTimeout(probe, 800);
</script>"#
    )
}

fn send_http1_bootstrap_response(
    conn: &mut rustls::ServerConnection,
    tcp: &mut TcpStream,
    body: &str,
    port: u16,
) {
    let mut tls = rustls::Stream::new(conn, tcp);
    let alt_svc = format!("h3=\":{port}\"; ma=86400");
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Cache-Control: no-store\r\n\
         Alt-Svc: {alt_svc}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    let _ = tls.write_all(response.as_bytes());
    let _ = tls.flush();
}

fn spawn_quic_bootstrap_server(
    port: u16,
    http_port: Option<u16>,
    tls_config: Arc<rustls::ServerConfig>,
) -> Result<(), String> {
    if let Some(hp) = http_port {
        let https_port = port;
        let http_bind = format!("0.0.0.0:{hp}");
        let http_listener = TcpListener::bind(&http_bind)
            .map_err(|e| format!("Failed to bind HTTP port {hp}: {e}"))?;
        std::thread::spawn(move || {
            for mut stream in http_listener.incoming().flatten() {
                send_http_redirect(&mut stream, https_port);
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
        });
    }

    let bind_addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&bind_addr)
        .map_err(|e| format!("Failed to bind TCP bootstrap port {port}: {e}"))?;

    std::thread::spawn(move || {
        let body = build_quic_bootstrap_html(port);
        let mut counter = 0u64;
        for accepted in listener.incoming() {
            let Ok(mut stream) = accepted else {
                continue;
            };
            counter += 1;
            let peer = stream.peer_addr().ok();
            if let Some(peer) = peer {
                eprintln!("--- Bootstrap Request #{counter} from {peer} ---");
            }

            match read_client_hello_from_stream(&mut stream) {
                Ok(ConnectionData::HttpRequest) => {
                    send_http_redirect(&mut stream, port);
                }
                Ok(ConnectionData::Unknown(byte)) => {
                    eprintln!("  Ignoring non-TLS bootstrap traffic: first byte 0x{byte:02x}");
                }
                Ok(ConnectionData::TlsRecord(data)) => {
                    match complete_tls_handshake(&tls_config, &mut stream, &data) {
                        Ok(mut conn) => {
                            let alpn = conn
                                .alpn_protocol()
                                .map(|p| String::from_utf8_lossy(p).to_string());
                            eprintln!("  Bootstrap TLS handshake complete (ALPN: {:?})", alpn);
                            if alpn.as_deref() == Some("h2") {
                                match capture_h2_fingerprint(&mut conn, &mut stream) {
                                    Ok((_fp, stream_id)) => {
                                        send_h2_bootstrap_response(
                                            &mut conn,
                                            &mut stream,
                                            stream_id,
                                            &body,
                                            port,
                                        );
                                    }
                                    Err(e) => {
                                        eprintln!("  Bootstrap H2 read failed: {e}");
                                        send_h2_bootstrap_response(
                                            &mut conn,
                                            &mut stream,
                                            1,
                                            &body,
                                            port,
                                        );
                                    }
                                }
                            } else {
                                send_http1_bootstrap_response(&mut conn, &mut stream, &body, port);
                            }
                        }
                        Err(e) => {
                            eprintln!("  Bootstrap TLS handshake failed: {e}");
                        }
                    }
                }
                Err(e) => eprintln!("  Bootstrap connection error: {e}"),
            }

            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    });

    Ok(())
}

async fn wait_for_observed_initial(
    shared: Arc<Mutex<HashMap<SocketAddr, PartialInitialCapture>>>,
    remote: SocketAddr,
    timeout: Duration,
) -> Result<ObservedInitialFingerprint, String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(guard) = shared.lock() {
            if let Some(parsed) = guard.get(&remote).and_then(|state| state.parsed.clone()) {
                return Ok(parsed);
            }
        }

        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for QUIC Initial capture data from {remote}"
            ));
        }

        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn handle_quic_connection(
    conn: quinn::Connection,
    remote: SocketAddr,
    name: &str,
    output: &Option<String>,
    shared: Arc<Mutex<HashMap<SocketAddr, PartialInitialCapture>>>,
) -> Result<(), String> {
    eprintln!("QUIC connection from {remote}");
    let (_control, _encoder, _decoder) = send_h3_server_prelude(&conn).await?;
    let initial_future =
        wait_for_observed_initial(Arc::clone(&shared), remote, Duration::from_secs(5));
    let control_stream_future = capture_h3_control_stream(conn.clone());
    let request_future = capture_h3_request(conn.clone());

    let (initial_result, control_stream_result, request_result) =
        tokio::join!(initial_future, control_stream_future, request_future);
    let control_stream = control_stream_result?;
    let (settings, grease_settings) = control_stream
        .settings
        .clone()
        .ok_or_else(|| "H3 control stream ended before SETTINGS".to_string())?;
    let request = request_result?;

    let pseudo_header_order = request.pseudo_header_order.clone();
    let json = match initial_result {
        Ok(initial) => {
            eprintln!(
                "  QUIC transport params: {} observed, CID len={}",
                initial.transport_parameters.len(),
                initial.connection_id_length
            );

            let mut profile = build_profile(name, &initial.client_hello);
            let pseudo_header_order_token: String = pseudo_header_order
                .iter()
                .filter_map(|name| pseudo_header_token(name))
                .collect();

            let quic_input = QuicFingerprintInput {
                transport_parameters: initial.transport_parameters.clone(),
                h3: H3FingerprintInput {
                    settings: settings.clone(),
                    pseudo_header_order: pseudo_header_order.clone(),
                    pseudo_header_order_token,
                    grease_settings,
                },
                connection_id_length: initial.connection_id_length,
                initial_destination_connection_id_length: None,
                grease_transport_params: initial.grease_transport_params,
                send_min_ack_delay: true,
                send_reserved_transport_parameter: true,
                extra_transport_parameters: Vec::new(),
                transport_parameter_order: initial.transport_parameter_order.clone(),
                packetization: QuicPacketizationFingerprint::default(),
            };
            let quic_fingerprint = collect_quic_fingerprint(&quic_input);
            profile.quic_fingerprint = Some(convert_quic_fingerprint(quic_fingerprint));
            if let Some(quic) = &mut profile.quic_fingerprint {
                quic.h3.priority_updates = control_stream.priority_updates.clone();
            }

            serde_json::to_string_pretty(&profile)
                .map_err(|e| format!("JSON serialization error: {e}"))?
        }
        Err(error) => {
            eprintln!("  Warning: QUIC Initial fingerprint capture failed: {error}");
            let payload = serde_json::json!({
                "error": error,
                "message": "HTTP/3 connection succeeded, but QUIC Initial fingerprint extraction did not complete",
                "h3_observation": build_h3_observation_json(
                    &settings,
                    grease_settings,
                    &pseudo_header_order,
                ),
                "priority_updates": control_stream.priority_updates,
            });
            serde_json::to_string_pretty(&payload)
                .map_err(|e| format!("JSON serialization error: {e}"))?
        }
    };

    if let Some(path) = output {
        fs::write(path, &json).map_err(|e| format!("Error writing {path}: {e}"))?;
        eprintln!("  Saved QUIC/H3 capture to {path}");
    }

    send_h3_json_response(request.send, &json).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    conn.close(0u32.into(), b"profile_collector done");
    if let Ok(mut guard) = shared.lock() {
        guard.remove(&remote);
    }
    eprintln!("  QUIC/H3 fingerprint returned to browser\n");
    Ok(())
}

async fn run_quic_capture_server_once(
    port: u16,
    name: String,
    output: Option<String>,
    http_port: Option<u16>,
    cert: Option<String>,
    key: Option<String>,
) -> Result<(), String> {
    let (certs, key_der, identity_kind) =
        load_or_generate_identity(cert.as_deref(), key.as_deref())?;
    let tls_config = make_tls_server_config_from_identity(&certs, &key_der)?;
    let quic_config = make_quic_server_config_from_identity(&certs, &key_der)?;
    spawn_quic_bootstrap_server(port, http_port, Arc::clone(&tls_config))?;

    let bind_addr = format!("0.0.0.0:{port}");
    let std_socket = std::net::UdpSocket::bind(&bind_addr)
        .map_err(|e| format!("Failed to bind UDP {bind_addr}: {e}"))?;
    std_socket
        .set_nonblocking(true)
        .map_err(|e| format!("Failed to set UDP socket nonblocking: {e}"))?;

    let udp_state = UdpSocketState::new((&std_socket).into())
        .map_err(|e| format!("UDP socket setup failed: {e}"))?;
    let udp_socket = Arc::new(
        tokio::net::UdpSocket::from_std(std_socket)
            .map_err(|e| format!("Failed to create async UDP socket: {e}"))?,
    );

    let (tx, mut rx) = mpsc::unbounded_channel::<DatagramObservation>();
    let shared: Arc<Mutex<HashMap<SocketAddr, PartialInitialCapture>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let shared_for_worker = Arc::clone(&shared);
    tokio::spawn(async move {
        while let Some(observation) = rx.recv().await {
            process_observed_datagram(&shared_for_worker, observation);
        }
    });

    let sniffing_socket = Arc::new(SniffingUdpSocket {
        io: udp_socket,
        inner: udp_state,
        tx,
    });

    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(quic_config),
        sniffing_socket,
        Arc::new(TokioRuntime),
    )
    .map_err(|e| format!("Failed to create QUIC endpoint: {e}"))?;

    eprintln!("CaptureChrome H3 bootstrap + QUIC server listening on https://localhost:{port}");
    eprintln!("Certificate mode: {identity_kind}");

    let Some(incoming) = endpoint.accept().await else {
        return Ok(());
    };

    let remote = incoming.remote_address();
    match incoming.await {
        Ok(conn) => handle_quic_connection(conn, remote, &name, &output, Arc::clone(&shared)).await,
        Err(error) => Err(format!("QUIC accept error from {remote}: {error}")),
    }
}

async fn run_quic_capture_server(
    port: u16,
    name: String,
    output: Option<String>,
    http_port: Option<u16>,
    cert: Option<String>,
    key: Option<String>,
) -> Result<(), String> {
    let (certs, key_der, identity_kind) =
        load_or_generate_identity(cert.as_deref(), key.as_deref())?;
    let tls_config = make_tls_server_config_from_identity(&certs, &key_der)?;
    let quic_config = make_quic_server_config_from_identity(&certs, &key_der)?;
    spawn_quic_bootstrap_server(port, http_port, Arc::clone(&tls_config))?;

    let bind_addr = format!("0.0.0.0:{port}");
    let std_socket = std::net::UdpSocket::bind(&bind_addr)
        .map_err(|e| format!("Failed to bind UDP {bind_addr}: {e}"))?;
    std_socket
        .set_nonblocking(true)
        .map_err(|e| format!("Failed to set UDP socket nonblocking: {e}"))?;

    let udp_state = UdpSocketState::new((&std_socket).into())
        .map_err(|e| format!("UDP socket setup failed: {e}"))?;
    let udp_socket = Arc::new(
        tokio::net::UdpSocket::from_std(std_socket)
            .map_err(|e| format!("Failed to create async UDP socket: {e}"))?,
    );

    let (tx, mut rx) = mpsc::unbounded_channel::<DatagramObservation>();
    let shared: Arc<Mutex<HashMap<SocketAddr, PartialInitialCapture>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let shared_for_worker = Arc::clone(&shared);
    tokio::spawn(async move {
        while let Some(observation) = rx.recv().await {
            process_observed_datagram(&shared_for_worker, observation);
        }
    });

    let sniffing_socket = Arc::new(SniffingUdpSocket {
        io: udp_socket,
        inner: udp_state,
        tx,
    });

    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(quic_config),
        sniffing_socket,
        Arc::new(TokioRuntime),
    )
    .map_err(|e| format!("Failed to create QUIC endpoint: {e}"))?;

    eprintln!("=== QUIC + HTTP/3 Fingerprint Capture Server ===");
    eprintln!("TCP bootstrap + UDP QUIC listening on https://localhost:{port}");
    eprintln!("Certificate mode: {identity_kind}");
    if let Some(hp) = http_port {
        eprintln!("HTTP redirect:  http://localhost:{hp} -> https://localhost:{port}");
    }
    eprintln!("Mode: QUIC + HTTP/3 fingerprint (JSON returned to browser)");
    eprintln!("Press Ctrl+C to stop.\n");
    if let Some(hp) = http_port {
        eprintln!("Visit: http://localhost:{hp}");
    } else {
        eprintln!("Visit: https://localhost:{port}");
    }
    eprintln!("  (Accept the self-signed certificate warning on first visit)");
    eprintln!("  The bootstrap page will retry until the browser upgrades to HTTP/3.\n");

    loop {
        let Some(incoming) = endpoint.accept().await else {
            return Ok(());
        };

        let remote = incoming.remote_address();
        let shared = Arc::clone(&shared);
        let name = name.clone();
        let output = output.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) =
                        handle_quic_connection(conn, remote, &name, &output, shared).await
                    {
                        eprintln!("  QUIC/H3 capture error for {remote}: {e}\n");
                    }
                }
                Err(e) => {
                    eprintln!("  QUIC accept error from {remote}: {e}\n");
                }
            }
        });
    }
}

// =============================================================================
// Main
// =============================================================================

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Extract {
            input,
            name,
            output,
        } => {
            let data = match read_hex(&input) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };
            let ch = match parse_client_hello(&data) {
                Ok(ch) => ch,
                Err(e) => {
                    eprintln!("Error parsing ClientHello: {e}");
                    std::process::exit(1);
                }
            };
            let profile = build_profile(&name, &ch);
            let json = serde_json::to_string_pretty(&profile).expect("Failed to serialize profile");
            write_output(&json, &output);
        }

        Commands::Inspect { input } => {
            let data = match read_hex(&input) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };
            let ch = match parse_client_hello(&data) {
                Ok(ch) => ch,
                Err(e) => {
                    eprintln!("Error parsing ClientHello: {e}");
                    std::process::exit(1);
                }
            };
            print_inspect(&ch);
        }

        Commands::Capture {
            port,
            name,
            output,
            tls_only,
            http_port,
            cert,
            key,
        } => {
            // Create TLS server config for H2 fingerprint capture (unless --tls-only)
            let tls_config = if tls_only {
                None
            } else {
                match load_or_generate_identity(cert.as_deref(), key.as_deref()) {
                    Ok((certs, key_der, source)) => {
                        match make_tls_server_config_from_identity(&certs, &key_der) {
                            Ok(config) => {
                                if source == "custom" {
                                    eprintln!("Loaded custom certificate for H2 capture");
                                } else {
                                    eprintln!("Self-signed certificate generated for localhost");
                                }
                                Some(config)
                            }
                            Err(e) => {
                                eprintln!("Warning: Failed to create TLS config: {e}");
                                eprintln!("Falling back to TLS-only mode (no H2 fingerprint)");
                                None
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to load/generate TLS identity: {e}");
                        eprintln!("Falling back to TLS-only mode (no H2 fingerprint)");
                        None
                    }
                }
            };

            // Start HTTP redirect listener if --http-port is specified
            if let Some(hp) = http_port {
                let https_port = port;
                let http_bind = format!("0.0.0.0:{hp}");
                match TcpListener::bind(&http_bind) {
                    Ok(http_listener) => {
                        eprintln!(
                            "HTTP redirect server on port {hp} → https://localhost:{https_port}/"
                        );
                        std::thread::spawn(move || {
                            for mut stream in http_listener.incoming().flatten() {
                                send_http_redirect(&mut stream, https_port);
                                let _ = stream.shutdown(std::net::Shutdown::Both);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to bind HTTP redirect port {hp}: {e}");
                    }
                }
            }

            let bind_addr = format!("0.0.0.0:{port}");
            let listener = TcpListener::bind(&bind_addr).unwrap_or_else(|e| {
                eprintln!("Failed to bind to {bind_addr}: {e}");
                std::process::exit(1);
            });

            eprintln!("=== TLS + HTTP/2 Fingerprint Capture Server ===");
            eprintln!("Listening on https://localhost:{port}");
            if let Some(hp) = http_port {
                eprintln!("HTTP redirect:  http://localhost:{hp} → https://localhost:{port}");
            }
            if tls_config.is_some() {
                eprintln!("Mode: TLS + HTTP/2 fingerprint (JSON returned to browser)");
            } else {
                eprintln!("Mode: TLS-only fingerprint capture");
            }
            eprintln!("Press Ctrl+C to stop.\n");

            if let Some(hp) = http_port {
                eprintln!("Visit: http://localhost:{hp}");
            } else {
                eprintln!("Visit: https://localhost:{port}");
            }
            eprintln!("  (Accept the self-signed certificate warning on first visit)\n");

            let mut request_counter: u64 = 0;
            loop {
                let (mut stream, addr) = match listener.accept() {
                    Ok(conn) => conn,
                    Err(e) => {
                        eprintln!("Accept error: {e}");
                        continue;
                    }
                };

                request_counter += 1;
                eprintln!("--- Request #{request_counter} ---");

                match handle_capture_connection(
                    &mut stream,
                    &name,
                    &addr,
                    port,
                    tls_config.as_ref(),
                ) {
                    CaptureResult::Success(json) => {
                        if tls_config.is_none() {
                            let alert = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
                            let _ = stream.write_all(&alert);
                        }
                        let _ = stream.shutdown(std::net::Shutdown::Both);

                        // Save to file if --output specified
                        if let Some(ref path) = output {
                            fs::write(path, &json).unwrap_or_else(|e| {
                                eprintln!("  Error writing {path}: {e}");
                            });
                            eprintln!("  Saved to {path}");
                        }
                        eprintln!("  Done (JSON returned to browser)\n");
                    }
                    CaptureResult::HttpRedirected => {
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        eprintln!("  Redirected to HTTPS\n");
                        request_counter -= 1; // don't count redirects
                    }
                    CaptureResult::Skipped(msg) => {
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        eprintln!("  {msg}\n");
                        request_counter -= 1;
                    }
                    CaptureResult::Error(e) => {
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        eprintln!("  Error: {e}\n");
                    }
                }
            }
        }

        Commands::CaptureQuic {
            port,
            name,
            output,
            http_port,
            cert,
            key,
        } => {
            if let Err(e) = run_quic_capture_server(port, name, output, http_port, cert, key).await
            {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }

        Commands::CaptureChrome {
            protocol,
            port,
            http_port,
            name,
            output,
            browser,
            user_data_dir,
            keep_user_data_dir,
            chrome_args,
            timeout_secs,
            cert,
            key,
        } => {
            if let Err(e) = run_capture_chrome_command(CaptureChromeOptions {
                protocol,
                port,
                http_port,
                name,
                output,
                browser,
                user_data_dir,
                keep_user_data_dir,
                chrome_args,
                timeout_secs,
                cert,
                key,
            })
            .await
            {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }

        Commands::CompareJson {
            left,
            right,
            left_label,
            right_label,
            json,
            output,
        } => {
            let left_json = read_json_file(&left).unwrap_or_else(|e| {
                eprintln!("Error: {e}");
                std::process::exit(1);
            });
            let right_json = read_json_file(&right).unwrap_or_else(|e| {
                eprintln!("Error: {e}");
                std::process::exit(1);
            });
            let report = compare_json_values(left_label, right_label, &left_json, &right_json);
            let rendered = if json {
                serde_json::to_string_pretty(&report).unwrap_or_else(|e| {
                    eprintln!("Error serializing comparison report: {e}");
                    std::process::exit(1);
                })
            } else {
                render_json_comparison_text(&report)
            };
            write_output(&rendered, &output);
        }

        Commands::ExportChromePreset {
            version,
            protocol,
            output,
        } => {
            let profile = export_chrome_preset_profile(version, protocol);
            let json = serde_json::to_string_pretty(&profile).unwrap_or_else(|e| {
                eprintln!("Error serializing preset profile: {e}");
                std::process::exit(1);
            });
            write_output(&json, &output);
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
        ch.extend_from_slice(&[0xAA; 32]);
        ch.push(32);
        ch.extend_from_slice(&[0xBB; 32]);
        ch.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);
        ch.extend_from_slice(&[0x01, 0x00]);
        let ext_start = ch.len();
        ch.extend_from_slice(&[0x00, 0x00]);
        let ext_data_start = ch.len();
        ch.extend_from_slice(&[0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03]);
        let ext_total_len = ch.len() - ext_data_start;
        ch[ext_start] = ((ext_total_len >> 8) & 0xff) as u8;
        ch[ext_start + 1] = (ext_total_len & 0xff) as u8;
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
        let ch = parse_client_hello(&data).expect("Should parse");
        assert_eq!(ch.protocol_version, 0x0303);
        assert_eq!(ch.session_id_length, 32);
        assert_eq!(ch.cipher_suites, vec![0x1301, 0x1302]);
        assert_eq!(ch.extensions.len(), 1);
    }

    #[test]
    fn test_build_profile() {
        let data = sample_client_hello();
        let ch = parse_client_hello(&data).expect("Should parse");
        let profile = build_profile("Test", &ch);
        assert_eq!(profile.cipher_suites, vec![0x1301, 0x1302]);
        assert_eq!(profile.tls_max_version, "tls13");
        assert!(profile.h2_fingerprint.is_none());
        assert!(profile.quic_fingerprint.is_none());
    }

    #[test]
    fn test_grease_detection() {
        assert!(is_grease_value(0x0a0a));
        assert!(is_grease_value(0x1a1a));
        assert!(is_grease_value(0xfafa));
        assert!(!is_grease_value(0x1301));
    }

    #[test]
    fn test_h2_settings_parsing() {
        // SETTINGS: HEADER_TABLE_SIZE=65536, MAX_CONCURRENT_STREAMS=1000
        let payload = [
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // id=1 value=65536
            0x00, 0x03, 0x00, 0x00, 0x03, 0xe8, // id=3 value=1000
        ];
        let settings = parse_h2_settings(&payload);
        assert_eq!(settings.len(), 2);
        assert_eq!(settings[0].id, 1);
        assert_eq!(settings[0].value, 65536);
        assert_eq!(settings[1].id, 3);
        assert_eq!(settings[1].value, 1000);
    }

    #[test]
    fn test_h2_window_update_parsing() {
        let payload = [0x00, 0xef, 0x00, 0x01]; // 15663105 = 0x00EF0001
        let increment = parse_h2_window_update(&payload);
        assert_eq!(increment, 0x00ef0001);
    }

    #[test]
    fn test_akamai_fingerprint_computation() {
        let settings = vec![
            H2Setting {
                id: 1,
                value: 65536,
            },
            H2Setting { id: 3, value: 1000 },
            H2Setting {
                id: 4,
                value: 6291456,
            },
            H2Setting {
                id: 6,
                value: 262144,
            },
        ];
        let pseudo = vec![
            ":method".to_string(),
            ":authority".to_string(),
            ":scheme".to_string(),
            ":path".to_string(),
        ];
        let fp = compute_akamai_fingerprint(&settings, 15663105, &[], &pseudo);
        assert_eq!(fp, "1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p");
    }

    #[test]
    fn test_hpack_pseudo_header_extraction_indexed() {
        // Simulate: :method GET (0x82), :authority (0x41 + value), :scheme https (0x87), :path / (0x84)
        // This is Chrome order: m, a, s, p
        let mut data = Vec::new();
        data.push(0x82); // indexed: index 2 = :method GET
        data.push(0x41); // literal incremental: index 1 = :authority
        data.push(0x09); // value length = 9 (raw)
        data.extend_from_slice(b"localhost");
        data.push(0x87); // indexed: index 7 = :scheme https
        data.push(0x84); // indexed: index 4 = :path /
                         // non-pseudo header follows
        data.push(0x40); // literal incremental: index 0 = literal name
        data.push(0x0a); // name length = 10
        data.extend_from_slice(b"user-agent");
        data.push(0x05); // value length
        data.extend_from_slice(b"test/");

        let order = extract_pseudo_header_order(&data);
        assert_eq!(order, vec![":method", ":authority", ":scheme", ":path"]);
    }

    #[test]
    #[allow(clippy::vec_init_then_push)]
    fn test_hpack_pseudo_header_firefox_order() {
        // Firefox order: m, p, a, s
        let mut data = Vec::new();
        data.push(0x82); // :method GET
        data.push(0x84); // :path /
        data.push(0x41); // :authority (literal incremental, name index 1)
        data.push(0x09); // value length
        data.extend_from_slice(b"localhost");
        data.push(0x87); // :scheme https

        let order = extract_pseudo_header_order(&data);
        assert_eq!(order, vec![":method", ":path", ":authority", ":scheme"]);
    }

    #[test]
    fn test_hpack_integer_decode() {
        // Single-byte: value < 2^prefix - 1
        assert_eq!(decode_hpack_integer(&[0x82], 7), (2, 1)); // 0x82 & 0x7f = 2
        assert_eq!(decode_hpack_integer(&[0x41], 6), (1, 1)); // 0x41 & 0x3f = 1

        // Multi-byte: value >= 2^prefix - 1
        // 7-bit prefix, value = 127 + 0 = 127
        assert_eq!(decode_hpack_integer(&[0xff, 0x00], 7), (127, 2));
    }

    #[test]
    fn test_extract_hpack_block_with_padding() {
        let payload = [
            0x03, // pad_length = 3
            0x82, 0x84, // HPACK data
            0x00, 0x00, 0x00, // padding
        ];
        let block = extract_hpack_block(&payload, 0x08); // PADDED flag
        assert_eq!(block, &[0x82, 0x84]);
    }

    #[test]
    fn test_extract_hpack_block_with_priority() {
        let payload = [
            0x80, 0x00, 0x00, 0x00, 0x0f, // priority: exclusive, dep=0, weight=15
            0x82, 0x84, // HPACK data
        ];
        let block = extract_hpack_block(&payload, 0x20); // PRIORITY flag
        assert_eq!(block, &[0x82, 0x84]);
    }

    #[test]
    fn test_md5_hex() {
        let hash = md5_hex("test");
        assert_eq!(hash.len(), 32); // MD5 = 16 bytes = 32 hex chars
        assert_eq!(hash, "098f6bcd4621d373cade4e832627b4f6");
    }

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex("test");
        assert_eq!(hash.len(), 64);
        assert_eq!(
            hash,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn test_try_decode_prefix_varint_handles_partial_input() {
        let mut pos = 0usize;
        assert_eq!(try_decode_prefix_varint(&[0x40], &mut pos).unwrap(), None);

        let mut pos = 0usize;
        assert_eq!(
            try_decode_prefix_varint(&[0x40, 0x2a], &mut pos).unwrap(),
            Some(42)
        );
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_parse_h3_settings_payload_preserves_wire_order() {
        let mut payload = Vec::new();
        encode_varint(0x01, &mut payload);
        encode_varint(65536, &mut payload);
        encode_varint(0x33, &mut payload);
        encode_varint(1, &mut payload);
        encode_varint(0x21, &mut payload);
        encode_varint(0, &mut payload);

        let (settings, grease) = parse_h3_settings_payload(&payload).unwrap();
        assert_eq!(settings, vec![(0x01, 65536), (0x33, 1), (0x21, 0)]);
        assert!(grease);
    }

    #[test]
    fn test_decode_h3_pseudo_header_order_from_qpack_block() {
        let mut block = BytesMut::new();
        encode_stateless(
            &mut block,
            vec![
                HeaderField::new(":method", "GET"),
                HeaderField::new(":authority", "localhost"),
                HeaderField::new(":scheme", "https"),
                HeaderField::new(":path", "/"),
                HeaderField::new("user-agent", "test"),
            ],
        )
        .unwrap();

        let order = decode_h3_pseudo_header_order(&block).unwrap();
        assert_eq!(order, vec![":method", ":authority", ":scheme", ":path"]);
    }

    #[test]
    fn test_read_client_hello_from_stream() {
        let data = sample_client_hello();
        let data_clone = data.clone();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let mut client = std::net::TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
            client.write_all(&data_clone).unwrap();
        });
        let (mut stream, _) = listener.accept().expect("accept");
        let result = read_client_hello_from_stream(&mut stream);
        handle.join().unwrap();
        assert!(result.is_ok());
        match result.unwrap() {
            ConnectionData::TlsRecord(record) => assert_eq!(record, data),
            other => panic!("Expected TlsRecord, got: {other:?}"),
        }
    }

    #[test]
    fn test_read_detects_http_request() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let mut client = std::net::TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
            client
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
        });
        let (mut stream, _) = listener.accept().expect("accept");
        let result = read_client_hello_from_stream(&mut stream);
        handle.join().unwrap();
        assert!(matches!(result.unwrap(), ConnectionData::HttpRequest));
    }
}
