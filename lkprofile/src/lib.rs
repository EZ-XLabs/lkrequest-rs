//! # lkprofile — TLS + HTTP/2 Fingerprint Profile Parser
//!
//! Parse raw TLS ClientHello bytes and HTTP/2 frame data into fingerprint
//! profiles usable by `lktls` and `lkrequest`.
//!
//! ## Quick Start
//!
//! ```text
//! use lkprofile::{parse_client_hello, build_tls_profile, h2_fingerprint_from_frames};
//!
//! // Parse ClientHello bytes → TlsProfile (directly usable by lktls)
//! let ch = parse_client_hello(&client_hello_bytes)?;
//! let tls_profile = build_tls_profile("My Browser", &ch);
//!
//! // Parse H2 frame bytes → H2Fingerprint
//! let h2_fp = h2_fingerprint_from_frames(&h2_data)?;
//!
//! // Convert H2ProfileData → lkrequest::h2::H2Profile via serde
//! let h2_profile: lkrequest::h2::H2Profile =
//!     serde_json::from_value(serde_json::to_value(&h2_fp.profile)?)?;
//! ```
//!
//! ## ECH Support
//!
//! `build_tls_profile` automatically:
//! - Extracts ECH GREASE parameters (`kdf_id`, `aead_id`, `enc_length`)
//! - Infers `payload_length_min`/`payload_length_max` from a single observed
//!   payload length (recognizes Chrome's {128..224} range)
//! - Auto-populates `ech_outer_extensions` with the BoringSSL default list
//!   when ECH is detected
//!
//! ## Architecture
//!
//! ```text
//! Raw ClientHello bytes ──→ ParsedClientHello ──→ TlsProfile (lktls)
//!
//! Raw H2 frame bytes ──→ H2Fingerprint ──→ H2ProfileData ──→ H2Profile (lkrequest)
//!                                        └──→ Akamai hash (metadata)
//! ```
//!
//! ## H2 Profile Conversion
//!
//! [`H2ProfileData`] uses serde attributes identical to `lkrequest::h2::H2Profile`,
//! enabling zero-friction conversion via `serde_json`:
//!
//! ```text
//! let value = serde_json::to_value(&h2_fingerprint.profile)?;
//! let h2_profile: lkrequest::h2::H2Profile = serde_json::from_value(value)?;
//! ```

pub mod client_hello;
pub mod error;
pub mod fingerprint;
pub mod h2;

// Re-export primary types and functions
pub use client_hello::{
    build_tls_profile, is_grease_value, parse_client_hello, ParsedClientHello, ParsedExtension,
};
pub use error::ParseError;
pub use fingerprint::{
    collect_quic_fingerprint, collect_tls_fingerprint, collect_tls_fingerprint_from_bytes,
    compare_collected_fingerprints, CollectedFingerprint, FingerprintComparison,
    FingerprintFieldComparison, FingerprintFieldStatus, H3FingerprintInput,
    QuicFingerprintCollection, QuicFingerprintInput, QuicPacketizationFingerprint,
    TlsFingerprintCollection,
};
pub use h2::{
    h2_fingerprint_from_frames, h2_fingerprint_from_frames_no_preface, H2Fingerprint,
    H2HeadersPriority, H2PriorityConfig, H2PriorityFrame, H2ProfileData, H2PseudoHeaderId,
    H2Setting, H2SettingId, H2StreamDepPolicy,
};

// Re-export extension extractors for advanced use
pub use client_hello::{
    extract_alpn_protocols, extract_compress_cert_algorithms, extract_delegated_credentials,
    extract_ec_point_formats, extract_key_share_curves, extract_record_size_limit,
    extract_signature_algorithms, extract_supported_groups, extract_supported_versions,
};
