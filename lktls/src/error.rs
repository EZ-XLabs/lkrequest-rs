//! Unified error types for the lktls TLS engine.
//!
//! This module provides:
//! - [`TlsError`] — the top-level error enum for all lktls operations.
//! - [`TlsAlert`] — a parsed TLS alert (level + description) received from the server.
//! - [`AlertLevel`] / [`AlertDescription`] — structured TLS alert components per RFC 5246/8446.

use std::fmt;
use thiserror::Error;

// ---------------------------------------------------------------------------
// TLS Alert types
// ---------------------------------------------------------------------------

/// TLS alert level (RFC 5246 Section 7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertLevel {
    /// Warning alert (level 1).
    Warning,
    /// Fatal alert (level 2).
    Fatal,
    /// Unknown alert level.
    Unknown(u8),
}

impl AlertLevel {
    /// Parse from raw byte.
    pub fn from_byte(b: u8) -> Self {
        match b {
            1 => AlertLevel::Warning,
            2 => AlertLevel::Fatal,
            other => AlertLevel::Unknown(other),
        }
    }

    /// Return the raw byte value.
    pub fn as_byte(&self) -> u8 {
        match self {
            AlertLevel::Warning => 1,
            AlertLevel::Fatal => 2,
            AlertLevel::Unknown(b) => *b,
        }
    }
}

impl fmt::Display for AlertLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlertLevel::Warning => write!(f, "warning"),
            AlertLevel::Fatal => write!(f, "fatal"),
            AlertLevel::Unknown(b) => write!(f, "unknown({})", b),
        }
    }
}

/// TLS alert description (RFC 5246 Section 7.2.2 + RFC 8446 Section 6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertDescription {
    /// `close_notify` (0).
    CloseNotify,
    /// `unexpected_message` (10).
    UnexpectedMessage,
    /// `bad_record_mac` (20).
    BadRecordMac,
    /// `decryption_failed` (21) — TLS 1.0; reserved thereafter.
    DecryptionFailed,
    /// `record_overflow` (22).
    RecordOverflow,
    /// `decompression_failure` (30) — TLS 1.2 and earlier.
    DecompressionFailure,
    /// `handshake_failure` (40).
    HandshakeFailure,
    /// `no_certificate` (41) — SSLv3 only.
    NoCertificate,
    /// `bad_certificate` (42).
    BadCertificate,
    /// `unsupported_certificate` (43).
    UnsupportedCertificate,
    /// `certificate_revoked` (44).
    CertificateRevoked,
    /// `certificate_expired` (45).
    CertificateExpired,
    /// `certificate_unknown` (46).
    CertificateUnknown,
    /// `illegal_parameter` (47).
    IllegalParameter,
    /// `unknown_ca` (48).
    UnknownCa,
    /// `access_denied` (49).
    AccessDenied,
    /// `decode_error` (50).
    DecodeError,
    /// `decrypt_error` (51).
    DecryptError,
    /// `export_restriction` (60) — TLS 1.0; reserved thereafter.
    ExportRestriction,
    /// `protocol_version` (70).
    ProtocolVersion,
    /// `insufficient_security` (71).
    InsufficientSecurity,
    /// `internal_error` (80).
    InternalError,
    /// `inappropriate_fallback` (86).
    InappropriateFallback,
    /// `user_canceled` (90).
    UserCanceled,
    /// `no_renegotiation` (100) — TLS 1.2 and earlier.
    NoRenegotiation,
    /// `missing_extension` (109).
    MissingExtension,
    /// `unsupported_extension` (110).
    UnsupportedExtension,
    /// `certificate_unobtainable` (111).
    CertificateUnobtainable,
    /// `unrecognized_name` (112).
    UnrecognizedName,
    /// `bad_certificate_status_response` (113).
    BadCertificateStatusResponse,
    /// `bad_certificate_hash_value` (114).
    BadCertificateHashValue,
    /// `unknown_psk_identity` (115).
    UnknownPskIdentity,
    /// `certificate_required` (116).
    CertificateRequired,
    /// `no_application_protocol` (120).
    NoApplicationProtocol,
    /// Unknown alert description code.
    Unknown(u8),
}

impl AlertDescription {
    /// Parse from raw byte.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => AlertDescription::CloseNotify,
            10 => AlertDescription::UnexpectedMessage,
            20 => AlertDescription::BadRecordMac,
            21 => AlertDescription::DecryptionFailed,
            22 => AlertDescription::RecordOverflow,
            30 => AlertDescription::DecompressionFailure,
            40 => AlertDescription::HandshakeFailure,
            41 => AlertDescription::NoCertificate,
            42 => AlertDescription::BadCertificate,
            43 => AlertDescription::UnsupportedCertificate,
            44 => AlertDescription::CertificateRevoked,
            45 => AlertDescription::CertificateExpired,
            46 => AlertDescription::CertificateUnknown,
            47 => AlertDescription::IllegalParameter,
            48 => AlertDescription::UnknownCa,
            49 => AlertDescription::AccessDenied,
            50 => AlertDescription::DecodeError,
            51 => AlertDescription::DecryptError,
            60 => AlertDescription::ExportRestriction,
            70 => AlertDescription::ProtocolVersion,
            71 => AlertDescription::InsufficientSecurity,
            80 => AlertDescription::InternalError,
            86 => AlertDescription::InappropriateFallback,
            90 => AlertDescription::UserCanceled,
            100 => AlertDescription::NoRenegotiation,
            109 => AlertDescription::MissingExtension,
            110 => AlertDescription::UnsupportedExtension,
            111 => AlertDescription::CertificateUnobtainable,
            112 => AlertDescription::UnrecognizedName,
            113 => AlertDescription::BadCertificateStatusResponse,
            114 => AlertDescription::BadCertificateHashValue,
            115 => AlertDescription::UnknownPskIdentity,
            116 => AlertDescription::CertificateRequired,
            120 => AlertDescription::NoApplicationProtocol,
            other => AlertDescription::Unknown(other),
        }
    }

    /// Return the raw byte value.
    pub fn as_byte(&self) -> u8 {
        match self {
            AlertDescription::CloseNotify => 0,
            AlertDescription::UnexpectedMessage => 10,
            AlertDescription::BadRecordMac => 20,
            AlertDescription::DecryptionFailed => 21,
            AlertDescription::RecordOverflow => 22,
            AlertDescription::DecompressionFailure => 30,
            AlertDescription::HandshakeFailure => 40,
            AlertDescription::NoCertificate => 41,
            AlertDescription::BadCertificate => 42,
            AlertDescription::UnsupportedCertificate => 43,
            AlertDescription::CertificateRevoked => 44,
            AlertDescription::CertificateExpired => 45,
            AlertDescription::CertificateUnknown => 46,
            AlertDescription::IllegalParameter => 47,
            AlertDescription::UnknownCa => 48,
            AlertDescription::AccessDenied => 49,
            AlertDescription::DecodeError => 50,
            AlertDescription::DecryptError => 51,
            AlertDescription::ExportRestriction => 60,
            AlertDescription::ProtocolVersion => 70,
            AlertDescription::InsufficientSecurity => 71,
            AlertDescription::InternalError => 80,
            AlertDescription::InappropriateFallback => 86,
            AlertDescription::UserCanceled => 90,
            AlertDescription::NoRenegotiation => 100,
            AlertDescription::MissingExtension => 109,
            AlertDescription::UnsupportedExtension => 110,
            AlertDescription::CertificateUnobtainable => 111,
            AlertDescription::UnrecognizedName => 112,
            AlertDescription::BadCertificateStatusResponse => 113,
            AlertDescription::BadCertificateHashValue => 114,
            AlertDescription::UnknownPskIdentity => 115,
            AlertDescription::CertificateRequired => 116,
            AlertDescription::NoApplicationProtocol => 120,
            AlertDescription::Unknown(b) => *b,
        }
    }

    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            AlertDescription::CloseNotify => "close_notify",
            AlertDescription::UnexpectedMessage => "unexpected_message",
            AlertDescription::BadRecordMac => "bad_record_mac",
            AlertDescription::DecryptionFailed => "decryption_failed",
            AlertDescription::RecordOverflow => "record_overflow",
            AlertDescription::DecompressionFailure => "decompression_failure",
            AlertDescription::HandshakeFailure => "handshake_failure",
            AlertDescription::NoCertificate => "no_certificate",
            AlertDescription::BadCertificate => "bad_certificate",
            AlertDescription::UnsupportedCertificate => "unsupported_certificate",
            AlertDescription::CertificateRevoked => "certificate_revoked",
            AlertDescription::CertificateExpired => "certificate_expired",
            AlertDescription::CertificateUnknown => "certificate_unknown",
            AlertDescription::IllegalParameter => "illegal_parameter",
            AlertDescription::UnknownCa => "unknown_ca",
            AlertDescription::AccessDenied => "access_denied",
            AlertDescription::DecodeError => "decode_error",
            AlertDescription::DecryptError => "decrypt_error",
            AlertDescription::ExportRestriction => "export_restriction",
            AlertDescription::ProtocolVersion => "protocol_version",
            AlertDescription::InsufficientSecurity => "insufficient_security",
            AlertDescription::InternalError => "internal_error",
            AlertDescription::InappropriateFallback => "inappropriate_fallback",
            AlertDescription::UserCanceled => "user_canceled",
            AlertDescription::NoRenegotiation => "no_renegotiation",
            AlertDescription::MissingExtension => "missing_extension",
            AlertDescription::UnsupportedExtension => "unsupported_extension",
            AlertDescription::CertificateUnobtainable => "certificate_unobtainable",
            AlertDescription::UnrecognizedName => "unrecognized_name",
            AlertDescription::BadCertificateStatusResponse => "bad_certificate_status_response",
            AlertDescription::BadCertificateHashValue => "bad_certificate_hash_value",
            AlertDescription::UnknownPskIdentity => "unknown_psk_identity",
            AlertDescription::CertificateRequired => "certificate_required",
            AlertDescription::NoApplicationProtocol => "no_application_protocol",
            AlertDescription::Unknown(_) => "unknown",
        }
    }
}

impl fmt::Display for AlertDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.as_byte())
    }
}

/// A parsed TLS alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsAlert {
    /// Alert level.
    pub level: AlertLevel,
    /// Alert description.
    pub description: AlertDescription,
}

impl TlsAlert {
    /// Parse a TLS alert from the 2-byte alert payload.
    pub fn from_bytes(level: u8, desc: u8) -> Self {
        TlsAlert {
            level: AlertLevel::from_byte(level),
            description: AlertDescription::from_byte(desc),
        }
    }

    /// Returns `true` if this is a fatal alert.
    pub fn is_fatal(&self) -> bool {
        self.level == AlertLevel::Fatal
    }

    /// Returns `true` if this is a close_notify alert.
    pub fn is_close_notify(&self) -> bool {
        self.description == AlertDescription::CloseNotify
    }
}

impl fmt::Display for TlsAlert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} alert: {}", self.level, self.description)
    }
}

// ---------------------------------------------------------------------------
// TlsError
// ---------------------------------------------------------------------------

/// Top-level error type for all lktls operations.
#[derive(Debug, Error)]
pub enum TlsError {
    /// I/O error from the underlying transport.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The fingerprint profile is invalid or contains unsupported values.
    #[error("invalid profile: {0}")]
    InvalidProfile(String),

    /// The TLS handshake failed.
    #[error("handshake failure: {0}")]
    HandshakeFailure(String),

    /// The server sent a TLS alert during the handshake.
    #[error("TLS alert from server: {0}")]
    Alert(TlsAlert),

    /// The local endpoint is terminating the handshake with a TLS alert.
    #[error("local TLS alert {alert}: {message}")]
    LocalAlert { alert: TlsAlert, message: String },

    /// An error occurred in a cryptographic operation.
    #[error("crypto error: {0}")]
    CryptoError(String),

    /// Certificate verification failed.
    #[error("certificate error: {0}")]
    CertificateError(String),

    /// The server sent an unexpected or malformed message.
    #[error("unexpected message: {0}")]
    UnexpectedMessage(String),

    /// A required feature is not yet implemented.
    #[error("not implemented: {0}")]
    NotImplemented(String),
}

impl TlsError {
    /// Construct a fatal alert generated by the local TLS state machine.
    pub fn local_alert(description: AlertDescription, message: impl Into<String>) -> Self {
        Self::LocalAlert {
            alert: TlsAlert {
                level: AlertLevel::Fatal,
                description,
            },
            message: message.into(),
        }
    }

    /// Returns the TLS alert if this is a received or locally generated alert error.
    pub fn as_alert(&self) -> Option<&TlsAlert> {
        match self {
            TlsError::Alert(alert) | TlsError::LocalAlert { alert, .. } => Some(alert),
            _ => None,
        }
    }

    /// Returns `true` if this error is a TLS alert.
    pub fn is_alert(&self) -> bool {
        matches!(self, TlsError::Alert(_) | TlsError::LocalAlert { .. })
    }
}

/// Convenience alias used throughout lktls.
pub type Result<T> = std::result::Result<T, TlsError>;

#[cfg(test)]
mod tests {
    use super::*;

    // -- AlertLevel ---------------------------------------------------------

    #[test]
    fn alert_level_from_byte_warning() {
        assert_eq!(AlertLevel::from_byte(1), AlertLevel::Warning);
    }

    #[test]
    fn alert_level_from_byte_fatal() {
        assert_eq!(AlertLevel::from_byte(2), AlertLevel::Fatal);
    }

    #[test]
    fn alert_level_from_byte_unknown() {
        assert_eq!(AlertLevel::from_byte(99), AlertLevel::Unknown(99));
    }

    #[test]
    fn alert_level_roundtrip() {
        for b in 0..=255u8 {
            let level = AlertLevel::from_byte(b);
            assert_eq!(level.as_byte(), b);
        }
    }

    #[test]
    fn alert_level_display() {
        assert_eq!(AlertLevel::Warning.to_string(), "warning");
        assert_eq!(AlertLevel::Fatal.to_string(), "fatal");
        assert!(AlertLevel::Unknown(42).to_string().contains("42"));
    }

    // -- AlertDescription ---------------------------------------------------

    #[test]
    fn alert_description_known_codes() {
        let cases: &[(u8, AlertDescription)] = &[
            (0, AlertDescription::CloseNotify),
            (10, AlertDescription::UnexpectedMessage),
            (20, AlertDescription::BadRecordMac),
            (40, AlertDescription::HandshakeFailure),
            (48, AlertDescription::UnknownCa),
            (70, AlertDescription::ProtocolVersion),
            (80, AlertDescription::InternalError),
            (120, AlertDescription::NoApplicationProtocol),
        ];
        for &(byte, ref expected) in cases {
            assert_eq!(AlertDescription::from_byte(byte), *expected);
        }
    }

    #[test]
    fn alert_description_unknown() {
        assert_eq!(
            AlertDescription::from_byte(255),
            AlertDescription::Unknown(255)
        );
    }

    #[test]
    fn alert_description_roundtrip() {
        for b in 0..=255u8 {
            let desc = AlertDescription::from_byte(b);
            assert_eq!(desc.as_byte(), b);
        }
    }

    #[test]
    fn alert_description_name_known() {
        assert_eq!(AlertDescription::CloseNotify.name(), "close_notify");
        assert_eq!(
            AlertDescription::HandshakeFailure.name(),
            "handshake_failure"
        );
        assert_eq!(AlertDescription::InternalError.name(), "internal_error");
    }

    #[test]
    fn alert_description_name_unknown() {
        assert_eq!(AlertDescription::Unknown(200).name(), "unknown");
    }

    #[test]
    fn alert_description_display_format() {
        let desc = AlertDescription::HandshakeFailure;
        let s = desc.to_string();
        assert!(s.contains("handshake_failure"));
        assert!(s.contains("40"));
    }

    // -- TlsAlert -----------------------------------------------------------

    #[test]
    fn tls_alert_from_bytes() {
        let alert = TlsAlert::from_bytes(2, 40);
        assert_eq!(alert.level, AlertLevel::Fatal);
        assert_eq!(alert.description, AlertDescription::HandshakeFailure);
    }

    #[test]
    fn tls_alert_is_fatal() {
        let fatal = TlsAlert::from_bytes(2, 40);
        assert!(fatal.is_fatal());

        let warning = TlsAlert::from_bytes(1, 0);
        assert!(!warning.is_fatal());
    }

    #[test]
    fn tls_alert_is_close_notify() {
        let cn = TlsAlert::from_bytes(1, 0);
        assert!(cn.is_close_notify());

        let other = TlsAlert::from_bytes(2, 40);
        assert!(!other.is_close_notify());
    }

    #[test]
    fn tls_alert_display() {
        let alert = TlsAlert::from_bytes(2, 40);
        let s = alert.to_string();
        assert!(s.contains("fatal"));
        assert!(s.contains("handshake_failure"));
    }

    // -- TlsError -----------------------------------------------------------

    #[test]
    fn tls_error_as_alert() {
        let alert = TlsAlert::from_bytes(2, 40);
        let err = TlsError::Alert(alert);
        assert!(err.is_alert());
        assert_eq!(err.as_alert(), Some(&alert));
    }

    #[test]
    fn tls_error_local_alert() {
        let err = TlsError::local_alert(AlertDescription::IllegalParameter, "bad HRR");
        let alert = err.as_alert().expect("local alert");
        assert!(err.is_alert());
        assert_eq!(alert.level, AlertLevel::Fatal);
        assert_eq!(alert.description, AlertDescription::IllegalParameter);
        assert!(err.to_string().contains("bad HRR"));
    }

    #[test]
    fn tls_error_non_alert() {
        let err = TlsError::HandshakeFailure("test".into());
        assert!(!err.is_alert());
        assert_eq!(err.as_alert(), None);
    }

    #[test]
    fn tls_error_display_variants() {
        let io_err = TlsError::Io(std::io::Error::other("test"));
        assert!(io_err.to_string().contains("I/O"));

        let profile_err = TlsError::InvalidProfile("bad field".into());
        assert!(profile_err.to_string().contains("bad field"));

        let crypto_err = TlsError::CryptoError("key failed".into());
        assert!(crypto_err.to_string().contains("key failed"));

        let cert_err = TlsError::CertificateError("expired".into());
        assert!(cert_err.to_string().contains("expired"));

        let unexpected = TlsError::UnexpectedMessage("bad msg".into());
        assert!(unexpected.to_string().contains("bad msg"));

        let not_impl = TlsError::NotImplemented("feature X".into());
        assert!(not_impl.to_string().contains("feature X"));
    }
}
