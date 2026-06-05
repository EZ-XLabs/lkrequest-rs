//! Certificate verification.
//!
//! Verifies the server's certificate chain and CertificateVerify signature
//! during the TLS handshake.
//!
//! ## Sub-modules
//!
//! - [`policy`] — [`VerificationPolicy`](policy::VerificationPolicy) with two
//!   trust models: `Strict` (default) and `Insecure`.
//! - [`certchain`] — Certificate chain verification against the Mozilla CA root store,
//!   CertificateVerify signature validation, and ServerKeyExchange signature verification.

pub mod certchain;
pub mod policy;
