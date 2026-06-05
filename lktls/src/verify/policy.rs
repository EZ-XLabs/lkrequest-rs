//! Certificate verification policies.
//!
//! Defines [`VerificationPolicy`] with two trust models: [`Strict`](VerificationPolicy::Strict)
//! (the default — full certificate-chain, hostname and signature verification)
//! and [`Insecure`](VerificationPolicy::Insecure) (skip everything; testing /
//! MITM-proxy debugging only).
//!
//! Note: certificate validation is **browser-agnostic and client-internal** —
//! the server cannot observe how the client validates its certificate, so it is
//! NOT a fingerprint dimension. There is therefore no impersonation reason to
//! relax it; the only choices offered are "verify properly" or "explicitly
//! don't". (A future feature may add browser-style *incomplete-chain* tolerance
//! via AIA intermediate fetching, but that must still enforce trust + hostname
//! + expiry — it is not a reason to swallow verification errors.)

use crate::error::Result;

/// Controls how strictly the TLS engine verifies server certificates and
/// handshake signatures.
///
/// | Policy     | Cert Chain | Hostname | CertificateVerify | SKE Signature | Use Case |
/// |:-----------|:-----------|:---------|:------------------|:--------------|:---------|
/// | `Strict`   | Fail       | Fail     | Fail              | Fail          | Production (default) |
/// | `Insecure` | Skip       | Skip     | Skip              | Skip          | Testing / MITM proxy only |
///
/// # Example
///
/// ```rust
/// use lktls::verify::policy::VerificationPolicy;
///
/// assert_eq!(VerificationPolicy::default(), VerificationPolicy::Strict);
/// assert!(VerificationPolicy::Insecure.is_insecure());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VerificationPolicy {
    /// Strict verification (default).
    ///
    /// All certificate-chain, hostname and signature checks must pass.  Any
    /// failure immediately aborts the handshake with an error.
    #[default]
    Strict,

    /// Skip all certificate verification.
    ///
    /// **Insecure — testing / MITM-proxy debugging only.**  No certificate
    /// chain, hostname, or signature checks are performed.
    Insecure,
}

impl VerificationPolicy {
    /// Returns `true` if this policy skips all verification.
    pub fn is_insecure(&self) -> bool {
        matches!(self, Self::Insecure)
    }

    /// Verify a certificate chain (trust + hostname + validity) per this policy.
    ///
    /// - `Strict`: errors are propagated (the handshake aborts).
    /// - `Insecure`: verification is skipped entirely.
    ///
    /// `custom_anchors` are optional additional trust anchors (e.g. a corporate
    /// CA) that are merged with the built-in Mozilla root store.
    pub fn verify_certificate_chain(
        &self,
        chain: &[Vec<u8>],
        hostname: &str,
        now: std::time::SystemTime,
        custom_anchors: Option<&[rustls_pki_types::TrustAnchor<'static>]>,
    ) -> Result<()> {
        match self {
            Self::Insecure => Ok(()),
            Self::Strict => {
                super::certchain::verify_certificate_chain(chain, hostname, now, custom_anchors)
            }
        }
    }

    /// Verify a TLS 1.3 CertificateVerify signature per this policy.
    ///
    /// - `Strict`: errors are propagated.
    /// - `Insecure`: verification is skipped.
    pub fn verify_certificate_verify(
        &self,
        signature_scheme: u16,
        cert_der: &[u8],
        transcript_hash: &[u8],
        sig_bytes: &[u8],
    ) -> Result<()> {
        match self {
            Self::Insecure => Ok(()),
            Self::Strict => super::certchain::verify_certificate_verify(
                signature_scheme,
                cert_der,
                transcript_hash,
                sig_bytes,
            ),
        }
    }

    /// Verify a TLS 1.2 ServerKeyExchange signature per this policy.
    ///
    /// - `Strict`: errors are propagated.
    /// - `Insecure`: verification is skipped.
    pub fn verify_server_key_exchange_signature(
        &self,
        server_cert_der: &[u8],
        sig_algorithm: u16,
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        match self {
            Self::Insecure => Ok(()),
            Self::Strict => super::certchain::verify_server_key_exchange_signature(
                server_cert_der,
                sig_algorithm,
                signed_data,
                signature,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A freshly generated self-signed leaf cert (DER), valid now.
    fn self_signed(name: &str) -> Vec<u8> {
        rcgen::generate_simple_self_signed(vec![name.to_string()])
            .expect("rcgen self-signed")
            .cert
            .der()
            .to_vec()
    }

    #[test]
    fn default_is_strict() {
        assert_eq!(VerificationPolicy::default(), VerificationPolicy::Strict);
    }

    #[test]
    fn strict_is_not_insecure() {
        assert!(!VerificationPolicy::Strict.is_insecure());
        assert!(VerificationPolicy::Insecure.is_insecure());
    }

    #[test]
    fn insecure_skips_all() {
        let policy = VerificationPolicy::Insecure;
        assert!(policy
            .verify_certificate_chain(&[], "example.com", std::time::SystemTime::now(), None)
            .is_ok());
        assert!(policy
            .verify_certificate_verify(0x0804, &[], &[], &[])
            .is_ok());
        assert!(policy
            .verify_server_key_exchange_signature(&[], 0x0401, &[], &[])
            .is_ok());
    }

    // ---------------------------------------------------------------------
    // Negative tests — the error-swallowing regression must never come back.
    // (These caught the old `BrowserCompat` default that silently accepted
    // untrusted / wrong-host certificates.)
    // ---------------------------------------------------------------------

    #[test]
    fn strict_rejects_untrusted_self_signed() {
        let chain = vec![self_signed("evil.example")];
        let now = std::time::SystemTime::now();
        // Not in the root store and no custom anchor → untrusted → must reject.
        assert!(
            VerificationPolicy::Strict
                .verify_certificate_chain(&chain, "evil.example", now, None)
                .is_err(),
            "Strict must reject an untrusted self-signed cert"
        );
        // Insecure is the only escape hatch.
        assert!(VerificationPolicy::Insecure
            .verify_certificate_chain(&chain, "evil.example", now, None)
            .is_ok());
    }

    #[test]
    fn strict_rejects_hostname_mismatch() {
        let der = self_signed("good.example");
        let chain = vec![der.clone()];
        // Trust the cert as its own anchor so the chain itself is valid; the
        // only remaining failure is the hostname — isolating hostname enforcement.
        let anchors = vec![crate::verify::certchain::parse_trust_anchor_from_der(&der)
            .expect("trust anchor from self-signed cert")];
        let now = std::time::SystemTime::now();
        assert!(
            VerificationPolicy::Strict
                .verify_certificate_chain(&chain, "good.example", now, Some(&anchors))
                .is_ok(),
            "matching hostname against a trusted anchor must pass"
        );
        assert!(
            VerificationPolicy::Strict
                .verify_certificate_chain(&chain, "evil.example", now, Some(&anchors))
                .is_err(),
            "Strict must reject a hostname mismatch even when the chain is trusted"
        );
    }

    #[test]
    fn strict_rejects_empty_chain() {
        assert!(VerificationPolicy::Strict
            .verify_certificate_chain(&[], "example.com", std::time::SystemTime::now(), None)
            .is_err());
    }
}
