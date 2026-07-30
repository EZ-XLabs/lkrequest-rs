//! Certificate chain verification and CertificateVerify signature validation.
//!
//! This module provides:
//! - [`verify_certificate_verify`]: Verifies the TLS 1.3 CertificateVerify
//!   signature using the leaf certificate's public key.
//! - [`verify_certificate_chain`]: Verifies the server's certificate chain
//!   against the Mozilla CA root store using `rustls-webpki`.

use aws_lc_rs::signature;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

use crate::error::{Result, TlsError};

// ---------------------------------------------------------------------------
// CertificateVerify
// ---------------------------------------------------------------------------

/// Verify a TLS 1.3 CertificateVerify signature.
///
/// The server signs the following content to prove it holds the private key
/// corresponding to its certificate:
///
/// ```text
/// 0x20 * 64 || "TLS 1.3, server CertificateVerify" || 0x00 || transcript_hash
/// ```
///
/// # Arguments
///
/// * `signature_scheme` - The TLS SignatureScheme code-point.
/// * `cert_der` - The leaf certificate in DER encoding (for public key extraction).
/// * `transcript_hash` - Hash of all handshake messages up to Certificate.
/// * `sig_bytes` - The signature bytes from CertificateVerify.
pub fn verify_certificate_verify(
    signature_scheme: u16,
    cert_der: &[u8],
    transcript_hash: &[u8],
    sig_bytes: &[u8],
) -> Result<()> {
    // Build the content that was signed
    let mut content = Vec::with_capacity(64 + 33 + 1 + transcript_hash.len());
    content.extend_from_slice(&[0x20u8; 64]);
    content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    content.push(0x00);
    content.extend_from_slice(transcript_hash);

    // Extract the SubjectPublicKeyInfo from the certificate
    let spki = extract_spki_from_cert(cert_der)?;

    // Map TLS signature scheme to ring verification algorithm + extract raw key
    match signature_scheme {
        // RSA-PSS schemes (TLS 1.3 only uses PSS for RSA)
        0x0804 => {
            // rsa_pss_rsae_sha256
            let rsa_pk = extract_rsa_public_key_from_spki(spki)?;
            let pk =
                signature::UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA256, rsa_pk);
            pk.verify(&content, sig_bytes).map_err(|_| {
                TlsError::CertificateError(
                    "RSA-PSS-SHA256 signature verification failed".to_string(),
                )
            })
        }
        0x0805 => {
            // rsa_pss_rsae_sha384
            let rsa_pk = extract_rsa_public_key_from_spki(spki)?;
            let pk =
                signature::UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA384, rsa_pk);
            pk.verify(&content, sig_bytes).map_err(|_| {
                TlsError::CertificateError(
                    "RSA-PSS-SHA384 signature verification failed".to_string(),
                )
            })
        }
        0x0806 => {
            // rsa_pss_rsae_sha512
            let rsa_pk = extract_rsa_public_key_from_spki(spki)?;
            let pk =
                signature::UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA512, rsa_pk);
            pk.verify(&content, sig_bytes).map_err(|_| {
                TlsError::CertificateError(
                    "RSA-PSS-SHA512 signature verification failed".to_string(),
                )
            })
        }

        // ECDSA schemes
        0x0403 => {
            // ecdsa_secp256r1_sha256
            let ec_point = extract_ec_point_from_spki(spki)?;
            let pk =
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, ec_point);
            pk.verify(&content, sig_bytes).map_err(|_| {
                TlsError::CertificateError(
                    "ECDSA-P256-SHA256 signature verification failed".to_string(),
                )
            })
        }
        0x0503 => {
            // ecdsa_secp384r1_sha384
            let ec_point = extract_ec_point_from_spki(spki)?;
            let pk =
                signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_ASN1, ec_point);
            pk.verify(&content, sig_bytes).map_err(|_| {
                TlsError::CertificateError(
                    "ECDSA-P384-SHA384 signature verification failed".to_string(),
                )
            })
        }

        // Ed25519
        0x0807 => {
            let raw_key = extract_ec_point_from_spki(spki)?;
            let pk = signature::UnparsedPublicKey::new(&signature::ED25519, raw_key);
            pk.verify(&content, sig_bytes).map_err(|_| {
                TlsError::CertificateError("Ed25519 signature verification failed".to_string())
            })
        }

        _ => Err(TlsError::CertificateError(format!(
            "unsupported signature scheme: 0x{signature_scheme:04x}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Certificate chain verification
// ---------------------------------------------------------------------------

/// Supported signature verification algorithms for webpki.
static SUPPORTED_SIG_ALGS: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] = &[
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA256,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA384,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA512,
    webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    webpki::aws_lc_rs::ECDSA_P256_SHA256,
    webpki::aws_lc_rs::ECDSA_P256_SHA384,
    webpki::aws_lc_rs::ECDSA_P384_SHA256,
    webpki::aws_lc_rs::ECDSA_P384_SHA384,
    webpki::aws_lc_rs::ED25519,
];

/// Verify a server certificate chain against the Mozilla CA root store,
/// optionally merged with custom trust anchors.
///
/// # Arguments
///
/// * `chain` - DER-encoded certificates, leaf first.
/// * `hostname` - The expected server hostname (for name verification).
/// * `now` - Current time (for validity period checking).
/// * `custom_anchors` - Optional additional trust anchors (e.g. corporate CA).
///   When provided, they are merged with the built-in Mozilla root store.
pub fn verify_certificate_chain(
    chain: &[Vec<u8>],
    hostname: &str,
    now: std::time::SystemTime,
    custom_anchors: Option<&[rustls_pki_types::TrustAnchor<'static>]>,
) -> Result<()> {
    if chain.is_empty() {
        return Err(TlsError::CertificateError(
            "empty certificate chain".to_string(),
        ));
    }

    // Convert DER bytes to webpki types
    let end_entity_cert = CertificateDer::from(chain[0].as_slice());
    let intermediates: Vec<CertificateDer<'_>> = chain[1..]
        .iter()
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();

    // Parse the end-entity certificate
    let ee = webpki::EndEntityCert::try_from(&end_entity_cert).map_err(|e| {
        TlsError::CertificateError(format!("failed to parse end-entity certificate: {e}"))
    })?;

    // Build trust anchor list: Mozilla roots + optional custom anchors
    let mut trust_anchors: Vec<rustls_pki_types::TrustAnchor<'_>> =
        webpki_roots::TLS_SERVER_ROOTS.to_vec();
    if let Some(custom) = custom_anchors {
        trust_anchors.extend(custom.iter().cloned());
    }

    // Convert system time to webpki time
    let unix_time = UnixTime::since_unix_epoch(
        now.duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default(),
    );

    // Verify the certificate chain
    ee.verify_for_usage(
        SUPPORTED_SIG_ALGS,
        &trust_anchors,
        &intermediates,
        unix_time,
        webpki::KeyUsage::server_auth(),
        None, // no revocation checking
        None, // no budget override
    )
    .map_err(|e| {
        TlsError::CertificateError(format!("certificate chain verification failed: {e}"))
    })?;

    // Verify hostname
    let server_name = ServerName::try_from(hostname)
        .map_err(|_| TlsError::CertificateError(format!("invalid hostname: {hostname}")))?;
    ee.verify_is_valid_for_subject_name(&server_name)
        .map_err(|e| {
            TlsError::CertificateError(format!(
                "hostname verification failed for '{hostname}': {e}"
            ))
        })?;

    Ok(())
}

/// Parse a DER-encoded X.509 certificate into a `TrustAnchor`.
///
/// This converts a DER certificate (e.g. a corporate root CA) into the
/// format needed by `webpki` for trust anchor verification.
pub fn parse_trust_anchor_from_der(der: &[u8]) -> Result<rustls_pki_types::TrustAnchor<'static>> {
    let cert = CertificateDer::from(der.to_vec());
    webpki::anchor_from_trusted_cert(&cert)
        .map(|ta| ta.to_owned())
        .map_err(|e| {
            TlsError::CertificateError(format!("failed to parse trust anchor from DER: {e}"))
        })
}

// ---------------------------------------------------------------------------
// DER / ASN.1 helpers for SPKI extraction
// ---------------------------------------------------------------------------

/// Parse a DER tag and length at the given position.
///
/// Returns `(tag, content_start, content_length)` relative to `data`.
fn parse_der_tl(data: &[u8]) -> Result<(u8, usize, usize)> {
    if data.is_empty() {
        return Err(TlsError::CertificateError(
            "DER: unexpected end of data".to_string(),
        ));
    }

    let tag = data[0];
    if data.len() < 2 {
        return Err(TlsError::CertificateError(
            "DER: missing length byte".to_string(),
        ));
    }

    let len_byte = data[1];
    if len_byte < 0x80 {
        // Short form: length is a single byte
        Ok((tag, 2, len_byte as usize))
    } else if len_byte == 0x81 {
        if data.len() < 3 {
            return Err(TlsError::CertificateError(
                "DER: truncated long length".to_string(),
            ));
        }
        Ok((tag, 3, data[2] as usize))
    } else if len_byte == 0x82 {
        if data.len() < 4 {
            return Err(TlsError::CertificateError(
                "DER: truncated long length".to_string(),
            ));
        }
        let length = ((data[2] as usize) << 8) | (data[3] as usize);
        Ok((tag, 4, length))
    } else if len_byte == 0x83 {
        if data.len() < 5 {
            return Err(TlsError::CertificateError(
                "DER: truncated long length".to_string(),
            ));
        }
        let length = ((data[2] as usize) << 16) | ((data[3] as usize) << 8) | (data[4] as usize);
        Ok((tag, 5, length))
    } else {
        Err(TlsError::CertificateError(format!(
            "DER: unsupported length encoding: 0x{len_byte:02x}"
        )))
    }
}

/// Skip one DER element, returning (element_total_bytes, remaining_data).
fn skip_der_element(data: &[u8]) -> Result<(usize, &[u8])> {
    let (_tag, _content, total) = parse_der_element(data)?;
    Ok((total, &data[total..]))
}

/// Parse one DER element and return `(tag, content_slice, element_total_bytes)`,
/// validating that the declared content length actually fits within `data`.
///
/// Unlike the raw [`parse_der_tl`] (which only reads the length *field*), this
/// guarantees the returned content slice is in bounds, so it is safe to call on
/// attacker-controlled certificate bytes. A declared length that overruns the
/// buffer (or overflows `usize`) yields a `CertificateError` instead of an
/// out-of-bounds slice panic.
fn parse_der_element(data: &[u8]) -> Result<(u8, &[u8], usize)> {
    let (tag, content_start, content_len) = parse_der_tl(data)?;
    let total = content_start
        .checked_add(content_len)
        .ok_or_else(|| TlsError::CertificateError("DER: length overflow".to_string()))?;
    if total > data.len() {
        return Err(TlsError::CertificateError(
            "DER: element extends past end of data".to_string(),
        ));
    }
    Ok((tag, &data[content_start..total], total))
}

/// Extract the SubjectPublicKeyInfo (SPKI) from a DER-encoded X.509 certificate.
///
/// The SPKI is the 7th field in the TBSCertificate SEQUENCE.
pub(crate) fn extract_spki_from_cert(cert_der: &[u8]) -> Result<&[u8]> {
    // Parse outer Certificate SEQUENCE
    let (tag, content_start, _content_len) = parse_der_tl(cert_der)?;
    if tag != 0x30 {
        return Err(TlsError::CertificateError(
            "Certificate: expected SEQUENCE".to_string(),
        ));
    }
    let cert_content = &cert_der[content_start..];

    // Parse TBSCertificate SEQUENCE (first element of Certificate)
    let (tag, tbs, _tbs_total) = parse_der_element(cert_content)?;
    if tag != 0x30 {
        return Err(TlsError::CertificateError(
            "TBSCertificate: expected SEQUENCE".to_string(),
        ));
    }

    // Navigate TBSCertificate fields:
    // 1. version [0] EXPLICIT (optional)
    // 2. serialNumber
    // 3. signature
    // 4. issuer
    // 5. validity
    // 6. subject
    // 7. subjectPublicKeyInfo <-- we want this
    let mut remaining = tbs;

    // Field 1: version (context-specific tag [0] = 0xA0)
    if !remaining.is_empty() && remaining[0] == 0xA0 {
        let (total, rest) = skip_der_element(remaining)?;
        let _ = total;
        remaining = rest;
    }

    // Fields 2-6: serialNumber, signature, issuer, validity, subject
    for field_name in &["serialNumber", "signature", "issuer", "validity", "subject"] {
        if remaining.is_empty() {
            return Err(TlsError::CertificateError(format!(
                "TBSCertificate: missing {field_name} field"
            )));
        }
        let (_total, rest) = skip_der_element(remaining)?;
        remaining = rest;
    }

    // Field 7: subjectPublicKeyInfo
    if remaining.is_empty() {
        return Err(TlsError::CertificateError(
            "TBSCertificate: missing subjectPublicKeyInfo".to_string(),
        ));
    }

    let (_tag, _spki_content, spki_total) = parse_der_element(remaining)?;
    Ok(&remaining[..spki_total])
}

/// Extract the raw RSA public key (DER-encoded RSAPublicKey) from an SPKI.
///
/// The SPKI BIT STRING contains the DER-encoded RSAPublicKey:
/// ```text
/// SEQUENCE {
///   SEQUENCE { algorithm OID, ... }
///   BIT STRING { 0x00, RSAPublicKey... }
/// }
/// ```
fn extract_rsa_public_key_from_spki(spki: &[u8]) -> Result<&[u8]> {
    // Parse SPKI SEQUENCE
    let (_tag, content_start, _content_len) = parse_der_tl(spki)?;
    let content = &spki[content_start..];

    // Skip AlgorithmIdentifier SEQUENCE
    let (_total, remaining) = skip_der_element(content)?;

    // Parse BIT STRING
    let (tag, bs_content, _bs_total) = parse_der_element(remaining)?;
    if tag != 0x03 {
        return Err(TlsError::CertificateError(
            "SPKI: expected BIT STRING for public key".to_string(),
        ));
    }

    if bs_content.is_empty() {
        return Err(TlsError::CertificateError(
            "SPKI: empty BIT STRING".to_string(),
        ));
    }

    // First byte of BIT STRING content is the unused bits count (should be 0)
    let _unused_bits = bs_content[0];
    Ok(&bs_content[1..])
}

/// Extract the raw EC point (or Ed25519 key) from an SPKI.
///
/// Similar to RSA extraction, but for EC keys the BIT STRING directly
/// contains the uncompressed point (0x04 || x || y).
fn extract_ec_point_from_spki(spki: &[u8]) -> Result<&[u8]> {
    // Same structure as RSA — the raw key is in the BIT STRING
    extract_rsa_public_key_from_spki(spki)
}

// ---------------------------------------------------------------------------
// TLS 1.2 ServerKeyExchange signature verification
// ---------------------------------------------------------------------------

/// Verify the signature in a TLS 1.2 ServerKeyExchange message.
///
/// The server signs: `ClientHello.random + ServerHello.random + ServerKeyExchange.params`
/// using the private key corresponding to the server certificate.
///
/// # Arguments
///
/// * `server_cert_der` - The server's end-entity certificate (DER-encoded)
/// * `sig_algorithm` - The signature algorithm (2-byte TLS code point)
/// * `signed_data` - The data that was signed (client_random + server_random + params)
/// * `signature` - The signature bytes
pub fn verify_server_key_exchange_signature(
    server_cert_der: &[u8],
    sig_algorithm: u16,
    signed_data: &[u8],
    signature: &[u8],
) -> Result<()> {
    // Extract SPKI from the certificate
    let spki = extract_spki_from_cert(server_cert_der)?;

    // Map the TLS signature algorithm to a ring verification algorithm
    match sig_algorithm {
        // RSA-PKCS1 schemes — extract RSAPublicKey from SPKI
        0x0401 | 0x0501 | 0x0601 | 0x0804 => {
            let rsa_pk = extract_rsa_public_key_from_spki(spki)?;
            let ring_algo: &dyn aws_lc_rs::signature::VerificationAlgorithm = match sig_algorithm {
                0x0401 => &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
                0x0501 => &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA384,
                0x0601 => &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA512,
                0x0804 => &aws_lc_rs::signature::RSA_PSS_2048_8192_SHA256,
                _ => unreachable!(),
            };
            let pk = aws_lc_rs::signature::UnparsedPublicKey::new(ring_algo, rsa_pk);
            pk.verify(signed_data, signature).map_err(|_| {
                TlsError::CryptoError("ServerKeyExchange RSA signature verification failed".into())
            })
        }
        // ECDSA schemes — extract EC point from SPKI
        0x0403 => {
            let ec_point = extract_ec_point_from_spki(spki)?;
            let pk = aws_lc_rs::signature::UnparsedPublicKey::new(
                &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
                ec_point,
            );
            pk.verify(signed_data, signature).map_err(|_| {
                TlsError::CryptoError(
                    "ServerKeyExchange ECDSA-P256 signature verification failed".into(),
                )
            })
        }
        0x0503 => {
            let ec_point = extract_ec_point_from_spki(spki)?;
            let pk = aws_lc_rs::signature::UnparsedPublicKey::new(
                &aws_lc_rs::signature::ECDSA_P384_SHA384_ASN1,
                ec_point,
            );
            pk.verify(signed_data, signature).map_err(|_| {
                TlsError::CryptoError(
                    "ServerKeyExchange ECDSA-P384 signature verification failed".into(),
                )
            })
        }
        // RSA-PKCS1 with SHA-1 (legacy, still used by some servers).
        // ring does not support SHA-1 signature verification; return an explicit
        // error so the caller's VerificationPolicy can decide how to handle it
        // (Strict rejects; Insecure skips verification entirely).
        0x0201 => Err(TlsError::CryptoError(
            "ServerKeyExchange uses legacy RSA-PKCS1-SHA1 (0x0201) which is not supported \
             for verification"
                .into(),
        )),
        other => Err(TlsError::CryptoError(format!(
            "unsupported ServerKeyExchange signature algorithm: 0x{other:04x}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // parse_der_tl
    // ========================================================================

    #[test]
    fn test_parse_der_tl_short_form() {
        let data = [0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        let (tag, content_start, content_len) = parse_der_tl(&data).unwrap();
        assert_eq!(tag, 0x30);
        assert_eq!(content_start, 2);
        assert_eq!(content_len, 5);
    }

    #[test]
    fn test_parse_der_tl_long_form_81() {
        // Tag=0x30, Length=0x81 0x80 = 128
        let mut data = vec![0x30, 0x81, 0x80];
        data.extend_from_slice(&[0u8; 128]);
        let (tag, content_start, content_len) = parse_der_tl(&data).unwrap();
        assert_eq!(tag, 0x30);
        assert_eq!(content_start, 3);
        assert_eq!(content_len, 128);
    }

    #[test]
    fn test_parse_der_tl_long_form_82() {
        let mut data = vec![0x30, 0x82, 0x01, 0x00];
        data.extend_from_slice(&[0u8; 256]);
        let (tag, content_start, content_len) = parse_der_tl(&data).unwrap();
        assert_eq!(tag, 0x30);
        assert_eq!(content_start, 4);
        assert_eq!(content_len, 256);
    }

    #[test]
    fn test_parse_der_tl_long_form_83() {
        let mut data = vec![0x30, 0x83, 0x01, 0x00, 0x00];
        data.extend_from_slice(&[0u8; 65536]);
        let (tag, content_start, content_len) = parse_der_tl(&data).unwrap();
        assert_eq!(tag, 0x30);
        assert_eq!(content_start, 5);
        assert_eq!(content_len, 65536);
    }

    #[test]
    fn test_parse_der_tl_empty() {
        let result = parse_der_tl(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_der_tl_missing_length() {
        let result = parse_der_tl(&[0x30]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_der_tl_truncated_long_form() {
        let result = parse_der_tl(&[0x30, 0x82, 0x01]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_der_tl_unsupported_length_encoding() {
        let result = parse_der_tl(&[0x30, 0x84, 0x00, 0x00, 0x00, 0x01]);
        assert!(result.is_err());
    }

    // ========================================================================
    // skip_der_element
    // ========================================================================

    #[test]
    fn test_skip_der_element() {
        let data = [0x02, 0x03, 0x01, 0x02, 0x03, 0x30, 0x00];
        let (total, remaining) = skip_der_element(&data).unwrap();
        assert_eq!(total, 5);
        assert_eq!(remaining, &[0x30, 0x00]);
    }

    #[test]
    fn test_skip_der_element_extends_past_end() {
        // Claim 10 bytes of content but only 3 available
        let data = [0x02, 0x0A, 0x01, 0x02, 0x03];
        let result = skip_der_element(&data);
        assert!(result.is_err());
    }

    // ========================================================================
    // extract_spki_from_cert
    // ========================================================================

    fn generate_ec_cert_der() -> Vec<u8> {
        let cert = rcgen::generate_simple_self_signed(vec!["test.example.com".to_string()])
            .expect("generate cert");
        cert.cert.der().to_vec()
    }

    #[test]
    fn test_extract_spki_from_ec_cert() {
        let cert_der = generate_ec_cert_der();
        let spki = extract_spki_from_cert(&cert_der).unwrap();
        assert!(!spki.is_empty());
        assert_eq!(spki[0], 0x30); // SPKI starts with SEQUENCE
    }

    #[test]
    fn test_extract_spki_empty_input() {
        let result = extract_spki_from_cert(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_spki_not_a_sequence() {
        let result = extract_spki_from_cert(&[0x02, 0x01, 0x00]);
        assert!(result.is_err());
    }

    // ========================================================================
    // extract_ec_point_from_spki
    // ========================================================================

    #[test]
    fn test_extract_ec_point_from_cert() {
        let cert_der = generate_ec_cert_der();
        let spki = extract_spki_from_cert(&cert_der).unwrap();
        let ec_point = extract_ec_point_from_spki(spki).unwrap();
        assert!(!ec_point.is_empty());
        // EC P-256 uncompressed point: 0x04 || x(32) || y(32) = 65 bytes
        // or possibly other EC key, check it starts with 0x04
        assert_eq!(ec_point[0], 0x04);
    }

    #[test]
    fn test_extract_rsa_public_key_bad_tag() {
        // SPKI with wrong inner tag (not BIT STRING)
        // SEQUENCE { SEQUENCE { ... }, INTEGER { ... } } instead of BIT STRING
        let data = [
            0x30, 0x08, // outer SEQUENCE
            0x30, 0x02, 0x05, 0x00, // AlgorithmIdentifier SEQUENCE
            0x02, 0x02, 0x00, 0x01, // INTEGER instead of BIT STRING
        ];
        let result = extract_rsa_public_key_from_spki(&data);
        assert!(result.is_err());
    }

    // ========================================================================
    // Malicious-certificate DER bounds (must error, never panic)
    //
    // A hostile server is the source of these bytes; an out-of-bounds slice
    // here is a remotely-triggerable panic (DoS) on the default Strict path,
    // where `verify_certificate_verify` parses the leaf SPKI *before* webpki
    // validates the chain.
    // ========================================================================

    #[test]
    fn extract_spki_rejects_oversized_tbs_length_without_panic() {
        // Outer Certificate SEQUENCE declares 0xFFFF content bytes and the
        // inner TBSCertificate SEQUENCE also declares 0xFFFF — both far beyond
        // the 10-byte buffer. The TBS slice must be bounds-checked.
        let malicious = [0x30, 0x82, 0xFF, 0xFF, 0x30, 0x82, 0xFF, 0xFF, 0x00, 0x01];
        let result = extract_spki_from_cert(&malicious);
        assert!(result.is_err(), "expected error, got {result:?}");
    }

    #[test]
    fn extract_rsa_pubkey_rejects_oversized_bitstring_without_panic() {
        // SPKI = SEQUENCE { AlgorithmIdentifier, BIT STRING } where the BIT
        // STRING declares 0xFFFF bytes but only 0 are present. The BIT STRING
        // content slice must be bounds-checked.
        let spki = [
            0x30, 0x08, // SPKI SEQUENCE, 8 content bytes
            0x30, 0x02, 0x05, 0x00, // AlgorithmIdentifier SEQUENCE { NULL }
            0x03, 0x82, 0xFF, 0xFF, // BIT STRING, declared length 0xFFFF
        ];
        let result = extract_rsa_public_key_from_spki(&spki);
        assert!(result.is_err(), "expected error, got {result:?}");
    }

    // ========================================================================
    // parse_trust_anchor_from_der
    // ========================================================================

    #[test]
    fn test_parse_trust_anchor_from_valid_cert() {
        let cert_der = generate_ec_cert_der();
        let result = parse_trust_anchor_from_der(&cert_der);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_trust_anchor_from_invalid_der() {
        let result = parse_trust_anchor_from_der(&[0x00, 0x01, 0x02]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_trust_anchor_from_empty() {
        let result = parse_trust_anchor_from_der(&[]);
        assert!(result.is_err());
    }

    // ========================================================================
    // verify_certificate_chain
    // ========================================================================

    #[test]
    fn test_verify_chain_empty() {
        let result =
            verify_certificate_chain(&[], "example.com", std::time::SystemTime::now(), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_chain_with_custom_ca() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};

        let mut ca_params = CertificateParams::new(vec!["Test CA".to_string()]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let leaf_params = CertificateParams::new(vec!["leaf.example.com".to_string()]).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

        let ca_der = ca_cert.der().to_vec();
        let leaf_der = leaf_cert.der().to_vec();

        let anchor = parse_trust_anchor_from_der(&ca_der).unwrap();
        let chain = vec![leaf_der];

        let result = verify_certificate_chain(
            &chain,
            "leaf.example.com",
            std::time::SystemTime::now(),
            Some(&[anchor]),
        );
        assert!(result.is_ok(), "chain verification failed: {result:?}");
    }

    #[test]
    fn test_verify_chain_wrong_hostname() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};

        let mut ca_params = CertificateParams::new(vec!["Test CA".to_string()]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let leaf_params = CertificateParams::new(vec!["leaf.example.com".to_string()]).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

        let anchor = parse_trust_anchor_from_der(ca_cert.der()).unwrap();
        let chain = vec![leaf_cert.der().to_vec()];

        let result = verify_certificate_chain(
            &chain,
            "wrong.example.com",
            std::time::SystemTime::now(),
            Some(&[anchor]),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_chain_self_signed_no_custom_anchors() {
        let cert_der = generate_ec_cert_der();
        let result = verify_certificate_chain(
            &[cert_der],
            "test.example.com",
            std::time::SystemTime::now(),
            None,
        );
        // Self-signed cert is not in Mozilla root store → should fail
        assert!(result.is_err());
    }

    // ========================================================================
    // verify_certificate_verify (TLS 1.3)
    // ========================================================================

    #[test]
    fn test_verify_certificate_verify_ecdsa_p256() {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();

        let rcgen_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let pkcs8_der = rcgen_kp.serialize_der();
        let ring_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8_der).unwrap();

        let params = rcgen::CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
        let cert = params.self_signed(&rcgen_kp).unwrap();
        let cert_der = cert.der().to_vec();

        let transcript_hash = [0x42u8; 32];

        let mut content = Vec::with_capacity(64 + 33 + 1 + 32);
        content.extend_from_slice(&[0x20u8; 64]);
        content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        content.push(0x00);
        content.extend_from_slice(&transcript_hash);

        let sig = ring_kp.sign(&rng, &content).unwrap();

        let result = verify_certificate_verify(
            0x0403, // ecdsa_secp256r1_sha256
            &cert_der,
            &transcript_hash,
            sig.as_ref(),
        );
        assert!(result.is_ok(), "verification failed: {result:?}");
    }

    #[test]
    fn test_verify_certificate_verify_bad_signature() {
        let cert_der = generate_ec_cert_der();
        let transcript_hash = [0x42u8; 32];
        let bad_sig = [0xFFu8; 64];

        let result = verify_certificate_verify(0x0403, &cert_der, &transcript_hash, &bad_sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_certificate_verify_unsupported_scheme() {
        let cert_der = generate_ec_cert_der();
        let result = verify_certificate_verify(0x9999, &cert_der, &[0u8; 32], &[0u8; 64]);
        assert!(result.is_err());
    }

    // ========================================================================
    // verify_server_key_exchange_signature (TLS 1.2)
    // ========================================================================

    #[test]
    fn test_verify_ske_ecdsa_p256() {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();

        let rcgen_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let pkcs8_der = rcgen_kp.serialize_der();
        let ring_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8_der).unwrap();

        let params = rcgen::CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
        let cert = params.self_signed(&rcgen_kp).unwrap();
        let cert_der = cert.der().to_vec();

        let signed_data = b"client_random_server_random_params";
        let sig = ring_kp.sign(&rng, signed_data).unwrap();

        let result = verify_server_key_exchange_signature(
            &cert_der,
            0x0403, // ecdsa_secp256r1_sha256
            signed_data,
            sig.as_ref(),
        );
        assert!(result.is_ok(), "verification failed: {result:?}");
    }

    #[test]
    fn test_verify_ske_bad_signature() {
        let cert_der = generate_ec_cert_der();
        let result =
            verify_server_key_exchange_signature(&cert_der, 0x0403, b"some data", &[0xFFu8; 64]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ske_sha1_unsupported() {
        let cert_der = generate_ec_cert_der();
        let result = verify_server_key_exchange_signature(
            &cert_der, 0x0201, // rsa_pkcs1_sha1
            b"data", &[0u8; 64],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ske_unknown_algorithm() {
        let cert_der = generate_ec_cert_der();
        let result = verify_server_key_exchange_signature(&cert_der, 0x9999, b"data", &[0u8; 64]);
        assert!(result.is_err());
    }
}
