//! Synthesis support for randomized fingerprints — structural validation.
//!
//! This is the safety net for synthesized (randomized) [`TlsProfile`]s: any
//! profile handed to the ClientHello builder must be *structurally valid* TLS,
//! or it serializes into a broken / rejected handshake. [`validate`] encodes
//! **browser-agnostic** invariants that hold for every real ClientHello.
//!
//! Contract: the (future) synthesizer must produce profiles that pass
//! [`validate`], and every shipped preset passes it too — the preset suite is
//! the calibration baseline (see tests). It deliberately does **not** check
//! browser-specific *shape* (GREASE presence, extension ordering); only
//! correctness that, if violated, breaks the handshake.

use super::types::{ExtensionSource, RandomizationConfig, TlsProfile, TlsVersion};
use crate::crypto::kx::KxGroup;
use crate::profile::presets;
use rand_core::RngCore;

/// X25519 (`0x001d`) — the near-universally negotiable group; always offered so
/// a synthesized profile can actually complete a handshake even when its other
/// groups (e.g. hybrid/PQ) are not yet widely supported by servers.
const GROUP_X25519: u16 = 0x001d;

/// `pre_shared_key` extension code-point — RFC 8446 §4.2.11 requires it last.
const EXT_PRE_SHARED_KEY: u16 = 0x0029;

/// TLS 1.3 cipher suite code-points the engine implements (RFC 8446 B.4).
/// This doubles as the **capability floor**: any offered `0x13xx` cipher must be
/// one of these, or the engine cannot complete a handshake the server picks.
const TLS13_CIPHERS: [u16; 3] = [0x1301, 0x1302, 0x1303];

/// Signature algorithms every synthesized profile MUST offer so that a real
/// server's certificate can actually be verified. If a client's
/// `signature_algorithms` covers none of the server certificate's key type, the
/// server aborts the handshake with `handshake_failure(40)` — the dominant cause
/// of un-negotiable synthetic fingerprints. This is the **negotiability floor**
/// (distinct from the engine-capability floor above): these three cover the
/// overwhelming majority of server certificates deployed today.
///
/// This is the built-in "universal-accept" default. A future configurable
/// `NegotiabilityFloor` can widen or (for fidelity) tighten it per target.
const NEGOTIABLE_SIG_ALGS: [u16; 3] = [
    0x0804, // rsa_pss_rsae_sha256    — RSA certs, TLS 1.3 CertificateVerify
    0x0401, // rsa_pkcs1_sha256       — RSA cert chains / TLS 1.2 fallback
    0x0403, // ecdsa_secp256r1_sha256 — ECDSA P-256 certs
];

/// The signature-algorithm negotiability floor (see [`NEGOTIABLE_SIG_ALGS`]).
/// Exposed so `validate`/tests share one source of truth.
pub fn negotiable_sig_algs() -> &'static [u16] {
    &NEGOTIABLE_SIG_ALGS
}

/// How much the synthesizer must guarantee about `signature_algorithms` so the
/// result stays server-negotiable. Different targets warrant different trade-offs
/// between JA3/JA4 diversity and browser-plausibility, so this is configurable;
/// the engine-capability floors (a TLS 1.3 cipher, X25519 in groups+key_share)
/// are always applied regardless.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum NegotiabilityFloor {
    /// Recombine sig algs freely, then guarantee the universal-accept core
    /// ([`NEGOTIABLE_SIG_ALGS`]). Maximum diversity, connects to any server — but
    /// the resulting sig-alg list matches no single real browser, so a detector
    /// that models sig-alg *shape* could flag it. The safe default.
    #[default]
    Universal,
    /// Keep the chosen base preset's real `signature_algorithms` unchanged:
    /// negotiable AND browser-plausible (no synthetic sig-alg anomaly). Prefer
    /// this against fingerprint-anomaly detectors; other layers still randomize.
    PresetFamily,
    /// Recombine freely, then guarantee a caller-supplied set. **Advanced**: if
    /// the set does not cover the target certificate's key type, negotiation
    /// fails — the caller owns negotiability.
    Custom(Vec<u16>),
}

// ---------------------------------------------------------------------------
// Capability registry — what the engine can actually negotiate AND perform.
//
// This is the lower bound for randomization: the synthesizer draws its
// cipher/curve pools from here, and `validate` rejects anything outside it, so
// a randomized profile can never offer crypto lktls cannot do (which would
// break the handshake when the server selects it).
// ---------------------------------------------------------------------------

/// Key-exchange groups the engine can perform (key_share / HRR). Source of
/// truth is [`KxGroup::from_code_point`]; the list is asserted in-sync by tests.
pub fn supported_kx_groups() -> &'static [u16] {
    // X25519, secp256r1, secp384r1, X25519MLKEM768.
    &[0x001d, 0x0017, 0x0018, 0x11ec]
}

/// TLS 1.3 cipher suites the engine implements.
pub fn supported_tls13_ciphers() -> &'static [u16] {
    &TLS13_CIPHERS
}

/// `true` if `cipher` is a TLS 1.3 cipher code-point (`0x13xx`).
fn is_tls13_cipher(cipher: u16) -> bool {
    (0x1300..=0x13ff).contains(&cipher)
}

/// A structural invariant violation in a [`TlsProfile`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidSpec {
    /// No cipher suites offered.
    NoCipherSuites,
    /// No supported groups (named curves) offered.
    NoSupportedGroups,
    /// No signature algorithms offered.
    NoSignatureAlgorithms,
    /// `tls_min_version` is greater than `tls_max_version`.
    VersionRangeInverted,
    /// A `key_share` curve is not present in `supported_groups`.
    KeyShareNotInGroups(u16),
    /// A `key_share` curve is not implemented by the engine (capability floor):
    /// the server could select it and the handshake would fail.
    KeyShareUnsupportedByEngine(u16),
    /// An offered TLS 1.3 cipher (`0x13xx`) is not implemented by the engine.
    Tls13CipherUnsupportedByEngine(u16),
    /// TLS 1.3 is offered but no `key_share` curve is provided.
    MissingKeyShareForTls13,
    /// TLS 1.3 is offered but no TLS 1.3 cipher suite is present.
    NoTls13Cipher,
    /// A non-GREASE extension type appears more than once.
    DuplicateExtension(u16),
    /// `pre_shared_key` is present but is not the last extension.
    PreSharedKeyNotLast,
}

impl std::fmt::Display for InvalidSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCipherSuites => write!(f, "no cipher suites"),
            Self::NoSupportedGroups => write!(f, "no supported groups"),
            Self::NoSignatureAlgorithms => write!(f, "no signature algorithms"),
            Self::VersionRangeInverted => write!(f, "tls_min_version > tls_max_version"),
            Self::KeyShareNotInGroups(g) => {
                write!(f, "key_share curve {g:#06x} not in supported_groups")
            }
            Self::KeyShareUnsupportedByEngine(g) => {
                write!(f, "key_share curve {g:#06x} not implemented by the engine")
            }
            Self::Tls13CipherUnsupportedByEngine(c) => {
                write!(f, "TLS 1.3 cipher {c:#06x} not implemented by the engine")
            }
            Self::MissingKeyShareForTls13 => write!(f, "TLS 1.3 offered but no key_share"),
            Self::NoTls13Cipher => write!(f, "TLS 1.3 offered but no TLS 1.3 cipher suite"),
            Self::DuplicateExtension(t) => write!(f, "duplicate extension {t:#06x}"),
            Self::PreSharedKeyNotLast => write!(f, "pre_shared_key is not the last extension"),
        }
    }
}

impl std::error::Error for InvalidSpec {}

/// Validate the structural invariants every real ClientHello must satisfy.
///
/// Returns `Ok(())` for any profile that serializes into a well-formed,
/// non-self-contradictory ClientHello. See the module docs for scope.
pub fn validate(profile: &TlsProfile) -> Result<(), InvalidSpec> {
    if profile.cipher_suites.is_empty() {
        return Err(InvalidSpec::NoCipherSuites);
    }
    if profile.supported_groups.is_empty() {
        return Err(InvalidSpec::NoSupportedGroups);
    }
    if profile.signature_algorithms.is_empty() {
        return Err(InvalidSpec::NoSignatureAlgorithms);
    }
    if profile.tls_min_version.as_u16() > profile.tls_max_version.as_u16() {
        return Err(InvalidSpec::VersionRangeInverted);
    }

    // Every key_share curve must be (a) advertised in supported_groups, and
    // (b) implementable by the engine — the server uses an offered key_share
    // directly, so an unimplemented one breaks the handshake.
    for &curve in &profile.key_share_curves {
        if !profile.supported_groups.contains(&curve) {
            return Err(InvalidSpec::KeyShareNotInGroups(curve));
        }
        if KxGroup::from_code_point(curve).is_none() {
            return Err(InvalidSpec::KeyShareUnsupportedByEngine(curve));
        }
    }

    // Capability floor for ciphers: any offered TLS 1.3 cipher could be picked
    // when 1.3 is negotiated, so all of them must be implemented. (TLS 1.2
    // ciphers are only reached on 1.2 fallback and may be advertise-only, so
    // they are not enforced here.)
    for &cipher in &profile.cipher_suites {
        if is_tls13_cipher(cipher) && !TLS13_CIPHERS.contains(&cipher) {
            return Err(InvalidSpec::Tls13CipherUnsupportedByEngine(cipher));
        }
    }

    if matches!(profile.tls_max_version, TlsVersion::Tls13) {
        if profile.key_share_curves.is_empty() {
            return Err(InvalidSpec::MissingKeyShareForTls13);
        }
        if !profile
            .cipher_suites
            .iter()
            .any(|c| TLS13_CIPHERS.contains(c))
        {
            return Err(InvalidSpec::NoTls13Cipher);
        }
    }

    // No duplicate non-GREASE extensions (GREASE legitimately appears as
    // leading/trailing bookends); pre_shared_key must be last if present.
    let mut seen = std::collections::HashSet::new();
    for ext in &profile.extensions {
        if matches!(ext.source, ExtensionSource::Grease) {
            continue;
        }
        if !seen.insert(ext.extension_type) {
            return Err(InvalidSpec::DuplicateExtension(ext.extension_type));
        }
    }
    if let Some(pos) = profile
        .extensions
        .iter()
        .position(|e| e.extension_type == EXT_PRE_SHARED_KEY)
    {
        if pos != profile.extensions.len() - 1 {
            return Err(InvalidSpec::PreSharedKeyNotLast);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Recombination synthesizer
// ---------------------------------------------------------------------------

/// Inputs that bound what [`synthesize`] may produce. For Recombine mode the
/// pools are the real-preset corpus intersected with engine capability, so any
/// output is capability-safe and passes [`validate`] by construction.
#[derive(Clone)]
pub struct Constraints {
    /// Real-browser profiles whose extension skeleton (GREASE, style, ALPN,
    /// versions, ECH, …) a synthesized profile is built on. One is chosen per
    /// call. All must be TLS 1.3 profiles.
    pub bases: Vec<TlsProfile>,
    /// TLS 1.3 cipher pool (always engine-implemented).
    pub tls13_ciphers: Vec<u16>,
    /// TLS 1.2 cipher pool (advertise-only; reached only on 1.2 fallback).
    pub tls12_ciphers: Vec<u16>,
    /// Key-exchange group pool (always engine-implemented).
    pub kx_groups: Vec<u16>,
    /// Signature algorithm pool.
    pub sig_algs: Vec<u16>,
}

impl Constraints {
    /// Recombine from the shipped real-browser presets, bounded to engine
    /// capability: cipher/group pools come from the capability registry, while
    /// the 1.2-cipher and signature-algorithm pools are the union across the
    /// preset corpus.
    pub fn recombine() -> Self {
        let bases = vec![
            presets::chrome_131(),
            presets::chrome_144(),
            presets::chrome_145(),
            presets::chrome_146(),
            presets::chrome_147(),
            presets::chrome_148(),
            presets::chrome_149(),
            presets::chrome_150(),
            presets::firefox_133(),
            presets::firefox_147(),
            presets::safari_18(),
            presets::safari_26(),
        ];
        let mut tls12_ciphers = Vec::new();
        let mut sig_algs = Vec::new();
        for b in &bases {
            for &c in &b.cipher_suites {
                if !is_tls13_cipher(c) && !tls12_ciphers.contains(&c) {
                    tls12_ciphers.push(c);
                }
            }
            for &s in &b.signature_algorithms {
                if !sig_algs.contains(&s) {
                    sig_algs.push(s);
                }
            }
        }
        Self {
            bases,
            tls13_ciphers: supported_tls13_ciphers().to_vec(),
            tls12_ciphers,
            kx_groups: supported_kx_groups().to_vec(),
            sig_algs,
        }
    }
}

/// Fisher–Yates shuffle in place using a caller-supplied RNG.
fn shuffle<T>(rng: &mut impl RngCore, v: &mut [T]) {
    for i in (1..v.len()).rev() {
        let j = (rng.next_u64() % (i as u64 + 1)) as usize;
        v.swap(i, j);
    }
}

/// A random **non-empty** prefix of a shuffled copy of `pool` (panics if empty).
fn pick_some<T: Clone>(rng: &mut impl RngCore, pool: &[T]) -> Vec<T> {
    debug_assert!(!pool.is_empty(), "pick_some on empty pool");
    let mut v = pool.to_vec();
    shuffle(rng, &mut v);
    let k = 1 + (rng.next_u64() as usize % v.len());
    v.truncate(k);
    v
}

/// Ensure `sig_algs` offers every member of `required`, prepending any missing
/// one (so it is preferred) while preserving the rest of the list. A random
/// recombination can drop negotiation-critical algorithms; this restores them so
/// the synthesized profile can verify the target server certificate.
fn ensure_sig_algs(sig_algs: Vec<u16>, required: &[u16]) -> Vec<u16> {
    let mut missing: Vec<u16> = required
        .iter()
        .copied()
        .filter(|a| !sig_algs.contains(a))
        .collect();
    if missing.is_empty() {
        return sig_algs;
    }
    missing.extend(sig_algs);
    missing
}

/// [`ensure_sig_algs`] with the universal-accept floor ([`NEGOTIABLE_SIG_ALGS`]).
fn ensure_negotiable_sig_algs(sig_algs: Vec<u16>) -> Vec<u16> {
    ensure_sig_algs(sig_algs, &NEGOTIABLE_SIG_ALGS)
}

/// A random (possibly empty) prefix of a shuffled copy of `pool`.
fn pick_any<T: Clone>(rng: &mut impl RngCore, pool: &[T]) -> Vec<T> {
    if pool.is_empty() {
        return Vec::new();
    }
    let mut v = pool.to_vec();
    shuffle(rng, &mut v);
    let k = rng.next_u64() as usize % (v.len() + 1);
    v.truncate(k);
    v
}

/// Synthesize a randomized [`TlsProfile`] within `constraints`.
///
/// Recombine v1: pick a real base preset for the extension skeleton, then
/// recombine the cipher / group / signature-algorithm lists from the
/// capability-bounded pools, guarantee a negotiable group (X25519) and the
/// signature-algorithm negotiability `floor` (so a real server cert always
/// verifies), and enable per-connection extension-order jitter. The result is
/// **always** capability-safe *and* server-negotiable, and passes [`validate`]
/// by construction (verified by property test).
pub fn synthesize(
    rng: &mut impl RngCore,
    constraints: &Constraints,
    floor: &NegotiabilityFloor,
) -> TlsProfile {
    let base = &constraints.bases[(rng.next_u64() as usize) % constraints.bases.len()];
    let mut p = base.clone();

    // Ciphers: >=1 engine-implemented TLS 1.3 cipher, then some 1.2 ciphers.
    let mut ciphers = pick_some(rng, &constraints.tls13_ciphers);
    ciphers.extend(pick_any(rng, &constraints.tls12_ciphers));
    p.cipher_suites = ciphers;

    // Groups + a key_share drawn from the chosen groups, so
    // key_share ⊆ supported_groups ⊆ capability holds.
    p.supported_groups = pick_some(rng, &constraints.kx_groups);
    p.key_share_curves = pick_some(rng, &p.supported_groups);

    // Always offer X25519 (in both groups and key_share) so the handshake is
    // negotiable even if the other picks are hybrid/PQ groups servers lack.
    if !p.supported_groups.contains(&GROUP_X25519) {
        p.supported_groups.push(GROUP_X25519);
    }
    if !p.key_share_curves.contains(&GROUP_X25519) {
        p.key_share_curves.push(GROUP_X25519);
    }

    // Signature algorithms per the negotiability floor. A bare random subset can
    // drop rsa_pss_rsae_sha256 / ecdsa_secp256r1_sha256, which servers whose cert
    // uses them reject with handshake_failure — so every floor keeps the result
    // verifiable.
    p.signature_algorithms = match floor {
        // Keep the base preset's real list — negotiable AND browser-plausible.
        NegotiabilityFloor::PresetFamily => base.signature_algorithms.clone(),
        // Recombine, then restore the universal-accept core.
        NegotiabilityFloor::Universal => {
            ensure_negotiable_sig_algs(pick_some(rng, &constraints.sig_algs))
        }
        // Recombine, then restore the caller's required set.
        NegotiabilityFloor::Custom(required) => {
            ensure_sig_algs(pick_some(rng, &constraints.sig_algs), required)
        }
    };

    // Per-connection extension-order jitter (BoringSSL-style; GREASE pinned).
    p.randomization = Some(RandomizationConfig {
        shuffle_extensions: true,
    });
    p.name = "synthetic-recombine".to_string();
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The calibration baseline: every shipped preset must pass `validate`.
    /// If a new preset fails here, either the preset is structurally broken or
    /// an invariant is mis-calibrated.
    #[test]
    fn all_shipped_presets_pass_validate() {
        let presets: Vec<(&str, TlsProfile)> = vec![
            ("chrome_131", presets::chrome_131()),
            ("chrome_144", presets::chrome_144()),
            ("chrome_145", presets::chrome_145()),
            ("chrome_146", presets::chrome_146()),
            ("chrome_146_quic", presets::chrome_146_quic()),
            ("chrome_147", presets::chrome_147()),
            ("chrome_148", presets::chrome_148()),
            ("chrome_149", presets::chrome_149()),
            ("chrome_150", presets::chrome_150()),
            ("chrome_150_quic", presets::chrome_150_quic()),
            ("firefox_133", presets::firefox_133()),
            ("firefox_147", presets::firefox_147()),
            ("safari_18", presets::safari_18()),
            ("safari_26", presets::safari_26()),
        ];
        for (name, profile) in presets {
            assert!(
                validate(&profile).is_ok(),
                "{name} failed validate: {:?}",
                validate(&profile)
            );
        }
    }

    #[test]
    fn rejects_empty_cipher_suites() {
        let mut p = presets::chrome_146();
        p.cipher_suites.clear();
        assert_eq!(validate(&p), Err(InvalidSpec::NoCipherSuites));
    }

    #[test]
    fn rejects_key_share_outside_supported_groups() {
        let mut p = presets::chrome_146();
        p.key_share_curves.push(0xBEEF); // not advertised in supported_groups
        assert_eq!(validate(&p), Err(InvalidSpec::KeyShareNotInGroups(0xBEEF)));
    }

    #[test]
    fn rejects_tls13_without_tls13_cipher() {
        let mut p = presets::chrome_146();
        assert!(matches!(p.tls_max_version, TlsVersion::Tls13));
        p.cipher_suites.retain(|c| !TLS13_CIPHERS.contains(c));
        assert_eq!(validate(&p), Err(InvalidSpec::NoTls13Cipher));
    }

    #[test]
    fn rejects_inverted_version_range() {
        let mut p = presets::chrome_146();
        p.tls_min_version = TlsVersion::Tls13;
        p.tls_max_version = TlsVersion::Tls12;
        assert_eq!(validate(&p), Err(InvalidSpec::VersionRangeInverted));
    }

    #[test]
    fn rejects_key_share_engine_cannot_perform() {
        // secp521r1 (0x0019) is a valid curve but the engine does not implement
        // its ECDH — advertising a key_share for it would break the handshake.
        let mut p = presets::chrome_146();
        p.supported_groups.push(0x0019); // pass the "in groups" check
        p.key_share_curves.push(0x0019);
        assert_eq!(
            validate(&p),
            Err(InvalidSpec::KeyShareUnsupportedByEngine(0x0019))
        );
    }

    #[test]
    fn rejects_unimplemented_tls13_cipher() {
        // TLS_AES_128_CCM_SHA256 (0x1304) is a real 1.3 cipher the engine lacks.
        let mut p = presets::chrome_146();
        p.cipher_suites.insert(0, 0x1304);
        assert_eq!(
            validate(&p),
            Err(InvalidSpec::Tls13CipherUnsupportedByEngine(0x1304))
        );
    }

    /// The hardcoded capability registry must stay in sync with the engine's
    /// actual key-exchange implementation (`KxGroup::from_code_point`).
    #[test]
    fn kx_registry_matches_engine() {
        for &g in supported_kx_groups() {
            assert!(
                KxGroup::from_code_point(g).is_some(),
                "listed group {g:#06x} is not implemented by KxGroup"
            );
        }
        // A curve not in the list must not be implemented (catches drift if the
        // engine gains a group but the registry isn't updated).
        assert!(
            KxGroup::from_code_point(0x0019).is_none(),
            "secp521r1 unexpectedly implemented"
        );
    }

    /// Headline test: across many seeds, every recombine output is valid, and
    /// outputs vary (proving it actually randomizes), and X25519 is always
    /// offered (negotiability guarantee).
    #[test]
    fn synthesize_recombine_is_always_valid_and_varied() {
        use rand_core::SeedableRng;
        let c = Constraints::recombine();
        let mut distinct = std::collections::HashSet::new();
        for seed in 0u64..400 {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&seed.to_le_bytes());
            let mut rng = rand_chacha::ChaCha20Rng::from_seed(bytes);
            let p = synthesize(&mut rng, &c, &NegotiabilityFloor::Universal);
            assert!(
                validate(&p).is_ok(),
                "seed {seed} produced invalid profile: {:?}",
                validate(&p)
            );
            assert!(p.supported_groups.contains(&GROUP_X25519));
            assert!(p.key_share_curves.contains(&GROUP_X25519));
            // Negotiability floor: a real server cert (RSA or ECDSA-P256) can
            // always be verified — no random subset drops the core sig algs.
            for &a in negotiable_sig_algs() {
                assert!(
                    p.signature_algorithms.contains(&a),
                    "seed {seed}: sig_algs {:04x?} missing negotiable floor {a:#06x}",
                    p.signature_algorithms
                );
            }
            distinct.insert((
                p.cipher_suites.clone(),
                p.supported_groups.clone(),
                p.signature_algorithms.clone(),
            ));
        }
        assert!(
            distinct.len() > 20,
            "synthesis not varied enough: only {} distinct profiles",
            distinct.len()
        );
    }

    #[test]
    fn ensure_negotiable_sig_algs_restores_missing_floor() {
        // A subset that dropped the whole floor gets it prepended (preferred),
        // with the original entries preserved after it.
        let out = ensure_negotiable_sig_algs(vec![0x0807, 0x0908]);
        for &a in negotiable_sig_algs() {
            assert!(out.contains(&a), "missing {a:#06x} in {out:04x?}");
        }
        assert!(out.ends_with(&[0x0807, 0x0908]));
        // An already-complete list is returned unchanged (order preserved).
        let full = vec![0x0403, 0x0804, 0x0401, 0x0503];
        assert_eq!(ensure_negotiable_sig_algs(full.clone()), full);
        // A partially-missing list only gains the missing member.
        let partial = ensure_negotiable_sig_algs(vec![0x0804, 0x0501]);
        assert_eq!(partial, vec![0x0401, 0x0403, 0x0804, 0x0501]);
    }

    #[test]
    fn floor_preset_family_keeps_a_real_browser_sig_alg_list() {
        use rand_core::SeedableRng;
        let c = Constraints::recombine();
        for seed in 0u64..64 {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&seed.to_le_bytes());
            let mut rng = rand_chacha::ChaCha20Rng::from_seed(bytes);
            let p = synthesize(&mut rng, &c, &NegotiabilityFloor::PresetFamily);
            // PresetFamily leaves sig_algs exactly as the chosen base preset's —
            // negotiable AND browser-plausible (no synthetic sig-alg shape).
            assert!(
                c.bases
                    .iter()
                    .any(|b| b.signature_algorithms == p.signature_algorithms),
                "seed {seed}: PresetFamily sig_algs {:04x?} matches no base preset",
                p.signature_algorithms
            );
            assert!(validate(&p).is_ok());
        }
    }

    #[test]
    fn floor_custom_guarantees_the_required_set() {
        use rand_core::SeedableRng;
        let c = Constraints::recombine();
        let required = vec![0x0804u16, 0x0403];
        for seed in 0u64..64 {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&seed.to_le_bytes());
            let mut rng = rand_chacha::ChaCha20Rng::from_seed(bytes);
            let p = synthesize(&mut rng, &c, &NegotiabilityFloor::Custom(required.clone()));
            for &a in &required {
                assert!(
                    p.signature_algorithms.contains(&a),
                    "seed {seed}: Custom floor missing {a:#06x} in {:04x?}",
                    p.signature_algorithms
                );
            }
            assert!(validate(&p).is_ok());
        }
    }

    /// Stronger than `validate`: synthesized profiles must actually serialize
    /// into a ClientHello (catches field/extension inconsistencies the
    /// structural oracle does not cover).
    #[test]
    fn synthesized_profiles_build_a_client_hello() {
        use crate::handshake::client_hello::ClientHelloBuilder;
        use rand_core::SeedableRng;
        let c = Constraints::recombine();
        for seed in 0u64..50 {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&seed.to_le_bytes());
            let mut rng = rand_chacha::ChaCha20Rng::from_seed(bytes);
            let p = synthesize(&mut rng, &c, &NegotiabilityFloor::Universal);
            let out = ClientHelloBuilder::new(&p, "example.com").build();
            assert!(
                out.is_ok(),
                "seed {seed} failed to build ClientHello: {:?}",
                out.err()
            );
        }
    }

    /// Reproducibility: the same seed must yield a byte-identical profile.
    #[test]
    fn synthesize_is_deterministic_for_same_seed() {
        use rand_core::SeedableRng;
        let c = Constraints::recombine();
        let build = || {
            let mut rng = rand_chacha::ChaCha20Rng::from_seed([9u8; 32]);
            serde_json::to_string(&synthesize(&mut rng, &c, &NegotiabilityFloor::Universal))
                .unwrap()
        };
        assert_eq!(
            build(),
            build(),
            "same seed must reproduce the same profile"
        );
    }

    /// Defense-in-depth: synthesized crypto must stay inside engine capability,
    /// independently of `validate`.
    #[test]
    fn synthesized_output_stays_within_capability() {
        use rand_core::SeedableRng;
        let c = Constraints::recombine();
        for seed in 0u64..100 {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&seed.to_le_bytes());
            let mut rng = rand_chacha::ChaCha20Rng::from_seed(bytes);
            let p = synthesize(&mut rng, &c, &NegotiabilityFloor::Universal);
            for &g in &p.key_share_curves {
                assert!(
                    KxGroup::from_code_point(g).is_some(),
                    "seed {seed}: key_share {g:#06x} not implemented"
                );
            }
            for &cipher in p.cipher_suites.iter().filter(|c| is_tls13_cipher(**c)) {
                assert!(
                    supported_tls13_ciphers().contains(&cipher),
                    "seed {seed}: 1.3 cipher {cipher:#06x} not implemented"
                );
            }
        }
    }

    // ---- remaining InvalidSpec variants (negative coverage) ----

    #[test]
    fn rejects_no_supported_groups() {
        let mut p = presets::chrome_146();
        p.supported_groups.clear();
        assert_eq!(validate(&p), Err(InvalidSpec::NoSupportedGroups));
    }

    #[test]
    fn rejects_no_signature_algorithms() {
        let mut p = presets::chrome_146();
        p.signature_algorithms.clear();
        assert_eq!(validate(&p), Err(InvalidSpec::NoSignatureAlgorithms));
    }

    #[test]
    fn rejects_missing_key_share_for_tls13() {
        let mut p = presets::chrome_146();
        assert!(matches!(p.tls_max_version, TlsVersion::Tls13));
        p.key_share_curves.clear();
        assert_eq!(validate(&p), Err(InvalidSpec::MissingKeyShareForTls13));
    }

    #[test]
    fn rejects_duplicate_extension() {
        use crate::profile::types::ExtensionSpec;
        let mut p = presets::chrome_146();
        // Duplicate SNI (0x0000) — a real (non-GREASE) extension already present.
        p.extensions.push(ExtensionSpec {
            extension_type: 0x0000,
            source: ExtensionSource::Auto,
        });
        assert_eq!(validate(&p), Err(InvalidSpec::DuplicateExtension(0x0000)));
    }

    #[test]
    fn rejects_pre_shared_key_not_last() {
        use crate::profile::types::ExtensionSpec;
        let mut p = presets::chrome_146();
        // Insert pre_shared_key (0x0029) anywhere but last.
        p.extensions.insert(
            0,
            ExtensionSpec {
                extension_type: 0x0029,
                source: ExtensionSource::Auto,
            },
        );
        assert_eq!(validate(&p), Err(InvalidSpec::PreSharedKeyNotLast));
    }
}
