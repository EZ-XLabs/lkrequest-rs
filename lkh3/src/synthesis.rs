//! Synthesis support for randomized HTTP/3 + QUIC fingerprints.
//!
//! The H3 sibling of `lktls::profile::synthesis` / `lkh2::synthesis`:
//! [`validate`] encodes the invariants a usable QUIC/H3 fingerprint must
//! satisfy, and [`synthesize`] recombines a randomized [`QuicProfile`] within
//! those bounds.
//!
//! Like H2 there is **no capability floor** on this layer — QUIC transport
//! parameters and H3 SETTINGS are values the client *advertises*, never crypto
//! the peer selects and we must then perform. The QUIC-native TLS 1.3 handshake
//! (the part with a real capability floor) is produced by `lktls`, so it is
//! bounded there, not here.
//!
//! The recombine corpus is currently the two captured Chrome QUIC presets, so
//! synthesis varies the session-stable *ordered* dimensions (SETTINGS order,
//! pseudo-header order) on top of a real base rather than mixing values across
//! many browsers. It widens automatically as more `QuicProfile` presets are
//! captured.

use crate::profile::{PseudoHeaderId, QuicProfile};
use rand_core::RngCore;

/// A structural / usability violation in a [`QuicProfile`] fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidQuicSpec {
    /// The profile failed [`QuicProfile::validate`] (transport-param / H3
    /// structural consistency). Carries that check's message.
    Structural(String),
    /// A request pseudo-header required on every H3 request is missing from
    /// `pseudo_header_order`.
    MissingPseudoHeader(&'static str),
}

impl std::fmt::Display for InvalidQuicSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Structural(msg) => write!(f, "quic profile invalid: {msg}"),
            Self::MissingPseudoHeader(name) => {
                write!(f, "pseudo_header_order is missing required {name}")
            }
        }
    }
}

impl std::error::Error for InvalidQuicSpec {}

/// Validate the invariants a usable QUIC/H3 fingerprint must satisfy.
///
/// Layers the fingerprint-usability requirement (all four request
/// pseudo-headers present) on top of [`QuicProfile::validate`]'s structural
/// checks. Synthesized output passes by construction.
pub fn validate(profile: &QuicProfile) -> Result<(), InvalidQuicSpec> {
    profile.validate().map_err(InvalidQuicSpec::Structural)?;

    for (id, name) in [
        (PseudoHeaderId::Method, ":method"),
        (PseudoHeaderId::Scheme, ":scheme"),
        (PseudoHeaderId::Authority, ":authority"),
        (PseudoHeaderId::Path, ":path"),
    ] {
        if !profile.h3.pseudo_header_order.contains(&id) {
            return Err(InvalidQuicSpec::MissingPseudoHeader(name));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Recombination synthesizer
// ---------------------------------------------------------------------------

/// Inputs that bound what [`synthesize`] may produce for the QUIC/H3 layer.
#[derive(Clone)]
pub struct QuicConstraints {
    /// Real-browser QUIC profiles to recombine from. One is chosen per call.
    pub bases: Vec<QuicProfile>,
}

impl QuicConstraints {
    /// Recombine from the shipped real-browser QUIC presets.
    pub fn recombine() -> Self {
        Self {
            bases: vec![
                crate::profile::chrome_quic(),
                crate::profile::chrome_146_quic(),
                crate::profile::chrome_150_quic(),
                crate::profile::chrome_151_quic(),
            ],
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

/// Synthesize a randomized [`QuicProfile`] within `constraints`.
///
/// Recombine v1: pick a real base for the value skeleton (transport-param
/// values, packetization, GREASE behavior), then randomize the session-stable
/// ordered dimensions that are valid in any order — the H3 SETTINGS order and
/// the pseudo-header order (all permutations are spec-valid). Per-connection
/// transport-parameter-order jitter is left enabled on top. The result always
/// passes [`validate`].
pub fn synthesize(rng: &mut impl RngCore, constraints: &QuicConstraints) -> QuicProfile {
    let base = &constraints.bases[(rng.next_u64() as usize) % constraints.bases.len()];
    let mut p = base.clone();
    shuffle(rng, &mut p.h3.settings);
    shuffle(rng, &mut p.h3.pseudo_header_order);
    // Keep Chrome's per-connection transport-parameter-order shuffle on top of
    // the session identity (it is connection jitter, not part of the identity).
    p.transport_params.shuffle_transport_parameters = true;
    p
}

/// `lo..=hi` inclusive, drawn from the caller's RNG.
fn rand_u64(rng: &mut impl RngCore, lo: u64, hi: u64) -> u64 {
    lo + rng.next_u64() % (hi - lo + 1)
}

/// Synthesize a randomized [`QuicProfile`] at the **Full** (Tier 3b) degree.
///
/// Starts from [`synthesize`] (real base + shuffled orders), then perturbs the
/// QUIC transport-parameter and H3 QPACK **values** to novel, non-browser
/// numbers within their valid ranges. These are advertised values the peer
/// adapts to (flow-control windows, stream limits, QPACK table sizes), never
/// peer-selected crypto, so arbitrary in-range values stay negotiable. Ranges
/// are kept sane (no throughput-killing extremes) and respect
/// [`QuicProfile::validate`] (e.g. `active_connection_id_limit >= 2`,
/// `max_udp_payload_size` in `1200..=65527`). The result always passes
/// [`validate`].
pub fn synthesize_full(rng: &mut impl RngCore, constraints: &QuicConstraints) -> QuicProfile {
    let mut p = synthesize(rng, constraints);

    let tp = &mut p.transport_params;
    tp.max_idle_timeout = rand_u64(rng, 10_000, 60_000);
    tp.initial_max_data = rand_u64(rng, 1 << 20, 32 << 20);
    tp.initial_max_stream_data_bidi_local = rand_u64(rng, 1 << 19, 16 << 20);
    tp.initial_max_stream_data_bidi_remote = rand_u64(rng, 1 << 19, 16 << 20);
    tp.initial_max_stream_data_uni = rand_u64(rng, 1 << 19, 16 << 20);
    tp.initial_max_streams_bidi = rand_u64(rng, 16, 256);
    tp.initial_max_streams_uni = rand_u64(rng, 16, 256);
    tp.active_connection_id_limit = rand_u64(rng, 2, 8);
    if tp.max_udp_payload_size.is_some() {
        tp.max_udp_payload_size = Some(rand_u64(rng, 1_200, 1_500));
    }

    // H3 QPACK limits + field-section size, then resync the SETTINGS values from
    // these fields while preserving the (already-shuffled) wire order.
    p.h3.qpack_max_table_capacity = rand_u64(rng, 0, 65_536);
    p.h3.qpack_blocked_streams = rand_u64(rng, 0, 256);
    if p.h3.max_field_section_size.is_some() {
        p.h3.max_field_section_size = Some(rand_u64(rng, 1 << 14, 1 << 19));
    }
    p.h3.settings = p.h3.effective_settings();
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::SeedableRng;

    fn all_quic_presets() -> Vec<(&'static str, QuicProfile)> {
        vec![
            ("chrome_quic", crate::profile::chrome_quic()),
            ("chrome_146_quic", crate::profile::chrome_146_quic()),
            ("chrome_150_quic", crate::profile::chrome_150_quic()),
            ("chrome_151_quic", crate::profile::chrome_151_quic()),
        ]
    }

    #[test]
    fn all_shipped_quic_presets_pass_validate() {
        for (name, p) in all_quic_presets() {
            assert!(validate(&p).is_ok(), "{name} failed: {:?}", validate(&p));
        }
    }

    #[test]
    fn rejects_missing_request_pseudo_header() {
        let mut p = crate::profile::chrome_quic();
        p.h3.pseudo_header_order
            .retain(|h| *h != PseudoHeaderId::Path);
        assert_eq!(
            validate(&p),
            Err(InvalidQuicSpec::MissingPseudoHeader(":path"))
        );
    }

    #[test]
    fn rejects_structurally_invalid() {
        let mut p = crate::profile::chrome_quic();
        // Duplicate pseudo-header trips QuicProfile::validate (structural).
        p.h3.pseudo_header_order.push(PseudoHeaderId::Method);
        assert!(matches!(validate(&p), Err(InvalidQuicSpec::Structural(_))));
    }

    #[test]
    fn synthesize_recombine_is_always_valid_and_varied() {
        let c = QuicConstraints::recombine();
        let mut distinct = std::collections::HashSet::new();
        for seed in 0u64..400 {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&seed.to_le_bytes());
            let mut rng = rand_chacha::ChaCha20Rng::from_seed(bytes);
            let p = synthesize(&mut rng, &c);
            assert!(
                validate(&p).is_ok(),
                "seed {seed} invalid: {:?}",
                validate(&p)
            );
            let settings: Vec<u64> = p.h3.settings.iter().map(|(id, _)| *id).collect();
            let pseudo = p.h3.pseudo_header_order_token();
            distinct.insert((settings, pseudo));
        }
        assert!(distinct.len() > 10, "not varied: {}", distinct.len());
    }

    #[test]
    fn synthesize_is_deterministic_for_same_seed() {
        let c = QuicConstraints::recombine();
        let build = || {
            let mut rng = rand_chacha::ChaCha20Rng::from_seed([7u8; 32]);
            serde_json::to_string(&synthesize(&mut rng, &c)).unwrap()
        };
        assert_eq!(build(), build());
    }

    #[test]
    fn synthesize_full_is_valid_and_perturbs_values() {
        let c = QuicConstraints::recombine();
        let mut idle_timeouts = std::collections::HashSet::new();
        for seed in 0u64..400 {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&seed.to_le_bytes());
            let mut rng = rand_chacha::ChaCha20Rng::from_seed(bytes);
            let p = synthesize_full(&mut rng, &c);
            assert!(
                validate(&p).is_ok(),
                "seed {seed} invalid: {:?}",
                validate(&p)
            );
            assert!(p.transport_params.active_connection_id_limit >= 2);
            if let Some(mups) = p.transport_params.max_udp_payload_size {
                assert!((1_200..=65_527).contains(&mups));
            }
            idle_timeouts.insert(p.transport_params.max_idle_timeout);
        }
        // Real presets carry one fixed idle timeout; Full perturbs it widely.
        assert!(
            idle_timeouts.len() > 50,
            "values not perturbed: {}",
            idle_timeouts.len()
        );
    }
}
