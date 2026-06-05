//! Synthesis support for randomized HTTP/2 fingerprints.
//!
//! Mirror of `lktls::profile::synthesis` for the H2 layer: [`validate`] encodes
//! the structural invariants a usable H2 fingerprint must satisfy, and
//! [`synthesize`] recombines a randomized [`H2Profile`] within those bounds.
//!
//! Unlike TLS there is **no capability floor** — H2 SETTINGS are values the
//! engine simply advertises (the peer never "selects one we cannot perform"),
//! so the only constraints are RFC 7540/9113 value ranges and pseudo-header
//! well-formedness.

use crate::profile::{H2Profile, PseudoHeaderId};
use rand_core::RngCore;

/// A structural invariant violation in an [`H2Profile`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidH2Spec {
    /// `pseudo_header_order` is not exactly the four pseudo-headers, once each.
    PseudoHeaderOrderInvalid,
    /// A SETTINGS id appears more than once.
    DuplicateSetting(u16),
    /// `SETTINGS_MAX_FRAME_SIZE` outside the RFC range [16384, 16777215].
    MaxFrameSizeOutOfRange(u32),
    /// `SETTINGS_INITIAL_WINDOW_SIZE` exceeds 2^31-1.
    InitialWindowTooLarge(u32),
    /// `SETTINGS_ENABLE_PUSH` is not 0 or 1.
    EnablePushNotBoolean(u32),
    /// The connection WINDOW_UPDATE increment would push the window past 2^31-1.
    WindowUpdateTooLarge(u32),
}

impl std::fmt::Display for InvalidH2Spec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PseudoHeaderOrderInvalid => {
                write!(
                    f,
                    "pseudo_header_order must be the four pseudo-headers, once each"
                )
            }
            Self::DuplicateSetting(id) => write!(f, "duplicate SETTINGS id {id:#06x}"),
            Self::MaxFrameSizeOutOfRange(v) => write!(f, "MAX_FRAME_SIZE {v} out of range"),
            Self::InitialWindowTooLarge(v) => write!(f, "INITIAL_WINDOW_SIZE {v} > 2^31-1"),
            Self::EnablePushNotBoolean(v) => write!(f, "ENABLE_PUSH {v} not 0/1"),
            Self::WindowUpdateTooLarge(v) => write!(f, "WINDOW_UPDATE increment {v} too large"),
        }
    }
}

impl std::error::Error for InvalidH2Spec {}

/// Default initial connection flow-control window (RFC 7540 §6.9.2).
const DEFAULT_CONN_WINDOW: u32 = 65535;
/// Maximum flow-control window value (2^31 - 1).
const MAX_WINDOW: u32 = 0x7fff_ffff;

/// Validate the structural invariants a usable H2 fingerprint must satisfy.
pub fn validate(profile: &H2Profile) -> Result<(), InvalidH2Spec> {
    // Exactly the four pseudo-headers, each once (RFC 9113 §8.3).
    let (mut m, mut a, mut s, mut p) = (0u32, 0u32, 0u32, 0u32);
    for ph in &profile.pseudo_header_order {
        match ph {
            PseudoHeaderId::Method => m += 1,
            PseudoHeaderId::Authority => a += 1,
            PseudoHeaderId::Scheme => s += 1,
            PseudoHeaderId::Path => p += 1,
        }
    }
    if (m, a, s, p) != (1, 1, 1, 1) {
        return Err(InvalidH2Spec::PseudoHeaderOrderInvalid);
    }

    // SETTINGS: unique ids + RFC value ranges.
    let mut seen = std::collections::HashSet::new();
    for setting in &profile.settings {
        let id = setting.id.as_u16();
        if !seen.insert(id) {
            return Err(InvalidH2Spec::DuplicateSetting(id));
        }
        match id {
            0x02 if setting.value > 1 => {
                return Err(InvalidH2Spec::EnablePushNotBoolean(setting.value));
            }
            0x04 if setting.value > MAX_WINDOW => {
                return Err(InvalidH2Spec::InitialWindowTooLarge(setting.value));
            }
            0x05 if !(16384..=16_777_215).contains(&setting.value) => {
                return Err(InvalidH2Spec::MaxFrameSizeOutOfRange(setting.value));
            }
            _ => {}
        }
    }

    // The connection window after the WINDOW_UPDATE must stay <= 2^31-1.
    if profile.window_update > MAX_WINDOW - DEFAULT_CONN_WINDOW {
        return Err(InvalidH2Spec::WindowUpdateTooLarge(profile.window_update));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Recombination synthesizer
// ---------------------------------------------------------------------------

/// Inputs that bound what [`synthesize`] may produce for the H2 layer.
#[derive(Clone)]
pub struct H2Constraints {
    /// Real-browser H2 profiles to recombine from. One is chosen per call.
    pub bases: Vec<H2Profile>,
}

impl H2Constraints {
    /// Recombine from the shipped real-browser H2 presets.
    pub fn recombine() -> Self {
        use crate::profile as p;
        Self {
            bases: vec![
                p::chrome_131_h2(),
                p::chrome_144_h2(),
                p::chrome_145_h2(),
                p::chrome_146_h2(),
                p::chrome_147_h2(),
                p::chrome_148_h2(),
                p::chrome_149_h2(),
                p::firefox_133_h2(),
                p::firefox_147_h2(),
                p::safari_18_h2(),
                p::safari_26_h2(),
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

/// Synthesize a randomized [`H2Profile`] within `constraints`.
///
/// Recombine v1: pick a real base for the skeleton (priority config, behavior,
/// window update), then randomize the two ordered fingerprint dimensions that
/// are valid in any order — the pseudo-header order (all 24 permutations are
/// spec-valid) and the SETTINGS order. The result always passes [`validate`].
pub fn synthesize(rng: &mut impl RngCore, constraints: &H2Constraints) -> H2Profile {
    let base = &constraints.bases[(rng.next_u64() as usize) % constraints.bases.len()];
    let mut p = base.clone();
    shuffle(rng, &mut p.pseudo_header_order);
    shuffle(rng, &mut p.settings);
    p
}

/// `lo..=hi` inclusive, drawn from the caller's RNG.
fn rand_u32(rng: &mut impl RngCore, lo: u32, hi: u32) -> u32 {
    lo + (rng.next_u64() % (hi as u64 - lo as u64 + 1)) as u32
}

/// Synthesize a randomized [`H2Profile`] at the **Full** (Tier 3b) degree.
///
/// Starts from [`synthesize`] (real base + shuffled orders), then perturbs the
/// numeric SETTINGS **values** to novel, non-browser numbers within their valid
/// ranges. H2 SETTINGS are advertised (the peer adapts), never peer-selected, so
/// arbitrary in-range values stay negotiable — unlike a real browser's fixed
/// values, which is the point against negative-model targets. `ENABLE_PUSH` is
/// left as the base set it (changing whether we accept push is behavior, not a
/// passive fingerprint value). The result always passes [`validate`].
pub fn synthesize_full(rng: &mut impl RngCore, constraints: &H2Constraints) -> H2Profile {
    let mut p = synthesize(rng, constraints);
    for s in &mut p.settings {
        s.value = match s.id.as_u16() {
            0x01 => rand_u32(rng, 0, 65_536),          // HEADER_TABLE_SIZE
            0x03 => rand_u32(rng, 64, 1_024),          // MAX_CONCURRENT_STREAMS
            0x04 => rand_u32(rng, 65_535, 16_777_216), // INITIAL_WINDOW_SIZE (<= 2^31-1)
            0x05 => rand_u32(rng, 16_384, 65_536),     // MAX_FRAME_SIZE in [16384, 2^24-1]
            0x06 => rand_u32(rng, 16_384, 262_144),    // MAX_HEADER_LIST_SIZE
            _ => s.value,                              // ENABLE_PUSH / unknown / GREASE: keep
        };
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile as preset;

    fn all_h2_presets() -> Vec<(&'static str, H2Profile)> {
        vec![
            ("chrome_131_h2", preset::chrome_131_h2()),
            ("chrome_144_h2", preset::chrome_144_h2()),
            ("chrome_145_h2", preset::chrome_145_h2()),
            ("chrome_146_h2", preset::chrome_146_h2()),
            ("chrome_147_h2", preset::chrome_147_h2()),
            ("chrome_148_h2", preset::chrome_148_h2()),
            ("chrome_149_h2", preset::chrome_149_h2()),
            ("firefox_133_h2", preset::firefox_133_h2()),
            ("firefox_147_h2", preset::firefox_147_h2()),
            ("safari_18_h2", preset::safari_18_h2()),
            ("safari_26_h2", preset::safari_26_h2()),
        ]
    }

    /// Stable discriminant for a pseudo-header (PseudoHeaderId is not Hash).
    fn ph_code(ph: &PseudoHeaderId) -> u8 {
        match ph {
            PseudoHeaderId::Method => 0,
            PseudoHeaderId::Authority => 1,
            PseudoHeaderId::Scheme => 2,
            PseudoHeaderId::Path => 3,
        }
    }

    #[test]
    fn all_shipped_h2_presets_pass_validate() {
        for (name, p) in all_h2_presets() {
            assert!(validate(&p).is_ok(), "{name} failed: {:?}", validate(&p));
        }
    }

    #[test]
    fn rejects_incomplete_pseudo_header_order() {
        let mut p = preset::chrome_146_h2();
        p.pseudo_header_order.pop(); // now only 3
        assert_eq!(validate(&p), Err(InvalidH2Spec::PseudoHeaderOrderInvalid));
    }

    #[test]
    fn rejects_duplicate_pseudo_header() {
        let mut p = preset::chrome_146_h2();
        p.pseudo_header_order[0] = p.pseudo_header_order[1]; // duplicate
        assert_eq!(validate(&p), Err(InvalidH2Spec::PseudoHeaderOrderInvalid));
    }

    #[test]
    fn rejects_bad_max_frame_size() {
        use crate::profile::{H2Setting, H2SettingId};
        let mut p = preset::chrome_146_h2();
        p.settings.retain(|s| s.id != H2SettingId::MaxFrameSize);
        p.settings.push(H2Setting {
            id: H2SettingId::MaxFrameSize,
            value: 1024, // < 16384
        });
        assert_eq!(
            validate(&p),
            Err(InvalidH2Spec::MaxFrameSizeOutOfRange(1024))
        );
    }

    #[test]
    fn synthesize_recombine_is_always_valid_and_varied() {
        use rand_core::SeedableRng;
        let c = H2Constraints::recombine();
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
            let settings_order: Vec<u16> = p.settings.iter().map(|s| s.id.as_u16()).collect();
            let ph_order: Vec<u8> = p.pseudo_header_order.iter().map(ph_code).collect();
            distinct.insert((ph_order, settings_order));
        }
        assert!(distinct.len() > 20, "not varied: {}", distinct.len());
    }

    #[test]
    fn synthesize_is_deterministic_for_same_seed() {
        use rand_core::SeedableRng;
        let c = H2Constraints::recombine();
        let build = || {
            let mut rng = rand_chacha::ChaCha20Rng::from_seed([5u8; 32]);
            serde_json::to_string(&synthesize(&mut rng, &c)).unwrap()
        };
        assert_eq!(build(), build());
    }

    #[test]
    fn synthesize_full_is_valid_and_perturbs_values() {
        use rand_core::SeedableRng;
        let c = H2Constraints::recombine();
        let mut values = std::collections::HashSet::new();
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
            for s in &p.settings {
                values.insert((s.id.as_u16(), s.value));
            }
        }
        // Far more distinct (id, value) pairs than the handful of fixed values
        // the real presets carry — proving values are actually perturbed.
        assert!(values.len() > 50, "values not perturbed: {}", values.len());
    }
}
