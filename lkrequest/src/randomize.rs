//! Fingerprint randomization policy.
//!
//! Selects *how much* of the client fingerprint varies and *toward what*
//! (real vs synthetic). The **scope** at which a given dimension varies
//! (per-session identity vs per-connection jitter) is derived automatically
//! from wire timing — it is not a free user choice. See the tier list below
//! for the full model.
//!
//! Construct a policy with a named tier and pass it to
//! [`ClientBuilder::randomize`](crate::client::ClientBuilder::randomize):
//!
//! ```rust
//! use lkrequest::{Client, Randomize};
//!
//! // Force Chrome-style per-connection extension-order jitter on.
//! let client = Client::builder()
//!     .randomize(Randomize::extension_order())
//!     .build();
//! ```
//!
//! ## Tiers
//!
//! Always available:
//!
//! - [`Randomize::off`] — **Tier 0**: emit the preset's fingerprint as-is (the
//!   preset's own authentic per-connection behavior, e.g. Chrome's native
//!   extension shuffle, still applies — `off` adds nothing on top).
//! - [`Randomize::extension_order`] — **Tier 1**: force per-connection
//!   extension-order permutation (BoringSSL-style; GREASE bookends pinned,
//!   `pre_shared_key` last). Drifts JA3 per connection **while staying a real
//!   browser**; JA4 is unaffected (it sorts extensions). This is the *safe*
//!   single-layer (TLS-only) option — it never produces a non-browser shape.
//!
//! Behind the off-by-default **`synthetic-fp`** feature (these synthesize
//! fingerprints that match *no* real browser — an escape hatch for
//! negative-model / blocklist targets only; against an allowlist they fail
//! instantly):
//!
//! - [`Randomize::recombine`] — **Tier 3a**: one novel-but-capability-safe
//!   identity per session, recombined from the real-preset corpus across **all**
//!   layers (TLS + H2 + H3). [`Randomize::recombine_layers`] restricts it to a
//!   [`Layers`] subset.
//! - [`Randomize::full`] — **Tier 3b**: the widest synthesis — like recombine,
//!   but the advertise-only layers (H2 SETTINGS, QUIC transport-param values)
//!   additionally take novel out-of-corpus numbers. [`Randomize::full_layers`]
//!   restricts it to a [`Layers`] subset.
//!
//! ### "No layer left constant"
//!
//! `recombine`/`full` synthesize **every** layer by default. Half-synthesis (a
//! novel TLS fingerprint next to an unchanged Chrome H2 profile) is itself an
//! anomalous combination, easier to flag than full synthesis — so the per-layer
//! [`Layers`] variants are a deliberate opt-in, not the default.
//!
//! ```rust
//! # #[cfg(feature = "synthetic-fp")] {
//! use lkrequest::{Client, Randomize, Layers};
//!
//! // A fresh synthetic identity per session, all layers (the safe default).
//! let client = Client::builder()
//!     .randomize(Randomize::recombine())
//!     .build();
//!
//! // Widest divergence (novel H2/QUIC values too), all layers.
//! let client = Client::builder()
//!     .randomize(Randomize::full())
//!     .build();
//!
//! // Deliberate subset: synthesize only TLS, keep the real H2/H3 preset.
//! let client = Client::builder()
//!     .randomize(Randomize::recombine_layers(Layers::TLS))
//!     .build();
//!
//! // Synthesize TLS + H2 together (compose any subset with `|`).
//! let client = Client::builder()
//!     .randomize(Randomize::recombine_layers(Layers::TLS | Layers::H2))
//!     .build();
//! # }
//! ```
//!
//! Each session draws its own seed, so two sessions from the same synthetic
//! client present different (but each internally consistent) fingerprints; a
//! synthetic session also gets its own TLS/QUIC ticket cache so resuming cannot
//! link two identities. Per-connection randomness (GREASE values, key shares)
//! stays random on top — as in a real browser — it is intentionally **not**
//! seed-derived.

/// Which randomization tier a [`Randomize`] policy selects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RandomizeMode {
    /// Tier 0 — no added randomization.
    Off,
    /// Tier 1 — per-connection extension-order permutation.
    ExtensionOrder,
    /// Tier 3a — synthetic recombination of the selected layers (per-session
    /// identity). Only present with the `synthetic-fp` feature.
    #[cfg(feature = "synthetic-fp")]
    Recombine(Layers),
    /// Tier 3b — like [`Recombine`](Self::Recombine), but the advertise-only
    /// layers (H2 SETTINGS, QUIC transport params) additionally take novel
    /// out-of-corpus values. Only present with the `synthetic-fp` feature.
    #[cfg(feature = "synthetic-fp")]
    Full(Layers),
}

#[cfg(feature = "synthetic-fp")]
bitflags::bitflags! {
    /// Which fingerprint layers a synthetic ([`Randomize::recombine_layers`])
    /// policy synthesizes. Layers not selected keep the client's real preset.
    ///
    /// [`Layers::all`] is the safe default ("no layer left constant"); selecting
    /// a subset is a deliberate trade-off — see [`Randomize::recombine_layers`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Layers: u8 {
        /// The TLS ClientHello (JA3/JA4); also drives the QUIC-native TLS.
        const TLS = 0b001;
        /// The HTTP/2 fingerprint (SETTINGS + pseudo-header order).
        const H2 = 0b010;
        /// The QUIC transport params + HTTP/3 fingerprint (needs `quic-h3`).
        const QUIC = 0b100;
    }
}

/// A fingerprint randomization policy.
///
/// Build one with a named tier constructor ([`Randomize::off`],
/// [`Randomize::extension_order`]) and hand it to
/// [`ClientBuilder::randomize`](crate::client::ClientBuilder::randomize).
#[derive(Clone, Debug)]
pub struct Randomize {
    mode: RandomizeMode,
}

impl Randomize {
    /// Tier 0 — no added randomization. The preset's own authentic behavior
    /// (e.g. Chrome's native extension shuffle) still applies; this adds nothing.
    pub fn off() -> Self {
        Self {
            mode: RandomizeMode::Off,
        }
    }

    /// Tier 1 — force per-connection extension-order permutation.
    ///
    /// Applies a BoringSSL-style Fisher–Yates shuffle to the real extensions on
    /// each new handshake (GREASE bookends stay pinned, `pre_shared_key` stays
    /// last). This drifts JA3 per connection while remaining a real browser —
    /// useful against per-JA3 blocklists / rate-limits. JA4 is unaffected (it
    /// sorts extensions).
    pub fn extension_order() -> Self {
        Self {
            mode: RandomizeMode::ExtensionOrder,
        }
    }

    /// Tier 3a — synthetic recombination across **all** layers (TLS + H2), one
    /// novel-but-capability-safe identity per session.
    ///
    /// Components are drawn from the real-preset corpus intersected with engine
    /// capability, so the result is structurally valid and negotiable but
    /// matches no real browser. Use only against negative-model (blocklist)
    /// targets — against an allowlist this is instant failure.
    ///
    /// Requires the `synthetic-fp` cargo feature.
    #[cfg(feature = "synthetic-fp")]
    pub fn recombine() -> Self {
        Self::recombine_layers(Layers::all())
    }

    /// Tier 3a restricted to specific layers — synthesize only the selected
    /// fingerprint layers; unselected layers keep the client's real preset.
    ///
    /// [`recombine`](Self::recombine) is the safe default ([`Layers::all`] — no
    /// layer left constant). Selecting a subset is a deliberate trade-off: a
    /// synthesized layer paired with constant real-browser layers (e.g. a novel
    /// TLS fingerprint next to an unchanged Chrome H2 profile) is itself an
    /// anomalous combination, easier to flag than full synthesis. Use only when
    /// the target is known to fingerprint just those layers.
    ///
    /// ```rust
    /// use lkrequest::{Randomize, Layers};
    /// // Synthesize only TLS; keep the real H2/H3 preset.
    /// let p = Randomize::recombine_layers(Layers::TLS);
    /// // Synthesize TLS + H2 together.
    /// let p = Randomize::recombine_layers(Layers::TLS | Layers::H2);
    /// ```
    #[cfg(feature = "synthetic-fp")]
    pub fn recombine_layers(layers: Layers) -> Self {
        Self {
            mode: RandomizeMode::Recombine(layers),
        }
    }

    /// Tier 3b — the widest synthesis: like [`recombine`](Self::recombine), but
    /// the advertise-only layers (H2 SETTINGS values, QUIC transport-parameter
    /// values) additionally take **novel out-of-corpus numbers** rather than
    /// real-browser values.
    ///
    /// The TLS layer is the same as `recombine`: the engine implements only a
    /// few TLS 1.3 ciphers + key-exchange groups and the preset corpus already
    /// spans the full 1.2-cipher / signature space, so `recombine` already
    /// explores TLS's entire negotiable fingerprint space. Full's extra
    /// divergence therefore comes from the H2/QUIC value layers.
    ///
    /// Maximally divergent from any real browser — use only against
    /// negative-model (blocklist) targets.
    #[cfg(feature = "synthetic-fp")]
    pub fn full() -> Self {
        Self::full_layers(Layers::all())
    }

    /// [`full`](Self::full) restricted to specific layers — see
    /// [`recombine_layers`](Self::recombine_layers) for the per-layer trade-off.
    /// Note that `Layers::TLS` alone behaves identically to
    /// `recombine_layers(Layers::TLS)` (TLS has no wider degree).
    #[cfg(feature = "synthetic-fp")]
    pub fn full_layers(layers: Layers) -> Self {
        Self {
            mode: RandomizeMode::Full(layers),
        }
    }

    pub(crate) fn mode(&self) -> RandomizeMode {
        self.mode
    }
}

impl Default for Randomize {
    fn default() -> Self {
        Self::off()
    }
}

/// A synthesized cross-layer fingerprint identity (one per session).
///
/// Every fingerprintable layer is resolved together from a single seed so the
/// identity is internally consistent ("no layer left constant") — a novel TLS
/// fingerprint is never paired with a constant real-browser H2 fingerprint.
#[cfg(feature = "synthetic-fp")]
#[derive(Clone)]
pub struct FingerprintIdentity {
    /// Synthesized TLS profile (ClientHello). Reused as the QUIC-native TLS
    /// fingerprint too, so the QUIC handshake stays consistent with the TCP one.
    pub tls: lktls::profile::TlsProfile,
    /// Synthesized HTTP/2 profile.
    pub h2: lkh2::H2Profile,
    /// Synthesized QUIC + HTTP/3 profile (transport params + H3). Only present
    /// with the `quic-h3` feature; applied only when the client enables QUIC.
    #[cfg(feature = "quic-h3")]
    pub quic: Option<lkh3::QuicProfile>,
}

/// Resolve a per-session [`FingerprintIdentity`] from a 32-byte seed.
///
/// The coordinator: feed **one** seeded RNG through both layers' synthesizers in
/// sequence, so all layers derive from the same seed and the whole identity is a
/// single reproducible draw (same seed ⇒ identical identity). Each layer's
/// output is capability-safe and passes its own `validate` by construction.
#[cfg(feature = "synthetic-fp")]
pub fn resolve_recombine_identity(seed: [u8; 32]) -> FingerprintIdentity {
    resolve_identity(seed, Degree::Recombine)
}

/// Resolve a per-session [`FingerprintIdentity`] at the **Full** (Tier 3b)
/// degree: the advertise-only H2/QUIC layers take novel out-of-corpus values.
///
/// The TLS layer is identical to [`resolve_recombine_identity`] — see
/// [`Randomize::full`] for why TLS has no wider degree.
#[cfg(feature = "synthetic-fp")]
pub fn resolve_full_identity(seed: [u8; 32]) -> FingerprintIdentity {
    resolve_identity(seed, Degree::Full)
}

/// Synthesis degree: how far the per-layer synthesizers stray from real values.
#[cfg(feature = "synthetic-fp")]
#[derive(Clone, Copy)]
enum Degree {
    /// Tier 3a — recombine from real-browser corpus values.
    Recombine,
    /// Tier 3b — additionally perturb advertise-only values out of corpus.
    Full,
}

#[cfg(feature = "synthetic-fp")]
fn resolve_identity(seed: [u8; 32], degree: Degree) -> FingerprintIdentity {
    use rand_core::SeedableRng;
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    // Fixed RNG consumption order; QUIC drawn last so the TLS and H2 draws are
    // identical whether or not `quic-h3` is compiled in.
    let tls = lktls::profile::synthesis::synthesize(
        &mut rng,
        &lktls::profile::synthesis::Constraints::recombine(),
    );
    let h2c = lkh2::synthesis::H2Constraints::recombine();
    let h2 = match degree {
        Degree::Recombine => lkh2::synthesis::synthesize(&mut rng, &h2c),
        Degree::Full => lkh2::synthesis::synthesize_full(&mut rng, &h2c),
    };
    #[cfg(feature = "quic-h3")]
    let quic = {
        let qc = lkh3::synthesis::QuicConstraints::recombine();
        Some(match degree {
            Degree::Recombine => lkh3::synthesis::synthesize(&mut rng, &qc),
            Degree::Full => lkh3::synthesis::synthesize_full(&mut rng, &qc),
        })
    };
    FingerprintIdentity {
        tls,
        h2,
        #[cfg(feature = "quic-h3")]
        quic,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_off() {
        assert_eq!(Randomize::default().mode(), RandomizeMode::Off);
        assert_eq!(Randomize::off().mode(), RandomizeMode::Off);
    }

    #[test]
    fn extension_order_selects_tier1() {
        assert_eq!(
            Randomize::extension_order().mode(),
            RandomizeMode::ExtensionOrder
        );
    }

    #[cfg(feature = "synthetic-fp")]
    #[test]
    fn recombine_selects_tier3a() {
        assert!(matches!(
            Randomize::recombine().mode(),
            RandomizeMode::Recombine(l) if l == Layers::all()
        ));
        assert!(matches!(
            Randomize::recombine_layers(Layers::TLS).mode(),
            RandomizeMode::Recombine(l) if l == Layers::TLS
        ));
    }

    #[cfg(feature = "synthetic-fp")]
    #[test]
    fn full_selects_tier3b() {
        assert!(matches!(
            Randomize::full().mode(),
            RandomizeMode::Full(l) if l == Layers::all()
        ));
        assert!(matches!(
            Randomize::full_layers(Layers::H2).mode(),
            RandomizeMode::Full(l) if l == Layers::H2
        ));
    }

    /// The coordinator: one seed → a consistent, valid, reproducible identity
    /// across both layers; different seeds vary.
    #[cfg(feature = "synthetic-fp")]
    #[test]
    fn recombine_identity_is_consistent_valid_and_reproducible() {
        let mut tls_sigs = std::collections::HashSet::new();
        let mut h2_sigs = std::collections::HashSet::new();
        for s in 0u8..50 {
            let id = resolve_recombine_identity([s; 32]);
            // Both layers valid by their own oracle.
            assert!(
                lktls::profile::synthesis::validate(&id.tls).is_ok(),
                "seed {s}: TLS invalid"
            );
            assert!(
                lkh2::synthesis::validate(&id.h2).is_ok(),
                "seed {s}: H2 invalid"
            );
            // Reproducible: same seed → identical identity (both layers).
            let again = resolve_recombine_identity([s; 32]);
            assert_eq!(
                serde_json::to_string(&id.tls).unwrap(),
                serde_json::to_string(&again.tls).unwrap()
            );
            assert_eq!(
                serde_json::to_string(&id.h2).unwrap(),
                serde_json::to_string(&again.h2).unwrap()
            );
            tls_sigs.insert(id.tls.cipher_suites.clone());
            h2_sigs.insert(
                id.h2
                    .settings
                    .iter()
                    .map(|x| x.id.as_u16())
                    .collect::<Vec<_>>(),
            );
        }
        // Both layers actually vary across seeds.
        assert!(tls_sigs.len() > 5, "TLS not varied: {}", tls_sigs.len());
        assert!(h2_sigs.len() > 3, "H2 not varied: {}", h2_sigs.len());
    }

    /// Full-degree identities are valid + reproducible per seed, and their H2
    /// values actually diverge from the recombine degree (out-of-corpus
    /// perturbation) for the same seed.
    #[cfg(feature = "synthetic-fp")]
    #[test]
    fn full_identity_is_valid_reproducible_and_diverges_from_recombine() {
        let mut diverged = false;
        for s in 0u8..50 {
            let full = resolve_full_identity([s; 32]);
            assert!(
                lktls::profile::synthesis::validate(&full.tls).is_ok(),
                "seed {s}: TLS invalid"
            );
            assert!(
                lkh2::synthesis::validate(&full.h2).is_ok(),
                "seed {s}: H2 invalid"
            );
            // Reproducible: same seed → identical H2.
            let again = resolve_full_identity([s; 32]);
            assert_eq!(
                serde_json::to_string(&full.h2).unwrap(),
                serde_json::to_string(&again.h2).unwrap()
            );
            // Full perturbs H2 values, so it generally differs from recombine.
            let recomb = resolve_recombine_identity([s; 32]);
            if serde_json::to_string(&full.h2).unwrap()
                != serde_json::to_string(&recomb.h2).unwrap()
            {
                diverged = true;
            }
        }
        assert!(diverged, "Full never diverged from recombine on H2");
    }

    /// Under `quic-h3` the coordinator also synthesizes a valid, varied,
    /// reproducible QUIC layer from the same seed — no layer left constant.
    #[cfg(all(feature = "synthetic-fp", feature = "quic-h3"))]
    #[test]
    fn recombine_identity_quic_layer_is_valid_and_varied() {
        let mut quic_sigs = std::collections::HashSet::new();
        for s in 0u8..50 {
            let id = resolve_recombine_identity([s; 32]);
            let quic = id.quic.expect("quic-h3 build synthesizes a QUIC profile");
            assert!(
                lkh3::synthesis::validate(&quic).is_ok(),
                "seed {s}: QUIC invalid"
            );
            let again = resolve_recombine_identity([s; 32]).quic.unwrap();
            assert_eq!(
                serde_json::to_string(&quic).unwrap(),
                serde_json::to_string(&again).unwrap()
            );
            quic_sigs.insert((
                quic.h3.settings.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
                quic.h3.pseudo_header_order_token(),
            ));
        }
        assert!(quic_sigs.len() > 3, "QUIC not varied: {}", quic_sigs.len());
    }
}
