//! Tier 2 (network): every synthetic (randomized) fingerprint the coordinator
//! materializes must be **capability-safe** — it has to actually negotiate a TLS
//! handshake and complete an HTTP round-trip against real, diverse server stacks.
//!
//! `recombine` (Tier 3a) and `full` (Tier 3b) both promise a result that is
//! "structurally valid and negotiable" (see `Randomize` docs); this test enforces
//! that promise across many random draws. A single out-of-capability combination
//! (e.g. a key-share group not in `supported_groups`, or a cipher the engine
//! can't drive) would show up here as a handshake failure.
//!
//! Success criterion = the request returned a response (**any** HTTP status)
//! without a transport/TLS error. We deliberately do NOT require 2xx: a synthetic
//! fingerprint matches no real browser, so an anti-bot edge may answer 403 — that
//! still proves the ClientHello negotiated, which is the invariant under test. A
//! transport/TLS `Err` (handshake failure, alert, reset) is the real failure.
//!
//! Gated: `#[ignore]` (Tier-2 convention) + `TEST_ALLOW_NETWORK=1`. Requires the
//! `synthetic-fp` feature. Tune the sample size with `SYNTH_FP_ITERS` (default 30).
#![cfg(feature = "synthetic-fp")]

use lkrequest::{preset, Client, Layers, NegotiabilityFloor, Randomize};

/// Diverse public server TLS stacks. Each random fingerprint is tested against
/// all of them so a stack-specific rejection of an odd ClientHello is caught.
const HOSTS: &[&str] = &[
    "https://example.com/",        // permissive / IANA
    "https://www.cloudflare.com/", // Cloudflare stack
    "https://www.google.com/",     // Google stack
];

fn network_enabled() -> bool {
    std::env::var("TEST_ALLOW_NETWORK").as_deref() == Ok("1")
}

fn iterations() -> usize {
    std::env::var("SYNTH_FP_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30)
}

/// Build N random-fingerprint sessions and probe each against every host.
/// Returns the list of failing draws (each entry carries the materialized
/// fingerprint that failed, for a seed-independent repro); an empty list means
/// every synthetic fingerprint negotiated. The caller asserts on the result so
/// the pass/fail invariant is explicit in each test body.
async fn probe_all_negotiate(label: &str, make_policy: impl Fn() -> Randomize) -> Vec<String> {
    let n = iterations();
    // One randomize-enabled client; each `session().build()` draws its own OS
    // seed and materializes a distinct capability-safe identity.
    let client = Client::builder()
        .preset(preset::chrome_146())
        .randomize(make_policy())
        .verify(true)
        .build();

    let mut failures: Vec<String> = Vec::new();
    let mut statuses: std::collections::BTreeMap<u16, usize> = std::collections::BTreeMap::new();
    let total = n * HOSTS.len();

    for i in 0..n {
        let session = client.session().build();
        // The identity this session actually presents — logged on failure so a
        // repro doesn't depend on the (not-yet-exposed) seed.
        let tls = session.client().tls_profile();
        let has_tls13_cipher = tls
            .cipher_suites
            .iter()
            .any(|&c| matches!(c, 0x1301..=0x1303));
        let fp = format!(
            "sigalgs={:04x?} groups={:?} keyshare={:?} tls13c={} ciphers={:04x?}",
            tls.signature_algorithms,
            tls.supported_groups,
            tls.key_share_curves,
            has_tls13_cipher,
            tls.cipher_suites,
        );

        for host in HOSTS {
            // Retry on the SAME session (same materialized fingerprint) to
            // separate a genuine fingerprint rejection (fails every attempt) from
            // a transient network blip (a retry succeeds).
            let mut last_err = String::new();
            let mut got: Option<u16> = None;
            for _ in 0..3 {
                match session.get(host).send().await {
                    Ok(resp) => {
                        got = Some(resp.status().as_u16());
                        break;
                    }
                    Err(e) => last_err = e.to_string(),
                }
            }
            match got {
                Some(code) => *statuses.entry(code).or_default() += 1,
                None => failures.push(format!("draw {i} → {host}: {last_err}\n    fp: {fp}")),
            }
        }
    }

    let ok = total - failures.len();
    println!("[{label}] {ok}/{total} negotiated; status tally: {statuses:?}");
    failures
}

/// Tier 3a — full recombination (TLS + H2 drawn from the real-preset corpus).
/// Every draw must negotiate: recombination stays inside engine capability.
#[tokio::test]
#[ignore = "Tier-2: network; run with TEST_ALLOW_NETWORK=1"]
async fn recombine_fingerprints_all_negotiate() {
    if !network_enabled() {
        eprintln!("skipped: set TEST_ALLOW_NETWORK=1 to run");
        return;
    }
    let failures = probe_all_negotiate("recombine (3a, TLS+H2)", Randomize::recombine).await;
    assert!(
        failures.is_empty(),
        "{} synthetic fingerprint(s) failed to negotiate:\n{}",
        failures.len(),
        failures.join("\n"),
    );
}

/// Tier 3b — full: advertise-only layers (H2 SETTINGS) additionally take novel
/// out-of-corpus values. The negotiated TLS parameters stay capability-safe, so
/// this must still negotiate everywhere.
#[tokio::test]
#[ignore = "Tier-2: network; run with TEST_ALLOW_NETWORK=1"]
async fn full_fingerprints_all_negotiate() {
    if !network_enabled() {
        eprintln!("skipped: set TEST_ALLOW_NETWORK=1 to run");
        return;
    }
    let failures = probe_all_negotiate("full (3b, novel advertise-only)", Randomize::full).await;
    assert!(
        failures.is_empty(),
        "{} synthetic fingerprint(s) failed to negotiate:\n{}",
        failures.len(),
        failures.join("\n"),
    );
}

/// TLS-only recombination (H2 kept as the real Chrome preset) — isolates whether
/// a synthetic ClientHello *by itself* negotiates, independent of the H2 layer.
#[tokio::test]
#[ignore = "Tier-2: network; run with TEST_ALLOW_NETWORK=1"]
async fn recombine_tls_only_fingerprints_all_negotiate() {
    if !network_enabled() {
        eprintln!("skipped: set TEST_ALLOW_NETWORK=1 to run");
        return;
    }
    let failures = probe_all_negotiate("recombine TLS-only", || {
        Randomize::recombine_layers(Layers::TLS)
    })
    .await;
    assert!(
        failures.is_empty(),
        "{} synthetic fingerprint(s) failed to negotiate:\n{}",
        failures.len(),
        failures.join("\n"),
    );
}

/// The `PresetFamily` negotiability floor (keeps the base preset's real sig algs
/// for browser-plausibility) must also negotiate everywhere — and this exercises
/// the `negotiability()` builder threading end to end.
#[tokio::test]
#[ignore = "Tier-2: network; run with TEST_ALLOW_NETWORK=1"]
async fn recombine_preset_family_floor_negotiates() {
    if !network_enabled() {
        eprintln!("skipped: set TEST_ALLOW_NETWORK=1 to run");
        return;
    }
    let failures = probe_all_negotiate("recombine + PresetFamily floor", || {
        Randomize::recombine().negotiability(NegotiabilityFloor::PresetFamily)
    })
    .await;
    assert!(
        failures.is_empty(),
        "{} synthetic fingerprint(s) failed to negotiate:\n{}",
        failures.len(),
        failures.join("\n"),
    );
}
