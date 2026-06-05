# fpverify — fingerprint verification core & developer guide

`fpverify` is the **client-agnostic** byte-level fingerprint machinery used by
lkrequest's fingerprint-regression gate: canonical (normalized) fingerprint
types, the GREASE/shape normalizer, the per-profile shape spec, the shape-aware
comparator, and capture decoding.

> **Client-agnostic invariant — keep it extractable.** Everything here operates
> on *raw/parsed* fingerprint bytes (a parsed ClientHello, H2 frames, a QUIC
> Initial). It does **not** depend on `lkrequest` or any HTTP client, so the
> same tooling is reusable by any browser-emulation / anti-bot project. **Do not
> add an `lkrequest` dependency to this crate.** The lkrequest-specific gate
> (which emits lkrequest's own bytes and compares committed goldens) lives in
> `lkrequest/tests/` with `fpverify` as a dev-dependency.

This README is the **developer guide** for working on / verifying fingerprints.
It includes the current design rationale and test-tier policy for the tracked
checkout.

---

## 1. The verification model (three layers)

Each layer answers a different question. Use the right one for the change you
make.

| Layer | Where | Answers | Network / browser | When to run |
|------|-------|---------|-------------------|-------------|
| **A — offline gate** | `lkrequest/tests/fingerprint_regression.rs` | "Did the on-wire fingerprint change vs the frozen snapshot?" | none (Tier 0) | every change; CI |
| **B — real-browser** | `lkrequest/tests/b_layer_real_chrome.rs` | "Does the snapshot still equal a *real* Chrome?" | real Chrome + network (Tier 2, `#[ignore]`) | when you change a profile / add a version |
| **wire-level** | `lkrequest/tests/quic_local_e2e.rs`, `lktls` `shuffle_pins_grease_bookends_and_psk_last` | dimensions the canonical form folds away (GREASE *position*, PRIORITY_UPDATE / control-stream frames) | loopback only | when you touch those areas |

Why three layers? The A-layer and JA3/JA4 deliberately **normalize GREASE away**
(values *and* position) so a fingerprint stays matchable despite per-connection
randomization — which also makes them **blind** to GREASE-position and
control-stream-frame bugs. The wire-level tests cover exactly those blind spots;
the B-layer proves a (re)frozen snapshot is actually Chrome-shaped.

> **Mental model:** A-layer catches *"did it change"* (run always, blocks
> regressions). B-layer catches *"is it correct"* (run when changing a profile).
> `UPDATE_FINGERPRINTS=1` only **re-freezes** the snapshot — it is **not**
> verification. Correctness is proven by the B-layer.

---

## 2. Environment setup

Prerequisites:

```bash
# 1. Submodules are mandatory — deps/quinn and deps/h3 are patched forks
#    (branch `lkrequest-patches`) referenced by path.
git submodule update --init --recursive

# 2. NASM (for aws-lc-rs prebuilt paths). Linux CI also needs cmake + libclang:
#    apt-get install nasm cmake libclang-dev
#    Windows: install NASM and ensure it is on PATH.

# 3. Build the workspace (Tier 0, no network, no QUIC)
cargo build --workspace
```

Extra tooling, only for the layer you run:

- **B-layer (real Chrome):** a locally installed Chrome/Chromium. The
  `headless_chrome` crate locates it via `default_executable()`. No extra setup
  beyond having Chrome on the machine.
- **pcap debugging (optional):** `tshark`/Wireshark, used ad-hoc to inspect raw
  bytes. Note: QUIC needs `SSLKEYLOGFILE` to decrypt, and a host that does *not*
  route QUIC through a TCP-only proxy (a TUN proxy will force Chrome back to H2).
  For control-stream inspection a local instrumented H3 server (see §5) is more
  reliable than decrypting public traffic.
- **FFI work (unrelated to fpverify):** `cargo install cbindgen --locked`.

Shell on Windows is bash — use Unix paths/redirects.

---

## 3. Verify a fingerprint change

```bash
# ① Run the offline gate (add --features quic-h3 to include the QUIC/H3 gates).
cargo test -p lkrequest --features quic-h3 --test fingerprint_regression
```

- **Passes** → your change did not alter any gated wire fingerprint (or you
  added a preset not yet wired into the gate — see §4).
- **Fails** → it prints a per-field diff. Decide which case you are in:
  - **You did *not* intend to change the fingerprint** → this is a **regression**.
    Fix the code. Do **not** regenerate the golden.
  - **You *did* intend it** (new capture / profile update) → regenerate, then
    validate:

```bash
# ② Re-freeze the golden(s) to the new output. (Re-freeze ≠ verify.)
UPDATE_FINGERPRINTS=1 cargo test -p lkrequest --features quic-h3 --test fingerprint_regression

# ③ Prove the new golden matches a REAL Chrome (this is the actual verification).
TEST_ALLOW_NETWORK=1 cargo test -p lkrequest --features quic-h3 \
  --test b_layer_real_chrome -- --ignored --nocapture

# ④ If you touched GREASE / priority / control-stream emission, also run the
#    wire-level tests (the canonical gate is blind to these):
cargo test -p lkrequest --features quic-h3 --test quic_local_e2e
cargo test -p lktls shuffle_pins_grease
```

Goldens live in `lkrequest/tests/fixtures/fingerprints/`. Commit the regenerated
golden together with the code change.

---

## 4. Add a new browser / version (e.g. `chrome_149`)

1. Add the profile data: `lktls/profiles/*.json` + `lktls::profile::presets`,
   `lkh2::profile`, `lkh3` (capture it — see §5, don't hand-edit to pass tests).
2. Register it in the gate macros in `fingerprint_regression.rs`
   (`tls_gate!` / `h2_gate!` / `quic_gate!`).
3. `UPDATE_FINGERPRINTS=1 …` to mint its golden.
4. Run the **B-layer** to confirm it matches the real browser.
5. Commit goldens + code together.

---

## 5. Capturing ground truth

- **Profiles** are captured from real browsers with
  `tools/profile_collector` (headless Chrome →
  TLS/H2/QUIC capture → lkrequest preset export → field-level compare). This is
  how `lktls/profiles/*.json` are produced — recapture when the target browser
  version actually changes; never hand-edit a golden to make a test pass.
- **Control-stream / priority behaviour** (PRIORITY_UPDATE frames, the
  `priority` header, control-stream GREASE frame) is captured with a **local
  instrumented H3 server** that real Chrome is forced onto, so the server reads
  the decrypted frames directly:
  - Force H3: `--origin-to-force-quic-on=127.0.0.1:PORT` +
    `--ignore-certificate-errors-spki-list=<base64 SHA256 of the cert SPKI>`.
  - **Use `127.0.0.1`, not `localhost`** — `localhost` resolves to `::1`, an
    IPv4 server never sees the packets, and Chrome reports
    `ERR_QUIC_PROTOCOL_ERROR`.
  - This method is reusable per Chrome version (priority values shift across
    versions).

---

## 6. Library API (for reuse in another client)

```rust
use fpverify::{
    CanonicalTlsFingerprint, canonicalize_tls, TlsShapeSpec, diff_values,
};

// 1. Parse your client's emitted ClientHello into a CanonicalTlsFingerprint.
let canonical = CanonicalTlsFingerprint::from_parsed(&parsed_client_hello);

// 2. Pick a shape: fixed_order(), or shuffled(pinned_last) for browsers that
//    permute extensions (Chrome pins only pre_shared_key, 0x0029, last).
let shape = TlsShapeSpec::shuffled(vec![0x0029]);

// 3. Canonicalize (folds away per-connection GREASE + the permutation) and
//    serialize to a comparable JSON value, then diff against a golden.
let comparable = canonicalize_tls(&canonical, &shape);
let diffs = diff_values(&golden_json, &serde_json::to_value(&comparable)?);
assert!(diffs.is_empty());
```

Modules / exports:

- `canonical` — `CanonicalTlsFingerprint::from_parsed`, `tokenize`,
  `GREASE_TOKEN`, `CanonicalExtension`, `CanonicalExtSource`.
- `shape` — `TlsShapeSpec::{fixed_order, shuffled}`.
- `compare` — `canonicalize_tls`, `diff_tls`, `diff_values`, `diff_json`,
  `FieldDiff`.

`diff_values` / `diff_json` are generic JSON diffs, so the same compare/golden
workflow extends to H2 and QUIC fingerprints (as the lkrequest gate does).

---

## 7. Related Tracked Files

| Path | Purpose |
|------|---------|
| `tools/profile_collector` | Capture real-browser profiles & export presets |
| `tools/pcap_diff` | Diff two ClientHello byte streams (debug a failing FP test) |
| `lkrequest/tests/fingerprint_regression.rs` | A-layer offline gate (uses this crate) |
| `lkrequest/tests/b_layer_real_chrome.rs` | B-layer real-Chrome validation |
