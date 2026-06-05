# Contributing to lkrequest

Thanks for your interest in contributing! `lkrequest` is a Rust HTTP client
workspace focused on **byte-level fingerprint control** of TLS, HTTP/2, and
HTTP/3/QUIC, plus a stable C ABI (`lkrequest-ffi`). Because the core invariant
is "match a specific browser's wire format exactly," changes that improve
abstract correctness but diverge from real browser output on the wire are
considered regressions. Keep that in mind throughout.

By contributing, you agree that your contributions will be licensed under the
project's Apache-2.0 license in `LICENSE.txt`. Please also review the
responsible-use expectations in `SECURITY.md`.

## Prerequisites

### Git submodules are MANDATORY

`deps/quinn` and `deps/h3` are **patched forks** (branch `lkrequest-patches`),
excluded from the workspace and referenced via path dependencies. **The build
will fail without them.**

```bash
# When cloning:
git clone --recurse-submodules <repo-url>

# If you already cloned without submodules:
git submodule update --init --recursive

# To update to the latest patches:
git submodule update --remote
```

Do **not** edit files inside `deps/quinn` or `deps/h3` from this repository
unless you are deliberately upstreaming a patch to the `lkrequest-patches`
branch. Otherwise, make the change in `lkh3` / `lkquic` / `lktls-quic` instead.

### Build dependencies

- **NASM** is required for the `aws-lc-rs` prebuilt assembly paths.
  - On Debian/Ubuntu CI: `apt-get install nasm cmake libclang-dev`
  - On Windows this typically works out of the box.
- **`cbindgen`** is required whenever you touch the FFI layer:
  `cargo install cbindgen --locked`
- Async runtime is **Tokio**. Rust edition 2021+ (some crates use 2024).

## Building & Testing

### Test tiers

The test suite is organized into tiers:

- **Tier 0 (default CI):** only `127.0.0.1`/`::1` or in-memory servers. This
  must stay green with **no network access**:
  ```bash
  cargo test --workspace
  ```
- **Tier 1:** local Docker / TLS-Attacker / mitmproxy — run manually, not in
  default CI.
- **Tier 2 (public network):** always `#[ignore]`d by default. By convention,
  set `TEST_ALLOW_NETWORK=1` (and optionally `TEST_PROXY=http://…`) before
  running:
  ```bash
  TEST_ALLOW_NETWORK=1 cargo test --workspace -- --include-ignored
  ```

### QUIC / HTTP/3 (`quic-h3` feature)

HTTP/3 + QUIC is gated behind the `quic-h3` feature and is **off by default**.
QUIC tests live behind `required-features = ["quic-h3"]`:

```bash
cargo test -p lkrequest --features quic-h3
```

The `network-e2e` feature additionally compiles public-network integration
helpers (e.g. `quic_network_e2e.rs`).

### FFI (`lkrequest-ffi`)

The public C header `lkrequest-ffi/include/lkrequest.h` is **not committed** —
`build.rs` regenerates it from the FFI export surface via `cbindgen` on every
build, and it is git-ignored. The Rust crate builds without `cbindgen`
(generation is skipped with a warning), so you only need `cbindgen` installed
when you want to produce the header locally:

```bash
# Refresh the header manually (otherwise any `cargo build` regenerates it):
cd lkrequest-ffi && cbindgen . --config cbindgen.toml > include/lkrequest.h

# Verify the FFI layer after changing the export surface:
cargo test -p lkrequest-ffi
cargo clippy -p lkrequest-ffi --all-targets --all-features -- -D warnings
```

FFI integration tests are sharded by concern — keep new tests in the matching
shard.

### Lint & format gates

CI runs with `-D warnings`. Before opening a PR, make sure both pass:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

## Fingerprint golden files

`lktls/profiles/*.json` are golden-file profiles captured from real browsers via
`tools/profile_collector`. **Do not hand-edit them to make a test pass.** If a
fingerprint test fails:

- Use `tools/pcap_diff` to diff the two ClientHello byte streams and understand
  the divergence.
- If the target browser version genuinely changed, **recapture** the profile
  with `tools/profile_collector` rather than editing the JSON by hand.

Golden fingerprints must not regress — matching the real browser on the wire is
the whole point.

## Pull Request Process

1. **Fork & branch.** Create a topic branch from the appropriate base branch.
2. **Make focused changes.** Edits generally belong in the **highest** layer of
   the workspace that can express the change. Keep PRs scoped to one concern.
3. **Run the gates locally:**
   - `cargo test --workspace` (Tier 0)
   - `cargo test -p lkrequest --features quic-h3` if you touched QUIC/H3
   - `cargo fmt --all -- --check`
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - If you touched FFI: `cargo test -p lkrequest-ffi`,
     `cargo clippy -p lkrequest-ffi --all-targets --all-features -- -D warnings`,
     and regenerate `lkrequest-ffi/include/lkrequest.h` locally if you need to
     inspect the ABI output.
4. **Add tests** for new behavior, respecting the tier conventions (Tier-2
   network tests must be `#[ignore]`d).
5. **Update docs** (`README.md`, crate README files, doc comments) when you change
   user-facing behavior.
6. **Open the PR** with a clear description of what changed and why, and note
   any fingerprint-affecting changes explicitly so reviewers can verify wire
   format.

## Reporting Bugs & Security Issues

- For **non-security** bugs and feature requests, open a GitHub issue with
  reproduction steps and environment details.
- For **security vulnerabilities**, do **not** open a public issue — follow the
  private disclosure process described in `SECURITY.md`.
