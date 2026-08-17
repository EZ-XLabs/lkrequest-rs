# lkrequest

<p align="center">
  <strong>Byte-level browser fingerprint control for Rust HTTP clients.</strong>
</p>

<p align="center">
  <a href="README-zh.md">简体中文</a> ·
  <a href="CONTRIBUTING.md">Contributing</a> ·
  <a href="SECURITY.md">Security</a> ·
  <a href="LICENSE.txt">Apache-2.0</a>
</p>

<p align="center">
  <img alt="Version 0.2.1" src="https://img.shields.io/badge/version-0.2.1-4c1.svg">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-2021%2B-orange.svg">
  <img alt="TLS" src="https://img.shields.io/badge/TLS-byte--level-blue.svg">
  <img alt="HTTP/3" src="https://img.shields.io/badge/HTTP%2F3-optional-5c2d91.svg">
  <img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg">
</p>


`lkrequest` is a Rust HTTP client workspace for **wire-level control** of TLS, HTTP/2, and HTTP/3/QUIC fingerprints. It is built for browser-protocol research, interoperability testing, fingerprint verification, and controlled automation where ordinary high-level HTTP clients do not expose enough of the wire format.

The core invariant is simple: **a browser preset should match the target browser on the wire**. Changes that are abstractly valid but diverge from real browser output are treated as regressions.

> [!IMPORTANT]
> This is a source-first workspace and currently depends on patched `quinn` and `h3` git submodules. Clone with submodules before building.

> [!WARNING]
> Use this project only on systems and targets you are authorized to test. See [Security and responsible use](SECURITY.md).

## Highlights

- **TLS ClientHello control** — extension ordering, GREASE, cipher suites, signature algorithms, key shares, ECH, ALPS, certificate compression, and handshake behavior.
- **Native HTTP/2 fingerprinting** — SETTINGS order, WINDOW_UPDATE, PRIORITY, pseudo-header order, HPACK behavior, and request priority.
- **HTTP/3 and QUIC** — optional H3 stack with QUIC Transport Parameters, QPACK settings, PRIORITY_UPDATE, Alt-Svc discovery, session resumption, and SOCKS5 UDP support.
- **Capture-backed browser presets** — Chrome 131 and 144–151, Firefox 133/147, and Safari 18/26.
- **Browser-like sessions** — isolated cookie jars, physically bounded connection pools, H2 stream backpressure, redirects, retries, decompression, streaming, WebSocket, system-DNS singleflight with optional positive caching, and HSTS policies.
- **Proxy orchestration** — HTTP CONNECT, SOCKS5, multi-hop proxy chains, resolved-address fallback, `ProxyPool`, and `SessionPool`.
- **Stable C ABI** — `lkrequest-ffi` mirrors the Rust Client/Session/Request model for other languages.
- **Offline regression gates** — serialized TLS/H2/QUIC fingerprints are checked against committed golden fixtures.

## Project Status

- Current workspace release: **0.2.1**.
- The public API is usable but still evolving before 1.0.
- The repository is currently consumed **from source**; examples below use a local checkout.
- HTTP/3, synthetic fingerprints, telemetry, and public-network tests are opt-in features.
- Real-browser fidelity is version-, platform-, Finch-, GREASE-, and request-context-sensitive. Preset documentation distinguishes captured stable fields from variable behavior.

## Quick Start

### 1. Clone and build

Git submodules are mandatory because `deps/quinn` and `deps/h3` contain the patched transport behavior used by the workspace.

```bash
git clone --recurse-submodules <repository-url>
cd lkrequest
cargo test --workspace
```

If the repository was cloned without submodules:

```bash
git submodule update --init --recursive
```

Build requirements:

- Rust toolchain with Cargo.
- NASM, CMake, and libclang where required by the crypto toolchain.
- `cbindgen` only when generating or changing the C header.

### 2. Use the local crate

From another Rust project:

```toml
[dependencies]
lkrequest = { path = "../lkrequest/lkrequest" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

For HTTP/3:

```toml
lkrequest = { path = "../lkrequest/lkrequest", features = ["quic-h3"] }
```

### 3. Send a request with an explicit browser preset

```rust
use lkrequest::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder()
        .preset(lkrequest::preset::chrome_151())
        .build();

    // A Session represents one virtual browser user: cookies and connections
    // are isolated from other sessions.
    let session = client.session().build();
    let response = session
        .get("https://example.com/")
        .send()
        .await?;

    println!("{}", response.status());
    println!("{}", response.text()?);
    Ok(())
}
```

Run the repository example:

```bash
cargo run -p lkrequest --example basic_get
```

## HTTP/3 and QUIC

Enable the `quic-h3` feature, then choose an explicit protocol policy:

```rust
use lkrequest::Client;

let client = Client::builder()
    .preset(lkrequest::preset::chrome_151())
    .build();

// Prefer H3 and fall back to H2 when QUIC is unavailable.
let session = client.session().http3_with_fallback().build();
```

Common modes:

| Mode | API | Behavior |
|---|---|---|
| Browser-style | default preset policy | Uses discovery and per-origin QUIC failure tracking |
| H3 only | `http3_only()` | No TCP fallback |
| H3 with fallback | `http3_with_fallback()` | Prefer H3, fall back to H2 |
| H2 only | `http2_only()` | Require HTTP/2 over TCP |

```bash
cargo run -p lkrequest --features quic-h3 --example basic_h3
cargo run -p lkrequest --features quic-h3 --example h3_auto_discovery
cargo run -p lkrequest --features quic-h3 --example h3_session_resumption
```

## Browser Presets

The high-level presets bundle TLS, H2, optional QUIC/H3, protocol policy, and header ordering:

| Family | Presets |
|---|---|
| Chrome | `chrome_131`, `chrome_144`–`chrome_151` |
| Firefox | `firefox_133`, `firefox_147` |
| Safari | `safari_18`, `safari_26` |

Use explicit versions for reproducible behavior:

```rust
let client = lkrequest::Client::builder()
    .preset(lkrequest::preset::chrome_151())
    .build();
```

Chrome 151 is capture-verified on Windows. Its TCP TLS/H2 stable fields match Chrome 150, while real public-site QUIC captures use the classic QUIC signature-algorithm list plus `rsa_pkcs1_sha1` without the three TCP ML-DSA entries.

## Capability Matrix

| Capability | Default | Feature / crate |
|---|---:|---|
| HTTP/1.1 | Yes | `lkrequest` |
| Native fingerprintable HTTP/2 | Yes | `h2-native` |
| HTTP/3 + QUIC | No | `quic-h3` |
| Public-network E2E helpers | No | `network-e2e` |
| Synthetic fingerprint generation | No | `synthetic-fp` |
| Operational telemetry | No | `telemetry` |
| C ABI | Separate crate | `lkrequest-ffi` |

Synthetic modes intentionally produce fingerprints that do not correspond to a captured browser. They are not substitutes for browser presets and should not be used where allowlist identity is expected.

TLS 1.2 and TLS 1.3 servers that request, but do not require, a client certificate are supported: `lkrequest` sends an empty client `Certificate` with the correct handshake context. Configuring an explicit client identity for mutual TLS is not yet part of the public API.

## Proxy, DNS, and Session Pools

Supported proxy paths:

- HTTP CONNECT and SOCKS5 for TCP protocols.
- SOCKS5 UDP for QUIC/H3.
- Multi-hop proxy chains; QUIC chains require every hop to support SOCKS5 UDP.
- Direct TCP and SOCKS5 connection setup try resolved addresses in resolver order, so one unreachable IPv4 or IPv6 candidate does not abort the route.
- `ProxyPool` for proxy allocation and concurrency control.
- `SessionPool` for reusable virtual-browser sessions.
### System DNS concurrency and caching

The default `SystemDns` resolver delegates to the operating system and automatically coalesces simultaneous lookups for the same `(host, port)` across the process. This prevents a burst of sessions from issuing duplicate `getaddrinfo` calls. Successes and errors are shared by current waiters, cancellation of one waiter does not cancel the shared lookup, and completed results are not cached by default.

Enable a short-lived positive cache when the same hosts are requested repeatedly after the original lookup has completed:

```rust
use std::time::Duration;
use lkrequest::{Client, SystemDnsCacheConfig};

let client = Client::builder()
    .system_dns_cache(
        SystemDnsCacheConfig::positive(Duration::from_secs(30))
            .with_max_entries(4096),
    )
    .build();
```

The cache belongs to that resolver instance, stores only successful non-empty address lists, and never caches errors. A zero TTL or zero capacity disables completed-result caching while retaining in-flight coalescing. Resolver configuration methods replace each other, so the last call to `.dns()`, `.dns_resolver()`, or `.system_dns_cache()` wins. Use `DnsConfig` or a custom `DnsResolver` instead when custom name servers, DoH/DoT, HTTPS/SVCB records, or ECH discovery are required.

Typical choices:

- **Concurrent bursts to the same origin:** use the default configuration; singleflight is automatic.
- **Repeated short-interval requests:** enable a positive cache with a bounded TTL and capacity.
- **Authoritative DNS freshness or custom DNS transports:** keep caching disabled or configure a custom resolver.

### Connection pool limits and the 0.2.1 migration

Connection limits count physical H1/H2/H3 connections rather than multiplexed requests. Native H2 honors the peer's concurrent-stream limit and applies backpressure while capacity is exhausted instead of silently falling back to H1 or opening unbounded connections. Stale pooled H1 connections encountered during redirect handling are evicted and reconnected through the normal retry policy.

Configure and observe pooling through `Session` for new code:

```rust
use std::time::Duration;
use lkrequest::Client;

let client = Client::builder().build();
let session = client
    .session()
    .max_connections(32)
    .idle_timeout(Duration::from_secs(90))
    .build();

let stats = session.pool_stats();
println!("physical connections: {}/{}", stats.total, stats.max_total);
```

The low-level `ConnectionPool` acquisition and mutation methods published in 0.2.0 remain source-compatible in 0.2.1, but are marked deprecated so IDEs highlight migration work. Existing callers can upgrade without an immediate rewrite; new integrations should use Session-managed pooling. These compatibility wrappers are planned for removal in 0.3.0.

Useful examples:

```bash
cargo run -p lkrequest --example proxy_pool
cargo run -p lkrequest --example session_pool
cargo run -p lkrequest --example proxy_dynamic
cargo run -p lkrequest --features quic-h3 --example h3_socks5_force
cargo run -p lkrequest --example dns_proxy_probe
```

## Architecture

```text
lkrequest-ffi
      │
      ▼
lkrequest ───────────── high-level Client / Session / Request API
  │       │       │
  ▼       ▼       ▼
lktls    lkh2    lkh3 + lkquic
  │                 │
  ▼                 ▼
lktls-quic       patched h3 / quinn submodules
```

| Component | Responsibility |
|---|---|
| `lkrequest` | Sessions, requests, cookies, pools, proxies, DNS, retries, redirects, streaming |
| `lktls` | Sans-I/O TLS engine and byte-level ClientHello profiles |
| `lkh2` | Native H2 codec, HPACK, SETTINGS, priority, and header ordering |
| `lkh3` | HTTP/3/QPACK profiles and H3 request behavior |
| `lkquic` | QUIC endpoint and backend integration |
| `lktls-quic` | TLS 1.3 bridge for QUIC |
| `lkprofile` | Fingerprint parsing and normalization |
| `lkrequest-ffi` | Stable C ABI and generated C header |
| `tools/profile_collector` | Browser/profile capture and preset export |
| `tools/pcap_diff` | Byte-level capture comparison |
| `tools/fpverify` | Canonical fingerprint verification |

## Fingerprint Methodology

Profiles are **capture-first**:

1. Capture a real browser with `tools/profile_collector`, Wireshark/tshark, or a controlled local endpoint.
2. Separate stable fields from per-connection and request-context variables.
3. Model the fingerprint at the highest layer that can express it.
4. Serialize through the real TLS/H2/H3 implementation.
5. Compare against normalized captures and committed golden files.

Do not hand-edit `lktls/profiles/*.json` merely to satisfy a failing test. Recapture the browser when the target version changes.

## Testing

Default CI is offline and deterministic:

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

QUIC/H3:

```bash
cargo test -p lkrequest --features quic-h3
```

Public-network tests are ignored by default. Run them only with explicit authorization:

```bash
TEST_ALLOW_NETWORK=1 cargo test --workspace -- --include-ignored
```

See [docs/TESTING.md](docs/TESTING.md) for test tiers and environment requirements.

## C ABI

`lkrequest-ffi` exposes opaque handles for Client, Session, Request, Response, streaming, proxy/session pools, multipart bodies, errors, and async operations.

```bash
cargo test -p lkrequest-ffi
cargo clippy -p lkrequest-ffi --all-targets --all-features -- -D warnings
```

The public header is generated from the Rust exports:

```bash
cd lkrequest-ffi
cbindgen . --config cbindgen.toml > include/lkrequest.h
```

See [lkrequest-ffi/README.md](lkrequest-ffi/README.md) for ownership, threading, and ABI rules.

## Documentation and Examples

- [Testing guide](docs/TESTING.md)
- [Contributing guide](CONTRIBUTING.md)
- [Security and responsible use](SECURITY.md)
- [FFI guide](lkrequest-ffi/README.md)
- [Rust examples](lkrequest/examples)
- [Fingerprint regression design](docs/fingerprint-regression-design.md)
- [QUIC/H3 fingerprint notes](docs/chrome146-quic-h3-fingerprint.md)

## Contributing

Contributions are welcome. Fingerprint changes must include evidence showing how the new output relates to a real browser capture. Keep source changes, golden updates, tests, and empirical claims clearly separated.

Before opening a pull request, read [CONTRIBUTING.md](CONTRIBUTING.md) and run the relevant offline gates.

## License

Licensed under the [Apache License 2.0](LICENSE.txt).
