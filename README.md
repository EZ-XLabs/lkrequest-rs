# lkrequest

**A Rust HTTP client with byte-level TLS, HTTP/2 and HTTP/3 fingerprint control.**

lkrequest enables precise simulation of real browser network fingerprints — including TLS ClientHello, HTTP/2 SETTINGS, QUIC Transport Parameters, and header order — making it suitable for web scraping, bot detection research, and browser emulation scenarios.

## Features

- **TLS Fingerprint Control** — Byte-level ClientHello generation that matches real browsers (Chrome, Firefox, Safari)
- **HTTP/2 Fingerprint Control** — SETTINGS frame order, pseudo-header order, WINDOW_UPDATE, PRIORITY frames, and per-request priority weights
- **HTTP/3 + QUIC** — Optional `quic-h3` feature for full HTTP/3 over QUIC with fingerprint-aware Transport Parameters, Alt-Svc auto-discovery, and H2→H3 seamless upgrade
- **Built-in Browser Presets** — Chrome 131/144/145/146/147/148/149/150, Firefox 133/147, Safari 18/26 (TLS + H2, plus QUIC when `quic-h3` is enabled)
- **Fingerprint Randomization** — Optional `synthetic-fp` feature: per-session *synthetic* fingerprints (extension-order jitter, preset recombination, out-of-corpus perturbation), composable per layer via a `Layers` mask and held to a configurable negotiability floor
- **Session Management** — Cookie jars, connection pooling, HTTP/2 multiplexing, and optional QUIC 0-RTT session resumption
- **Connection Prewarming** — `session.preconnect()` pre-establishes DNS + TCP + TLS + H2 (or, with `quic-h3`, QUIC + H3) connections
- **Custom DNS Resolver** — Pluggable DNS with DoH support, auto ECH config and H3 hints via HTTPS/SVCB records
- **Alt-Svc Discovery** — Automatic HTTP/2 → HTTP/3 protocol upgrade via Alt-Svc headers with broken-QUIC fallback
- **SessionPool** — High-concurrency pool with proxy rotation (round-robin / random)
- **Proxy Support** — SOCKS5 and HTTP CONNECT with authentication, plus multi-hop **proxy chains** (QUIC/H3 supported over an all-SOCKS5 chain)
- **WebSocket** — HTTP/1.1 Upgrade (RFC 6455) and H2 Extended CONNECT (RFC 8441)
- **Middleware** — Interceptor chain for request/response modification
- **Retry Policies** — Exponential backoff, fixed interval, custom strategies
- **Redirect Control** — `RedirectPolicy::Follow(n)` or `RedirectPolicy::None` for manual handling
- **Auto-Decompression** — Brotli, gzip, deflate, zstd
- **Blocking API** — Synchronous wrapper for non-async contexts
- **Multipart/Form-Data** — File uploads with streaming support
- **TCP Fingerprint** — JA4T-style TCP SYN fingerprinting

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                lkrequest  (HTTP Client)                   │
│                                                          │
│   Client ──► Session ──► Request                         │
│   (fingerprint    (virtual       (single                 │
│    template)       browser        HTTP                   │
│                    user)          call)                   │
├────────────┬────────────┬────────────┬───────────────────┤
│   lktls    │   lkh2     │   lkh3     │   lkquic          │
│  (TLS FP   │  (H2 FP    │  (H3 FP    │  (QUIC endpoint   │
│   engine)  │   engine)  │   config)  │   abstraction)    │
├────────────┤            ├────────────┤                   │
│ lktls-quic │            │ deps/h3    │   deps/quinn      │
│ (QUIC-TLS  │            │ (patched)  │   (patched)       │
│  bridge)   │            │            │                   │
├────────────┴────────────┴────────────┴───────────────────┤
│   Crypto Backend:  aws-lc-rs (TLS) + ring (QUIC)         │
└──────────────────────────────────────────────────────────┘
```

| Crate | Description |
|-------|-------------|
| **lkrequest** | High-level HTTP client — sessions, cookies, proxies, retry, WebSocket, H2/H3 dual dispatch |
| **lkrequest-ffi** | Stable C ABI facade — sync/async requests, streaming, diagnostics, Session/Proxy pools |
| **lktls** | Byte-level TLS fingerprint engine — ClientHello, handshake, record layer |
| **lktls-quic** | Bridge between lktls and quinn for QUIC-native TLS 1.3 handshake |
| **lkh2** | HTTP/2 fingerprint-controlled connections — SETTINGS, HEADERS, PRIORITY |
| **lkh3** | HTTP/3 configuration and QUIC Transport Parameter fingerprinting |
| **lkquic** | QUIC endpoint abstraction with pluggable backend (default: quinn) |
| **lkprofile** | Profile parser — converts raw ClientHello / H2 / QUIC captures to profiles |
| **tools/pcap_diff** | CLI tool for byte-level ClientHello comparison |
| **tools/profile_collector** | CLI tool for extracting TLS + H2 + QUIC profiles from captures |

## Prerequisites

### Rust

Edition 2021+ (some crates use 2024). Async runtime: **Tokio**.

### Git Submodules

This project uses patched forks of quinn and h3 as git submodules. You **must** initialize them before building:

```bash
git clone --recurse-submodules <repo-url>

# Or if you already cloned without submodules:
git submodule update --init
```

The submodules track the `lkrequest-patches` branch. To update to the latest patches:

```bash
git submodule update --remote
```

### Build Dependencies

- **aws-lc-rs**: Uses prebuilt NASM binaries. On Windows this usually works out of the box.
- **ring**: Required by quinn for QUIC crypto.

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
lkrequest = { path = "lkrequest" }
lktls = { path = "lktls" }
tokio = { version = "1", features = ["full"] }
```

Enable HTTP/3 / QUIC explicitly when you need it:

```toml
[dependencies]
lkrequest = { path = "lkrequest", features = ["quic-h3"] }
```

### Zero-Config (Chrome 144 defaults)

```rust
use lkrequest::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::default();
    let session = client.session().build();
    let resp = session.get("https://httpbin.org/get").send().await?;

    println!("Status: {}", resp.status());
    println!("{}", resp.text()?);
    Ok(())
}
```

### Custom Fingerprint

```rust
use lkrequest::Client;
use lkrequest::h2::profile::chrome_146_h2;
use lktls::profile::presets;

let client = Client::builder()
    .fingerprint(presets::chrome_146())
    .h2_profile(chrome_146_h2())
    .default_header(
        "user-agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    )
    .build();

let session = client.session().build();
let resp = session.get("https://example.com/json").send().await?;
```

### Using a Preset (TLS + H2 + optional QUIC + Header Order bundled)

```rust
use lkrequest::{preset, Client};

let client = Client::builder()
    .preset(preset::chrome_146())
    .build();
```

### POST with JSON

```rust
use serde::Serialize;

#[derive(Serialize)]
struct Payload {
    name: String,
    email: String,
}

let resp = session
    .post("https://httpbin.org/post")
    .json(&Payload {
        name: "Alice".into(),
        email: "alice@example.com".into(),
    })?
    .send()
    .await?;
```

### Custom Headers & Cookie Persistence

```rust
let client = Client::builder()
    .fingerprint(presets::chrome_146())
    .h2_profile(chrome_146_h2())
    .default_header("accept-language", "en-US,en;q=0.9")
    .build();

let session = client.session().build();

// Per-request headers
let resp = session
    .get("https://httpbin.org/headers")
    .header("x-custom-id", "12345")
    .send()
    .await?;

// Cookies are automatically persisted within the same session
session.get("https://httpbin.org/cookies/set/token/abc").send().await?;
let resp = session.get("https://httpbin.org/cookies").send().await?;
// → cookies: { "token": "abc" }
```

## HTTP/3 & QUIC

HTTP/3 support is behind the `quic-h3` feature and is disabled by default.

Enable it in your dependency declaration first:

```toml
lkrequest = { path = "lkrequest", features = ["quic-h3"] }
```

With that feature enabled, the client can operate in several modes:

### Automatic H3 (via Alt-Svc Discovery)

```rust
let client = Client::builder()
    .preset(preset::chrome_146())
    .build();

let session = client.session().build();

// First request goes over H2; server responds with Alt-Svc: h3=":443"
// Subsequent requests automatically upgrade to H3
let resp = session.get("https://example.com").send().await?;
println!("Protocol: {:?}", resp.version()); // HTTP/2 or HTTP/3
```

### Force HTTP/3 Only

```rust
let session = client.session()
    .http3_only()
    .build();

let resp = session.get("https://example.com").send().await?;
// Always uses QUIC + HTTP/3; fails if server doesn't support it
```

### H3 with H2 Fallback

```rust
let session = client.session()
    .http3_with_fallback()
    .build();

// Tries H3 first, falls back to H2 if QUIC fails
let resp = session.get("https://example.com").send().await?;
```

### Disable HTTP/3

```rust
let client = Client::builder()
    .fingerprint(presets::chrome_146())
    .disable_http3()
    .build();
```

### DNS-Driven H3 Discovery

When using DoH, HTTPS/SVCB DNS records can provide H3 hints (ALPN `h3`) and ECH configs before connecting:

```rust
use lkrequest::{Client, DnsConfig};

let client = Client::builder()
    .dns(DnsConfig::CloudflareHttps)
    .preset(preset::chrome_146())
    .build();

// DNS HTTPS record → ECH config + h3 ALPN hint → direct H3 connection
let session = client.session().build();
let resp = session.get("https://cloudflare.com").send().await?;
```

### QUIC Session Resumption (0-RTT)

```rust
let session = client.session().build();

// First connection: full QUIC handshake
session.get("https://example.com").send().await?;

// Second connection: 0-RTT resumption (if server supports it)
session.get("https://example.com/page2").send().await?;
```

## Proxy

### Single Proxy

```rust
use lkrequest::proxy::ProxyConfig;

let session = client.session()
    .proxy(ProxyConfig::parse("socks5://user:pass@proxy:1080")?)
    .build();
```

### Proxy Chain (multi-hop)

Route through an ordered chain of proxies (client → hop1 → hop2 → … → target).
TCP (HTTP/1.1, HTTP/2) works with any mix of HTTP CONNECT and SOCKS5 hops.
**QUIC/HTTP/3** works over an **all-SOCKS5** chain (nested UDP ASSOCIATE); a chain
containing an HTTP hop errors for QUIC, so the request falls back to H2.

```rust
use lkrequest::proxy::ProxyConfig;

// client → hop1 → hop2 → target
let chain = ProxyConfig::parse_chain([
    "socks5://user:pass@hop1:1080",
    "socks5://user:pass@hop2:1080",
])?;

let session = client.session()
    .proxy_config(chain)
    .build();
```

### SessionPool with Proxy Rotation

```rust
use std::time::Duration;
use lkrequest::{Client, SessionPool};
use lkrequest::proxy::ProxyConfig;

let pool = SessionPool::builder()
    .client(&client)
    .proxies(vec![
        ProxyConfig::parse("socks5://user:pass@proxy1:1080")?,
        ProxyConfig::parse("http://user:pass@proxy2:8080")?,
    ])
    .max_sessions(100)
    .idle_timeout(Duration::from_secs(300))
    .build();

let guard = pool.acquire().await;
let resp = guard.get("https://httpbin.org/ip").send().await?;
// guard dropped → session returns to pool
```

### Dynamic Proxy Provider

```rust
let client = Client::builder()
    .preset(preset::chrome_146())
    .build();

let pool = SessionPool::builder()
    .client(&client)
    .proxy_fn(|| async {
        // Return a fresh proxy from your provider on each call
        Ok(ProxyConfig::parse("http://rotating-proxy.example.com:8080")?)
    })
    .build();
```

## DNS Configuration

```rust
use lkrequest::{Client, DnsConfig};

// Preset resolvers
let client = Client::builder().dns(DnsConfig::System).build();          // OS default
let client = Client::builder().dns(DnsConfig::GoogleHttps).build();     // Google DoH
let client = Client::builder().dns(DnsConfig::CloudflareHttps).build(); // Cloudflare DoH
let client = Client::builder().dns(DnsConfig::Quad9Https).build();      // Quad9 DoH

// DoH resolvers also fetch HTTPS/SVCB records for:
// - ECH (Encrypted Client Hello) config auto-discovery
// - H3 ALPN hints for direct QUIC connections
```

## Connection Prewarming

```rust
let session = client.session().build();

// Pre-establish connection (DNS + TCP + TLS + H2 SETTINGS, or DNS + QUIC + H3)
session.preconnect("https://api.example.com").await?;

// Subsequent request reuses the pre-warmed connection
let resp = session.get("https://api.example.com/data").send().await?;

// Batch preconnect multiple origins concurrently
session.preconnect_many(&[
    "https://api.example.com",
    "https://cdn.example.com",
]).await;
```

## Retry & Redirect

### Retry Policies

```rust
use lkrequest::retry::{RetryPolicy, ExponentialBackoff, FixedInterval};

let session = client.session()
    .retry_policy(ExponentialBackoff::new(3))  // 3 retries with exponential backoff
    .build();

// Or fixed interval
let session = client.session()
    .retry_policy(FixedInterval::new(3, Duration::from_secs(1)))
    .build();
```

### Redirect Control

```rust
use lkrequest::RedirectPolicy;

// Auto-follow up to 10 redirects (default)
let session = client.session().build();

// Disable auto-redirect
let session = client.session()
    .redirect_policy(RedirectPolicy::None)
    .build();

// Custom limit
let session = client.session()
    .max_redirects(5)
    .build();
```

## WebSocket

```rust
let session = client.session().build();

// HTTP/1.1 Upgrade or H2 Extended CONNECT (automatic based on connection)
let ws = session.websocket("wss://echo.websocket.org")
    .header("Origin", "https://example.com")
    .connect()
    .await?;
```

## Timeout Configuration

```rust
use std::time::Duration;

let client = Client::builder()
    .dns_timeout(Duration::from_secs(5))
    .tcp_connect_timeout(Duration::from_secs(10))
    .tls_handshake_timeout(Duration::from_secs(10))
    .ttfb_timeout(Duration::from_secs(30))
    .total_timeout(Duration::from_secs(60))
    .build();
```

## Fingerprint Verification

```rust
// Verify TLS + H2 fingerprint
let resp = session.get("https://example.com/json").send().await?;
let json: serde_json::Value = resp.json()?;
println!("JA3:    {}", json["ja3_hash"]);
println!("JA4:    {}", json["ja4"]);
println!("Akamai: {}", json["akamai_hash"]);

// Verify H3/QUIC fingerprint
let h3_session = client.session().http3_only().build();
let resp = h3_session.get("https://quic.browserleaks.com/json").send().await?;
```

## Built-in Fingerprint Profiles

### TLS Profiles

| Profile | JA3 Hash | Browser |
|---------|----------|---------|
| `chrome_131()` | — | Chrome 131 (Windows) |
| `chrome_144()` | `991d71ee69967b7325077b71bad10393` | Chrome 144 (Windows) |
| `chrome_145()` | — | Chrome 145 (Windows) |
| `chrome_146()` | `991d71ee69967b7325077b71bad10393` | Chrome 146 (Windows) |
| `chrome_147()` | — | Chrome 147 (Windows) |
| `chrome_148()` | — | Chrome 148 (Windows) |
| `chrome_149()` | — | Chrome 149 (Windows) |
| `chrome_150()` | — | Chrome 150 (Windows) |
| `firefox_133()` | — | Firefox 133 |
| `firefox_147()` | — | Firefox 147 |
| `safari_18()` | — | Safari 18 (macOS) |
| `safari_26()` | — | Safari 26 (macOS) |

> **Chrome 150** matches Chrome 149 on the wire **except** for one change captured on the TLS/H2 (TCP) ClientHello: it prepends three ML-DSA post-quantum signature code-points (`0x0904`/`0x0905`/`0x0906` = `mldsa44`/`65`/`87`) to `signature_algorithms`. This shifts **JA4** but not **JA3** (JA3 excludes signature algorithms), and requires no PQC crypto since the codepoints are only advertised, never negotiated by real servers.
>
> **HTTP/3 is not updated for Chrome 150.** `preset::chrome_150()` still reuses the shared Chrome 146 QUIC/H3 transport profile (as Chrome 144–149 do), so its QUIC ClientHello does **not** yet carry the ML-DSA signature algorithms. A dedicated Chrome 150 H3 capture is pending — the local capture path is blocked by Chrome's QUIC certificate enforcement.

### Client Presets (TLS + H2 + optional QUIC + Header/Cookie Order)

| Preset | Includes |
|--------|----------|
| `preset::chrome_146()` | TLS + H2 + optional QUIC profile + header order + cookie order |
| `preset::chrome_147()` | TLS + H2 + optional QUIC profile + header order + cookie order |
| (more) | See `lkrequest/src/preset.rs` |

Profiles are defined as JSON files in `lktls/profiles/` and can be extended with custom profiles captured via the `profile_collector` tool.

## TLS Capabilities

- TLS 1.2 & TLS 1.3 handshake (including static RSA key exchange suites)
- Extension order control (critical for fingerprint matching)
- GREASE support (cipher suites, extensions, named groups)
- ECH (Encrypted Client Hello) support with auto-discovery via DNS
- Session resumption (PSK / Session Tickets)
- ALPS (Application-Layer Protocol Settings)
- Certificate compression (Brotli)
- Crypto backend: `aws-lc-rs` (supports ML-KEM-768 post-quantum, TLS 1.2 CBC)
- Certificate verification with custom CA roots

## HTTP/2 Capabilities

- SETTINGS frame parameter order control
- Pseudo-header order (`:method`, `:authority`, `:scheme`, `:path`)
- Connection-level WINDOW_UPDATE
- HEADERS stream dependency with configurable policy (Flat / Chain)
- Standalone PRIORITY frames
- Per-request priority with browser-aware urgency-to-weight mapping (RFC 9218)

## HTTP/3 & QUIC Capabilities

- Full QUIC transport over UDP via patched quinn
- QUIC Transport Parameter fingerprinting (initial_max_data, max_streams, etc.)
- Alt-Svc header parsing for automatic H2→H3 upgrade
- HTTPS/SVCB DNS record resolution for H3 discovery
- QUIC session resumption and 0-RTT
- Broken-QUIC tracking with automatic fallback to H2
- H3-specific header order control

## FFI (C ABI)

`lkrequest-ffi` provides a stable C ABI for non-Rust consumers.

Exported object model:
- `Client` / `Session` / `Request` / `Response` / `StreamingResponse` / `Error` / `Op`
- `ProxyPool` / `ProxyPoolBuilder` / `ProxyGuard`
- `SessionPool` / `SessionPoolBuilder` / `SessionPoolGuard`
- `Multipart`

FFI coverage includes:
- Sync + async request execution with H1/H2/H3 protocol selection
- Streaming reads with diagnostics and header lookups
- Session cookie CRUD, preconnect, connection-pool stats
- ProxyPool / SessionPool acquire, bad-marking
- Multipart/form-data request bodies
- DNS preset/custom configuration and native cert toggle
- File logger and callback logger sinks

The public C header is generated at build time by `build.rs` (via cbindgen) at `lkrequest-ffi/include/lkrequest.h`; it is not committed to the repository.

```bash
cargo test -p lkrequest-ffi
```

## Examples

```bash
# Basic usage
cargo run -p lkrequest --example basic_get
cargo run -p lkrequest --example post_json
cargo run -p lkrequest --example custom_headers

# Fingerprint verification
cargo run -p lkrequest --example fingerprint_check
cargo run -p lkrequest --example fingerprint_check_146
cargo run -p lkrequest --example fingerprint_compare

# HTTP/3 & QUIC
cargo run -p lkrequest --features quic-h3 --example basic_h3
cargo run -p lkrequest --features quic-h3 --example h3_vs_h2
cargo run -p lkrequest --features quic-h3 --example h3_auto_discovery
cargo run -p lkrequest --features quic-h3 --example h3_fingerprint_check
cargo run -p lkrequest --features quic-h3 --example h3_session_resumption
cargo run -p lkrequest --features quic-h3 --example h3_dns_to_response
cargo run -p lkrequest --features quic-h3 --example fingerprint_compare_quic

# Proxy & pool
cargo run -p lkrequest --example session_pool
cargo run -p lkrequest --example proxy_pool

# Header ordering
cargo run -p lkrequest --example header_order_test

# ECH
cargo run -p lkrequest --example ech_test
```

## Cargo Features

| Feature | Default | Description |
|---------|---------|-------------|
| `h2-native` | Yes | Use lkh2's native HPACK encoder for full H2 fingerprint control |
| `quic-h3` | No | Enable QUIC / HTTP/3 support, QUIC-aware presets, and H3 examples/tests |
| `network-e2e` | No | Enable public-network integration tests (not run in default CI) |

## License

Apache License 2.0 — Copyright 2026 EZXLabs
