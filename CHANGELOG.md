# Changelog

All important changes to this project will be documented in this file.



## lkrequest 0.1.0

> [!NOTE]
>
> This is the first major version.

### 🚀 Features

- **TLS Fingerprint Control** — Byte-level ClientHello generation that matches real browsers (Chrome, Firefox, Safari)
- **HTTP/2 Fingerprint Control** — SETTINGS frame order, pseudo-header order, WINDOW_UPDATE, PRIORITY frames, and per-request priority weights
- **HTTP/3 + QUIC** — Optional `quic-h3` feature for full HTTP/3 over QUIC with fingerprint-aware Transport Parameters, Alt-Svc auto-discovery, and H2→H3 seamless upgrade
- **Built-in Browser Presets** — Chrome 131/144/145/146/147/148/149, Firefox 133/147, Safari 18/26 (TLS + H2, plus QUIC when `quic-h3` is enabled)
- **Session Management** — Cookie jars, connection pooling, HTTP/2 multiplexing, and optional QUIC 0-RTT session resumption
- **Connection Prewarming** — `session.preconnect()` pre-establishes DNS + TCP + TLS + H2 (or, with `quic-h3`, QUIC + H3) connections
- **Custom DNS Resolver** — Pluggable DNS with DoH support, auto ECH config and H3 hints via HTTPS/SVCB records
- **Alt-Svc Discovery** — Automatic HTTP/2 → HTTP/3 protocol upgrade via Alt-Svc headers with broken-QUIC fallback
- **SessionPool** — High-concurrency pool with proxy rotation (round-robin / random)
- **Proxy Support** — SOCKS5 and HTTP CONNECT with authentication
- **WebSocket** — HTTP/1.1 Upgrade (RFC 6455) and H2 Extended CONNECT (RFC 8441)
- **Middleware** — Interceptor chain for request/response modification
- **Retry Policies** — Exponential backoff, fixed interval, custom strategies
- **Redirect Control** — `RedirectPolicy::Follow(n)` or `RedirectPolicy::None` for manual handling
- **Auto-Decompression** — Brotli, gzip, deflate, zstd
- **Blocking API** — Synchronous wrapper for non-async contexts
- **Multipart/Form-Data** — File uploads with streaming support
- **TCP Fingerprint** — JA4T-style TCP SYN fingerprinting





