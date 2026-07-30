# Changelog

All important changes to this project will be documented in this file.



## Unreleased

No unreleased changes yet.



## lkrequest 0.2.0

This release includes the changes developed since the initial **v0.1.0** release.

### 🚀 Features

- **Dedicated Chrome 150 QUIC / HTTP/3 preset** — Chrome 150 now has its own QUIC-TLS and H3 profiles instead of reusing Chrome 146. The preset covers the captured signature-algorithm set, QUIC transport parameters, QPACK limits, navigation `PRIORITY_UPDATE`, connection-ID lengths, and Initial datagram sizing; milestone-, platform-, GREASE-, and Finch-dependent fields remain explicitly version-sensitive.
- **Fingerprint Randomization (`synthetic-fp`)** — Per-session *synthetic* fingerprints that stay browser-plausible: extension-order jitter, recombination from the shipped-preset corpus, and full out-of-corpus value perturbation — composable per layer (TLS / H2 / QUIC) through a `Layers` mask and materialized per session from a seed. A configurable **negotiability floor** keeps every synthetic ClientHello able to complete a real TLS handshake.
- **Multi-hop Proxy Chains** — Route through an ordered chain of proxies with `ProxyConfig::parse_chain([...])` / `.through(...)`. TCP (HTTP/1.1, HTTP/2) works with any mix of HTTP CONNECT and SOCKS5 hops. **QUIC/HTTP/3** additionally works over an **all-SOCKS5** chain via nested UDP ASSOCIATE (one UDP relay per hop, stacked as nested per-datagram headers); a chain containing an HTTP hop errors so the caller falls back to H2.
- **Pluggable HSTS Policy** — `HstsPolicy` trait to control `http`→`https` scheme upgrades (default off; `StaticHsts` / `DynamicHsts` provided).
- **FFI — Fingerprint Randomization** — `lk_client_builder_set_randomize` exposes the randomization tiers through the C ABI.
- **DNS — Fallible Hickory Constructors** — new fallible `HickoryDns` constructors with documented panic paths.

### 🐞 Fixes

- **TLS 1.3 ECH + HelloRetryRequest parity** — real ECH CH2 now reuses the ECH config, HPKE sender context, Inner random, GREASE values, and extension permutation; fake ECH bytes are also reused verbatim. HRR confirmation, selected-group, cookie-only retry, duplicate/invalid extension, dummy-CCS, and local fatal-alert handling now follow the browser/RFC flow.
- **ECH + PSK + HRR binders** — `pre_shared_key` remains exclusively in `ClientHelloInner`; CH1 uses `Truncate(ClientHelloInner1)` and CH2 uses `message_hash(ClientHelloInner1) + HRR + Truncate(ClientHelloInner2)`. The previous unsupported-error path no longer aborts resumed real-ECH handshakes.
- **QUIC/H3 HRR state transitions** — QUIC immediately revokes 0-RTT stream and packet state after HRR, maps local TLS alerts to QUIC `CRYPTO_ERROR` codes, and completes a forced P-384 HRR through a real local H3 request/response flow.
- **TLS handshake reassembly across records** — a handshake message fragmented across several TLS records (RFC 8446 §5.1) — e.g. a large server Certificate flight, as Facebook sends — no longer fails the handshake with `truncated handshake message in record`. Both the TLS 1.3 and TLS 1.2 read paths now buffer decrypted handshake bytes and process only complete messages, matching what the QUIC path already did. Receive-side only: the ClientHello and all wire-visible client output (JA3/JA4/JA4_r, Akamai hash) are byte-for-byte unchanged.
- **Real ECH correctness & hardening** — corrected the Encrypted-ClientHello transcript, gated SVCB/ECH discovery lookups behind remote-DNS to close a DNS leak on `socks5h`/CONNECT routes, and restricted ALPS to HTTP/1.1 where applicable.
- **ALPS advertisement decoupled from payload** — advertising ALPS in the ClientHello no longer forces a non-empty client-settings payload, matching real Chrome (which advertises ALPS with an empty payload — a server-visible tell otherwise).
- **HTTP/2 frame-size bound** — inbound frames are bounded by *our* advertised `MAX_FRAME_SIZE`, not the peer's.
- **Certificate DER bounds-checking** — a malicious certificate can no longer panic the TLS layer via out-of-range DER slices.
- **Redirect handling** — the total timeout now spans the entire redirect chain, `303 See Other` is followed correctly, and an opt-in `https_only` knob is available.
- **Middleware on retry** — `on_response` middleware now runs when a retry policy is configured.
- **SOCKS5 UDP reply matching** — relay replies are accepted on a source-**IP** match instead of exact `ip:port`. Real relays commonly egress replies from a UDP port other than the advertised `BND.PORT` (separate egress socket, relay pools, load balancers); the strict match dropped every such reply and hung QUIC-over-SOCKS5. quinn's header protection + AEAD still reject forged packets.

### 🔒 Security & Dependencies

- **crossbeam-epoch → 0.9.20** — RUSTSEC-2026-0204.
- **quinn-proto → 0.11.15** — backported fix for RUSTSEC-2026-0185.

---

### 🚀 功能（中文）

- **独立 Chrome 150 QUIC / HTTP/3 预设** — Chrome 150 不再复用 Chrome 146 的 QUIC-TLS 与 H3 profile；新预设覆盖抓包确认的签名算法、QUIC Transport Parameters、QPACK 上限、导航请求 `PRIORITY_UPDATE`、Connection ID 长度和 Initial datagram 尺寸。与 milestone、平台、GREASE 和 Finch 相关的字段继续明确标记为版本易变项。
- **指纹随机化（`synthetic-fp`）** — 每个会话生成保持“像浏览器”的*合成*指纹：扩展顺序抖动、从已内置预设语料库重组、以及完全的语料外取值扰动 —— 可通过 `Layers` 掩码按层（TLS / H2 / QUIC）组合，并由种子在每个会话中具体化。可配置的**可协商底线**保证每个合成 ClientHello 都能完成真实 TLS 握手。
- **多跳代理链** — 用 `ProxyConfig::parse_chain([...])` / `.through(...)` 经一串有序代理转发。TCP（HTTP/1.1、HTTP/2）支持 HTTP CONNECT 与 SOCKS5 任意混合的跳。**QUIC/HTTP/3** 额外支持在**全 SOCKS5** 链上运行，采用嵌套 UDP ASSOCIATE（每跳一个 UDP relay，逐跳堆叠嵌套头）；链中若含 HTTP 跳则报错，由调用方回退 H2。
- **可插拔 HSTS 策略** — `HstsPolicy` trait 控制 `http`→`https` 协议升级（默认关闭；提供 `StaticHsts` / `DynamicHsts`）。
- **FFI —— 指纹随机化** — `lk_client_builder_set_randomize` 通过 C ABI 暴露随机化档位。
- **DNS —— 可失败的 Hickory 构造器** — 新增可返回错误的 `HickoryDns` 构造器，并文档化了 panic 路径。

### 🐞 修复（中文）

- **TLS 1.3 ECH + HelloRetryRequest 对齐** — real ECH CH2 现在复用 ECH config、HPKE sender context、Inner random、GREASE values 和扩展排列；fake ECH bytes 也逐字节复用。HRR confirmation、selected-group、cookie-only retry、重复/非法扩展、dummy CCS 与本地 fatal alert 均按浏览器/RFC 流程处理。
- **ECH + PSK + HRR binder** — `pre_shared_key` 仅存在于 `ClientHelloInner`；CH1 使用 `Truncate(ClientHelloInner1)`，CH2 使用 `message_hash(ClientHelloInner1) + HRR + Truncate(ClientHelloInner2)`。此前明确报不支持并中止的 real-ECH 恢复握手路径已补齐。
- **QUIC/H3 HRR 状态切换** — 收到 HRR 后立即撤销 QUIC 0-RTT stream/packet 状态；本地 TLS alert 映射为 QUIC `CRYPTO_ERROR`；强制 P-384 HRR 已通过真实本地 H3 request/response 流程。
- **TLS 握手跨 record 重组** — 一条握手消息被拆分到多个 TLS record 时（RFC 8446 §5.1，例如 Facebook 那样较大的服务器 Certificate flight），不再以 `truncated handshake message in record` 握手失败。TLS 1.3 与 TLS 1.2 的读取路径现在都会缓冲解密后的握手字节、只处理完整消息（QUIC 路径早已如此）。**仅接收侧改动**:ClientHello 及所有线上可见的客户端输出(JA3/JA4/JA4_r、Akamai hash)逐字节不变。
- **真实 ECH 正确性与加固** — 修正加密 ClientHello 的转录（transcript）；把 SVCB/ECH 发现查询限制在远程 DNS 下，堵住 `socks5h`/CONNECT 路由上的 DNS 泄漏；在适用处将 ALPS 限定为 HTTP/1.1。
- **ALPS 宣告与载荷解耦** — 在 ClientHello 里宣告 ALPS 不再强制一个非空的 client-settings 载荷，与真实 Chrome 一致（Chrome 宣告 ALPS 但载荷为空 —— 否则是一个服务端可见的破绽）。
- **HTTP/2 帧大小上限** — 入站帧以*我方*宣告的 `MAX_FRAME_SIZE` 为界，而非对端的。
- **证书 DER 边界检查** — 恶意证书不再能通过越界的 DER 切片让 TLS 层 panic。
- **重定向处理** — 总超时现在覆盖整条重定向链，`303 See Other` 被正确跟随，并提供可选的 `https_only` 开关。
- **重试时的中间件** — 配置了重试策略时，`on_response` 中间件现在会运行。
- **SOCKS5 UDP 回包匹配** — relay 回包改为按源 **IP** 匹配而非精确 `ip:port`。真实 relay 常从不同于 `BND.PORT` 的 UDP 端口回包（独立 egress socket、relay 池、负载均衡）；严格匹配会丢掉所有此类回包，导致 QUIC-over-SOCKS5 挂死。quinn 的头保护 + AEAD 仍会拒绝伪造包。

### 🔒 安全与依赖（中文）

- **crossbeam-epoch → 0.9.20** —— RUSTSEC-2026-0204。
- **quinn-proto → 0.11.15** —— 回移 RUSTSEC-2026-0185 的修复。



## lkrequest 0.1.0

> [!NOTE]
>
> This is the first major version.

### 🚀 Features

- **TLS Fingerprint Control** — Byte-level ClientHello generation that matches real browsers (Chrome, Firefox, Safari)
- **HTTP/2 Fingerprint Control** — SETTINGS frame order, pseudo-header order, WINDOW_UPDATE, PRIORITY frames, and per-request priority weights
- **HTTP/3 + QUIC** — Optional `quic-h3` feature for full HTTP/3 over QUIC with fingerprint-aware Transport Parameters, Alt-Svc auto-discovery, and H2→H3 seamless upgrade
- **Built-in Browser Presets** — Chrome 131/144/145/146/147/148/149/150, Firefox 133/147, Safari 18/26 (TLS + H2, plus QUIC when `quic-h3` is enabled)
- **Session Management** — Cookie jars, connection pooling, HTTP/2 multiplexing, and optional QUIC 0-RTT session resumption
- **Connection Prewarming** — `session.preconnect()` pre-establishes DNS + TCP + TLS + H2 (or, with `quic-h3`, QUIC + H3) connections
- **Custom DNS Resolver** — Pluggable DNS with DoH support, auto ECH config and H3 hints via HTTPS/SVCB records
- **Alt-Svc Discovery** — Automatic HTTP/2 → HTTP/3 protocol upgrade via Alt-Svc headers with broken-QUIC fallback
- **SessionPool** — High-concurrency pool with proxy rotation (round-robin / random)
- **Proxy Support** — SOCKS5 and HTTP CONNECT with authentication
- **WebSocket** — HTTP/1.1 Upgrade (RFC 6455) and H2 Extended CONNECT (RFC 8441)
- **Middleware** — Interceptor chain for request/response modification
- **Retry Policies** — Exponential backoff, fixed interval, custom strategies; idempotency-aware (non-idempotent methods are not silently replayed after a possibly-already-sent failure unless marked `Idempotency::Idempotent`)
- **Redirect Control** — `RedirectPolicy::Follow(n)` or `RedirectPolicy::None` for manual handling
- **Auto-Decompression** — Brotli, gzip, deflate, zstd
- **Blocking API** — Synchronous wrapper for non-async contexts
- **Multipart/Form-Data** — File uploads with streaming support
- **TCP Fingerprint** — JA4T-style TCP SYN fingerprinting





