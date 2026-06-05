# lkrequest

**一个支持字节级 TLS、HTTP/2 和 HTTP/3 指纹控制的 Rust HTTP 客户端。**

lkrequest 可以精确模拟真实浏览器的网络指纹——包括 TLS ClientHello、HTTP/2 SETTINGS、QUIC 传输参数和请求头顺序——适用于网页抓取、反检测研究和浏览器模拟场景。

## 功能特性

- **TLS 指纹控制** — 字节级 ClientHello 生成，精确匹配真实浏览器（Chrome、Firefox、Safari）
- **HTTP/2 指纹控制** — SETTINGS 帧顺序、伪头顺序、WINDOW_UPDATE、PRIORITY 帧、每请求优先级权重
- **HTTP/3 + QUIC** — 通过可选的 `quic-h3` feature 启用完整 HTTP/3 协议栈，支持指纹感知的传输参数、Alt-Svc 自动发现、H2→H3 无缝升级
- **内置浏览器预设** — Chrome 131/144/145/146/147/148/149、Firefox 133/147、Safari 18/26（TLS + H2；启用 `quic-h3` 后再带 QUIC）
- **会话管理** — Cookie 容器、连接池、HTTP/2 多路复用，以及可选的 QUIC 0-RTT 会话恢复
- **连接预热** — `session.preconnect()` 预建立 DNS + TCP + TLS + H2（启用 `quic-h3` 时也可预热 QUIC + H3）连接
- **自定义 DNS 解析器** — 可插拔 DNS，支持 DoH，通过 HTTPS/SVCB 记录自动获取 ECH 配置和 H3 提示
- **Alt-Svc 发现** — 通过 Alt-Svc 头自动从 HTTP/2 升级到 HTTP/3，含 QUIC 故障回退
- **SessionPool** — 高并发会话池，支持代理轮换（轮询 / 随机）
- **代理支持** — SOCKS5 和 HTTP CONNECT，支持认证
- **WebSocket** — HTTP/1.1 Upgrade (RFC 6455) 和 H2 Extended CONNECT (RFC 8441)
- **中间件** — 拦截器链，用于请求/响应修改
- **重试策略** — 指数退避、固定间隔、自定义策略
- **重定向控制** — `RedirectPolicy::Follow(n)` 或 `RedirectPolicy::None` 手动处理
- **自动解压** — Brotli、gzip、deflate、zstd
- **阻塞式 API** — 同步包装器，适用于非异步上下文
- **Multipart/Form-Data** — 支持流式文件上传
- **TCP 指纹** — JA4T 风格的 TCP SYN 指纹

## 架构

```
┌──────────────────────────────────────────────────────────┐
│                lkrequest（HTTP 客户端）                    │
│                                                          │
│   Client ──► Session ──► Request                         │
│  （指纹模板）  （虚拟浏览器    （单次 HTTP                  │
│                 用户）         请求）                      │
├────────────┬────────────┬────────────┬───────────────────┤
│   lktls    │   lkh2     │   lkh3     │   lkquic          │
│ （TLS 指纹  │ （H2 指纹   │ （H3 指纹   │ （QUIC 端点       │
│   引擎）    │   引擎）    │   配置）    │   抽象层）        │
├────────────┤            ├────────────┤                   │
│ lktls-quic │            │ deps/h3    │   deps/quinn      │
│（QUIC-TLS  │            │（已补丁）   │  （已补丁）        │
│  桥接层）   │            │            │                   │
├────────────┴────────────┴────────────┴───────────────────┤
│   密码学后端：aws-lc-rs（TLS）+ ring（QUIC）               │
└──────────────────────────────────────────────────────────┘
```

| Crate | 说明 |
|-------|------|
| **lkrequest** | 高层 HTTP 客户端——会话、Cookie、代理、重试、WebSocket、H2/H3 双协议分发 |
| **lkrequest-ffi** | 稳定的 C ABI 外观——同步/异步请求、流式传输、诊断、Session/Proxy 池 |
| **lktls** | 字节级 TLS 指纹引擎——ClientHello、握手、记录层 |
| **lktls-quic** | lktls 与 quinn 之间的桥接层，用于 QUIC 原生 TLS 1.3 握手 |
| **lkh2** | HTTP/2 指纹控制连接——SETTINGS、HEADERS、PRIORITY |
| **lkh3** | HTTP/3 配置与 QUIC 传输参数指纹 |
| **lkquic** | QUIC 端点抽象层，支持可插拔后端（默认：quinn） |
| **lkprofile** | 配置文件解析器——将原始 ClientHello / H2 / QUIC 抓包转换为指纹配置 |
| **tools/pcap_diff** | CLI 工具，用于字节级 ClientHello 对比 |
| **tools/profile_collector** | CLI 工具，从抓包中提取 TLS + H2 + QUIC 指纹配置 |

## 前置要求

### Rust

Edition 2021+（部分 crate 使用 2024）。异步运行时：**Tokio**。

### Git 子模块

本项目使用 quinn 和 h3 的补丁分支作为 git 子模块。构建前**必须**初始化：

```bash
git clone --recurse-submodules <仓库地址>

# 如果已经 clone 但没有拉取子模块：
git submodule update --init
```

子模块跟踪 `lkrequest-patches` 分支。更新到最新补丁：

```bash
git submodule update --remote
```

### 构建依赖

- **aws-lc-rs**：使用预编译的 NASM 二进制。Windows 上通常开箱即用。
- **ring**：quinn QUIC 加密所需。

## 快速开始

在你的 `Cargo.toml` 中添加：

```toml
[dependencies]
lkrequest = { path = "lkrequest" }
lktls = { path = "lktls" }
tokio = { version = "1", features = ["full"] }
```

如果需要 HTTP/3 / QUIC，再显式开启：

```toml
[dependencies]
lkrequest = { path = "lkrequest", features = ["quic-h3"] }
```

### 零配置（默认 Chrome 144）

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

### 自定义指纹

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

### 使用预设（TLS + H2 + 可选 QUIC + 请求头顺序 一体打包）

```rust
use lkrequest::{preset, Client};

let client = Client::builder()
    .preset(preset::chrome_146())
    .build();
```

### POST JSON 请求

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

### 自定义请求头与 Cookie 持久化

```rust
let client = Client::builder()
    .fingerprint(presets::chrome_146())
    .h2_profile(chrome_146_h2())
    .default_header("accept-language", "en-US,en;q=0.9")
    .build();

let session = client.session().build();

// 单个请求的自定义头
let resp = session
    .get("https://httpbin.org/headers")
    .header("x-custom-id", "12345")
    .send()
    .await?;

// 同一 Session 内 Cookie 自动持久化
session.get("https://httpbin.org/cookies/set/token/abc").send().await?;
let resp = session.get("https://httpbin.org/cookies").send().await?;
// → cookies: { "token": "abc" }
```

## HTTP/3 与 QUIC

HTTP/3 通过 `quic-h3` feature 提供，默认不启用。

先在依赖里显式打开：

```toml
lkrequest = { path = "lkrequest", features = ["quic-h3"] }
```

启用后，客户端支持多种协议模式：

### 自动 H3（通过 Alt-Svc 发现）

```rust
let client = Client::builder()
    .preset(preset::chrome_146())
    .build();

let session = client.session().build();

// 首次请求走 H2；服务器响应 Alt-Svc: h3=":443"
// 后续请求自动升级到 H3
let resp = session.get("https://example.com").send().await?;
println!("协议: {:?}", resp.version()); // HTTP/2 或 HTTP/3
```

### 强制仅用 HTTP/3

```rust
let session = client.session()
    .http3_only()
    .build();

let resp = session.get("https://example.com").send().await?;
// 始终使用 QUIC + HTTP/3；如果服务器不支持则失败
```

### H3 优先，H2 回退

```rust
let session = client.session()
    .http3_with_fallback()
    .build();

// 优先尝试 H3，QUIC 失败时回退到 H2
let resp = session.get("https://example.com").send().await?;
```

### 禁用 HTTP/3

```rust
let client = Client::builder()
    .fingerprint(presets::chrome_146())
    .disable_http3()
    .build();
```

### DNS 驱动的 H3 发现

使用 DoH 时，HTTPS/SVCB DNS 记录可在连接前提供 H3 提示（ALPN `h3`）和 ECH 配置：

```rust
use lkrequest::{Client, DnsConfig};

let client = Client::builder()
    .dns(DnsConfig::CloudflareHttps)
    .preset(preset::chrome_146())
    .build();

// DNS HTTPS 记录 → ECH 配置 + h3 ALPN 提示 → 直接建立 H3 连接
let session = client.session().build();
let resp = session.get("https://cloudflare.com").send().await?;
```

### QUIC 会话恢复（0-RTT）

```rust
let session = client.session().build();

// 首次连接：完整 QUIC 握手
session.get("https://example.com").send().await?;

// 第二次连接：0-RTT 恢复（如果服务器支持）
session.get("https://example.com/page2").send().await?;
```

## 代理

### 单个代理

```rust
use lkrequest::proxy::ProxyConfig;

let session = client.session()
    .proxy(ProxyConfig::parse("socks5://user:pass@proxy:1080")?)
    .build();
```

### SessionPool 代理轮换

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
// guard 被 drop → Session 回归池中
```

### 动态代理提供者

```rust
let client = Client::builder()
    .preset(preset::chrome_146())
    .build();

let pool = SessionPool::builder()
    .client(&client)
    .proxy_fn(|| async {
        // 每次调用返回一个新的代理
        Ok(ProxyConfig::parse("http://rotating-proxy.example.com:8080")?)
    })
    .build();
```

## DNS 配置

```rust
use lkrequest::{Client, DnsConfig};

// 预设解析器
let client = Client::builder().dns(DnsConfig::System).build();          // 系统默认
let client = Client::builder().dns(DnsConfig::GoogleHttps).build();     // Google DoH
let client = Client::builder().dns(DnsConfig::CloudflareHttps).build(); // Cloudflare DoH
let client = Client::builder().dns(DnsConfig::Quad9Https).build();      // Quad9 DoH

// DoH 解析器还会获取 HTTPS/SVCB 记录，用于：
// - ECH（加密客户端 Hello）配置自动发现
// - H3 ALPN 提示，支持直接建立 QUIC 连接
```

## 连接预热

```rust
let session = client.session().build();

// 预建立连接（DNS + TCP + TLS + H2 SETTINGS，或 DNS + QUIC + H3）
session.preconnect("https://api.example.com").await?;

// 后续请求复用预热连接
let resp = session.get("https://api.example.com/data").send().await?;

// 批量并发预热多个源
session.preconnect_many(&[
    "https://api.example.com",
    "https://cdn.example.com",
]).await;
```

## 重试与重定向

### 重试策略

```rust
use lkrequest::retry::{RetryPolicy, ExponentialBackoff, FixedInterval};

let session = client.session()
    .retry_policy(ExponentialBackoff::new(3))  // 3 次指数退避重试
    .build();

// 或固定间隔
let session = client.session()
    .retry_policy(FixedInterval::new(3, Duration::from_secs(1)))
    .build();
```

### 重定向控制

```rust
use lkrequest::RedirectPolicy;

// 自动跟随最多 10 次重定向（默认）
let session = client.session().build();

// 禁用自动重定向
let session = client.session()
    .redirect_policy(RedirectPolicy::None)
    .build();

// 自定义次数限制
let session = client.session()
    .max_redirects(5)
    .build();
```

## WebSocket

```rust
let session = client.session().build();

// HTTP/1.1 Upgrade 或 H2 Extended CONNECT（根据连接自动选择）
let ws = session.websocket("wss://echo.websocket.org")
    .header("Origin", "https://example.com")
    .connect()
    .await?;
```

## 超时配置

```rust
use std::time::Duration;

let client = Client::builder()
    .dns_timeout(Duration::from_secs(5))           // DNS 解析超时
    .tcp_connect_timeout(Duration::from_secs(10))   // TCP 连接超时
    .tls_handshake_timeout(Duration::from_secs(10)) // TLS 握手超时
    .ttfb_timeout(Duration::from_secs(30))          // 首字节超时
    .total_timeout(Duration::from_secs(60))         // 总请求超时
    .build();
```

## 指纹验证

```rust
// 验证 TLS + H2 指纹
let resp = session.get("https://example.com/json").send().await?;
let json: serde_json::Value = resp.json()?;
println!("JA3:    {}", json["ja3_hash"]);
println!("JA4:    {}", json["ja4"]);
println!("Akamai: {}", json["akamai_hash"]);

// 验证 H3/QUIC 指纹
let h3_session = client.session().http3_only().build();
let resp = h3_session.get("https://quic.browserleaks.com/json").send().await?;
```

## 内置指纹配置

### TLS 配置

| 配置 | JA3 Hash | 浏览器 |
|------|----------|--------|
| `chrome_131()` | — | Chrome 131 (Windows) |
| `chrome_144()` | `991d71ee69967b7325077b71bad10393` | Chrome 144 (Windows) |
| `chrome_145()` | — | Chrome 145 (Windows) |
| `chrome_146()` | `991d71ee69967b7325077b71bad10393` | Chrome 146 (Windows) |
| `chrome_147()` | — | Chrome 147 (Windows) |
| `chrome_148()` | — | Chrome 148 (Windows) |
| `chrome_149()` | — | Chrome 149 (Windows) |
| `firefox_133()` | — | Firefox 133 |
| `firefox_147()` | — | Firefox 147 |
| `safari_18()` | — | Safari 18 (macOS) |
| `safari_26()` | — | Safari 26 (macOS) |

### 客户端预设（TLS + H2 + 可选 QUIC + 请求头/Cookie 顺序）

| 预设 | 包含内容 |
|------|----------|
| `preset::chrome_146()` | TLS + H2 + 可选 QUIC 配置 + 请求头顺序 + Cookie 顺序 |
| `preset::chrome_147()` | TLS + H2 + 可选 QUIC 配置 + 请求头顺序 + Cookie 顺序 |
| （更多） | 参见 `lkrequest/src/preset.rs` |

指纹配置以 JSON 文件形式定义在 `lktls/profiles/` 目录下，可使用 `profile_collector` 工具从抓包中提取自定义配置来扩展。

## TLS 能力

- TLS 1.2 和 TLS 1.3 握手（包括静态 RSA 密钥交换套件）
- 扩展顺序控制（对指纹匹配至关重要）
- GREASE 支持（密码套件、扩展、命名组）
- ECH（加密客户端 Hello）支持，通过 DNS 自动发现
- 会话恢复（PSK / Session Tickets）
- ALPS（应用层协议设置）
- 证书压缩（Brotli）
- 密码学后端：`aws-lc-rs`（支持 ML-KEM-768 后量子密钥交换、TLS 1.2 CBC）
- 证书验证，支持自定义 CA 根证书

## HTTP/2 能力

- SETTINGS 帧参数顺序控制
- 伪头顺序（`:method`、`:authority`、`:scheme`、`:path`）
- 连接级 WINDOW_UPDATE
- HEADERS 流依赖，支持可配置策略（Flat / Chain）
- 独立 PRIORITY 帧
- 每请求优先级，支持浏览器感知的 urgency-to-weight 映射（RFC 9218）

## HTTP/3 与 QUIC 能力

- 基于补丁版 quinn 的完整 QUIC UDP 传输
- QUIC 传输参数指纹（initial_max_data、max_streams 等）
- Alt-Svc 头解析，自动 H2→H3 升级
- HTTPS/SVCB DNS 记录解析，用于 H3 发现
- QUIC 会话恢复和 0-RTT
- QUIC 故障追踪，自动回退到 H2
- H3 专用请求头顺序控制

## FFI（C ABI）

`lkrequest-ffi` 为非 Rust 使用者提供稳定的 C ABI。

导出对象模型：
- `Client` / `Session` / `Request` / `Response` / `StreamingResponse` / `Error` / `Op`
- `ProxyPool` / `ProxyPoolBuilder` / `ProxyGuard`
- `SessionPool` / `SessionPoolBuilder` / `SessionPoolGuard`
- `Multipart`

FFI 覆盖功能：
- 同步 + 异步请求执行，支持 H1/H2/H3 协议选择
- 流式读取，含诊断信息和请求头查询
- Session Cookie CRUD、预连接、连接池统计
- ProxyPool / SessionPool 获取、标记坏代理
- Multipart/form-data 请求体
- DNS 预设/自定义配置和系统证书开关
- 文件日志和回调日志

公共 C 头文件由 `build.rs`（通过 cbindgen）在构建时生成于 `lkrequest-ffi/include/lkrequest.h`，不提交到仓库。

```bash
cargo test -p lkrequest-ffi
```

## 示例

```bash
# 基础用法
cargo run -p lkrequest --example basic_get
cargo run -p lkrequest --example post_json
cargo run -p lkrequest --example custom_headers

# 指纹验证
cargo run -p lkrequest --example fingerprint_check
cargo run -p lkrequest --example fingerprint_check_146
cargo run -p lkrequest --example fingerprint_compare

# HTTP/3 与 QUIC
cargo run -p lkrequest --features quic-h3 --example basic_h3
cargo run -p lkrequest --features quic-h3 --example h3_vs_h2
cargo run -p lkrequest --features quic-h3 --example h3_auto_discovery
cargo run -p lkrequest --features quic-h3 --example h3_fingerprint_check
cargo run -p lkrequest --features quic-h3 --example h3_session_resumption
cargo run -p lkrequest --features quic-h3 --example h3_dns_to_response
cargo run -p lkrequest --features quic-h3 --example fingerprint_compare_quic

# 代理与连接池
cargo run -p lkrequest --example session_pool
cargo run -p lkrequest --example proxy_pool

# 请求头顺序
cargo run -p lkrequest --example header_order_test

# ECH
cargo run -p lkrequest --example ech_test
```

## Cargo Features

| Feature | 默认 | 说明 |
|---------|------|------|
| `h2-native` | 是 | 使用 lkh2 原生 HPACK 编码器，实现完整 H2 指纹控制 |
| `quic-h3` | 否 | 启用 QUIC / HTTP/3 支持、QUIC 预设，以及 H3 相关示例和测试 |
| `network-e2e` | 否 | 启用公网集成测试（默认 CI 不运行） |

## License

Apache License 2.0 — Copyright 2026 EZXLabs
