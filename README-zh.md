# lkrequest

<p align="center">
  <strong>面向 Rust HTTP 客户端的字节级浏览器指纹控制。</strong>
</p>

<p align="center">
  <a href="README.md">English</a> ·
  <a href="CONTRIBUTING.md">参与贡献</a> ·
  <a href="SECURITY.md">安全说明</a> ·
  <a href="LICENSE.txt">Apache-2.0</a>
</p>

<p align="center">
  <img alt="Version 0.2.1" src="https://img.shields.io/badge/version-0.2.1-4c1.svg">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-2021%2B-orange.svg">
  <img alt="TLS" src="https://img.shields.io/badge/TLS-byte--level-blue.svg">
  <img alt="HTTP/3" src="https://img.shields.io/badge/HTTP%2F3-optional-5c2d91.svg">
  <img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg">
</p>

`lkrequest` 是一个提供 **TLS、HTTP/2 与 HTTP/3/QUIC 线缆级控制** 的 Rust HTTP 客户端工作区。它适用于浏览器协议研究、互操作测试、指纹验证，以及普通高层 HTTP 客户端无法暴露底层格式的受控自动化场景。

项目的核心不变量是：**浏览器预设应在网络线缆上匹配目标浏览器**。即使某项修改在协议层面合法，只要偏离真实浏览器输出，也会被视为回归。

> [!IMPORTANT]
> 当前项目以源码工作区形式使用，并依赖经过补丁修改的 `quinn` 与 `h3` git submodule。构建前必须初始化子模块。

> [!WARNING]
> 仅在你拥有测试授权的系统和目标上使用本项目。请阅读[安全与负责任使用说明](SECURITY.md)。

## 核心能力

- **TLS ClientHello 控制** — 扩展顺序、GREASE、cipher suites、签名算法、key share、ECH、ALPS、证书压缩和握手行为。
- **原生 HTTP/2 指纹** — SETTINGS 顺序、WINDOW_UPDATE、PRIORITY、伪头顺序、HPACK 行为和请求优先级。
- **HTTP/3 与 QUIC** — 可选 H3 协议栈，支持 QUIC Transport Parameters、QPACK、PRIORITY_UPDATE、Alt-Svc、会话恢复和 SOCKS5 UDP。
- **真实抓包驱动的预设** — Chrome 131、144–151，Firefox 133/147，Safari 18/26。
- **浏览器式 Session** — 独立 Cookie、受物理连接上限约束的连接池、H2 stream 背压、重定向、重试、解压、流式响应、WebSocket、系统 DNS singleflight 与可选正向缓存，以及 HSTS 策略。
- **代理编排** — HTTP CONNECT、SOCKS5、多跳代理链、解析地址回退、`ProxyPool` 和 `SessionPool`。
- **稳定 C ABI** — `lkrequest-ffi` 将 Rust Client/Session/Request 模型暴露给其他语言。
- **离线回归门禁** — 实际序列化的 TLS/H2/QUIC 指纹会与仓库内 golden fixture 对比。

## 项目状态

- 当前工作区发布版本：**0.2.1**。
- API 已可使用，但在 1.0 前仍可能演进。
- 当前以**源码方式**集成；下面示例使用本地 checkout。
- HTTP/3、合成指纹、遥测和公网测试均为显式 opt-in。
- 浏览器指纹会受版本、平台、Finch、GREASE 与请求上下文影响。预设文档会区分已抓包确认的稳定字段和变量行为。

## 快速开始

### 1. Clone 与构建

`deps/quinn` 和 `deps/h3` 包含工作区所需的传输层补丁，因此 Git submodule 是必需的。

```bash
git clone --recurse-submodules <repository-url>
cd lkrequest
cargo test --workspace
```

如果已经 clone 但没有初始化子模块：

```bash
git submodule update --init --recursive
```

构建要求：

- Rust 工具链与 Cargo。
- 加密工具链需要时安装 NASM、CMake 和 libclang。
- 仅在生成或修改 C header 时需要 `cbindgen`。

### 2. 从本地工作区引用

在另一个 Rust 项目中：

```toml
[dependencies]
lkrequest = { path = "../lkrequest/lkrequest" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

启用 HTTP/3：

```toml
lkrequest = { path = "../lkrequest/lkrequest", features = ["quic-h3"] }
```

### 3. 使用明确的浏览器预设发送请求

```rust
use lkrequest::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder()
        .preset(lkrequest::preset::chrome_151())
        .build();

    // 一个 Session 对应一个虚拟浏览器用户；Cookie 和连接不会与其他
    // Session 共享。
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

运行仓库示例：

```bash
cargo run -p lkrequest --example basic_get
```

## HTTP/3 与 QUIC

启用 `quic-h3` feature 后选择明确的协议策略：

```rust
use lkrequest::Client;

let client = Client::builder()
    .preset(lkrequest::preset::chrome_151())
    .build();

// 优先使用 H3，QUIC 不可用时回退 H2。
let session = client.session().http3_with_fallback().build();
```

常用模式：

| 模式 | API | 行为 |
|---|---|---|
| 浏览器式 | 预设默认策略 | 使用发现机制，并记录 origin 的 QUIC 失败状态 |
| 仅 H3 | `http3_only()` | 不允许 TCP 回退 |
| H3 + 回退 | `http3_with_fallback()` | 优先 H3，失败后回退 H2 |
| 仅 H2 | `http2_only()` | 强制使用 TCP HTTP/2 |

```bash
cargo run -p lkrequest --features quic-h3 --example basic_h3
cargo run -p lkrequest --features quic-h3 --example h3_auto_discovery
cargo run -p lkrequest --features quic-h3 --example h3_session_resumption
```

## 浏览器预设

高层预设会打包 TLS、H2、可选 QUIC/H3、协议策略和请求头顺序：

| 浏览器家族 | 预设 |
|---|---|
| Chrome | `chrome_131`、`chrome_144`–`chrome_151` |
| Firefox | `firefox_133`、`firefox_147` |
| Safari | `safari_18`、`safari_26` |

为保证可复现性，建议明确指定版本：

```rust
let client = lkrequest::Client::builder()
    .preset(lkrequest::preset::chrome_151())
    .build();
```

Chrome 151 已通过 Windows 真实抓包验证。其 TCP TLS/H2 稳定字段与 Chrome 150 一致；多个公网 H3 站点的真实 QUIC 抓包使用经典 QUIC 签名算法列表并追加 `rsa_pkcs1_sha1`，不包含 TCP 中的三个 ML-DSA 项。

## 能力矩阵

| 能力 | 默认启用 | Feature / crate |
|---|---:|---|
| HTTP/1.1 | 是 | `lkrequest` |
| 可控指纹的原生 HTTP/2 | 是 | `h2-native` |
| HTTP/3 + QUIC | 否 | `quic-h3` |
| 公网 E2E 辅助测试 | 否 | `network-e2e` |
| 合成指纹 | 否 | `synthetic-fp` |
| 运行指标遥测 | 否 | `telemetry` |
| C ABI | 独立 crate | `lkrequest-ffi` |

合成模式会刻意生成不对应任何真实浏览器的指纹。它不是浏览器预设的替代品，也不应在需要 allowlist 身份的场景中使用。

TLS 1.2 与 TLS 1.3 服务端在“请求但不强制要求”客户端证书时可正常握手：`lkrequest` 会携带正确握手上下文发送空的客户端 `Certificate`。显式配置客户端身份以完成双向 TLS（mTLS）目前尚未进入公开 API。

## 代理、DNS 与 Session Pool

支持的代理路径：

- TCP 协议支持 HTTP CONNECT 与 SOCKS5。
- QUIC/H3 支持 SOCKS5 UDP。
- 支持多跳代理链；QUIC 链要求每一跳都支持 SOCKS5 UDP。
- 直连 TCP 与 SOCKS5 建连会按 resolver 返回顺序尝试多个地址，单个不可达的 IPv4 或 IPv6 地址不会直接终止整条路由。
- `ProxyPool` 用于代理分配与并发控制。
- `SessionPool` 用于复用虚拟浏览器 Session。
### 系统 DNS 并发合并与缓存

默认 `SystemDns` 会调用操作系统解析器，并在进程范围内自动合并相同 `(host, port)` 的并发查询，避免大量 Session 在同一时刻重复触发 `getaddrinfo`。当前等待者会共享成功结果或错误；单个等待者被取消不会取消共享查询；查询完成后默认不保留结果缓存。

如果同一批域名会在查询完成后被频繁重复访问，可以启用短周期正向缓存：

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

缓存属于当前 resolver 实例，只保存成功且非空的地址列表，不缓存错误。TTL 或容量设为零会关闭已完成结果缓存，但仍保留并发查询合并。Resolver 配置方法互相替换，因此 `.dns()`、`.dns_resolver()` 和 `.system_dns_cache()` 中最后一次调用生效。需要自定义 DNS 服务器、DoH/DoT、HTTPS/SVCB 记录或 ECH 发现时，应继续使用 `DnsConfig` 或自定义 `DnsResolver`。

常见选择：

- **同一 origin 的瞬时并发请求：** 直接使用默认配置，singleflight 会自动生效。
- **短时间内重复访问同一批域名：** 启用带 TTL 与容量限制的正向缓存。
- **强调权威 DNS 实时性或需要自定义 DNS 传输：** 保持缓存关闭，或使用自定义 resolver。

### 连接池限制与 0.2.1 迁移说明

连接上限按实际 H1/H2/H3 物理连接计数，而不是按复用请求数计数。原生 H2 会遵守对端的并发 stream 上限，并在容量耗尽时施加背压，而不是静默降级到 H1 或无限创建连接。重定向过程中遇到失效的池化 H1 连接时，会淘汰旧连接并通过正常重试策略重新建连。

新代码应通过 `Session` 配置和观察连接池：

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

0.2.0 已发布的低层 `ConnectionPool` 获取与写入方法在 0.2.1 中继续保持源码兼容，但已标记为 deprecated，因此 IDE 会提示迁移。现有调用方可以先升级版本再逐步改造；新集成应直接使用 Session 管理的连接池。这些兼容入口计划在 0.3.0 移除。

相关示例：

```bash
cargo run -p lkrequest --example proxy_pool
cargo run -p lkrequest --example session_pool
cargo run -p lkrequest --example proxy_dynamic
cargo run -p lkrequest --features quic-h3 --example h3_socks5_force
cargo run -p lkrequest --example dns_proxy_probe
```

## 架构

```text
lkrequest-ffi
      │
      ▼
lkrequest ───────────── 高层 Client / Session / Request API
  │       │       │
  ▼       ▼       ▼
lktls    lkh2    lkh3 + lkquic
  │                 │
  ▼                 ▼
lktls-quic       patched h3 / quinn submodules
```

| 组件 | 职责 |
|---|---|
| `lkrequest` | Session、请求、Cookie、连接池、代理、DNS、重试、重定向与流式响应 |
| `lktls` | Sans-I/O TLS 引擎与字节级 ClientHello profile |
| `lkh2` | 原生 H2 codec、HPACK、SETTINGS、优先级和请求头顺序 |
| `lkh3` | HTTP/3/QPACK profile 与 H3 请求行为 |
| `lkquic` | QUIC endpoint 与后端集成 |
| `lktls-quic` | QUIC 的 TLS 1.3 bridge |
| `lkprofile` | 指纹解析与规范化 |
| `lkrequest-ffi` | 稳定 C ABI 与生成的 C header |
| `tools/profile_collector` | 浏览器抓取与 preset 导出 |
| `tools/pcap_diff` | 字节级抓包比较 |
| `tools/fpverify` | 规范化指纹验证 |

## 指纹方法论

所有 profile 均遵循 **capture-first**：

1. 使用 `tools/profile_collector`、Wireshark/tshark 或受控本地服务抓取真实浏览器。
2. 将稳定字段与每连接、每请求上下文变量分开。
3. 在能够表达该行为的最高层建模。
4. 通过真实 TLS/H2/H3 实现完成序列化。
5. 与规范化抓包及仓库内 golden 文件对比。

不要为了让测试通过而手工修改 `lktls/profiles/*.json`。目标浏览器版本发生变化时，应重新抓取。

## 测试

默认 CI 完全离线且可确定：

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

QUIC/H3：

```bash
cargo test -p lkrequest --features quic-h3
```

公网测试默认标记为 ignored，仅应在得到明确授权后运行：

```bash
TEST_ALLOW_NETWORK=1 cargo test --workspace -- --include-ignored
```

测试分层和环境要求见 [docs/TESTING.md](docs/TESTING.md)。

## C ABI

`lkrequest-ffi` 为 Client、Session、Request、Response、流式读取、代理/Session Pool、multipart、错误和异步操作提供 opaque handle。

```bash
cargo test -p lkrequest-ffi
cargo clippy -p lkrequest-ffi --all-targets --all-features -- -D warnings
```

C header 从 Rust 导出自动生成：

```bash
cd lkrequest-ffi
cbindgen . --config cbindgen.toml > include/lkrequest.h
```

所有权、线程和 ABI 规则见 [lkrequest-ffi/README.md](lkrequest-ffi/README.md)。

## 文档与示例

- [测试指南](docs/TESTING.md)
- [贡献指南](CONTRIBUTING.md)
- [安全与负责任使用](SECURITY.md)
- [FFI 指南](lkrequest-ffi/README.md)
- [Rust 示例](lkrequest/examples)
- [指纹回归设计](docs/fingerprint-regression-design.md)
- [QUIC/H3 指纹说明](docs/chrome146-quic-h3-fingerprint.md)

## 参与贡献

欢迎贡献。指纹变更必须提供证据，说明新输出与真实浏览器抓包之间的关系。请明确区分源码修改、golden 更新、测试结果和经验性结论。

提交 Pull Request 前，请阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 并运行相关离线门禁。

## License

项目基于 [Apache License 2.0](LICENSE.txt) 发布。
