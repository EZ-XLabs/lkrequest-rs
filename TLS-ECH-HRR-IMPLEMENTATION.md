# TLS ECH / HelloRetryRequest 实现记录

## 基线与变动标签

- lkrequest 基线：`90ff401e90c21e1bed8b0c7b4bddc9051cc4c629`
- 更新日期：2026-07-30
- 稳定协议基线：RFC 9846（TLS 1.3）、RFC 9849（ECH）
- 易变实现基线：更新日期当天的 Chromium LKGR 与 BoringSSL `main`

变动等级：

- **低**：RFC 协议不变量。
- **中**：BoringSSL 内部状态和函数组织可能变化，但 wire 行为应保持。
- **高**：Chromium 策略、Feature/Finch、默认开关、GREASE 分布和具体浏览器指纹，升级版本时必须重新抓包。

## 差异与当前状态

| 项目 | Chromium / BoringSSL | 修复前实现 | 2026-07-29 状态 | 变动等级 |
|---|---|---|---|---|
| 初始 real ECH | 构造 Inner/Outer，选择 ECHConfig 与 HPKE suite | 已有配置选择、AAD、padding 和 HPKE seal | 保留 | 低/中 |
| HRR ECH confirmation | 解析并验证 HRR `encrypted_client_hello` confirmation | parser 忽略 | 已修复 | 低 |
| real ECH CH2 | 复用 config/suite/HPKE context，`enc` 为空 | retry builder 绕过 real ECH | 已修复 | 低 |
| fake ECH CH2 | 完整复制 CH1 fake ECH extension | 重新随机生成 | 已修复 | 低 |
| CH1/CH2 扩展排列 | 同一握手复用一次 permutation | CH2 重新洗牌 | 已修复 | 低；具体排列算法为高 |
| Inner random | HRR 只允许规定字段变化 | CH2 Inner 重新生成 random | 已修复 | 低 |
| ECH transcript | 维护 Inner/Outer transcript，检查 HRR 与最终 SH 一致性 | 最终阶段临时拼接且 HRR 输入不完整 | 已修复核心路径 | 低 |
| PSK + HRR | 保留 identity 并基于 HRR transcript 重算 binder | CH2 丢失 PSK extension | 非 ECH 路径已修复 | 低 |
| ECH + PSK + HRR | PSK 仅位于 Inner；CH1 binder 覆盖 `Truncate(ClientHelloInner1)`，CH2 覆盖 `message_hash(ClientHelloInner1) + HRR + Truncate(ClientHelloInner2)` | PSK 被追加到 Outer，HRR 路径明确失败 | 已修复并增加 CH1/CH2 binder 回归 | 低 |
| cookie-only HRR | 保留原 key_share，仅加入 cookie | 强制要求 selected_group | 已修复 | 低 |
| HRR selected_group | 必须在 supported_groups 中且不能已在 CH1 key_share | 仅检查本地是否支持该算法 | 已修复 | 低 |
| HRR 扩展解析 | 拒绝重复、畸形和不允许的扩展 | 未知/部分畸形扩展被忽略 | 已收紧 | 低 |
| TLS 1.3 dummy CCS | 每个连接只发送一次兼容 CCS | HRR 后最终 ServerHello 又发送一次 | 已修复并抓包确认 | 中；浏览器实现策略可变 |
| ECH 策略 | Chromium 当前区分 Disabled、Opportunistic、Strict | 高层只有 ECHConfigList | 待高层阶段 | 高 |
| retry configs | 向策略层暴露并决定重试/失败 | `lktls` 解析后只写日志 | 待高层阶段 | 高/低 |
| H3 | QUIC TLS 与 TCP TLS 使用相同 ECH/HRR 语义 | 共享 `lktls` 缺陷 | HRR、0-RTT 撤销和 QUIC alert 映射已修复并通过 H3 端到端测试 | 中；Quinn 接口随版本可能变化 |

## TLS 状态模型

CH1 现在保存并在 CH2 复用：

- ClientRandom、Session ID、GREASE values。
- 完整 extension permutation。
- 完整 fake ECH extension bytes。
- real ECH 的 ECHConfig、HPKE cipher suite、sender context 和 Inner random。
- HRR 原始消息、Inner CH1 和 Inner CH2 transcript bytes。

real ECH CH2 使用相同 HPKE sender context 的下一个 sequence number，并发送空 `enc`。收到 HRR ECH confirmation 时使用 `hrr ech accept confirmation` label 验证；最终 ServerHello 继续检查服务器没有在 HRR 前后改变 ECH 接受状态。

非 ECH 的 PSK+HRR 会保留 ticket identity，并基于 `message_hash(CH1) + HRR + Truncate(CH2)` 重新计算 binder。real ECH 下 `pre_shared_key` 不再出现在 ClientHelloOuter，而是在 HPKE seal 前作为 ClientHelloInner 的最后一个扩展写入并回填 binder。CH2 使用 `message_hash(ClientHelloInner1) + HRR + Truncate(ClientHelloInner2)`，同时复用原 ECH HPKE sender context 并保持空 `enc`。

## 验证结果

- `cargo test -p lktls`：423 个单元测试和 3 个 doc-test 通过。
- `test_ech_psk_hrr_binders_cover_inner_client_hellos`：验证 CH1/CH2 Outer 均无 PSK、Inner 的 PSK 位于最后、CH1/CH2 binder 分别按 RFC 9849 transcript 独立重算。
- fake ECH HRR：CH1/CH2 ECH extension 完全相同，extension permutation 相同。
- real ECH HRR：config/suite 相同，CH2 `enc_len == 0`，Inner random 相同。
- HRR parser：识别 8-byte ECH confirmation，并在计算前正确清零。
- `cargo clippy -p lktls --all-targets -- -D warnings`：通过。
- `cargo test -p lktls-quic`：5 个测试通过；持久化 HPKE context 满足 QUIC Session 的 `Send + Sync` 要求。
- `cargo test -p lkh3`：26 个单元测试通过，包含 Chrome 150 独立 preset 校验。

### 2026-07-29 Outlook 真实网络抓包

验证对象：

- 浏览器基线：`browser_outlook_with_embedded_keys.pcapng`，`tcp.stream == 78`。
- lkrequest 最终修复后：`target/captures/lkrequest-outlook-hrr-fixed-20260729.pcapng`，`tcp.stream == 30`。
- lkrequest 本地复抓：`captures/lkrequest-outlook-chrome150-embedded-keys-20260729.pcapng`，`tcp.stream == 206`；stream 207 是 Mihomo 镜像。
- 目标 origin：`https://outlook.live.com/`；lkrequest 完成 TLS/HTTP 并收到 `417 Expectation Failed`。
- 本机流量经过 Mihomo，抓包中同一连接在两个接口上有镜像流；以下固定使用 stream 30，避免重复计数。

| 检查项 | 浏览器 stream 78 | lkrequest stream 30 | 结论 | 变动等级 |
|---|---|---|---|---|
| ClientHello 帧 | CH1=`795`，CH2=`802` | CH1=`322`，CH2=`383` | 均触发一次 HRR | 低 |
| HRR / 最终 ServerHello | `801` / `816` | `382` / `443` | 均选择 TLS_AES_256_GCM_SHA384 (`0x1302`) | 中；服务端选择可变 |
| HRR requested group | P-384 (`24`) | P-384 (`24`) | 匹配 | 中；服务端策略可变 |
| CH2 key_share | 仅 P-384 (`24`) | 仅 P-384 (`24`) | 匹配 | 低 |
| Client random | CH1/CH2 完全相同 | CH1/CH2 完全相同 | 匹配 RFC/Chromium 行为 | 低 |
| Legacy session ID | CH1/CH2 完全相同 | CH1/CH2 完全相同 | 匹配 | 低 |
| 扩展类型序列 | CH1/CH2 完全相同 | CH1/CH2 完全相同 | 修复生效 | 低；具体排列为高 |
| fake ECH config id | CH1/CH2 均为 `214` | CH1/CH2 均为 `129` | 单连接内复用；跨连接随机差异正常 | 高 |
| fake ECH `enc` | CH1/CH2 均为同一 32-byte 值 | CH1/CH2 均为同一 32-byte 值 | 逐字节复用 | 低；具体值为高 |
| fake ECH payload | CH1/CH2 均为同一 240-byte 值 | CH1/CH2 均为同一 176-byte 值 | 逐字节复用；长度分布可随版本变化 | 高 |
| 客户端 dummy CCS | 仅 CH2 前一次 | 仅 CH2 前一次 | 最终 ServerHello 后的重复 CCS 已消失 | 中 |

lkrequest 的 CH1/CH2 扩展类型序列均为：

```text
19018,18,27,35,65037,51,16,17613,23,10,13,65281,5,0,45,11,43,47802
```

浏览器的 CH1/CH2 扩展类型序列均为：

```text
35466,18,35,5,51,16,45,13,43,10,23,27,0,17613,11,65281,65037,56026
```

两条连接的 GREASE code point、排列、ECH config id、payload 长度和随机内容不应跨连接直接判等；应验证的稳定不变量是同一 HRR 握手内 CH1/CH2 的复用关系。此次抓包中这些不变量全部成立。该 Outlook 连接使用 fake/grease ECH，没有覆盖 real ECH accepted、HRR confirmation 或 retry configs；这些仍需本地可控 ECH 服务端单独验证。

lkrequest 本地复抓再次得到 `CH1(frame 21729) -> HRR(frame 22222) -> CH2(frame 22223) -> final ServerHello(frame 22235)`。浏览器 stream 78 与 lkrequest stream 206 都选择 `0x1302` 和 P-384 (`24`)；各自 CH1/CH2 的 random、legacy session ID、完整 extension type sequence、fake ECH config id/enc/payload 均逐字节复用，客户端 dummy CCS 都仅在 CH2 前出现一次。请求完成 H2 并收到 `417 Expectation Failed`。复抓 pcap 已嵌入 TLS secrets，未保留独立 keylog，也不应提交到 Git。

修复后的 record 顺序为：`CH1 <- HRR+CCS -> CCS+CH2 <- final ServerHello <- encrypted server flight -> encrypted Finished/application data`。最终 ServerHello 后不再出现第二条明文 CCS，与浏览器 stream 78 的流程一致。

TCP Sans-I/O 驱动现在会把本地 `LocalAlert` 序列化为 fatal Alert record，并通过连接器 best-effort 写回服务端；HRR `illegal_parameter` 在握手密钥安装前发送明文 `15 03 03 00 02 02 2f`。密钥安装后的本地告警复用当前 `RecordWriter`，因此按 TLS 1.3 encrypted alert 发送。该行为由 `local_hrr_error_queues_plaintext_fatal_alert` 锁定。

Outlook 是否返回 HRR 依赖服务端、出口和路由，属于版本/环境可变项；没有 HRR 本身不能判定客户端回归。包含具体目标路径、请求头或密钥日志配置的复抓程序只保留在本地，不提交到 Git。

### H3 / QUIC HRR 验证

QUIC 没有 TLS record layer，也不发送兼容 CCS。`QuicHandshakeDriver` 在 Initial CRYPTO 中发送 CH1；收到 HRR 后，在尚未安装 Handshake keys 的情况下返回 CH2，因此 CH2 继续位于 Initial CRYPTO。最终 ServerHello 到达后才向 quinn 提供 Handshake packet keys。

已增加本地强制 HRR 的真实 H3 端到端测试：服务端只启用 P-384，而 Chrome profile 的 `supported_groups` 包含 P-384、CH1 `key_share` 不包含 P-384，因此服务端必须发送 HRR。客户端完成 CH2、QUIC handshake、H3 control stream 和实际 request/response：

- `cargo test -p lktls-quic lktls_quic_hrr_with_p384_server_and_h3_request -- --nocapture`：通过。
- `cargo test -p lktls-quic`：5 个测试全部通过。
- QUIC CH1/CH2 的 `legacy_session_id` 均为空。
- QUIC Transport Parameters extension 在 CH1/CH2 中逐字节相同。
- CH2 仅发送 HRR 指定的 P-384 key_share。
- TLS HRR transcript、fake/real ECH CH2 和 selected_group 校验与 TCP 共用同一状态机。

H3 / QUIC 本轮修复：

| 项目 | 2026-07-29 状态 | 验证 | 变动等级 |
|---|---|---|---|
| HRR 后立即停止 0-RTT | 已增加 crypto-session 撤销信号；Quinn 收到 HRR 后立即撤销 0-RTT stream/packet 状态，不再等待握手完成 | `hrr_rejects_zero_rtt_before_handshake_completion` 通过 | 低协议语义；中/高 Quinn 内部接口 |
| 本地 TLS 错误到 QUIC error code | 已引入本地 fatal alert 语义；HRR 的 decode/illegal_parameter/unsupported_extension 等错误映射为 `CRYPTO_ERROR(0x100 + alert)` | `local_tls_alert_maps_to_quic_crypto_error` 通过 | 低 |
| 强制 HRR H3 请求 | CH1、HRR、CH2、最终 ServerHello、H3 request/response 完整成功 | `lktls_quic_hrr_with_p384_server_and_h3_request` 通过 | 低协议语义；中 packetization |

H3 / QUIC 后续验证项：

| 项目 | 当前状态 | 风险 |
|---|---|---|
| ECH + PSK + HRR 公网互操作 | 协议实现与本地 transcript 回归已完成，尚无稳定公网目标可同时触发 real ECH、PSK resumption 与 HRR | 需要可控 BoringSSL/QUICHE 服务端或固定浏览器实验环境补充 wire 对照 |
| 真实 Chromium H3+HRR 抓包 | 尚无可控公网目标稳定触发 | 本地互操作已证明协议路径，但 packetization、ACK/PADDING/CRYPTO fragmentation 仍需浏览器对照 |

### Chrome 150 QUIC / H3 preset

已新增独立的 `lktls::chrome_150_quic()`、`lkh3::chrome_150_h3()` 和
`lkh3::chrome_150_quic()`，`lkrequest::preset::chrome_150()` 不再复用
Chrome 146 的 QUIC TLS/H3 profile。

当前按 Chrome 150.0.7871.47 Outlook 抓包锁定：

- QUIC TLS 使用 Chrome 150 的 ML-DSA signature algorithms，并追加 QUIC 的 `rsa_pkcs1_sha1`。
- H3 QPACK table capacity `65536`、blocked streams `100`、field section size `262144`。
- 首请求 PRIORITY_UPDATE 为导航上下文 `u=0, i`。
- Initial DCID 长度 `8`、SCID 长度 `0`、Initial UDP payload 目标 `1250`。
- `initial_max_streams_uni=103`、`max_datagram_frame_size=65536`，不发送 `min_ack_delay`。
- 包含 `version_information`、`google_connection_options=ORIG` 和一字节 GREASE TP 占位；GREASE id/value 每连接随机化但保持一字节长度。

未作为 Chrome 150 稳定不变量锁定：精确 CRYPTO/PADDING fragmentation、TP 具体排列、GREASE 具体 ID/value、`google_initial_rtt` 数值。`PRIORITY_UPDATE` 也与请求类型相关；当前 `u=0, i` 只代表该 Outlook 导航样本。以上项目升级 milestone、平台或 Finch 配置后必须重新抓包。

## 后续工作

1. 向 `HandshakeResult` 和高层诊断暴露 ECH offered/accepted/retry configs。
2. 增加 Disabled/Opportunistic/Required 策略。
3. 增加按 origin、代理和网络隔离的 retry-config cache，最多自动重试一次。
4. 使用本地 BoringSSL/QUICHE 服务端覆盖 accepted、rejected、PSK、HRR 和 H3 互操作。
5. Chrome 具体 GREASE、扩展开关、PQ group 和排列算法必须按 milestone 与完整 build 号重新抓包，不作为长期不变量。
