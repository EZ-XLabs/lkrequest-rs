# Browser ClientHello Baselines

本目录存放从真实浏览器抓取的 ClientHello 原始 hex 数据，用作 `pcap-diff` 的对比基准。

## 采集步骤

### 方法一：Wireshark 抓包

1. **安装 Wireshark** 并启动抓包
2. **设置过滤器**: `tls.handshake.type == 1`
3. **打开目标浏览器**, 访问 `https://example.com/api/all`
4. **找到 ClientHello 包**, 右键 → Copy → "...as Hex Stream"
5. **粘贴到对应的 `.hex` 文件中**

### 方法二：profile-collector capture

```bash
cargo run -p profile-collector -- capture --port 8443 --name "Chrome 146" -o chrome_146.json
```
然后浏览器访问 `https://localhost:8443`，同时可抓取 TLS + HTTP/2 指纹。

## 文件格式

- 每行为 hex 字符 (0-9, a-f, A-F)
- 以 `#` 开头的行为注释，会被自动忽略
- 空格和换行会被自动忽略
- hex 应从 TLS Record Header 开始: `16 03 01 ...`

## 当前基准

| 文件 | 浏览器 | 状态 |
|:---|:---|:---|
| `chrome_131.hex` | Chrome 131 (Windows) | 🔲 待采集（旧版，建议更新至 Chrome 146+） |
| `firefox_133.hex` | Firefox 133 (Windows) | 🔲 待采集（旧版，建议更新至 Firefox 149+） |
| `safari_18.hex` | Safari 18 (macOS) | 🔲 待采集（旧版，建议更新至 Safari 26+） |

> **注意**: 上述基准文件对应的浏览器版本已过时。当前最新稳定版：
> - Chrome 146 (2026-03-10)
> - Firefox ~149 (2026-03)
> - Safari 26.3+ (2026-02)
>
> 建议抓取最新版本的 ClientHello 并更新文件名。

## 验证

采集完成后，可以用 `pcap-diff` 工具验证解析是否正确：

```bash
cargo run -p pcap-diff -- annotate baselines/chrome_131.hex
cargo run -p pcap-diff -- info baselines/chrome_131.hex
```
