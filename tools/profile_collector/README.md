# Profile Collector

`profile-collector` captures and compares browser network-layer fingerprints.
It can collect TLS/H2 and QUIC/H3 data from a local Chrome/Chromium binary in
headless mode, export the corresponding lkrequest Chrome preset, and compare the
two JSON files at field level.

The Chrome flow is implemented in Rust rather than as a platform shell script,
so it is usable on Windows, macOS, and Linux when the requested Chrome binary is
available.

## Supported Chrome Matrix

| Version | H2 Capture | H2 Preset Export | H3 Capture | H3 Preset Export |
|:--|:--|:--|:--|:--|
| `chrome_131` | yes | yes | yes | generic Chromium QUIC/H3 |
| `chrome_144` | yes | yes | yes | generic Chromium QUIC/H3 |
| `chrome_145` | yes | yes | yes | generic Chromium QUIC/H3 |
| `chrome_146` | yes | yes | yes | captured Chrome 146 QUIC/H3 |
| `chrome_147` | yes | yes | yes | generic Chromium QUIC/H3 |
| `chrome_148` | yes | yes | yes | generic Chromium QUIC/H3 |
| `chrome_149` | yes | yes | yes | generic Chromium QUIC/H3 |
| `chrome_150` | yes | yes | yes | generic Chromium QUIC/H3 |

`capture-chrome` takes any local Chrome/Chromium executable, including Chrome
for Testing milestone builds. Headless mode can change application-layer
headers, but the TLS, H2, QUIC transport, and H3 setup fields are the intended
comparison surface.

## Capture Chrome

H2:

```bash
cargo run -p profile-collector -- capture-chrome \
  --protocol h2 \
  --browser /path/to/chrome \
  --name "Chrome 148 H2" \
  -o target/captures/chrome_148_h2.json
```

H3:

```bash
cargo run -p profile-collector -- capture-chrome \
  --protocol h3 \
  --browser /path/to/chrome \
  --name "Chrome 148 H3" \
  -o target/captures/chrome_148_h3.json
```

Notes:

- `--browser` may be omitted when Chrome or Chromium is discoverable on `PATH`
  or in common platform install locations.
- H2 capture adds Chrome's `--dump-dom` flag automatically to force a single
  deterministic navigation. H3 capture keeps the browser process alive so the
  bootstrap page can retry until Chrome upgrades through `Alt-Svc`.
- The generated capture URL uses `127.0.0.1` instead of `localhost` so Chrome
  cannot choose IPv6 while the local capture sockets are bound on IPv4.
- `--chrome-arg` is repeatable for per-version flags.
- `--cert` and `--key` may be used for H3 capture when a locally trusted
  certificate is needed. Otherwise the tool generates a localhost certificate
  and launches Chrome with local insecure-certificate allowances.
- The H3 path uses a TCP bootstrap response with `Alt-Svc` and then waits for a
  real HTTP/3 request before writing JSON.

## Export Preset

```bash
cargo run -p profile-collector -- export-chrome-preset \
  --version chrome_148 \
  --protocol h2 \
  -o target/captures/lkrequest_chrome_148_h2.json
```

```bash
cargo run -p profile-collector -- export-chrome-preset \
  --version chrome_146 \
  --protocol h3 \
  -o target/captures/lkrequest_chrome_146_h3.json
```

For H3, `chrome_146` exports the captured QUIC/H3 profile. Other Chrome versions
export the generic Chromium QUIC/H3 profile until version-specific captures are
added.

## Field-Level Diff

```bash
cargo run -p profile-collector -- compare-json \
  --left target/captures/chrome_148_h2.json \
  --right target/captures/lkrequest_chrome_148_h2.json \
  --left-label chrome \
  --right-label lkrequest \
  -o target/captures/chrome_148_h2.diff.txt
```

Use `--json` when the diff should be consumed by CI or another tool:

```bash
cargo run -p profile-collector -- compare-json \
  --left target/captures/chrome_146_h3.json \
  --right target/captures/lkrequest_chrome_146_h3.json \
  --left-label chrome \
  --right-label lkrequest \
  --json \
  -o target/captures/chrome_146_h3.diff.json
```

The diff flattens nested objects and arrays, so mismatches are reported at paths
such as:

- `cipher_suites[0]`
- `extensions[4].extension_type`
- `h2_fingerprint.settings[2].value`
- `h2_fingerprint.akamai_fingerprint`
- `quic_fingerprint.transport_parameters[3].value`
- `quic_fingerprint.h3.settings[1].value`
- `quic_fingerprint.h3.pseudo_header_order[2]`
- `quic_fingerprint.packetization_fingerprint`

## Recommended Version Loop

Run the three commands for each supported version and protocol:

```bash
# H2
cargo run -p profile-collector -- capture-chrome --protocol h2 --browser /path/to/chrome -o target/captures/chrome_148_h2.json
cargo run -p profile-collector -- export-chrome-preset --version chrome_148 --protocol h2 -o target/captures/lkrequest_chrome_148_h2.json
cargo run -p profile-collector -- compare-json --left target/captures/chrome_148_h2.json --right target/captures/lkrequest_chrome_148_h2.json --left-label chrome --right-label lkrequest -o target/captures/chrome_148_h2.diff.txt

# H3
cargo run -p profile-collector -- capture-chrome --protocol h3 --browser /path/to/chrome -o target/captures/chrome_148_h3.json
cargo run -p profile-collector -- export-chrome-preset --version chrome_148 --protocol h3 -o target/captures/lkrequest_chrome_148_h3.json
cargo run -p profile-collector -- compare-json --left target/captures/chrome_148_h3.json --right target/captures/lkrequest_chrome_148_h3.json --left-label chrome --right-label lkrequest -o target/captures/chrome_148_h3.diff.txt
```

Replace `chrome_148` and `/path/to/chrome` with the milestone being validated.
