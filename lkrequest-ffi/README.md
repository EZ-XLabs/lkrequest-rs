# lkrequest-ffi

`lkrequest-ffi` is the stable C ABI facade for `lkrequest`.

It exposes the high-value parts of the Rust client to C/C++/Go/Python style bindings without leaking Rust async, ownership, or internal transport details across the ABI boundary.

## Build Output

`lkrequest-ffi` builds both:

- `cdylib`: native dynamic library for external language bindings
- `rlib`: internal Rust reuse and testing

Manifest: `lkrequest-ffi/Cargo.toml`.

Public C header (generated, **not committed** — git-ignored):

- `include/lkrequest.h`

`build.rs` regenerates it from the export surface via `cbindgen` on every
`cargo build` / `cargo test`. To produce or refresh it manually:

```bash
cd lkrequest-ffi
cbindgen . --config cbindgen.toml > include/lkrequest.h
```

The Rust crate builds without `cbindgen`; in that case header generation is
skipped with a build warning.

## Object Model

Current exported opaque handles:

- `lk_client_t`
- `lk_session_t`
- `lk_request_t`
- `lk_response_t`
- `lk_streaming_response_t`
- `lk_error_t`
- `lk_op_t`
- `lk_proxy_pool_t`
- `lk_proxy_pool_builder_t`
- `lk_proxy_guard_t`
- `lk_session_pool_t`
- `lk_session_pool_builder_t`
- `lk_session_pool_guard_t`
- `lk_multipart_t`

## Current Coverage

Implemented ABI surface includes:

- Sync + async request execution
- Streaming reads and chunk ops
- Response text / cookies / redirect history / diagnostics
- Streaming diagnostics and header-by-name lookup
- Session cookie CRUD
- Session preconnect sync/async
- Session connection-pool stats / clear
- Request `cookie_override`
- Multipart/form-data handles and request integration
- ProxyPool builder / acquire / acquire_async / acquire_fresh / mark_bad
- SessionPool builder / acquire / acquire_async / acquire_fresh / mark_bad
- DNS preset / custom socket address / native cert toggle
- File logging and callback logging
- Fingerprint randomization policy (`lk_client_builder_set_randomize`)

## Fingerprint Randomization

`lk_client_builder_set_randomize(builder, mode, layers)` selects how much of the
emitted fingerprint varies:

| `lk_randomize_mode_t` | Effect | Requires |
|---|---|---|
| `LK_RANDOMIZE_OFF` | the preset's fingerprint as-is | — |
| `LK_RANDOMIZE_EXTENSION_ORDER` | per-connection TLS extension-order jitter (still a real browser; drifts JA3, not JA4) | — |
| `LK_RANDOMIZE_RECOMBINE` | per-session synthetic identity recombined from the real-browser corpus | `synthetic-fp` |
| `LK_RANDOMIZE_FULL` | recombine **plus** out-of-corpus H2/QUIC values (widest divergence) | `synthetic-fp` |

`layers` is a bitmask applied to the synthetic modes only —
`LK_FP_LAYER_TLS | LK_FP_LAYER_H2 | LK_FP_LAYER_QUIC`; `0` means all layers (the
safe default). Unselected layers keep the client's real preset.

The synthetic modes (`RECOMBINE` / `FULL`) require building `lkrequest-ffi` with
the **`synthetic-fp`** feature (and **`quic-h3`** for the QUIC layer); without it
the setter returns an error rather than silently doing nothing. They emit
fingerprints that match **no** real browser — use only against negative-model
(blocklist) targets, never an allowlist.

```c
lk_client_builder_t *b = lk_client_builder_new();
lk_client_builder_set_preset(b, "chrome_146");

/* Tier 1 — real-browser per-connection jitter (always available): */
lk_client_builder_set_randomize(b, LK_RANDOMIZE_EXTENSION_ORDER, 0);

/* Tier 3a — fresh synthetic identity per session, all layers (synthetic-fp): */
lk_client_builder_set_randomize(b, LK_RANDOMIZE_RECOMBINE, 0);

/* Or synthesize only TLS, keeping the real H2/H3 preset: */
lk_client_builder_set_randomize(b, LK_RANDOMIZE_RECOMBINE, LK_FP_LAYER_TLS);
```

## ABI Notes

Important integration rules:

- All exported objects are opaque handles and must be released with their matching `free` function.
- `Client`, `Session`, and `Op` are shareable handles.
- `Request` and `StreamingResponse` are single-owner handles and must not be driven concurrently.
- Borrowed output pointers are owned by the handle that produced them.
- Borrowed chunk pointers from streaming reads are invalidated by the next mutating stream read, close, or free.
- String-returning `const char*` JSON getters are NUL-terminated.
- `lk_session_get_cookie()` returns a borrowed pointer backed by `SessionHandle` cache; it remains valid until a later cookie getter/mutator on that session or `lk_session_free()`.

There is one naming deviation from the original v2 draft:

- Session-local connection pool APIs are exported as `lk_session_connection_pool_stats` and `lk_session_connection_pool_clear`

This avoids ABI name collision with `lk_session_pool_t`.

## Runtime Model

`lkrequest-ffi` uses an internal global Tokio runtime.

Bindings do not need to provide:

- Tokio runtime handles
- wakers
- event-loop callbacks

Operations that create async work internally, including `ProxyPool` / `SessionPool` build and bad-marking paths, are routed back into the library runtime inside the facade.

## Recommended Verification

Before changing exported ABI or handle semantics, run:

```bash
cargo fmt --all
cargo test -p lkrequest-ffi
cargo clippy -p lkrequest-ffi --all-targets --all-features -- -D warnings
```

If the header changed:

```bash
cd lkrequest-ffi
cbindgen . --config cbindgen.toml > include/lkrequest.h
```

`build.rs` already does this during normal Rust builds; the command above is only the manual fallback.

## Test Layout

Current integration tests are organized by responsibility:

- `tests/request_api_basics.rs`
  - ABI smoke
  - sync request/response basics
  - async op basics
- `tests/streaming_diagnostics_and_configuration.rs`
  - streaming sync/async
  - decoded streaming
  - diagnostics
  - builder configuration coverage
- `tests/ffi_contract_edge_cases.rs`
  - single-consume guarantees
  - wrong `take_*` API behavior
  - header lookup edge cases
  - debug-registry stale handle checks
- `tests/v2_capabilities_smoke.rs`
  - Response/Session v2 getters
  - Multipart
  - ProxyPool / SessionPool
  - DNS builder extensions
  - logging callback

C ABI smoke test:

- `tests/c_smoke.c`

## Windows C Smoke Example

```powershell
$env:PATH='D:\Misc\tools\cygwin\bin;' + $env:PATH
& 'D:\Misc\tools\cygwin\bin\x86_64-w64-mingw32-gcc.exe' `
  -I lkrequest-ffi\include `
  -o target\debug\c_smoke.exe `
  lkrequest-ffi\tests\c_smoke.c `
  target\debug\lkrequest_ffi.dll.lib

$env:PATH='D:\Project\lkrequest\target\debug;D:\Misc\tools\cygwin\bin;' + $env:PATH
& 'D:\Project\lkrequest\target\debug\c_smoke.exe'
```

## Tracked References

- `lkrequest-ffi/Cargo.toml`
- `lkrequest-ffi/cbindgen.toml`
- `lkrequest-ffi/src/`
- `lkrequest-ffi/tests/`
