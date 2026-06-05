#![allow(dead_code)]
// Test support is compiled into many integration-test crates; not every helper is used in each binary.

pub mod local_https;
pub mod local_proxy;
pub mod local_wss;

/// When set to `1`, Tier-2 tests may be run (`cargo test -- --include-ignored`).
/// Default CI does not set this; see [docs/TESTING.md](../../../../docs/TESTING.md).
pub fn test_allow_network() -> bool {
    matches!(
        std::env::var("TEST_ALLOW_NETWORK").as_deref(),
        Ok("1" | "true" | "yes")
    )
}

#[allow(dead_code)]
/// Maximum retry attempts for network-dependent tests.
pub const MAX_RETRIES: u32 = 3;

#[allow(dead_code)]
/// Test proxy address. Reads from `TEST_PROXY` env var, falls back to `http://127.0.0.1:7897`.
pub fn test_proxy() -> String {
    std::env::var("TEST_PROXY").unwrap_or_else(|_| "http://127.0.0.1:7897".to_string())
}

/// Retry an async expression that returns `Result<T, E>` up to `$max` times.
///
/// On each failure, prints the error and waits 1 second before retrying.
/// Returns `T` on success, panics with `$msg` and the last error on exhaustion.
///
/// # Usage
/// ```ignore
/// let resp = retry!(3, session.get(url).send(), "request should succeed");
/// ```
#[allow(unused_macros)]
macro_rules! retry {
    ($max:expr, $expr:expr, $msg:expr) => {{
        let mut _last_err = String::new();
        let mut _result = None;
        for _attempt in 1..=$max {
            match $expr.await {
                Ok(v) => {
                    _result = Some(v);
                    break;
                }
                Err(e) => {
                    _last_err = format!("{e}");
                    if _attempt < $max {
                        eprintln!("  [retry {_attempt}/{}] {e}", $max);
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        }
        _result.unwrap_or_else(|| panic!("{}: {}", $msg, _last_err))
    }};
}

// Macro is auto-exported via #[macro_use] on `mod support;` in each test file.
