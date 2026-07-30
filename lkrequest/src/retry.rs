//! Retry strategies for HTTP requests.
//!
//! Provides a [`RetryPolicy`] trait and built-in strategies for retrying
//! failed requests based on error type, HTTP status code, and configurable
//! backoff timing.
//!
//! # Replay safety (idempotency)
//!
//! A retry re-sends the (buffered) request body, so error-based retries are
//! gated on whether the request is safe to replay — the policy decides the
//! backoff, [`retry_is_replay_safe`] decides whether a replay is allowed at
//! all. Safe methods (`GET`/`HEAD`/`OPTIONS`/`TRACE`) are always retried;
//! non-idempotent methods (`POST`/`PUT`/`PATCH`/`DELETE`) are retried only
//! when the failure proves the request was never processed
//! (connection-establishment failures, HTTP/2 `REFUSED_STREAM`), or when the
//! request is explicitly marked [`Idempotency::Idempotent`](crate::Idempotency).
//! This prevents a timeout/reset *after* a `POST` was sent from silently
//! duplicating a side effect. Retryable status-code responses (429/502/503/…)
//! are retried regardless of method.
//!
//! # Built-in Strategies
//!
//! - [`ExponentialBackoff`]: Doubles the delay between retries (with jitter).
//! - [`FixedInterval`]: Waits a fixed duration between retries.
//!
//! # Usage
//!
//! ```rust,no_run
//! # use lkrequest::Client;
//! # use lktls::profile::presets;
//! use lkrequest::retry::ExponentialBackoff;
//!
//! # let client = Client::builder().fingerprint(presets::chrome_131()).build();
//! let session = client.session()
//!     .retry_policy(ExponentialBackoff::default())
//!     .build();
//! ```

use std::time::Duration;

use crate::error::Error;

// ---------------------------------------------------------------------------
// RetryPolicy trait
// ---------------------------------------------------------------------------

/// Policy that determines whether a failed request should be retried.
///
/// Implementors inspect the attempt number, error (if any), and HTTP status
/// code to decide whether to retry and how long to wait.
pub trait RetryPolicy: Send + Sync + std::fmt::Debug {
    /// Determine whether to retry after a failure.
    ///
    /// # Arguments
    ///
    /// * `attempt` - The current attempt number (1 = first retry, 2 = second, etc.)
    /// * `error` - The error from the request (if it failed at the transport/TLS/proxy level).
    /// * `status` - The HTTP status code (if a response was received).
    ///
    /// # Returns
    ///
    /// * `Some(duration)` — retry after waiting `duration`.
    /// * `None` — do not retry; propagate the error.
    fn should_retry(
        &self,
        attempt: u32,
        error: Option<&Error>,
        status: Option<http::StatusCode>,
    ) -> Option<Duration>;
}

// ---------------------------------------------------------------------------
// Default retryable status codes
// ---------------------------------------------------------------------------

/// Default set of HTTP status codes that should trigger a retry.
///
/// Includes server errors and rate limiting responses:
/// - 429 Too Many Requests
/// - 502 Bad Gateway
/// - 503 Service Unavailable
/// - 520-530 Cloudflare custom errors
pub fn is_retryable_status(status: http::StatusCode) -> bool {
    matches!(status.as_u16(), 429 | 502 | 503 | 520..=530)
}

// ---------------------------------------------------------------------------
// Replay safety (idempotency-aware retry gate)
// ---------------------------------------------------------------------------

/// Whether a request that failed with `error` is safe to **auto-retry** given
/// its HTTP method and idempotency setting.
///
/// A retry re-sends the (fully buffered) request body, so a non-idempotent
/// request — `POST`/`PUT`/`PATCH`/`DELETE`, or any custom non-safe method —
/// must only be retried when **either**:
///
/// - the failure proves the server never processed the request
///   ([`Error::is_safe_to_replay`]: connection-establishment failures and
///   HTTP/2 `REFUSED_STREAM`); or
/// - the caller has declared the request replay-safe via
///   [`Idempotency::Idempotent`](crate::Idempotency) (e.g. it carries an
///   `Idempotency-Key` header).
///
/// Safe methods (`GET`/`HEAD`/`OPTIONS`/`TRACE`) are always replay-safe. This
/// mirrors Chromium's transaction-restart rules and reqwest's behaviour: a
/// timeout or connection reset that occurs *after* a `POST` was transmitted is
/// not auto-retried, because the server may already have applied it and a
/// silent replay would duplicate the side effect.
///
/// The [`RetryPolicy`] still decides *whether and how long* to back off; this
/// gate is an additional safety check applied to the error-retry path.
pub fn retry_is_replay_safe(
    method: &http::Method,
    idempotency: crate::session::Idempotency,
    error: &Error,
) -> bool {
    error.is_safe_to_replay() || crate::session::can_send_early_data(method, idempotency)
}

// ---------------------------------------------------------------------------
// ExponentialBackoff
// ---------------------------------------------------------------------------

/// Exponential backoff retry strategy with optional jitter.
///
/// Delay doubles with each retry: base_delay * 2^(attempt-1), capped at max_delay.
/// When jitter is enabled, a random factor ±25% is applied to avoid thundering herd.
///
/// # Default Configuration
///
/// - `max_retries`: 3
/// - `base_delay`: 500ms
/// - `max_delay`: 30s
/// - `jitter`: true
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    /// Maximum number of retries before giving up.
    pub max_retries: u32,
    /// Base delay for the first retry.
    pub base_delay: Duration,
    /// Maximum delay between retries.
    pub max_delay: Duration,
    /// Whether to add random jitter (±25%) to the delay.
    pub jitter: bool,
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
            jitter: true,
        }
    }
}

impl ExponentialBackoff {
    /// Create with custom settings.
    pub fn new(max_retries: u32, base_delay: Duration, max_delay: Duration) -> Self {
        Self {
            max_retries,
            base_delay,
            max_delay,
            jitter: true,
        }
    }

    /// Enable or disable jitter.
    pub fn with_jitter(mut self, jitter: bool) -> Self {
        self.jitter = jitter;
        self
    }
}

impl RetryPolicy for ExponentialBackoff {
    fn should_retry(
        &self,
        attempt: u32,
        error: Option<&Error>,
        status: Option<http::StatusCode>,
    ) -> Option<Duration> {
        if attempt > self.max_retries {
            return None;
        }

        // Check if the error/status is retryable
        let retryable = match (error, status) {
            (Some(e), _) => e.is_retryable(),
            (None, Some(s)) => is_retryable_status(s),
            (None, None) => false,
        };

        if !retryable {
            return None;
        }

        // Calculate delay: base_delay * 2^(attempt-1)
        let multiplier = 2u64.saturating_pow(attempt.saturating_sub(1));
        let delay_ms = self.base_delay.as_millis() as u64 * multiplier;
        let delay_ms = delay_ms.min(self.max_delay.as_millis() as u64);

        let delay = if self.jitter {
            apply_jitter(delay_ms)
        } else {
            Duration::from_millis(delay_ms)
        };

        Some(delay)
    }
}

// ---------------------------------------------------------------------------
// FixedInterval
// ---------------------------------------------------------------------------

/// Fixed interval retry strategy — waits a constant duration between retries.
///
/// # Default Configuration
///
/// - `max_retries`: 3
/// - `interval`: 1s
#[derive(Debug, Clone)]
pub struct FixedInterval {
    /// Maximum number of retries before giving up.
    pub max_retries: u32,
    /// Fixed delay between retries.
    pub interval: Duration,
}

impl Default for FixedInterval {
    fn default() -> Self {
        Self {
            max_retries: 3,
            interval: Duration::from_secs(1),
        }
    }
}

impl FixedInterval {
    /// Create with custom settings.
    pub fn new(max_retries: u32, interval: Duration) -> Self {
        Self {
            max_retries,
            interval,
        }
    }
}

impl RetryPolicy for FixedInterval {
    fn should_retry(
        &self,
        attempt: u32,
        error: Option<&Error>,
        status: Option<http::StatusCode>,
    ) -> Option<Duration> {
        if attempt > self.max_retries {
            return None;
        }

        let retryable = match (error, status) {
            (Some(e), _) => e.is_retryable(),
            (None, Some(s)) => is_retryable_status(s),
            (None, None) => false,
        };

        if retryable {
            Some(self.interval)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Apply ±25% random jitter to a delay.
fn apply_jitter(delay_ms: u64) -> Duration {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};

    let rng = SystemRandom::new();
    let mut buf = [0u8; 4];
    if rng.fill(&mut buf).is_ok() {
        let random_u32 = u32::from_ne_bytes(buf);
        // Map to range [0.75, 1.25]
        let factor = 0.75 + (random_u32 as f64 / u32::MAX as f64) * 0.5;
        let jittered = (delay_ms as f64 * factor) as u64;
        Duration::from_millis(jittered.max(1))
    } else {
        Duration::from_millis(delay_ms)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exponential_backoff_within_max_retries() {
        let policy = ExponentialBackoff {
            max_retries: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            jitter: false,
        };

        let timeout_error = Error::timeout("test", None, None);

        // Attempt 1: 100ms
        let d1 = policy.should_retry(1, Some(&timeout_error), None).unwrap();
        assert_eq!(d1, Duration::from_millis(100));

        // Attempt 2: 200ms
        let d2 = policy.should_retry(2, Some(&timeout_error), None).unwrap();
        assert_eq!(d2, Duration::from_millis(200));

        // Attempt 3: 400ms
        let d3 = policy.should_retry(3, Some(&timeout_error), None).unwrap();
        assert_eq!(d3, Duration::from_millis(400));

        // Attempt 4: exceeded max_retries
        assert!(policy.should_retry(4, Some(&timeout_error), None).is_none());
    }

    #[test]
    fn test_exponential_backoff_max_delay_cap() {
        let policy = ExponentialBackoff {
            max_retries: 10,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(5),
            jitter: false,
        };

        let timeout_error = Error::timeout("test", None, None);
        let d = policy.should_retry(5, Some(&timeout_error), None).unwrap();
        assert_eq!(d, Duration::from_secs(5)); // 1*16=16, capped at 5
    }

    #[test]
    fn test_non_retryable_error_returns_none() {
        let policy = ExponentialBackoff::default();
        let config_error = Error::InvalidConfig("test".into());
        assert!(policy.should_retry(1, Some(&config_error), None).is_none());
    }

    #[test]
    fn test_retryable_status_codes() {
        assert!(is_retryable_status(http::StatusCode::TOO_MANY_REQUESTS));
        assert!(is_retryable_status(http::StatusCode::BAD_GATEWAY));
        assert!(is_retryable_status(http::StatusCode::SERVICE_UNAVAILABLE));
        assert!(!is_retryable_status(http::StatusCode::OK));
        assert!(!is_retryable_status(http::StatusCode::NOT_FOUND));
        assert!(!is_retryable_status(
            http::StatusCode::INTERNAL_SERVER_ERROR
        ));
    }

    #[test]
    fn test_fixed_interval() {
        let policy = FixedInterval::new(2, Duration::from_millis(500));
        let timeout_error = Error::timeout("test", None, None);

        let d1 = policy.should_retry(1, Some(&timeout_error), None).unwrap();
        assert_eq!(d1, Duration::from_millis(500));

        let d2 = policy.should_retry(2, Some(&timeout_error), None).unwrap();
        assert_eq!(d2, Duration::from_millis(500));

        assert!(policy.should_retry(3, Some(&timeout_error), None).is_none());
    }

    #[test]
    fn poc_non_idempotent_post_not_replayed_after_post_send_failure() {
        use crate::error::{ConnectionClosedKind, ConnectionError, ConnectionPhase};
        use crate::session::Idempotency;

        // A response timeout can fire *after* the request bytes were
        // transmitted — the server may already have processed the POST. The
        // backoff policy alone (the only pre-fix gatekeeper) treats it as
        // retryable, which is exactly how the duplicate-POST bug arose:
        let policy = ExponentialBackoff::default();
        let post_send = Error::timeout("response timeout", None, None);
        assert!(
            policy.should_retry(1, Some(&post_send), None).is_some(),
            "baseline: the backoff policy alone treats a timeout as retryable",
        );

        // ...but replaying a POST risks a duplicate side effect, so the replay
        // gate must refuse it.
        assert!(
            !retry_is_replay_safe(&http::Method::POST, Idempotency::Default, &post_send),
            "POST must not be auto-replayed after a possibly-processed failure",
        );

        // Safe methods (RFC 9110 §9.2.1) are always replay-safe.
        assert!(retry_is_replay_safe(
            &http::Method::GET,
            Idempotency::Default,
            &post_send
        ));

        // An explicit replay guard (e.g. an Idempotency-Key) opts a POST in.
        assert!(retry_is_replay_safe(
            &http::Method::POST,
            Idempotency::Idempotent,
            &post_send
        ));

        // A failure that proves the request was never processed is replay-safe
        // for any method — pre-send connection failure...
        let pre_send = Error::Connection(Box::new(ConnectionError {
            phase: ConnectionPhase::TcpConnect,
            message: "connection refused".into(),
            source: None,
        }));
        assert!(retry_is_replay_safe(
            &http::Method::POST,
            Idempotency::Default,
            &pre_send
        ));

        // ...and HTTP/2 REFUSED_STREAM (declined before processing).
        let refused = Error::ConnectionClosed {
            phase: ConnectionPhase::HttpRequest,
            kind: ConnectionClosedKind::RefusedStream,
            message: "refused stream".into(),
        };
        assert!(retry_is_replay_safe(
            &http::Method::POST,
            Idempotency::Default,
            &refused
        ));

        // An explicit opt-out is never replayed on a post-send failure.
        assert!(!retry_is_replay_safe(
            &http::Method::DELETE,
            Idempotency::NotIdempotent,
            &post_send
        ));
    }

    #[test]
    fn test_retry_on_status_code() {
        let policy = ExponentialBackoff {
            max_retries: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            jitter: false,
        };

        // 429 should trigger retry
        let d = policy.should_retry(1, None, Some(http::StatusCode::TOO_MANY_REQUESTS));
        assert!(d.is_some());

        // 200 should not
        let d = policy.should_retry(1, None, Some(http::StatusCode::OK));
        assert!(d.is_none());
    }
}
