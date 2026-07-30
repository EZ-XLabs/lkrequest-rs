use std::sync::Arc;
use std::time::Duration;
use tracing::Instrument;

use http::HeaderMap;
use url::Url;

use crate::error::{Error, Result};
use crate::protocol::{HttpIntent, ProtocolPolicy};
use crate::proxy::ProxyConfig;
use crate::response::{HttpVersion, Response, StreamingResponse};

use super::next_request_id;
use super::streaming::StreamRequestBuilder;
use super::{AcceptEncoding, Idempotency, PreferredHttpVersion, Session};

/// Builder for a single HTTP request.
///
/// Created via `session.get(url)`, `session.post(url)`, etc.
///
/// # Merging headers vs. wire order
///
/// | What you want | Use |
/// |---------------|-----|
/// | Merge extra headers into the request (`HeaderMap` or one-by-one) | [`header`](Self::header), [`headers`](Self::headers), [`headers_with_order`](Self::headers_with_order), [`headers_ordered`](Self::headers_ordered) |
/// | Control **send order** of header *names* (fingerprint / browser-like ordering) | [`header_order`](Self::header_order) on the builder, or session/client defaults |
///
/// `headers_with_order` only affects **insertion order** for keys coming from a merged map; it does **not** replace [`header_order`](Self::header_order). When a TLS/H2 fingerprint template applies, its ordering rules can still take precedence over plain insertion order.
///
/// # Example
///
/// ```rust,no_run
/// # use lkrequest::Client;
/// # use lktls::profile::presets;
/// # use std::time::Duration;
/// # async fn example() -> Result<(), lkrequest::error::Error> {
/// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
/// # let session = client.session().build();
/// let resp = session.get("https://example.com")
///     .header("Accept", "application/json")
///     .bearer_auth("my-token")
///     .timeout(Duration::from_secs(5))
///     .send()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct RequestBuilder {
    pub(crate) session: Session,
    pub(crate) method: http::Method,
    pub(crate) url: String,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Option<bytes::Bytes>,
    pub(crate) query_params: Vec<(String, String)>,
    /// Request-level cookies (appended to jar cookies at send time).
    pub(crate) extra_cookies: Vec<(String, String)>,
    /// Cookie names that should fully replace all same-name jar cookies.
    pub(crate) cookie_overrides: Vec<String>,
    /// Per-request end-to-end deadline override (see [`RequestBuilder::timeout`]).
    pub(crate) timeout: Option<Duration>,
    /// Per-request proxy override (overrides session proxy).
    pub(crate) proxy_override: Option<ProxyConfig>,
    /// Per-request HTTP version override.
    pub(crate) version_override: Option<PreferredHttpVersion>,
    /// Per-request protocol policy override.
    pub(crate) protocol_policy_override: Option<ProtocolPolicy>,
    /// Per-request Accept-Encoding override.
    pub(crate) accept_encoding: Option<AcceptEncoding>,
    /// Whether to skip automatic response body decompression.
    pub(crate) no_decompress: bool,
    /// Per-request header sending order override.
    pub(crate) header_order: Option<Vec<http::header::HeaderName>>,
    /// Per-request HTTP/3-specific header sending order override.
    pub(crate) h3_header_order: Option<Vec<http::header::HeaderName>>,
    /// Per-request cookie sending order override.
    pub(crate) cookie_order: Option<Vec<Box<str>>>,
    /// Tracks the order in which headers were added via .header() calls.
    pub(crate) header_insertion_order: Vec<http::header::HeaderName>,
    /// Per-request RFC 9218 priority (urgency + incremental).
    /// Used to derive both the H2 HEADERS frame weight and the
    /// HTTP `priority` header.
    pub(crate) priority: Option<lkh2::RequestPriority>,
    /// Per-request 0-RTT / early-data gate. See [`Idempotency`].
    pub(crate) idempotency: Idempotency,
    /// Deferred error from infallible builder methods (e.g. json/form
    /// serialization failure). Surfaced at `send()` time so that the
    /// builder chain is never broken by `Result`.
    pub(crate) deferred_error: Option<Error>,
    /// When true, collect per-request diagnostics and attach them to the
    /// `Response`. Opt-in: off by default so the request hot path is unaffected.
    pub(crate) collect_diagnostics: bool,
}

/// Immutable request fields shared across retries via `Arc`.
///
/// When a retry policy is configured, this avoids deep-cloning `HeaderMap`,
/// `String`, and `Vec` fields on every retry attempt.  Only the `Arc`
/// reference count is incremented (O(1)).
pub(crate) struct SharedRequestContext {
    pub(crate) method: http::Method,
    pub(crate) url: String,
    pub(crate) headers: HeaderMap,
    pub(crate) query_params: Vec<(String, String)>,
    pub(crate) extra_cookies: Vec<(String, String)>,
    pub(crate) cookie_overrides: Vec<String>,
    pub(crate) timeout: Option<Duration>,
    pub(crate) proxy_override: Option<ProxyConfig>,
    pub(crate) version_override: Option<PreferredHttpVersion>,
    pub(crate) protocol_policy_override: Option<ProtocolPolicy>,
    pub(crate) no_decompress: bool,
    pub(crate) header_order: Option<Vec<http::header::HeaderName>>,
    pub(crate) h3_header_order: Option<Vec<http::header::HeaderName>>,
    pub(crate) cookie_order: Option<Vec<Box<str>>>,
    pub(crate) header_insertion_order: Vec<http::header::HeaderName>,
    pub(crate) priority: Option<lkh2::RequestPriority>,
    pub(crate) idempotency: Idempotency,
}

impl RequestBuilder {
    pub(crate) fn new(session: Session, method: http::Method, url: &str) -> Self {
        Self {
            session,
            method,
            url: url.to_string(),
            headers: HeaderMap::new(),
            body: None,
            query_params: Vec::new(),
            extra_cookies: Vec::new(),
            cookie_overrides: Vec::new(),
            timeout: None,
            proxy_override: None,
            version_override: None,
            protocol_policy_override: None,
            accept_encoding: None,
            no_decompress: false,
            header_order: None,
            h3_header_order: None,
            cookie_order: None,
            header_insertion_order: Vec::new(),
            priority: None,
            idempotency: Idempotency::default(),
            deferred_error: None,
            collect_diagnostics: false,
        }
    }

    /// Create a RequestBuilder from a shared context (used by retry loop).
    /// Only `session` (Arc) and `body` (Bytes, O(1) clone) are per-attempt.
    pub(crate) fn from_shared_context(
        session: Session,
        ctx: Arc<SharedRequestContext>,
        body: Option<bytes::Bytes>,
    ) -> Self {
        Self {
            session,
            method: ctx.method.clone(),
            url: ctx.url.clone(),
            headers: ctx.headers.clone(),
            body,
            query_params: ctx.query_params.clone(),
            extra_cookies: ctx.extra_cookies.clone(),
            cookie_overrides: ctx.cookie_overrides.clone(),
            timeout: ctx.timeout,
            proxy_override: ctx.proxy_override.clone(),
            version_override: ctx.version_override,
            protocol_policy_override: ctx.protocol_policy_override.clone(),
            accept_encoding: None,
            no_decompress: ctx.no_decompress,
            header_order: ctx.header_order.clone(),
            h3_header_order: ctx.h3_header_order.clone(),
            cookie_order: ctx.cookie_order.clone(),
            header_insertion_order: ctx.header_insertion_order.clone(),
            priority: ctx.priority,
            idempotency: ctx.idempotency,
            deferred_error: None,
            collect_diagnostics: false,
        }
    }

    /// Add a cookie to this request only (does not modify the session jar).
    ///
    /// When the outgoing `Cookie` header is built, pairs appear in this order:
    /// explicit `Cookie` header pairs (from [`header`](Self::header) /
    /// [`headers`](Self::headers)), then jar matches for names not overridden
    /// by those pairs, then request-level cookies from this method. If the jar
    /// already contains a cookie with the same name, **both** can be sent
    /// (the request-level one is appended after jar-derived pairs). This
    /// matches real browser behavior where the same cookie name can exist at
    /// different paths.
    ///
    /// Use [`cookie_override`](Self::cookie_override) to replace all
    /// same-name jar cookies instead.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://example.com")
    ///     .cookie("extra_token", "xyz")
    ///     .cookie("extra_token", "abc")  // both are sent
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn cookie(mut self, name: &str, value: &str) -> Self {
        self.extra_cookies
            .push((name.to_string(), value.to_string()));
        self
    }

    /// Add a cookie that **overrides** all same-name cookies from the jar.
    ///
    /// Unlike [`cookie`](Self::cookie), this removes all jar cookies with
    /// the same name and replaces them with the given value.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// // If jar has "token=old_val" at "/" and "token=api_val" at "/api",
    /// // this replaces both with a single "token=override".
    /// let resp = session.get("https://example.com/api")
    ///     .cookie_override("token", "override")
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn cookie_override(mut self, name: &str, value: &str) -> Self {
        self.extra_cookies
            .push((name.to_string(), value.to_string()));
        // Mark this name for full replacement (prefix with \0 as sentinel)
        self.cookie_overrides.push(name.to_string());
        self
    }

    /// Add a header to this request.
    ///
    /// For the `Cookie` header, values are merged with the session jar and
    /// [`cookie`](Self::cookie) entries at send time: your pairs are sent first
    /// and override the jar for the same cookie names.
    ///
    /// If `name` or `value` fails HTTP parsing, this call is a no-op (the header
    /// is skipped). Use [`header_typed`](Self::header_typed) with pre-validated
    /// values when you need explicit control.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        if let (Ok(n), Ok(v)) = (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            http::header::HeaderValue::from_str(value),
        ) {
            if !self.header_insertion_order.contains(&n) {
                self.header_insertion_order.push(n.clone());
            }
            self.headers.insert(n, v);
        }
        self
    }

    /// Add a header using pre-parsed `HeaderName` and `HeaderValue`.
    ///
    /// Avoids the parsing overhead of [`header()`](Self::header) when
    /// the caller already has typed header values.
    pub fn header_typed(
        mut self,
        name: http::header::HeaderName,
        value: http::header::HeaderValue,
    ) -> Self {
        if !self.header_insertion_order.contains(&name) {
            self.header_insertion_order.push(name.clone());
        }
        self.headers.insert(name, value);
        self
    }

    /// Add a set of headers to this request.
    ///
    /// Headers are merged into any already set on this request, with new
    /// values overriding existing ones for the same header name.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// use http::HeaderMap;
    ///
    /// let mut headers = HeaderMap::new();
    /// headers.insert("X-Custom", "value".parse().unwrap());
    /// headers.insert("Accept", "application/json".parse().unwrap());
    ///
    /// let resp = session.get("https://example.com")
    ///     .headers(headers)
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// `HeaderMap` does not guarantee a stable ordering when iterating. If you
    /// need a specific wire order when no client/session [`header_order`](Self::header_order)
    /// is set, use [`headers_with_order`](Self::headers_with_order) or
    /// [`headers_ordered`](Self::headers_ordered).
    pub fn headers(self, map: HeaderMap) -> Self {
        self.merge_header_map(map, None)
    }

    /// Merge a [`HeaderMap`] like [`headers`](Self::headers), but set **insertion
    /// order** for keys coming from `map` using `order` (field names as strings).
    ///
    /// Names listed in `order` are placed first (in that order); any other keys
    /// from `map` follow in their original map iteration order. Headers added
    /// earlier in the builder chain keep their relative positions **before** the
    /// keys merged from `map`.
    ///
    /// Invalid or unknown header names in `order` are skipped. This only affects
    /// insertion order when merging the map; it does **not** replace
    /// [`header_order`](Self::header_order) (fingerprint-style wire order).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # use http::HeaderMap;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let mut h = HeaderMap::new();
    /// h.insert("accept", "application/json".parse().unwrap());
    /// h.insert("cookie", "a=b".parse().unwrap());
    /// let _ = session
    ///     .get("https://example.com")
    ///     .headers_with_order(h, &["cookie", "accept"]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn headers_with_order(self, map: HeaderMap, order: &[&str]) -> Self {
        self.merge_header_map(map, Some(order))
    }

    /// Add many headers from an iterator of `(name, value)` pairs.
    ///
    /// Order on the wire (when no fingerprint `header_order` applies) matches
    /// iterator order; duplicate names only add to insertion order once (same
    /// rules as repeated [`header`](Self::header) calls).
    ///
    /// Pairs with invalid header names or values are skipped, matching
    /// [`header`](Self::header).
    pub fn headers_ordered<N, V>(mut self, pairs: impl IntoIterator<Item = (N, V)>) -> Self
    where
        N: AsRef<str>,
        V: AsRef<str>,
    {
        for (name, value) in pairs {
            if let (Ok(n), Ok(v)) = (
                http::header::HeaderName::from_bytes(name.as_ref().as_bytes()),
                http::header::HeaderValue::from_str(value.as_ref()),
            ) {
                if !self.header_insertion_order.contains(&n) {
                    self.header_insertion_order.push(n.clone());
                }
                self.headers.insert(n, v);
            }
        }
        self
    }

    fn merge_header_map(mut self, map: HeaderMap, order: Option<&[&str]>) -> Self {
        use std::collections::HashSet;

        let entries: Vec<(http::header::HeaderName, http::header::HeaderValue)> = map
            .into_iter()
            .filter_map(|(opt_n, v)| opt_n.map(|n| (n, v)))
            .collect();
        let map_names: HashSet<_> = entries.iter().map(|(n, _)| n.clone()).collect();

        if let Some(order_sl) = order {
            for (name, value) in &entries {
                self.headers.insert(name.clone(), value.clone());
            }
            self.header_insertion_order
                .retain(|n| !map_names.contains(n));
            let mut tail = Vec::new();
            let mut seen_in_tail = HashSet::new();
            for s in order_sl {
                if let Ok(n) = http::header::HeaderName::from_bytes(s.as_bytes()) {
                    if map_names.contains(&n)
                        && self.headers.contains_key(&n)
                        && seen_in_tail.insert(n.clone())
                    {
                        tail.push(n);
                    }
                }
            }
            for (n, _) in &entries {
                if !seen_in_tail.contains(n) {
                    tail.push(n.clone());
                    seen_in_tail.insert(n.clone());
                }
            }
            self.header_insertion_order.extend(tail);
        } else {
            for (name, value) in entries {
                if !self.header_insertion_order.contains(&name) {
                    self.header_insertion_order.push(name.clone());
                }
                self.headers.insert(name, value);
            }
        }

        self
    }

    /// Set the header **sending** order for this request only (fingerprint-style
    /// name order on the wire), not to be confused with merging a [`HeaderMap`]
    /// via [`headers`](Self::headers) / [`headers_with_order`](Self::headers_with_order).
    ///
    /// Overrides session-level and client-level `header_order`.
    pub fn header_order(mut self, order: Vec<&str>) -> Self {
        let names: Vec<http::header::HeaderName> = order
            .into_iter()
            .filter_map(|s| http::header::HeaderName::from_bytes(s.as_bytes()).ok())
            .collect();
        if !names.is_empty() {
            self.header_order = Some(names);
        }
        self
    }

    /// Set the HTTP/3-specific header sending order for this request only.
    ///
    /// Overrides request/session/client generic `header_order` for H3 requests.
    pub fn h3_header_order(mut self, order: Vec<&str>) -> Self {
        let names: Vec<http::header::HeaderName> = order
            .into_iter()
            .filter_map(|s| http::header::HeaderName::from_bytes(s.as_bytes()).ok())
            .collect();
        if !names.is_empty() {
            self.h3_header_order = Some(names);
        }
        self
    }

    /// Set the cookie sending order for this request only.
    pub fn cookie_order(mut self, order: Vec<&str>) -> Self {
        let names: Vec<Box<str>> = order.into_iter().map(|s| s.into()).collect();
        if !names.is_empty() {
            self.cookie_order = Some(names);
        }
        self
    }

    /// Enable HTTP basic authentication.
    ///
    /// Encodes `username:password` in Base64 and sets the `Authorization`
    /// header to `Basic <encoded>`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://api.example.com")
    ///     .basic_auth("admin", Some("secret"))
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn basic_auth(mut self, username: &str, password: Option<&str>) -> Self {
        use base64::Engine;
        let credentials = match password {
            Some(pw) => format!("{username}:{pw}"),
            None => format!("{username}:"),
        };
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
        let value = format!("Basic {encoded}");
        if let Ok(v) = http::header::HeaderValue::from_str(&value) {
            self.headers.insert(http::header::AUTHORIZATION, v);
        }
        self
    }

    /// Enable HTTP bearer token authentication.
    ///
    /// Sets the `Authorization` header to `Bearer <token>`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://api.example.com")
    ///     .bearer_auth("eyJhbGciOiJIUzI1NiIs...")
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn bearer_auth(mut self, token: &str) -> Self {
        let value = format!("Bearer {token}");
        if let Ok(v) = http::header::HeaderValue::from_str(&value) {
            self.headers.insert(http::header::AUTHORIZATION, v);
        }
        self
    }

    /// Set a per-request **end-to-end** deadline.
    ///
    /// When set, this duration bounds the **whole** attempt: connection setup,
    /// request write, and response read (until the body is fully received for
    /// [`send`](Self::send)). It is **not** the same thing as the client’s
    /// [`Client::read_timeout`](crate::Client::read_timeout) alone (read phase
    /// after connect) or [`Client::connect_timeout`](crate::Client::connect_timeout)
    /// alone; it overrides those for this request’s combined operation.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// use std::time::Duration;
    ///
    /// let resp = session.get("https://slow-api.example.com")
    ///     .timeout(Duration::from_secs(60))
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    /// Set the RFC 9218 request priority (urgency + incremental).
    ///
    /// This controls both the H2 HEADERS frame weight and the HTTP
    /// `priority` header. The mapping from urgency to weight is
    /// determined by the browser H2 profile (e.g. Chrome: u=1 → weight 219).
    ///
    /// If not called, the profile's default priority is used
    /// (Chrome defaults to `u=1, i` for fetch/XHR).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().build();
    /// # let session = client.session().build();
    /// use lkh2::RequestPriority;
    ///
    /// let resp = session.get("https://example.com/image.png")
    ///     .priority(RequestPriority::image())
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn priority(mut self, priority: lkh2::RequestPriority) -> Self {
        self.priority = Some(priority);
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set a per-request proxy.
    ///
    /// Overrides the session-level proxy for this request only. Useful when
    /// you want to route specific requests through different proxies while
    /// sharing the same session (cookie jar, connection pool).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://example.com")
    ///     .proxy("socks5://special-proxy:1080")
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn proxy(mut self, proxy_url: &str) -> Self {
        match ProxyConfig::parse(proxy_url) {
            Ok(config) => self.proxy_override = Some(config),
            Err(e) => {
                tracing::warn!(url = %proxy_url, error = %e, "request.invalid_proxy_url");
            }
        }
        self
    }

    /// Prefer a specific HTTP version behavior for this request.
    ///
    /// Overrides the session-level HTTP version preference without changing
    /// the rest of the protocol policy.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// use lkrequest::PreferredHttpVersion;
    ///
    /// let resp = session.get("https://example.com")
    ///     .preferred_http_version(PreferredHttpVersion::Http2Only)
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn preferred_http_version(mut self, version: PreferredHttpVersion) -> Self {
        self.version_override = Some(version);
        self
    }

    /// Force a specific HTTP version for this request.
    ///
    /// Legacy request-side setter. New code should call
    /// [`RequestBuilder::preferred_http_version`].
    ///
    /// [`HttpVersion::Unknown`] is treated as
    /// “no override” (ALPN / session preference decides).
    #[deprecated(
        since = "0.3.0",
        note = "use `preferred_http_version(PreferredHttpVersion)`"
    )]
    pub fn version(self, version: HttpVersion) -> Self {
        self.preferred_http_version(version.into())
    }

    /// Override the runtime protocol behavior for this request only.
    pub fn protocol_policy(mut self, policy: ProtocolPolicy) -> Self {
        self.protocol_policy_override = Some(policy);
        self
    }

    /// Override only this request's high-level H2/H3 intent.
    pub fn http_intent(mut self, intent: HttpIntent) -> Self {
        let policy = self
            .protocol_policy_override
            .take()
            .unwrap_or_else(|| self.session.protocol_policy().clone())
            .with_intent(intent);
        self.protocol_policy_override = Some(policy);
        self
    }

    /// Declare whether this request is safe to send in QUIC 0-RTT / TLS
    /// early data.
    ///
    /// See [`Idempotency`] for the exact semantics. The default is
    /// [`Idempotency::Default`], which lets lkrequest decide based on the
    /// HTTP method (RFC 9110 §9.2.1 safe methods → yes; everything else →
    /// no). Override to [`Idempotency::Idempotent`] if the request carries
    /// an application-level replay guard (e.g. an `Idempotency-Key` header)
    /// and you want non-safe methods to benefit from 0-RTT; override to
    /// [`Idempotency::NotIdempotent`] to force a full 1-RTT handshake even
    /// for GET/HEAD.
    ///
    /// This API matches Chromium's `HttpRequestInfo::idempotency` tri-state.
    pub fn idempotency(mut self, kind: Idempotency) -> Self {
        self.idempotency = kind;
        self
    }

    /// Set the `Accept-Encoding` for this request.
    ///
    /// Controls which compression algorithms are advertised to the server,
    /// and which decompression to apply on the response body. Overrides
    /// the session-level `default_accept_encoding`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// use lkrequest::AcceptEncoding;
    ///
    /// // First request: only gzip
    /// let resp1 = session.get("https://example.com/page1")
    ///     .accept_encoding(AcceptEncoding::GZIP)
    ///     .send().await?;
    ///
    /// // Second request: only brotli
    /// let resp2 = session.get("https://example.com/page2")
    ///     .accept_encoding(AcceptEncoding::BR)
    ///     .send().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn accept_encoding(mut self, encoding: AcceptEncoding) -> Self {
        self.accept_encoding = Some(encoding);
        self
    }

    /// Disable automatic response body decompression for this request.
    ///
    /// The raw response body is returned as-is, regardless of the
    /// `content-encoding` header. Useful when you need the raw compressed
    /// bytes or want to handle decompression yourself.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://example.com")
    ///     .no_auto_decompress()
    ///     .send()
    ///     .await?;
    /// // resp.bytes() returns the raw (possibly compressed) bytes
    /// # Ok(())
    /// # }
    /// ```
    pub fn no_auto_decompress(mut self) -> Self {
        self.no_decompress = true;
        self
    }

    /// Collect per-request diagnostics (phase timings, protocol, remote address)
    /// and attach them to the [`Response`](crate::response::Response), readable
    /// via [`Response::diagnostics`](crate::response::Response::diagnostics).
    ///
    /// Opt-in and off by default: when not enabled the request carries no
    /// diagnostics-collection overhead at all.
    pub fn collect_diagnostics(mut self, enabled: bool) -> Self {
        self.collect_diagnostics = enabled;
        self
    }

    /// Set the request body as raw bytes.
    ///
    /// Accepts any type that implements `Into<Bytes>`, including `Vec<u8>`,
    /// `&'static [u8]`, `String`, `Bytes`, etc.
    pub fn body(mut self, body: impl Into<bytes::Bytes>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Set the request body as a UTF-8 string.
    pub fn text_body(mut self, text: &str) -> Self {
        self.body = Some(bytes::Bytes::copy_from_slice(text.as_bytes()));
        self
    }

    /// Set the request body as JSON, serializing the given value.
    ///
    /// If serialization fails, the error is deferred until
    /// [`send()`](Self::send) / [`send_streaming()`](Self::send_streaming)
    /// so the builder chain is never broken.
    pub fn json<T: serde::Serialize>(mut self, value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(body) => {
                self.body = Some(bytes::Bytes::from(body));
                self.headers.insert(
                    http::header::CONTENT_TYPE,
                    http::header::HeaderValue::from_static("application/json"),
                );
            }
            Err(e) => {
                self.deferred_error =
                    Some(Error::Http(format!("failed to serialize JSON body: {e}")));
            }
        }
        self
    }

    /// Set the request body as `application/x-www-form-urlencoded`.
    ///
    /// Serializes the given value using `serde_urlencoded` and automatically
    /// sets the `Content-Type` header.
    ///
    /// If serialization fails, the error is deferred until
    /// [`send()`](Self::send) / [`send_streaming()`](Self::send_streaming)
    /// so the builder chain is never broken.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.post("https://example.com/login")
    ///     .form(&[("username", "alice"), ("password", "secret")])
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn form<T: serde::Serialize>(mut self, value: &T) -> Self {
        match serde_urlencoded::to_string(value) {
            Ok(body) => {
                self.body = Some(bytes::Bytes::from(body));
                self.headers.insert(
                    http::header::CONTENT_TYPE,
                    http::header::HeaderValue::from_static("application/x-www-form-urlencoded"),
                );
            }
            Err(e) => {
                self.deferred_error =
                    Some(Error::Http(format!("failed to serialize form body: {e}")));
            }
        }
        self
    }

    /// Set the request body as multipart/form-data.
    ///
    /// Encodes the multipart form and automatically sets the `Content-Type`
    /// header with the correct boundary.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// # let photo_bytes = vec![0u8];
    /// use lkrequest::multipart::Multipart;
    ///
    /// let form = Multipart::new()
    ///     .text("field", "value")
    ///     .file("upload", "photo.jpg", "image/jpeg", photo_bytes);
    ///
    /// let resp = session.post("https://example.com/upload")
    ///     .multipart(form)
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn multipart(mut self, form: crate::multipart::Multipart) -> Self {
        let content_type = form.content_type_header();
        self.body = Some(bytes::Bytes::from(form.encode()));
        if let Ok(v) = http::header::HeaderValue::from_str(&content_type) {
            self.headers.insert(http::header::CONTENT_TYPE, v);
        }
        self
    }

    /// Append URL query parameters to this request.
    ///
    /// Multiple calls accumulate parameters.  Existing query parameters in
    /// the URL are preserved; the new ones are appended.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://api.example.com/search")
    ///     .query(&[("q", "rust"), ("page", "1")])
    ///     .send()
    ///     .await?;
    /// // Requests: GET https://api.example.com/search?q=rust&page=1
    /// # Ok(())
    /// # }
    /// ```
    pub fn query(mut self, params: &[(&str, &str)]) -> Self {
        for &(key, value) in params {
            self.query_params.push((key.to_string(), value.to_string()));
        }
        self
    }

    /// Send the request and return the response.
    ///
    /// For a **streaming** body, no automatic redirect following, or no session
    /// retries, use [`send_streaming`](Self::send_streaming) instead—it behaves
    /// differently; read its documentation before choosing.
    ///
    /// Follows redirects according to the session's [`RedirectPolicy`](super::RedirectPolicy):
    /// - `RedirectPolicy::Follow(n)` — automatically follow
    ///   up to `n` redirects (301, 302, 307, 308).
    /// - [`RedirectPolicy::None`](super::RedirectPolicy::None) — return the 3xx response as-is.
    ///
    /// Redirect behavior:
    /// - 301/302: Changes method to GET, drops body.
    /// - 307/308: Preserves original method and body.
    /// - Cross-origin redirects strip sensitive headers (Authorization, Cookie).
    ///
    /// If a retry policy is configured on the session, retryable failures will
    /// be automatically retried according to the policy.
    #[allow(clippy::let_and_return)] // `result` is consumed by the telemetry cfg arm
    pub async fn send(self) -> Result<Response> {
        let collect_diagnostics = self.collect_diagnostics;
        let result = if collect_diagnostics {
            // Opt-in path: wrap execution in the diagnostics task-local scope so
            // the phase recorders populate, then attach the snapshot. Only paid
            // when explicitly enabled.
            let (r, diag) = crate::diagnostics::capture_request_diagnostics(self.send_impl()).await;
            r.map(|mut resp| {
                resp.set_diagnostics(diag);
                resp
            })
        } else {
            self.send_impl().await
        };
        #[cfg(feature = "telemetry")]
        crate::telemetry::counters().record_request(result.is_err());
        result
    }

    async fn send_impl(self) -> Result<Response> {
        if let Some(err) = self.deferred_error {
            return Err(err);
        }

        let req_id = next_request_id();
        let span = tracing::info_span!(
            "http.request",
            req_id = req_id,
            method = %self.method,
            url = %self.url,
            // Result fields recorded after completion so a `tracing` subscriber
            // (e.g. tracing-opentelemetry) picks them up as span attributes.
            status = tracing::field::Empty,
            error = tracing::field::Empty,
        );

        let retry_policy = self.session.inner.retry_policy.clone();

        // --- Inject Accept-Encoding header if configured ---
        let mut headers = self.headers;
        if !headers.contains_key(http::header::ACCEPT_ENCODING) {
            let encoding = self
                .accept_encoding
                .or(self.session.inner.default_accept_encoding);
            if let Some(enc) = encoding {
                if let Ok(v) = http::header::HeaderValue::from_str(&enc.to_header_value()) {
                    headers.insert(http::header::ACCEPT_ENCODING, v);
                }
            }
        }

        // --- Middleware: on_request phase ---
        let mw_req = crate::middleware::MiddlewareRequest {
            method: self.method,
            url: self.url,
            headers,
            body: self.body,
        };

        let client_mws = self.session.inner.client.middlewares();
        let session_mws = &self.session.inner.middlewares;

        let mw_req = crate::middleware::apply_request_middlewares(client_mws, mw_req)?;
        let mw_req = crate::middleware::apply_request_middlewares(session_mws, mw_req)?;

        // Destructure middleware-processed request for retries.
        // Immutable fields are wrapped in Arc to avoid deep cloning on retries.
        let session = self.session;
        let body = mw_req.body;
        let ctx = Arc::new(SharedRequestContext {
            method: mw_req.method,
            url: mw_req.url,
            headers: mw_req.headers,
            query_params: self.query_params,
            extra_cookies: self.extra_cookies,
            cookie_overrides: self.cookie_overrides,
            timeout: self.timeout,
            proxy_override: self.proxy_override,
            version_override: self.version_override,
            protocol_policy_override: self.protocol_policy_override,
            no_decompress: self.no_decompress,
            header_order: self.header_order,
            h3_header_order: self.h3_header_order,
            cookie_order: self.cookie_order,
            header_insertion_order: self.header_insertion_order,
            priority: self.priority,
            idempotency: self.idempotency,
        });

        let result = async move {
            // --- Core send logic (retry + redirect) ---
            let raw_response = if let Some(policy) = retry_policy {
                let mut attempt = 0u32;
                loop {
                    let rb = RequestBuilder::from_shared_context(
                        session.clone(),
                        ctx.clone(),
                        body.clone(),
                    );
                    let result = rb.send_with_redirects().await;

                    match result {
                        Ok(resp) => {
                            let status = resp.status();
                            if crate::retry::is_retryable_status(status) {
                                attempt += 1;
                                if let Some(delay) =
                                    policy.should_retry(attempt, None, Some(status))
                                {
                                    tracing::warn!(
                                        attempt = attempt,
                                        status = status.as_u16(),
                                        delay_ms = delay.as_millis() as u64,
                                        "http.retry_on_status",
                                    );
                                    tokio::time::sleep(delay).await;
                                    continue;
                                }
                            }
                            break Ok(resp);
                        }
                        Err(e) => {
                            attempt += 1;
                            if let Some(delay) = policy.should_retry(attempt, Some(&e), None) {
                                // Only replay if doing so cannot duplicate a
                                // server-side side effect (RFC 9110 §9.2.2):
                                // safe/idempotent methods, or a failure that
                                // proves the request was never processed. A
                                // non-idempotent POST that failed *after*
                                // transmission must surface the error rather
                                // than be silently re-sent.
                                if crate::retry::retry_is_replay_safe(
                                    &ctx.method,
                                    ctx.idempotency,
                                    &e,
                                ) {
                                    tracing::warn!(
                                        attempt = attempt,
                                        error = %e,
                                        delay_ms = delay.as_millis() as u64,
                                        "http.retry_on_error",
                                    );
                                    tokio::time::sleep(delay).await;
                                    continue;
                                }
                                tracing::warn!(
                                    attempt = attempt,
                                    error = %e,
                                    method = %ctx.method,
                                    "http.retry_skipped_non_idempotent",
                                );
                            }
                            break Err(e);
                        }
                    }
                }
            } else {
                let rb = RequestBuilder::from_shared_context(session.clone(), ctx, body);
                rb.send_with_redirects().await
            };

            // --- Middleware: on_response phase ---
            match raw_response {
                Ok(mut resp) => {
                    let resp_url = resp.url().to_string();
                    let resp_version = resp.version();
                    let redirect_history = resp.take_redirect_history();

                    let mw_resp = crate::middleware::MiddlewareResponse {
                        status: resp.status(),
                        headers: resp.headers().clone(),
                        body: resp.into_bytes(),
                    };

                    let session_mws = &session.inner.middlewares;
                    let client_mws = session.inner.client.middlewares();

                    let mw_resp =
                        crate::middleware::apply_response_middlewares(session_mws, mw_resp)?;
                    let mw_resp =
                        crate::middleware::apply_response_middlewares(client_mws, mw_resp)?;

                    let mut final_resp =
                        Response::from_parts(mw_resp.status, mw_resp.headers, mw_resp.body);
                    final_resp.set_url(resp_url);
                    final_resp.set_http_version(resp_version);
                    final_resp.set_redirect_history(redirect_history);
                    Ok(final_resp)
                }
                Err(e) => Err(e),
            }
        }
        .instrument(span.clone())
        .await;

        // Record result fields on the request span (zero cost without a subscriber).
        match &result {
            Ok(resp) => {
                span.record("status", resp.status().as_u16());
            }
            Err(err) => {
                span.record("error", tracing::field::display(err));
            }
        }
        result
    }

    /// Send the request and return a streaming response.
    ///
    /// **Important:** This is **not** a streaming variant of [`send`](Self::send)
    /// with the same semantics. Compared to [`send`](Self::send), streaming mode
    /// does **not** follow redirects, does **not** apply the session retry
    /// policy, and returns the first response as-is. Inspect `status()`, read
    /// `Location`, and retry or follow manually if you need redirect behavior.
    ///
    /// Unlike [`send`](Self::send), the response body is **not** fully
    /// buffered. Instead, the body is read on demand via
    /// [`StreamingResponse::chunk()`].
    ///
    /// This is suitable for:
    /// - Large file downloads (avoids OOM)
    /// - Server-Sent Events (SSE)
    /// - Chunked transfer responses
    /// - Long-polling connections
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// # fn process(_: bytes::Bytes) {}
    /// let mut resp = session.get("https://example.com/stream")
    ///     .send_streaming()
    ///     .await?;
    ///
    /// while let Some(chunk) = resp.chunk().await? {
    ///     process(chunk);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_streaming(self) -> Result<StreamingResponse> {
        #[cfg(feature = "telemetry")]
        {
            let result = self.send_streaming_impl().await;
            crate::telemetry::counters().record_request(result.is_err());
            result
        }
        #[cfg(not(feature = "telemetry"))]
        {
            self.send_streaming_impl().await
        }
    }

    async fn send_streaming_impl(self) -> Result<StreamingResponse> {
        if let Some(err) = self.deferred_error {
            return Err(err);
        }

        let req_id = next_request_id();
        let span = tracing::info_span!(
            "http.stream_request",
            req_id = req_id,
            method = %self.method,
            url = %self.url,
            status = tracing::field::Empty,
            error = tracing::field::Empty,
        );

        let mut headers = self.headers;
        if !headers.contains_key(http::header::ACCEPT_ENCODING) {
            let encoding = self
                .accept_encoding
                .or(self.session.inner.default_accept_encoding);
            if let Some(enc) = encoding {
                if let Ok(v) = http::header::HeaderValue::from_str(&enc.to_header_value()) {
                    headers.insert(http::header::ACCEPT_ENCODING, v);
                }
            }
        }

        // Apply query parameters
        let url = if self.query_params.is_empty() {
            self.url
        } else {
            let mut parsed =
                Url::parse(&self.url).map_err(|e| Error::UrlParse(format!("{}: {e}", self.url)))?;
            {
                let mut pairs = parsed.query_pairs_mut();
                for (key, value) in &self.query_params {
                    pairs.append_pair(key, value);
                }
            }
            parsed.to_string()
        };

        let read_timeout = self.timeout.unwrap_or_else(|| {
            self.session
                .inner
                .client
                .timeouts()
                .total_timeout_or(Duration::from_secs(60))
        });
        let rb = StreamRequestBuilder {
            session: self.session,
            method: self.method,
            url,
            headers,
            body: self.body,
            extra_cookies: self.extra_cookies,
            cookie_overrides: self.cookie_overrides,
            proxy_override: self.proxy_override,
            version_override: self.version_override,
            protocol_policy_override: self.protocol_policy_override,
            no_decompress: self.no_decompress,
            header_order: self.header_order,
            h3_header_order: self.h3_header_order,
            cookie_order: self.cookie_order,
            header_insertion_order: self.header_insertion_order,
            priority: self.priority,
        };

        let result = async move {
            tokio::time::timeout(read_timeout, rb.send_streaming_inner())
                .await
                .map_err(|_| {
                    Error::timeout(
                        format!("streaming request timed out after {:?}", read_timeout),
                        None,
                        Some(read_timeout),
                    )
                })?
        }
        .instrument(span.clone())
        .await;

        match &result {
            Ok(resp) => {
                span.record("status", resp.status().as_u16());
            }
            Err(err) => {
                span.record("error", tracing::field::display(err));
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Client;

    fn test_session() -> Session {
        Client::builder()
            .fingerprint(lktls::profile::presets::chrome_144())
            .build()
            .session()
            .build()
    }

    // ====================================================================
    // json() / form() — deferred error mechanism
    // ====================================================================

    #[test]
    fn json_sets_body_and_content_type() {
        let session = test_session();
        let rb = session
            .post("https://example.com")
            .json(&serde_json::json!({"a": 1}));
        assert!(rb.deferred_error.is_none());
        assert!(rb.body.is_some());
        assert_eq!(
            rb.headers.get(http::header::CONTENT_TYPE).unwrap(),
            "application/json",
        );
    }

    #[test]
    fn json_with_valid_data_no_deferred_error() {
        let session = test_session();
        let rb = session.post("https://example.com").json(&vec![1, 2, 3]);
        assert!(rb.deferred_error.is_none());
    }

    /// A type whose `Serialize` impl always fails.
    struct FailSerialize;
    impl serde::Serialize for FailSerialize {
        fn serialize<S: serde::Serializer>(&self, _s: S) -> std::result::Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("intentional failure"))
        }
    }

    #[test]
    fn json_serialization_failure_defers_error() {
        let session = test_session();
        let rb = session.post("https://example.com").json(&FailSerialize);
        assert!(rb.deferred_error.is_some());
        let err_msg = format!("{}", rb.deferred_error.unwrap());
        assert!(err_msg.contains("serialize"), "err={err_msg}");
    }

    #[test]
    fn json_deferred_error_surfaces_at_send() {
        let session = test_session();
        let rb = session.post("https://example.com").json(&FailSerialize);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(rb.send());
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("serialize"),
            "should surface json error: {err_msg}"
        );
    }

    #[test]
    fn form_serialization_failure_defers_error() {
        let session = test_session();
        let rb = session.post("https://example.com").form(&FailSerialize);
        assert!(rb.deferred_error.is_some());
        let err_msg = format!("{}", rb.deferred_error.unwrap());
        assert!(err_msg.contains("serialize"), "err={err_msg}");
    }

    #[test]
    fn form_sets_body_and_content_type() {
        let session = test_session();
        let rb = session
            .post("https://example.com")
            .form(&[("user", "alice"), ("pass", "secret")]);
        assert!(rb.deferred_error.is_none());
        assert!(rb.body.is_some());
        assert_eq!(
            rb.headers.get(http::header::CONTENT_TYPE).unwrap(),
            "application/x-www-form-urlencoded",
        );
        let body_str = std::str::from_utf8(rb.body.as_ref().unwrap()).unwrap();
        assert!(body_str.contains("user=alice"));
        assert!(body_str.contains("pass=secret"));
    }

    #[test]
    fn json_chains_with_other_builders() {
        let session = test_session();
        let rb = session
            .post("https://example.com")
            .header("X-Custom", "value")
            .json(&serde_json::json!({"key": "val"}))
            .timeout(std::time::Duration::from_secs(5));
        assert!(rb.deferred_error.is_none());
        assert!(rb.headers.contains_key("x-custom"));
        assert_eq!(rb.timeout, Some(std::time::Duration::from_secs(5)));
    }

    #[test]
    fn form_chains_with_other_builders() {
        let session = test_session();
        let rb = session
            .post("https://example.com")
            .header("X-Custom", "value")
            .form(&[("k", "v")])
            .timeout(std::time::Duration::from_secs(5));
        assert!(rb.deferred_error.is_none());
        assert!(rb.headers.contains_key("x-custom"));
        assert_eq!(rb.timeout, Some(std::time::Duration::from_secs(5)));
    }

    // ====================================================================
    // preferred_http_version() / legacy version()
    // ====================================================================

    #[test]
    fn preferred_http_version_setter_records_preference() {
        let session = test_session();
        let rb = session
            .get("https://example.com")
            .preferred_http_version(PreferredHttpVersion::Http2Only);
        assert_eq!(rb.version_override, Some(PreferredHttpVersion::Http2Only));
    }

    #[test]
    #[allow(deprecated)]
    fn version_http10_maps_to_http1only() {
        let session = test_session();
        let rb = session
            .get("https://example.com")
            .version(HttpVersion::Http10);
        assert_eq!(rb.version_override, Some(PreferredHttpVersion::Http1Only));
    }

    #[test]
    #[allow(deprecated)]
    fn version_h2_maps_to_http2only() {
        let session = test_session();
        let rb = session.get("https://example.com").version(HttpVersion::H2);
        assert_eq!(rb.version_override, Some(PreferredHttpVersion::Http2Only));
    }

    #[test]
    #[allow(deprecated)]
    fn version_unknown_maps_to_auto() {
        let session = test_session();
        let rb = session
            .get("https://example.com")
            .version(HttpVersion::Unknown);
        assert_eq!(rb.version_override, Some(PreferredHttpVersion::Auto));
    }

    #[test]
    fn request_http_intent_override_updates_effective_policy() {
        let client = Client::builder()
            .protocol_policy(crate::protocol::ProtocolPolicy::crawler_throughput())
            .build();
        let session = client
            .session()
            .protocol_policy(crate::protocol::ProtocolPolicy::chrome_conservative())
            .build();
        let rb = session
            .get("https://example.com")
            .http_intent(crate::protocol::HttpIntent::H3Only);

        assert_eq!(
            rb.protocol_policy_override
                .as_ref()
                .expect("request policy override")
                .intent,
            crate::protocol::HttpIntent::H3Only
        );
        assert_eq!(
            rb.protocol_policy_override
                .as_ref()
                .expect("request policy override")
                .fallback,
            crate::protocol::FallbackPolicy::NoFallback
        );
    }

    // ====================================================================
    // headers / headers_with_order / headers_ordered
    // ====================================================================

    #[test]
    fn headers_with_order_places_template_before_rest() {
        let session = test_session();
        let mut map = http::HeaderMap::new();
        map.insert("accept", "application/json".parse().unwrap());
        map.insert("user-agent", "t".parse().unwrap());
        map.insert("cookie", "a=1".parse().unwrap());
        let rb = session
            .get("https://example.com")
            .headers_with_order(map, &["cookie", "accept", "user-agent"]);

        let names: Vec<&str> = rb
            .header_insertion_order
            .iter()
            .map(|n| n.as_str())
            .collect();
        assert_eq!(names, vec!["cookie", "accept", "user-agent"]);
    }

    #[test]
    fn headers_with_order_after_header_keeps_prefix() {
        let session = test_session();
        let mut map = http::HeaderMap::new();
        map.insert("accept", "application/json".parse().unwrap());
        map.insert("cookie", "a=1".parse().unwrap());
        let rb = session
            .get("https://example.com")
            .header("x-first", "1")
            .headers_with_order(map, &["cookie", "accept"]);

        let names: Vec<&str> = rb
            .header_insertion_order
            .iter()
            .map(|n| n.as_str())
            .collect();
        assert_eq!(names, vec!["x-first", "cookie", "accept"]);
    }

    #[test]
    fn headers_ordered_matches_pair_order() {
        let session = test_session();
        let rb = session.get("https://example.com").headers_ordered(vec![
            ("accept", "text/html"),
            ("user-agent", "u"),
            ("accept", "application/json"),
        ]);

        let names: Vec<&str> = rb
            .header_insertion_order
            .iter()
            .map(|n| n.as_str())
            .collect();
        assert_eq!(names, vec!["accept", "user-agent"]);
        assert_eq!(
            rb.headers.get("accept").unwrap().to_str().unwrap(),
            "application/json"
        );
    }
}
