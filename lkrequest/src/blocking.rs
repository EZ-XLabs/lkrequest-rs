//! Synchronous (blocking) HTTP client API.
//!
//! This module provides a blocking (non-async) wrapper around the async
//! `lkrequest` API, following the same pattern as `reqwest::blocking`.
//!
//! Internally, a dedicated Tokio runtime is created to drive async operations.
//! All async calls are executed via `block_on()`.
//!
//! # Example
//!
//! ```rust,no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use lkrequest::blocking::{Client, Session};
//! use lktls::profile::presets;
//!
//! let client = Client::new(
//!     lkrequest::Client::builder()
//!         .fingerprint(presets::chrome_131())
//!         .build()
//! );
//!
//! let session = client.session().build();
//! let resp = session.get("https://example.com").send()?;
//! println!("Status: {}", resp.status());
//! println!("Body: {}", resp.text()?);
//! # Ok(())
//! # }
//! ```
//!
//! # Limitations
//!
//! - **Do NOT use from within an async context.** Calling `block_on()` inside
//!   a Tokio runtime will panic. If you need both sync and async, use the
//!   async API directly in async contexts.
//! - `StreamingResponse::chunk()` blocks the calling thread until data arrives.

use std::sync::OnceLock;
use std::time::Duration;

use http::HeaderMap;
use tokio::runtime::{self, Runtime};

use crate::error::Result;
use crate::proxy::ProxyConfig;
use crate::response::HttpVersion;
use crate::session::{AcceptEncoding, PreferredHttpVersion};

// ---------------------------------------------------------------------------
// Global Tokio runtime for blocking operations
// ---------------------------------------------------------------------------

/// Returns a reference to the shared Tokio runtime used by all blocking APIs.
///
/// The runtime is lazily initialized on first use and lives for the entire
/// program lifetime.
fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("lkrequest-blocking")
            .build()
            .expect("failed to create Tokio runtime for lkrequest::blocking")
    })
}

// ===========================================================================
// Client
// ===========================================================================

/// A blocking wrapper around [`crate::Client`].
///
/// `Client` itself is already synchronous (no async methods), but this wrapper
/// ensures that `Session`s created from it return blocking types.
///
/// # Example
///
/// ```rust,no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use lkrequest::blocking::Client;
/// use lktls::profile::presets;
///
/// let client = Client::new(
///     lkrequest::Client::builder()
///         .fingerprint(presets::chrome_131())
///         .build()
/// );
///
/// // Convenience one-off request (creates a temporary session)
/// let resp = client.get("https://example.com").send()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Client {
    inner: crate::Client,
}

impl Client {
    /// Create a blocking `Client` from an async [`crate::Client`].
    pub fn new(inner: crate::Client) -> Self {
        Self { inner }
    }

    /// Start building a new blocking `Client`.
    ///
    /// The returned [`ClientBuilder`] mirrors the async
    /// [`crate::client::ClientBuilder`] API but its `.build()` produces a
    /// blocking [`Client`] directly.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use lkrequest::blocking::Client;
    /// use lktls::profile::presets;
    ///
    /// let client = Client::builder()
    ///     .fingerprint(presets::chrome_144())
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> ClientBuilder {
        ClientBuilder {
            inner: crate::Client::builder(),
        }
    }

    /// Create a [`SessionBuilder`] from this client.
    pub fn session(&self) -> SessionBuilder {
        SessionBuilder {
            inner: self.inner.session(),
        }
    }

    /// Returns a reference to the underlying async `Client`.
    pub fn inner(&self) -> &crate::Client {
        &self.inner
    }

    // -------------------------------------------------------------------
    // Convenience one-off request methods
    // -------------------------------------------------------------------

    /// Start building a GET request using a temporary session.
    pub fn get(&self, url: &str) -> RequestBuilder {
        self.session().build().get(url)
    }

    /// Start building a POST request using a temporary session.
    pub fn post(&self, url: &str) -> RequestBuilder {
        self.session().build().post(url)
    }

    /// Start building a PUT request using a temporary session.
    pub fn put(&self, url: &str) -> RequestBuilder {
        self.session().build().put(url)
    }

    /// Start building a DELETE request using a temporary session.
    pub fn delete(&self, url: &str) -> RequestBuilder {
        self.session().build().delete(url)
    }

    /// Start building a HEAD request using a temporary session.
    pub fn head(&self, url: &str) -> RequestBuilder {
        self.session().build().head(url)
    }

    /// Start building a PATCH request using a temporary session.
    pub fn patch(&self, url: &str) -> RequestBuilder {
        self.session().build().patch(url)
    }

    /// Start building an OPTIONS request using a temporary session.
    pub fn options(&self, url: &str) -> RequestBuilder {
        self.session().build().options(url)
    }
}

// ===========================================================================
// ClientBuilder
// ===========================================================================

/// A blocking wrapper around [`crate::client::ClientBuilder`].
///
/// Provides the same builder API as [`crate::client::ClientBuilder`] but
/// its [`build()`](Self::build) method returns a blocking [`Client`].
pub struct ClientBuilder {
    inner: crate::client::ClientBuilder,
}

impl ClientBuilder {
    /// Set the TLS fingerprint profile.
    pub fn fingerprint(mut self, profile: lktls::profile::types::TlsProfile) -> Self {
        self.inner = self.inner.fingerprint(profile);
        self
    }

    /// Set the HTTP/2 fingerprint profile.
    pub fn h2_profile(mut self, profile: crate::h2::H2Profile) -> Self {
        self.inner = self.inner.h2_profile(profile);
        self
    }

    /// Add a default header that will be included in every request.
    pub fn default_header(mut self, name: &str, value: &str) -> Self {
        self.inner = self.inner.default_header(name, value);
        self
    }

    /// Set the header sending order for requests.
    pub fn header_order(mut self, order: Vec<&str>) -> Self {
        self.inner = self.inner.header_order(order);
        self
    }

    /// Set the cookie sending order within the `Cookie` header.
    pub fn cookie_order(mut self, order: Vec<&str>) -> Self {
        self.inner = self.inner.cookie_order(order);
        self
    }

    /// Set the connect timeout (TCP + TLS combined).
    pub fn connect_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.inner = self.inner.connect_timeout(timeout);
        self
    }

    /// Set the read/response timeout.
    pub fn read_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.inner = self.inner.read_timeout(timeout);
        self
    }

    /// Set the full timeout configuration.
    pub fn timeout_config(mut self, config: crate::client::TimeoutConfig) -> Self {
        self.inner = self.inner.timeout_config(config);
        self
    }

    /// Set the full fallback configuration.
    pub fn fallback_config(mut self, config: crate::client::FallbackConfig) -> Self {
        self.inner = self.inner.fallback_config(config);
        self
    }

    /// Set resource limits.
    pub fn resource_limits(mut self, limits: crate::client::ResourceLimits) -> Self {
        self.inner = self.inner.resource_limits(limits);
        self
    }

    /// Enable or disable TLS certificate verification.
    pub fn verify(mut self, enabled: bool) -> Self {
        self.inner = self.inner.verify(enabled);
        self
    }

    /// Add a middleware to the client-level middleware stack.
    pub fn middleware(mut self, mw: impl crate::middleware::Middleware + 'static) -> Self {
        self.inner = self.inner.middleware(mw);
        self
    }

    /// Set a TLS key log callback for SSLKEYLOGFILE-compatible output.
    pub fn keylog(mut self, callback: lktls::KeyLogCallback) -> Self {
        self.inner = self.inner.keylog(callback);
        self
    }

    /// Set the DNS resolver via a [`DnsConfig`](crate::dns::DnsConfig) preset.
    pub fn dns(mut self, config: crate::dns::DnsConfig) -> Self {
        self.inner = self.inner.dns(config);
        self
    }

    /// Build the blocking [`Client`].
    pub fn build(self) -> Client {
        Client {
            inner: self.inner.build(),
        }
    }
}

// ===========================================================================
// SessionBuilder
// ===========================================================================

/// A blocking wrapper around [`crate::session::SessionBuilder`].
pub struct SessionBuilder {
    inner: crate::session::SessionBuilder,
}

impl SessionBuilder {
    /// Set the proxy for this session from a URL string.
    pub fn proxy(self, proxy_url: &str) -> Self {
        Self {
            inner: self.inner.proxy(proxy_url),
        }
    }

    /// Set the proxy from a `ProxyConfig`.
    pub fn proxy_config(self, config: ProxyConfig) -> Self {
        Self {
            inner: self.inner.proxy_config(config),
        }
    }

    /// Set the maximum number of redirects to follow (default: 10).
    ///
    /// Equivalent to `redirect_policy(RedirectPolicy::Follow(n))`.
    pub fn max_redirects(self, n: u32) -> Self {
        Self {
            inner: self.inner.max_redirects(n),
        }
    }

    /// Set the redirect policy for this session.
    ///
    /// See [`RedirectPolicy`](crate::session::RedirectPolicy) for details.
    pub fn redirect_policy(self, policy: crate::session::RedirectPolicy) -> Self {
        Self {
            inner: self.inner.redirect_policy(policy),
        }
    }

    /// Set a retry policy for failed requests.
    pub fn retry_policy(self, policy: impl crate::retry::RetryPolicy + 'static) -> Self {
        Self {
            inner: self.inner.retry_policy(policy),
        }
    }

    /// Add a middleware to the session-level middleware stack.
    pub fn middleware(self, mw: impl crate::middleware::Middleware + 'static) -> Self {
        Self {
            inner: self.inner.middleware(mw),
        }
    }

    /// Set an ECHConfigList for this session (raw DER bytes).
    pub fn ech_config(self, config_list: Vec<u8>) -> Self {
        Self {
            inner: self.inner.ech_config(config_list),
        }
    }

    /// Force this session to only use HTTP/1.1.
    pub fn http1_only(self) -> Self {
        Self {
            inner: self.inner.http1_only(),
        }
    }

    /// Force this session to only use HTTP/2.
    pub fn http2_only(self) -> Self {
        Self {
            inner: self.inner.http2_only(),
        }
    }

    /// Set the default `Accept-Encoding` for all requests in this session.
    pub fn default_accept_encoding(self, encoding: AcceptEncoding) -> Self {
        Self {
            inner: self.inner.default_accept_encoding(encoding),
        }
    }

    /// Build the blocking [`Session`].
    pub fn build(self) -> Session {
        Session {
            inner: self.inner.build(),
        }
    }
}

// ===========================================================================
// Session
// ===========================================================================

/// A blocking wrapper around [`crate::Session`].
///
/// All cookie management methods are delegated directly (they are already
/// synchronous).  Request builder methods return blocking [`RequestBuilder`]s.
///
/// # Example
///
/// ```rust,no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # use lkrequest::blocking::Client;
/// # use lktls::profile::presets;
/// # let client = Client::new(lkrequest::Client::builder().fingerprint(presets::chrome_131()).build());
/// let session = client.session().build();
///
/// session.set_cookie("https://example.com", "id", "abc");
/// let resp = session.get("https://example.com").send()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Session {
    inner: crate::Session,
}

impl Session {
    /// Create a blocking `Session` from an async [`crate::Session`].
    pub fn new(inner: crate::Session) -> Self {
        Self { inner }
    }

    /// Returns a reference to the underlying async `Session`.
    pub fn inner(&self) -> &crate::Session {
        &self.inner
    }

    /// Returns a reference to the underlying client.
    pub fn client(&self) -> &crate::Client {
        self.inner.client()
    }

    // -------------------------------------------------------------------
    // Cookie management (delegated — already sync)
    // -------------------------------------------------------------------

    /// Set a cookie in the session's cookie jar.
    pub fn set_cookie(&self, url: &str, name: &str, value: &str) {
        self.inner.set_cookie(url, name, value);
    }

    /// Set a cookie with full attributes (path, domain, etc.).
    #[allow(clippy::too_many_arguments)]
    pub fn set_cookie_with_attrs(
        &self,
        url: &str,
        name: &str,
        value: &str,
        path: Option<&str>,
        domain: Option<&str>,
        secure: bool,
        http_only: bool,
    ) {
        self.inner
            .set_cookie_with_attrs(url, name, value, path, domain, secure, http_only);
    }

    /// Set a cookie from a raw `Set-Cookie` header string.
    pub fn set_cookie_raw(&self, url: &str, set_cookie_header: &str) {
        self.inner.set_cookie_raw(url, set_cookie_header);
    }

    /// Get all cookies that would be sent for the given URL.
    pub fn get_cookies(&self, url: &str) -> Vec<(String, String)> {
        self.inner.get_cookies(url)
    }

    /// Get the value of a specific cookie by name for the given URL.
    pub fn get_cookie(&self, url: &str, name: &str) -> Option<String> {
        self.inner.get_cookie(url, name)
    }

    /// Get all values for a specific cookie name matching the given URL.
    pub fn get_cookie_values(&self, url: &str, name: &str) -> Vec<String> {
        self.inner.get_cookie_values(url, name)
    }

    /// Remove all cookies matching the given name for the specified URL's domain.
    pub fn remove_cookie(&self, url: &str, name: &str) {
        self.inner.remove_cookie(url, name);
    }

    /// Remove all cookies from the session's cookie jar.
    pub fn clear_cookies(&self) {
        self.inner.clear_cookies();
    }

    /// Get the cookie header string that would be sent for the given URL.
    pub fn cookie_header(&self, url: &str) -> Option<String> {
        self.inner.cookie_header(url)
    }

    // -------------------------------------------------------------------
    // Request builders
    // -------------------------------------------------------------------

    /// Start building a GET request.
    pub fn get(&self, url: &str) -> RequestBuilder {
        RequestBuilder {
            inner: self.inner.get(url),
        }
    }

    /// Start building a POST request.
    pub fn post(&self, url: &str) -> RequestBuilder {
        RequestBuilder {
            inner: self.inner.post(url),
        }
    }

    /// Start building a PUT request.
    pub fn put(&self, url: &str) -> RequestBuilder {
        RequestBuilder {
            inner: self.inner.put(url),
        }
    }

    /// Start building a DELETE request.
    pub fn delete(&self, url: &str) -> RequestBuilder {
        RequestBuilder {
            inner: self.inner.delete(url),
        }
    }

    /// Start building a HEAD request.
    pub fn head(&self, url: &str) -> RequestBuilder {
        RequestBuilder {
            inner: self.inner.head(url),
        }
    }

    /// Start building a PATCH request.
    pub fn patch(&self, url: &str) -> RequestBuilder {
        RequestBuilder {
            inner: self.inner.patch(url),
        }
    }

    /// Start building an OPTIONS request.
    pub fn options(&self, url: &str) -> RequestBuilder {
        RequestBuilder {
            inner: self.inner.options(url),
        }
    }

    /// Pre-establish a connection to the given URL (blocks).
    ///
    /// See [`crate::Session::preconnect`] for details.
    pub fn preconnect(&self, url: &str) -> Result<()> {
        runtime().block_on(self.inner.preconnect(url))
    }

    /// Pre-establish connections to multiple URLs concurrently (blocks).
    ///
    /// See [`crate::Session::preconnect_many`] for details.
    pub fn preconnect_many(&self, urls: &[&str]) -> Vec<Result<()>> {
        runtime().block_on(self.inner.preconnect_many(urls))
    }

    /// Start building a WebSocket connection.
    ///
    /// Returns a [`WsBuilder`] that can be configured and then connected
    /// via [`WsBuilder::connect()`] (blocking).
    pub fn websocket(&self, url: &str) -> WsBuilder {
        WsBuilder {
            inner: self.inner.websocket(url),
        }
    }
}

// ===========================================================================
// Blocking WsBuilder
// ===========================================================================

/// A blocking wrapper around [`crate::ws::builder::WsBuilder`].
pub struct WsBuilder {
    inner: crate::ws::builder::WsBuilder,
}

impl WsBuilder {
    /// Add a custom header to the WebSocket upgrade request.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.inner = self.inner.header(name, value);
        self
    }

    /// Set the `Sec-WebSocket-Protocol` subprotocol(s).
    pub fn protocol(mut self, protocol: &str) -> Self {
        self.inner = self.inner.protocol(protocol);
        self
    }

    /// Set the `Sec-WebSocket-Extensions` extension(s).
    pub fn extension(mut self, extension: &str) -> Self {
        self.inner = self.inner.extension(extension);
        self
    }

    /// Establish the WebSocket connection (blocks the calling thread).
    pub fn connect(self) -> Result<WsConnection> {
        runtime().block_on(async { self.inner.connect().await.map(WsConnection::new) })
    }
}

// ===========================================================================
// Blocking WsConnection
// ===========================================================================

/// A blocking wrapper around [`crate::ws::WsConnection`].
///
/// All I/O methods (`send_text`, `recv`, `close`) block the calling thread.
pub struct WsConnection {
    inner: crate::ws::WsConnection<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>>,
}

impl WsConnection {
    fn new(
        inner: crate::ws::WsConnection<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>>,
    ) -> Self {
        Self { inner }
    }

    /// Returns the URL of this WebSocket connection.
    pub fn url(&self) -> &str {
        self.inner.url()
    }

    /// Send a text message (blocks).
    pub fn send_text(&mut self, text: &str) -> Result<()> {
        runtime().block_on(self.inner.send_text(text))
    }

    /// Send a binary message (blocks).
    pub fn send_binary(&mut self, data: &[u8]) -> Result<()> {
        runtime().block_on(self.inner.send_binary(data))
    }

    /// Send a [`WsMessage`](crate::ws::WsMessage) (blocks).
    pub fn send(&mut self, msg: crate::ws::WsMessage) -> Result<()> {
        runtime().block_on(self.inner.send(msg))
    }

    /// Receive the next message (blocks).
    pub fn recv(&mut self) -> Result<crate::ws::WsMessage> {
        runtime().block_on(self.inner.recv())
    }

    /// Close the WebSocket connection (blocks).
    pub fn close(&mut self, close_info: Option<(u16, &str)>) -> Result<()> {
        runtime().block_on(self.inner.close(close_info))
    }
}

// ===========================================================================
// RequestBuilder
// ===========================================================================

/// A blocking wrapper around [`crate::session::RequestBuilder`].
///
/// All builder methods are delegated directly (they are already synchronous).
/// The key difference is that `send()` and `send_streaming()` block the
/// calling thread instead of returning a future.
///
/// # Example
///
/// ```rust,no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # use lkrequest::blocking::Client;
/// # use lktls::profile::presets;
/// # let client = Client::new(lkrequest::Client::builder().fingerprint(presets::chrome_131()).build());
/// # let session = client.session().build();
/// use std::time::Duration;
///
/// let resp = session.get("https://example.com")
///     .header("Accept", "application/json")
///     .bearer_auth("my-token")
///     .timeout(Duration::from_secs(5))
///     .send()?;
/// # Ok(())
/// # }
/// ```
pub struct RequestBuilder {
    inner: crate::session::RequestBuilder,
}

impl RequestBuilder {
    // -------------------------------------------------------------------
    // Builder methods (delegated — already sync)
    // -------------------------------------------------------------------

    /// Add a cookie to this request only.
    pub fn cookie(self, name: &str, value: &str) -> Self {
        Self {
            inner: self.inner.cookie(name, value),
        }
    }

    /// Add a cookie that overrides all same-name cookies from the jar.
    pub fn cookie_override(self, name: &str, value: &str) -> Self {
        Self {
            inner: self.inner.cookie_override(name, value),
        }
    }

    /// Add a header to this request.
    pub fn header(self, name: &str, value: &str) -> Self {
        Self {
            inner: self.inner.header(name, value),
        }
    }

    /// Add a set of headers to this request.
    pub fn headers(self, headers: HeaderMap) -> Self {
        Self {
            inner: self.inner.headers(headers),
        }
    }

    /// Enable HTTP basic authentication.
    pub fn basic_auth(self, username: &str, password: Option<&str>) -> Self {
        Self {
            inner: self.inner.basic_auth(username, password),
        }
    }

    /// Enable HTTP bearer token authentication.
    pub fn bearer_auth(self, token: &str) -> Self {
        Self {
            inner: self.inner.bearer_auth(token),
        }
    }

    /// Set a per-request timeout.
    pub fn timeout(self, timeout: Duration) -> Self {
        Self {
            inner: self.inner.timeout(timeout),
        }
    }

    /// Set a per-request proxy override.
    pub fn proxy(self, proxy_url: &str) -> Self {
        Self {
            inner: self.inner.proxy(proxy_url),
        }
    }

    /// Prefer a specific HTTP version behavior for this request.
    pub fn preferred_http_version(self, version: PreferredHttpVersion) -> Self {
        Self {
            inner: self.inner.preferred_http_version(version),
        }
    }

    /// Force a specific HTTP version for this request.
    #[deprecated(
        since = "0.3.0",
        note = "use `preferred_http_version(PreferredHttpVersion)`"
    )]
    pub fn version(self, version: HttpVersion) -> Self {
        Self {
            inner: self.inner.preferred_http_version(version.into()),
        }
    }

    /// Set the `Accept-Encoding` for this request.
    pub fn accept_encoding(self, encoding: AcceptEncoding) -> Self {
        Self {
            inner: self.inner.accept_encoding(encoding),
        }
    }

    /// Disable automatic response body decompression for this request.
    pub fn no_auto_decompress(self) -> Self {
        Self {
            inner: self.inner.no_auto_decompress(),
        }
    }

    /// Set the request body as raw bytes.
    ///
    /// Accepts any type that implements `Into<Bytes>`, including `Vec<u8>`,
    /// `&'static [u8]`, `String`, `Bytes`, etc.
    pub fn body(self, body: impl Into<bytes::Bytes>) -> Self {
        Self {
            inner: self.inner.body(body),
        }
    }

    /// Set the request body as a UTF-8 string.
    pub fn text_body(self, text: &str) -> Self {
        Self {
            inner: self.inner.text_body(text),
        }
    }

    /// Set the request body as JSON.
    ///
    /// If serialization fails, the error is deferred until
    /// [`send()`](Self::send) so the builder chain is never broken.
    pub fn json<T: serde::Serialize>(self, value: &T) -> Self {
        Self {
            inner: self.inner.json(value),
        }
    }

    /// Set the request body as `application/x-www-form-urlencoded`.
    ///
    /// If serialization fails, the error is deferred until
    /// [`send()`](Self::send) so the builder chain is never broken.
    pub fn form<T: serde::Serialize>(self, value: &T) -> Self {
        Self {
            inner: self.inner.form(value),
        }
    }

    /// Set the request body as multipart/form-data.
    pub fn multipart(self, form: crate::multipart::Multipart) -> Self {
        Self {
            inner: self.inner.multipart(form),
        }
    }

    /// Append URL query parameters to this request.
    pub fn query(self, params: &[(&str, &str)]) -> Self {
        Self {
            inner: self.inner.query(params),
        }
    }

    // -------------------------------------------------------------------
    // Sending (blocking)
    // -------------------------------------------------------------------

    /// Send the request and block until the response is received.
    ///
    /// This is the blocking equivalent of the async
    /// [`RequestBuilder::send()`](crate::session::RequestBuilder::send).
    ///
    /// # Panics
    ///
    /// Panics if called from within a Tokio async context (nested `block_on`).
    pub fn send(self) -> Result<crate::Response> {
        runtime().block_on(self.inner.send())
    }

    /// Send the request and return a blocking streaming response.
    ///
    /// # Panics
    ///
    /// Panics if called from within a Tokio async context.
    pub fn send_streaming(self) -> Result<StreamingResponse> {
        let inner = runtime().block_on(self.inner.send_streaming())?;
        Ok(StreamingResponse { inner })
    }
}

// ===========================================================================
// StreamingResponse
// ===========================================================================

/// A blocking wrapper around [`crate::response::StreamingResponse`].
///
/// Reads body chunks synchronously by blocking the calling thread.
///
/// # Example
///
/// ```rust,no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # use lkrequest::blocking::Client;
/// # use lktls::profile::presets;
/// # let client = Client::new(lkrequest::Client::builder().fingerprint(presets::chrome_131()).build());
/// # let session = client.session().build();
/// # fn write_to_disk(_chunk: &[u8]) {}
/// let mut resp = session.get("https://example.com/large-file")
///     .send_streaming()?;
///
/// while let Some(chunk) = resp.chunk()? {
///     write_to_disk(&chunk);
/// }
/// # Ok(())
/// # }
/// ```
pub struct StreamingResponse {
    inner: crate::response::StreamingResponse,
}

impl StreamingResponse {
    /// Returns the HTTP status code.
    pub fn status(&self) -> http::StatusCode {
        self.inner.status()
    }

    /// Returns a reference to the response headers.
    pub fn headers(&self) -> &HeaderMap {
        self.inner.headers()
    }

    /// Read the next chunk of the response body (blocking).
    ///
    /// Returns `Ok(Some(chunk))` for each data chunk, `Ok(None)` at EOF.
    ///
    /// # Panics
    ///
    /// Panics if called from within a Tokio async context.
    pub fn chunk(&mut self) -> Result<Option<bytes::Bytes>> {
        runtime().block_on(self.inner.chunk())
    }

    /// Consume the response and read the full body into memory (blocking).
    ///
    /// The body is automatically decompressed based on `content-encoding`.
    ///
    /// # Panics
    ///
    /// Panics if called from within a Tokio async context.
    pub fn bytes(self) -> Result<bytes::Bytes> {
        runtime().block_on(self.inner.bytes())
    }

    /// Consume the response and read the full body as a UTF-8 string (blocking).
    ///
    /// The body is automatically decompressed.
    ///
    /// # Panics
    ///
    /// Panics if called from within a Tokio async context.
    pub fn text(self) -> Result<String> {
        runtime().block_on(self.inner.text())
    }
}

impl std::fmt::Debug for StreamingResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("blocking::StreamingResponse")
            .field("status", &self.inner.status())
            .finish()
    }
}

// ===========================================================================
// SessionPool + SessionGuard
// ===========================================================================

/// A blocking wrapper around [`crate::SessionPool`].
///
/// Provides synchronous `acquire()` that blocks until a Session is available.
///
/// # Example
///
/// ```rust,no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # use lktls::profile::presets;
/// use lkrequest::blocking;
/// use lkrequest::session_pool::SessionPool;
///
/// # let async_client = lkrequest::Client::builder().fingerprint(presets::chrome_131()).build();
/// # let proxy_configs = vec![lkrequest::proxy::ProxyConfig::parse("http://proxy:8080").unwrap()];
/// let pool = blocking::SessionPool::new(
///     SessionPool::builder()
///         .client(&async_client)
///         .proxies(proxy_configs)
///         .build()
/// );
///
/// let guard = pool.acquire();
/// let resp = guard.get("https://target.com").send()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct SessionPool {
    inner: crate::SessionPool,
}

impl SessionPool {
    /// Create a blocking `SessionPool` from an async [`crate::SessionPool`].
    ///
    /// Note: The async `SessionPool::builder().build()` must be called inside
    /// a Tokio context (it spawns a background task). Use
    /// [`SessionPool::build`] for a convenient blocking builder.
    pub fn new(inner: crate::SessionPool) -> Self {
        Self { inner }
    }

    /// Build a `SessionPool` in a blocking context.
    ///
    /// This handles the runtime requirement for the background maintenance task.
    pub fn build(builder: crate::session_pool::SessionPoolBuilder) -> Self {
        let inner = runtime().block_on(async { builder.build() });
        Self { inner }
    }

    /// Returns a reference to the underlying async `SessionPool`.
    pub fn inner(&self) -> &crate::SessionPool {
        &self.inner
    }

    /// Acquire a Session from the pool (blocking).
    ///
    /// Blocks if all Sessions are in use and the pool is at capacity.
    ///
    /// # Panics
    ///
    /// Panics if called from within a Tokio async context.
    pub fn acquire(&self) -> SessionGuard {
        let inner_guard = runtime().block_on(self.inner.acquire());
        SessionGuard {
            inner: Some(inner_guard),
        }
    }

    /// Mark a Session's proxy as "bad".
    pub fn mark_bad(&self, guard: &SessionGuard) {
        if let Some(ref inner_guard) = guard.inner {
            self.inner.mark_bad(inner_guard);
        }
    }

    /// Acquire a fresh Session with a different proxy (blocking).
    ///
    /// Marks the current session's proxy as bad and acquires a new session.
    ///
    /// # Panics
    ///
    /// Panics if called from within a Tokio async context.
    pub fn acquire_fresh(&self, bad_guard: &SessionGuard) -> SessionGuard {
        if let Some(ref inner_guard) = bad_guard.inner {
            let inner = runtime().block_on(self.inner.acquire_fresh(inner_guard));
            SessionGuard { inner: Some(inner) }
        } else {
            self.acquire()
        }
    }
}

/// A blocking RAII guard for a borrowed Session from a [`SessionPool`].
///
/// When dropped, the Session is automatically returned to the pool.
/// Use `Deref` to access the underlying blocking [`Session`] methods.
///
/// # Example
///
/// ```rust,no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # use lktls::profile::presets;
/// # use lkrequest::blocking;
/// # use lkrequest::session_pool::SessionPool;
/// # let async_client = lkrequest::Client::builder().fingerprint(presets::chrome_131()).build();
/// # let proxy_configs = vec![lkrequest::proxy::ProxyConfig::parse("http://proxy:8080").unwrap()];
/// # let pool = blocking::SessionPool::new(SessionPool::builder().client(&async_client).proxies(proxy_configs).build());
/// let guard = pool.acquire();
/// let resp = guard.get("https://target.com").send()?;
/// // guard drops → Session returned to pool
/// # Ok(())
/// # }
/// ```
pub struct SessionGuard {
    inner: Option<crate::SessionGuard>,
}

impl SessionGuard {
    /// Start building a GET request.
    pub fn get(&self, url: &str) -> RequestBuilder {
        let session = self.inner.as_ref().expect("SessionGuard already consumed");
        RequestBuilder {
            inner: session.get(url),
        }
    }

    /// Start building a POST request.
    pub fn post(&self, url: &str) -> RequestBuilder {
        let session = self.inner.as_ref().expect("SessionGuard already consumed");
        RequestBuilder {
            inner: session.post(url),
        }
    }

    /// Start building a PUT request.
    pub fn put(&self, url: &str) -> RequestBuilder {
        let session = self.inner.as_ref().expect("SessionGuard already consumed");
        RequestBuilder {
            inner: session.put(url),
        }
    }

    /// Start building a DELETE request.
    pub fn delete(&self, url: &str) -> RequestBuilder {
        let session = self.inner.as_ref().expect("SessionGuard already consumed");
        RequestBuilder {
            inner: session.delete(url),
        }
    }

    /// Start building a HEAD request.
    pub fn head(&self, url: &str) -> RequestBuilder {
        let session = self.inner.as_ref().expect("SessionGuard already consumed");
        RequestBuilder {
            inner: session.head(url),
        }
    }

    /// Start building a PATCH request.
    pub fn patch(&self, url: &str) -> RequestBuilder {
        let session = self.inner.as_ref().expect("SessionGuard already consumed");
        RequestBuilder {
            inner: session.patch(url),
        }
    }

    /// Start building an OPTIONS request.
    pub fn options(&self, url: &str) -> RequestBuilder {
        let session = self.inner.as_ref().expect("SessionGuard already consumed");
        RequestBuilder {
            inner: session.options(url),
        }
    }
}
