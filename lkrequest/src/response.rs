//! HTTP response type.
//!
//! The [`Response`] struct wraps an HTTP response (status, headers, body)
//! and provides convenience methods for reading the body in different formats.
//!
//! Response bodies are **automatically decompressed** based on the
//! `content-encoding` header. Supported encodings: `br` (Brotli),
//! `gzip`/`deflate`, `zstd`.

use bytes::Bytes;
use http::{HeaderMap, StatusCode};

/// Legacy HTTP version type.
///
/// This type is kept for backwards compatibility with
/// [`Response::version`]. New response-side code should prefer
/// [`NegotiatedHttpVersion`]. New request-side code should prefer
/// [`crate::PreferredHttpVersion`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
    /// HTTP/2
    H2,
    /// HTTP/3
    H3,
    /// Unknown / not determined on the wire for responses.
    ///
    /// When passed to [`crate::session::RequestBuilder::version`], this selects
    /// no HTTP-version override (ALPN / session preference decides).
    Unknown,
}

/// HTTP version negotiated for a response.
///
/// Unlike [`HttpVersion`], this type has no `Unknown` variant: a completed
/// response always has an observed protocol version. If an internal fallback
/// path cannot report a better value, lkrequest uses HTTP/1.1 as the most
/// conservative compatibility value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiatedHttpVersion {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
    /// HTTP/2
    Http2,
    /// HTTP/3
    Http3,
}

impl NegotiatedHttpVersion {
    pub(crate) fn from_legacy_or_default(version: HttpVersion) -> Self {
        match version {
            HttpVersion::Http10 => Self::Http10,
            HttpVersion::Http11 | HttpVersion::Unknown => Self::Http11,
            HttpVersion::H2 => Self::Http2,
            HttpVersion::H3 => Self::Http3,
        }
    }
}

impl From<NegotiatedHttpVersion> for HttpVersion {
    fn from(version: NegotiatedHttpVersion) -> Self {
        match version {
            NegotiatedHttpVersion::Http10 => Self::Http10,
            NegotiatedHttpVersion::Http11 => Self::Http11,
            NegotiatedHttpVersion::Http2 => Self::H2,
            NegotiatedHttpVersion::Http3 => Self::H3,
        }
    }
}

impl std::fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpVersion::Http10 => write!(f, "HTTP/1.0"),
            HttpVersion::Http11 => write!(f, "HTTP/1.1"),
            HttpVersion::H2 => write!(f, "h2"),
            HttpVersion::H3 => write!(f, "h3"),
            HttpVersion::Unknown => write!(f, "unknown"),
        }
    }
}

/// A single hop in the redirect chain.
///
/// When a request follows redirects (301, 302, 307, 308), each intermediate
/// response is captured as a `RedirectRecord`. The full chain is available
/// via [`Response::redirect_history()`].
#[derive(Debug, Clone)]
pub struct RedirectRecord {
    /// The URL that was requested (before redirect).
    url: String,
    /// The HTTP status code (301, 302, 307, 308).
    status: StatusCode,
    /// The response headers from this hop.
    headers: HeaderMap,
    /// The target URL from the Location header.
    redirect_to: String,
}

impl RedirectRecord {
    pub(crate) fn new(
        url: String,
        status: StatusCode,
        headers: HeaderMap,
        redirect_to: String,
    ) -> Self {
        Self {
            url,
            status,
            headers,
            redirect_to,
        }
    }

    /// Returns the URL that was requested **for this redirect hop** (before
    /// following `Location`).
    ///
    /// This is **not** the same as [`Response::url`], which is the **final**
    /// URL after the full redirect chain completes.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Returns the HTTP status code of this redirect response.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns a reference to the response headers of this hop.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Returns the target URL that this hop redirected to.
    pub fn redirect_to(&self) -> &str {
        &self.redirect_to
    }
}

/// An HTTP response.
///
/// The body is automatically decompressed if the `content-encoding` header
/// indicates compression (br, gzip, deflate, zstd).
///
/// # Example
///
/// ```rust,no_run
/// # async fn example() -> Result<(), lkrequest::error::Error> {
/// # use lkrequest::Client;
/// # use lktls::profile::presets;
/// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
/// # let session = client.session().build();
/// let resp = session.get("https://example.com").send().await?;
/// println!("Status: {}", resp.status());
/// println!("Body: {}", resp.text()?);
/// # Ok(())
/// # }
/// ```
pub struct Response {
    /// HTTP status code.
    status: StatusCode,
    /// Response headers.
    headers: HeaderMap,
    /// Response body bytes (decompressed if content-encoding was present).
    body: Bytes,
    /// The final URL (after redirects).
    url: String,
    /// The HTTP version used for this response.
    http_version: HttpVersion,
    /// Strict negotiated HTTP version used for this response.
    negotiated_version: NegotiatedHttpVersion,
    /// The redirect chain that led to this response (empty if no redirects).
    redirect_history: Vec<RedirectRecord>,
    /// Per-request diagnostics (phase timings, protocol, remote address).
    /// Present only when the request opted in via `collect_diagnostics(true)`;
    /// `None` (and zero extra cost) otherwise. Boxed to keep `Response` small on
    /// the common path (the allocation only happens when diagnostics are set).
    diagnostics: Option<Box<crate::diagnostics::RequestDiagnostics>>,
}

impl Response {
    /// Create a new Response from parts, automatically decompressing the body
    /// if a `content-encoding` header is present.
    pub(crate) fn new(
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
    ) -> crate::error::Result<Self> {
        let decompressed = decompress_body(&headers, body)?;
        Ok(Self {
            status,
            headers,
            body: decompressed,
            url: String::new(),
            http_version: HttpVersion::Unknown,
            negotiated_version: NegotiatedHttpVersion::Http11,
            redirect_history: Vec::new(),
            diagnostics: None,
        })
    }

    /// Create a Response from pre-processed parts (no decompression).
    ///
    /// Used after middleware processing where the body has already been
    /// decompressed.
    pub(crate) fn from_parts(status: StatusCode, headers: HeaderMap, body: Bytes) -> Self {
        Self {
            status,
            headers,
            body,
            url: String::new(),
            http_version: HttpVersion::Unknown,
            negotiated_version: NegotiatedHttpVersion::Http11,
            redirect_history: Vec::new(),
            diagnostics: None,
        }
    }

    /// Set the final URL (called internally after redirect chain completes).
    pub(crate) fn set_url(&mut self, url: String) {
        self.url = url;
    }

    /// Set the HTTP version (called internally based on ALPN result).
    pub(crate) fn set_http_version(&mut self, version: HttpVersion) {
        self.http_version = version;
        self.negotiated_version = NegotiatedHttpVersion::from_legacy_or_default(version);
    }

    /// Set the redirect history (called internally after redirect chain completes).
    pub(crate) fn set_redirect_history(&mut self, history: Vec<RedirectRecord>) {
        self.redirect_history = history;
    }

    /// Attach per-request diagnostics (called internally when the session opted
    /// into diagnostics collection).
    pub(crate) fn set_diagnostics(&mut self, diagnostics: crate::diagnostics::RequestDiagnostics) {
        self.diagnostics = Some(Box::new(diagnostics));
    }

    /// Per-request diagnostics (phase timings, protocol, remote address), if the
    /// session enabled collection via `collect_diagnostics(true)`.
    ///
    /// Returns `None` when diagnostics collection was not enabled.
    pub fn diagnostics(&self) -> Option<&crate::diagnostics::RequestDiagnostics> {
        self.diagnostics.as_deref()
    }

    /// Take ownership of the redirect history, leaving an empty vec behind.
    pub(crate) fn take_redirect_history(&mut self) -> Vec<RedirectRecord> {
        std::mem::take(&mut self.redirect_history)
    }

    /// Returns the redirect chain that led to this response.
    ///
    /// Each entry represents one hop: the URL that was requested,
    /// the 3xx status code received, the response headers, and the
    /// `Location` URL the server redirected to.
    ///
    /// Returns an empty slice if no redirects occurred.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://example.com/old").send().await?;
    /// for hop in resp.redirect_history() {
    ///     println!("{} -> {} ({})", hop.url(), hop.redirect_to(), hop.status());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn redirect_history(&self) -> &[RedirectRecord] {
        &self.redirect_history
    }

    /// Returns `true` if the request followed at least one redirect.
    pub fn was_redirected(&self) -> bool {
        !self.redirect_history.is_empty()
    }

    /// Returns the HTTP status code.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns a reference to the response headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Returns the final URL of this response.
    ///
    /// If the request followed redirects, this is the URL of the final
    /// response (not the original request URL). For per-hop URLs in the chain,
    /// see [`RedirectRecord::url`](RedirectRecord::url) on
    /// [`redirect_history`](Self::redirect_history) entries.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://example.com/old-page").send().await?;
    /// // If 301 redirected to /new-page:
    /// assert_eq!(resp.url(), "https://example.com/new-page");
    /// # Ok(())
    /// # }
    /// ```
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Returns the HTTP version used for this response.
    ///
    /// This legacy method returns [`HttpVersion`] for backwards
    /// compatibility. New response-side code should call
    /// [`Response::negotiated_version`], whose return type has no
    /// `Unknown` variant.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://example.com").send().await?;
    /// println!("Protocol: {}", resp.version()); // "h2" or "HTTP/1.1"
    /// # Ok(())
    /// # }
    /// ```
    pub fn version(&self) -> HttpVersion {
        self.http_version
    }

    /// Returns the negotiated HTTP version for this response.
    pub fn negotiated_version(&self) -> NegotiatedHttpVersion {
        self.negotiated_version
    }

    /// Returns the `Content-Length` of the response body, if known.
    ///
    /// Reads the `content-length` header. Note that after decompression,
    /// the actual body length may differ from this value.
    pub fn content_length(&self) -> Option<u64> {
        self.headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
    }

    /// Returns the cookies set by this response (`Set-Cookie` headers).
    ///
    /// Returns a list of `(name, value)` pairs from all `Set-Cookie` headers.
    /// This is useful for inspecting what cookies the server sent, even
    /// though they are automatically stored in the session's cookie jar.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://example.com").send().await?;
    /// for (name, value) in resp.cookies() {
    ///     println!("Set-Cookie: {name}={value}");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn cookies(&self) -> Vec<(&str, &str)> {
        self.headers
            .get_all(http::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .filter_map(|s| {
                let name_value = s.trim().split(';').next()?;
                let mut parts = name_value.splitn(2, '=');
                let name = parts.next()?.trim();
                let value = parts.next().unwrap_or("").trim();
                Some((name, value))
            })
            .collect()
    }

    /// Returns the response body as a UTF-8 string.
    ///
    /// Returns an error if the body is not valid UTF-8.
    pub fn text(&self) -> crate::error::Result<&str> {
        std::str::from_utf8(&self.body).map_err(|e| {
            crate::error::Error::Http(format!("response body is not valid UTF-8: {e}"))
        })
    }

    /// Consume the response and return the body as an owned UTF-8 string.
    ///
    /// This is the owned version of [`text()`](Self::text). Use this when
    /// you need to move the string out of the response (e.g. to store it
    /// in a struct or return from a function) without an extra copy.
    ///
    /// Returns an error if the body is not valid UTF-8.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// # let resp = session.get("https://example.com").send().await?;
    /// let body: String = resp.into_text()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn into_text(self) -> crate::error::Result<String> {
        // Try zero-copy path: if Bytes is sole owner, Vec conversion is free.
        String::from_utf8(self.body.into()).map_err(|e| {
            crate::error::Error::Http(format!("response body is not valid UTF-8: {e}"))
        })
    }

    /// Returns the response body as raw bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.body
    }

    /// Consume the response and return the body as `Bytes` (zero-copy).
    pub fn into_bytes(self) -> Bytes {
        self.body
    }

    /// Consume the response and return the body as `Vec<u8>`.
    ///
    /// Use [`into_bytes()`](Self::into_bytes) when possible to avoid a copy.
    pub fn into_vec(self) -> Vec<u8> {
        self.body.into()
    }

    /// Deserialize the response body as JSON.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # use serde::Deserialize;
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// # let resp = session.get("https://example.com").send().await?;
    /// #[derive(Deserialize)]
    /// struct ApiResponse { data: String }
    ///
    /// let api: ApiResponse = resp.json()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> crate::error::Result<T> {
        serde_json::from_slice(&self.body)
            .map_err(|e| crate::error::Error::Http(format!("failed to deserialize JSON: {e}")))
    }

    /// Turn a response into an error if the server returned a client (4xx)
    /// or server (5xx) error status code.
    ///
    /// Consumes the response. If the status is 1xx/2xx/3xx, returns `Ok(self)`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://example.com/api")
    ///     .send()
    ///     .await?
    ///     .error_for_status()?;
    /// // If status was 404, error_for_status returns Err(Error::Status { .. })
    /// # Ok(())
    /// # }
    /// ```
    pub fn error_for_status(self) -> crate::error::Result<Self> {
        let status = self.status;
        if status.is_client_error() || status.is_server_error() {
            Err(crate::error::Error::Status {
                status,
                url: self.url.clone(),
            })
        } else {
            Ok(self)
        }
    }

    /// Check the status code, returning a reference to the response on
    /// success or an error on 4xx/5xx — without consuming the response.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://example.com/api").send().await?;
    /// resp.error_for_status_ref()?;
    /// println!("Body: {}", resp.text()?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn error_for_status_ref(&self) -> crate::error::Result<&Self> {
        if self.status.is_client_error() || self.status.is_server_error() {
            Err(crate::error::Error::Status {
                status: self.status,
                url: self.url.clone(),
            })
        } else {
            Ok(self)
        }
    }
}

// ---------------------------------------------------------------------------
// Body decompression
// ---------------------------------------------------------------------------

/// Decompress the response body based on the `content-encoding` header.
///
/// Returns the original body unchanged if:
/// - No content-encoding header is present
/// - The encoding is "identity" or unrecognized
///
/// Returns [`crate::error::Error::Body`] if the server declared a supported
/// compressed encoding but the body cannot be decoded.
fn decompress_body(headers: &HeaderMap, body: Bytes) -> crate::error::Result<Bytes> {
    let encoding = match headers.get(http::header::CONTENT_ENCODING) {
        Some(v) => v.to_str().unwrap_or("").to_lowercase(),
        None => return Ok(body),
    };

    if body.is_empty() {
        return Ok(body);
    }

    let result = match encoding.as_str() {
        "br" => decompress_brotli(&body),
        "gzip" | "x-gzip" => decompress_gzip(&body),
        "deflate" => decompress_deflate(&body),
        "zstd" => decompress_zstd(&body),
        "identity" | "" => return Ok(body),
        other => {
            tracing::warn!(encoding = %other, "http.unknown_content_encoding");
            return Ok(body);
        }
    };

    match result {
        Ok(decompressed) => {
            tracing::trace!(
                encoding = %encoding,
                raw_bytes = body.len(),
                decoded_bytes = decompressed.len(),
                "http.body_decompressed",
            );
            Ok(Bytes::from(decompressed))
        }
        Err(e) => {
            tracing::warn!(
                encoding = %encoding,
                raw_bytes = body.len(),
                error = %e,
                "http.decompress_failed",
            );
            Err(crate::error::Error::Body(format!(
                "decompression failed for content-encoding `{encoding}`: {e}"
            )))
        }
    }
}

/// Hard cap on decompressed body size to prevent decompression bombs.
/// A small compressed payload can decompress to gigabytes; this limit
/// caps decompressed output regardless of `ResourceLimits` (which may
/// not be available at decompression time).
const MAX_DECOMPRESSED_SIZE: usize = 256 * 1024 * 1024; // 256 MB

fn size_limited_read(reader: &mut dyn std::io::Read, encoding: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut output = Vec::new();
    reader
        .take((MAX_DECOMPRESSED_SIZE as u64) + 1)
        .read_to_end(&mut output)
        .map_err(|e| format!("{encoding} decompression failed: {e}"))?;
    if output.len() > MAX_DECOMPRESSED_SIZE {
        return Err(format!(
            "{encoding} decompressed data exceeds {MAX_DECOMPRESSED_SIZE} byte safety limit"
        ));
    }
    Ok(output)
}

fn decompress_brotli(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = brotli::Decompressor::new(data, 4096);
    size_limited_read(&mut decoder, "brotli")
}

fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = flate2::read::GzDecoder::new(data);
    size_limited_read(&mut decoder, "gzip")
}

fn decompress_deflate(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = flate2::read::DeflateDecoder::new(data);
    size_limited_read(&mut decoder, "deflate")
}

fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder =
        zstd::Decoder::new(data).map_err(|e| format!("zstd decoder init failed: {e}"))?;
    size_limited_read(&mut decoder, "zstd")
}

// ---------------------------------------------------------------------------
// Streaming decompression
// ---------------------------------------------------------------------------

/// Stateful streaming decompressor wrapping Write-based decoders.
///
/// Compressed chunks are fed via [`decode_chunk`](Self::decode_chunk) and
/// decompressed output is returned incrementally. Call [`finish`](Self::finish)
/// after the compressed stream ends to flush any remaining buffered output.
enum StreamDecoder {
    Gzip(flate2::write::GzDecoder<Vec<u8>>),
    Deflate(flate2::write::DeflateDecoder<Vec<u8>>),
    Brotli(Box<brotli::DecompressorWriter<Vec<u8>>>),
    Zstd(zstd::stream::write::Decoder<'static, Vec<u8>>),
}

impl StreamDecoder {
    fn new(encoding: &str) -> Result<Self, String> {
        match encoding {
            "gzip" | "x-gzip" => Ok(Self::Gzip(flate2::write::GzDecoder::new(Vec::new()))),
            "deflate" => Ok(Self::Deflate(
                flate2::write::DeflateDecoder::new(Vec::new()),
            )),
            "br" => Ok(Self::Brotli(Box::new(brotli::DecompressorWriter::new(
                Vec::new(),
                4096,
            )))),
            "zstd" => {
                let dec = zstd::stream::write::Decoder::new(Vec::new())
                    .map_err(|e| format!("zstd stream decoder init: {e}"))?;
                Ok(Self::Zstd(dec))
            }
            other => Err(format!("unsupported stream encoding: {other}")),
        }
    }

    /// Feed a compressed chunk and return whatever decompressed output is
    /// available. May return empty `Bytes` if the decoder is still
    /// accumulating header/dictionary data.
    fn decode_chunk(&mut self, data: &[u8]) -> Result<Bytes, String> {
        use std::io::Write;
        let inner = match self {
            Self::Gzip(d) => {
                d.write_all(data)
                    .map_err(|e| format!("gzip stream decode: {e}"))?;
                d.get_mut()
            }
            Self::Deflate(d) => {
                d.write_all(data)
                    .map_err(|e| format!("deflate stream decode: {e}"))?;
                d.get_mut()
            }
            Self::Brotli(d) => {
                d.write_all(data)
                    .map_err(|e| format!("brotli stream decode: {e}"))?;
                d.get_mut()
            }
            Self::Zstd(d) => {
                d.write_all(data)
                    .map_err(|e| format!("zstd stream decode: {e}"))?;
                d.get_mut()
            }
        };
        Ok(Bytes::from(std::mem::take(inner)))
    }

    /// Finalize the decoder and return any remaining buffered output.
    fn finish(self) -> Result<Bytes, String> {
        match self {
            Self::Gzip(d) => d
                .finish()
                .map(Bytes::from)
                .map_err(|e| format!("gzip stream finish: {e}")),
            Self::Deflate(d) => d
                .finish()
                .map(Bytes::from)
                .map_err(|e| format!("deflate stream finish: {e}")),
            Self::Brotli(mut d) => {
                d.close()
                    .map_err(|e| format!("brotli stream finish: {e}"))?;
                Ok(Bytes::from(std::mem::take(d.get_mut())))
            }
            Self::Zstd(mut d) => {
                use std::io::Write;
                d.flush().map_err(|e| format!("zstd stream finish: {e}"))?;
                Ok(Bytes::from(d.into_inner()))
            }
        }
    }
}

/// State machine for the streaming decoder in [`StreamingResponse`].
enum DecoderState {
    /// Not yet initialized — will inspect `content-encoding` on first use.
    Uninit,
    /// No decoding needed (identity / unknown / no content-encoding).
    Passthrough,
    /// Actively decoding compressed chunks.
    Active(Box<StreamDecoder>),
    /// The compressed stream has been fully consumed and finalized.
    Finished,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("Response");
        s.field("status", &self.status)
            .field("url", &self.url)
            .field("version", &self.http_version)
            .field("headers", &self.headers)
            .field("body_len", &self.body.len());
        if !self.redirect_history.is_empty() {
            s.field("redirect_history", &self.redirect_history);
        }
        s.finish()
    }
}

// ===========================================================================
// Streaming response
// ===========================================================================

/// Internal enum wrapping different body stream types.
#[allow(clippy::large_enum_variant)]
pub(crate) enum BodyStream {
    /// HTTP/2 body stream.
    H2(lkh2::H2RecvStream),
    /// HTTP/1.1 body chunks forwarded from a bridge task via mpsc channel.
    ///
    /// A dedicated bridge task drives the hyper Connection and reads from
    /// `Incoming` in a single `select!` loop, forwarding chunks through
    /// this channel.  This avoids a deadlock that occurs when the
    /// connection driver and body consumer live in separate tasks: the
    /// connection parks its waker on the TCP transport (which has no more
    /// data) while the body consumer waits for data that is buffered
    /// inside hyper but never pushed.
    H1(tokio::sync::mpsc::Receiver<Result<bytes::Bytes, String>>),
    /// HTTP/3 body stream.
    #[cfg(feature = "quic-h3")]
    H3(Box<lkh3::H3RecvStream>),
}

/// A streaming HTTP response whose body is read on demand.
///
/// Unlike [`Response`], the body is **not** buffered into memory upfront.
/// Instead, callers read it chunk by chunk via [`chunk()`](Self::chunk),
/// making it suitable for large downloads, SSE, and long-lived streams.
///
/// # Example
///
/// ```rust,no_run
/// # async fn example() -> Result<(), lkrequest::error::Error> {
/// # use lkrequest::Client;
/// # use lktls::profile::presets;
/// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
/// # let session = client.session().build();
/// # fn write_to_disk(_: &[u8]) {}
/// let mut resp = session.get("https://example.com/large-file")
///     .send_streaming()
///     .await?;
///
/// println!("Status: {}", resp.status());
///
/// while let Some(chunk) = resp.chunk().await? {
///     // Process chunk (bytes::Bytes)
///     write_to_disk(&chunk);
/// }
/// # Ok(())
/// # }
/// ```
pub struct StreamingResponse {
    /// HTTP status code.
    status: StatusCode,
    /// Response headers.
    headers: HeaderMap,
    /// The underlying body stream.
    body_stream: BodyStream,
    /// Streaming decompression state (lazy-initialized on first `chunk_decoded()` call).
    decoder: DecoderState,
    /// Cumulative decompressed bytes produced by the streaming decoder (bomb protection).
    decompressed_total: usize,
    /// Maximum response body size (from ResourceLimits). `usize::MAX` = unlimited.
    max_body_size: usize,
    /// Cumulative bytes received so far (for body size limit enforcement).
    body_received: usize,
    /// Skip automatic decompression in `bytes()` / `chunk_decoded()`.
    no_decompress: bool,
}

impl StreamingResponse {
    /// Create a new streaming response (internal).
    pub(crate) fn new(status: StatusCode, headers: HeaderMap, body_stream: BodyStream) -> Self {
        Self {
            status,
            headers,
            body_stream,
            decoder: DecoderState::Uninit,
            decompressed_total: 0,
            max_body_size: usize::MAX,
            body_received: 0,
            no_decompress: false,
        }
    }

    pub(crate) fn with_max_body_size(mut self, max: usize) -> Self {
        self.max_body_size = max;
        self
    }

    pub(crate) fn with_no_decompress(mut self, no_decompress: bool) -> Self {
        self.no_decompress = no_decompress;
        self
    }

    /// Returns the HTTP status code.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns a reference to the response headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Read the next chunk of the response body.
    ///
    /// Returns `Ok(Some(chunk))` for each data chunk and `Ok(None)` when
    /// the body has been fully consumed (EOF).
    ///
    /// Chunks are returned as raw bytes — no automatic decompression is
    /// applied in streaming mode.  Use [`bytes()`](Self::bytes) or
    /// [`text()`](Self::text) for decompressed full-body reads.
    pub async fn chunk(&mut self) -> crate::error::Result<Option<bytes::Bytes>> {
        let result = match &mut self.body_stream {
            BodyStream::H2(recv_stream) => match recv_stream.data().await {
                Some(Ok(chunk)) => {
                    let len = chunk.len();
                    let _ = recv_stream.flow_control().release_capacity(len);
                    Ok(Some(chunk))
                }
                Some(Err(e)) => Err(crate::error::Error::h2_or_connection_closed(
                    crate::error::ConnectionPhase::HttpRequest,
                    e.to_string(),
                )),
                None => Ok(None),
            },
            BodyStream::H1(rx) => match rx.recv().await {
                Some(Ok(data)) => Ok(Some(data)),
                Some(Err(e)) => Err(crate::error::Error::http_or_connection_closed(
                    crate::error::ConnectionPhase::HttpRequest,
                    e,
                )),
                None => Ok(None),
            },
            #[cfg(feature = "quic-h3")]
            BodyStream::H3(recv_stream) => match recv_stream.data().await {
                Some(Ok(chunk)) => Ok(Some(chunk)),
                Some(Err(e)) => Err(crate::error::Error::http3_or_connection_closed(
                    crate::error::ConnectionPhase::HttpRequest,
                    e.to_string(),
                )),
                None => Ok(None),
            },
        };

        if let Ok(Some(ref data)) = result {
            self.body_received += data.len();
            if self.body_received > self.max_body_size {
                return Err(crate::error::Error::ResourceLimitExceeded(format!(
                    "response body exceeded limit: {} > {} bytes",
                    self.body_received, self.max_body_size,
                )));
            }
        }

        result
    }

    /// Consume the streaming response and read the full body into memory.
    ///
    /// The body is automatically decompressed based on the `content-encoding`
    /// header (same behavior as [`Response`]), unless `no_auto_decompress()`
    /// was set on the request.
    pub async fn bytes(mut self) -> crate::error::Result<Bytes> {
        let mut buf = bytes::BytesMut::new();
        while let Some(chunk) = self.chunk().await? {
            buf.extend_from_slice(&chunk);
        }
        let raw = buf.freeze();
        if self.no_decompress {
            Ok(raw)
        } else {
            decompress_body(&self.headers, raw)
        }
    }

    /// Consume the streaming response and read the full body as a UTF-8 string.
    ///
    /// The body is automatically decompressed.
    pub async fn text(self) -> crate::error::Result<String> {
        let bytes = self.bytes().await?;
        String::from_utf8(bytes.into()).map_err(|e| {
            crate::error::Error::Http(format!("response body is not valid UTF-8: {e}"))
        })
    }

    /// Read the next chunk of the response body with automatic decompression.
    ///
    /// Unlike [`chunk()`](Self::chunk) which returns raw (possibly compressed)
    /// bytes, this method decompresses each chunk incrementally using a
    /// stateful streaming decoder. Decompressed output is returned as it
    /// becomes available — callers do **not** need to wait for the entire
    /// body to arrive before processing.
    ///
    /// Returns:
    /// - `Ok(Some(chunk))` — a decompressed chunk of data.
    /// - `Ok(None)` — the body has been fully consumed.
    ///
    /// For uncompressed responses (`identity` or no `content-encoding`),
    /// this behaves identically to [`chunk()`](Self::chunk).
    pub async fn chunk_decoded(&mut self) -> crate::error::Result<Option<Bytes>> {
        if self.no_decompress {
            return self.chunk().await;
        }

        // Lazy-initialize the decoder on first call.
        if matches!(self.decoder, DecoderState::Uninit) {
            let encoding = self
                .headers
                .get(http::header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_lowercase();

            let needs_decode = matches!(
                encoding.as_str(),
                "br" | "gzip" | "x-gzip" | "deflate" | "zstd"
            );

            if needs_decode {
                match StreamDecoder::new(&encoding) {
                    Ok(dec) => self.decoder = DecoderState::Active(Box::new(dec)),
                    Err(e) => {
                        return Err(crate::error::Error::Body(format!(
                            "failed to init stream decoder: {e}"
                        )));
                    }
                }
            } else {
                self.decoder = DecoderState::Passthrough;
            }
        }

        if matches!(self.decoder, DecoderState::Passthrough) {
            return self.chunk().await;
        }

        if matches!(self.decoder, DecoderState::Finished) {
            return Ok(None);
        }

        // Active decoder — feed raw chunks and return decoded output.
        loop {
            match self.chunk().await? {
                Some(chunk) => {
                    let decoded = match &mut self.decoder {
                        DecoderState::Active(dec) => dec.decode_chunk(&chunk).map_err(|e| {
                            crate::error::Error::Body(format!("stream decompression error: {e}"))
                        })?,
                        _ => {
                            return Err(crate::error::Error::Http(
                                "internal error: chunk_decoded expected active decoder".into(),
                            ));
                        }
                    };

                    self.decompressed_total += decoded.len();
                    if self.decompressed_total > MAX_DECOMPRESSED_SIZE {
                        return Err(crate::error::Error::Body(format!(
                            "decompressed stream exceeds {} byte safety limit",
                            MAX_DECOMPRESSED_SIZE,
                        )));
                    }

                    if !decoded.is_empty() {
                        return Ok(Some(decoded));
                    }
                    // Decoder buffering internally (e.g. headers); keep reading.
                }
                None => {
                    // EOF — finalize the decoder and return residual output.
                    let prev = std::mem::replace(&mut self.decoder, DecoderState::Finished);
                    let remaining = match prev {
                        DecoderState::Active(dec) => dec.finish().map_err(|e| {
                            crate::error::Error::Body(format!(
                                "stream decompression finish error: {e}"
                            ))
                        })?,
                        _ => {
                            return Err(crate::error::Error::Http(
                                "internal error: chunk_decoded finish expected active decoder"
                                    .into(),
                            ));
                        }
                    };

                    self.decompressed_total += remaining.len();
                    if self.decompressed_total > MAX_DECOMPRESSED_SIZE {
                        return Err(crate::error::Error::Body(format!(
                            "decompressed stream exceeds {} byte safety limit",
                            MAX_DECOMPRESSED_SIZE,
                        )));
                    }

                    if remaining.is_empty() {
                        return Ok(None);
                    }
                    return Ok(Some(remaining));
                }
            }
        }
    }
}

impl std::fmt::Debug for StreamingResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamingResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- HttpVersion -------------------------------------------------------

    #[test]
    fn http_version_display() {
        assert_eq!(HttpVersion::Http10.to_string(), "HTTP/1.0");
        assert_eq!(HttpVersion::Http11.to_string(), "HTTP/1.1");
        assert_eq!(HttpVersion::H2.to_string(), "h2");
        assert_eq!(HttpVersion::H3.to_string(), "h3");
        assert_eq!(HttpVersion::Unknown.to_string(), "unknown");
    }

    #[test]
    fn negotiated_http_version_maps_to_legacy_version() {
        assert_eq!(
            HttpVersion::from(NegotiatedHttpVersion::Http10),
            HttpVersion::Http10
        );
        assert_eq!(
            HttpVersion::from(NegotiatedHttpVersion::Http11),
            HttpVersion::Http11
        );
        assert_eq!(
            HttpVersion::from(NegotiatedHttpVersion::Http2),
            HttpVersion::H2
        );
        assert_eq!(
            HttpVersion::from(NegotiatedHttpVersion::Http3),
            HttpVersion::H3
        );
    }

    #[test]
    fn response_exposes_legacy_and_negotiated_versions() {
        let mut resp = Response::new(StatusCode::OK, HeaderMap::new(), Bytes::new()).unwrap();
        resp.set_http_version(HttpVersion::H2);

        assert_eq!(resp.version(), HttpVersion::H2);
        assert_eq!(resp.negotiated_version(), NegotiatedHttpVersion::Http2);
    }

    // -- Response construction + accessors ---------------------------------

    #[test]
    fn response_no_encoding() {
        let body = Bytes::from("hello world");
        let headers = HeaderMap::new();
        let resp = Response::new(StatusCode::OK, headers, body.clone()).unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.bytes(), &body[..]);
        assert_eq!(resp.text().unwrap(), "hello world");
    }

    #[test]
    fn response_empty_body() {
        let resp = Response::new(StatusCode::NO_CONTENT, HeaderMap::new(), Bytes::new()).unwrap();
        assert_eq!(resp.bytes().len(), 0);
        assert_eq!(resp.text().unwrap(), "");
    }

    // -- Decompression: gzip -----------------------------------------------

    #[test]
    fn decompress_gzip_roundtrip() {
        use flate2::write::GzEncoder;
        use std::io::Write;

        let original = b"Hello, gzip compressed world!";
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_ENCODING, "gzip".parse().unwrap());

        let resp = Response::new(StatusCode::OK, headers, Bytes::from(compressed)).unwrap();
        assert_eq!(resp.text().unwrap(), "Hello, gzip compressed world!");
    }

    // -- Decompression: brotli ---------------------------------------------

    #[test]
    fn decompress_brotli_roundtrip() {
        use std::io::Write;

        let original = b"Hello, brotli compressed world!";
        let mut compressed = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 6, 22);
            writer.write_all(original).unwrap();
        }

        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_ENCODING, "br".parse().unwrap());

        let resp = Response::new(StatusCode::OK, headers, Bytes::from(compressed)).unwrap();
        assert_eq!(resp.text().unwrap(), "Hello, brotli compressed world!");
    }

    // -- Decompression: deflate -------------------------------------------

    #[test]
    fn decompress_deflate_roundtrip() {
        use flate2::write::DeflateEncoder;
        use std::io::Write;

        let original = b"Hello, deflate compressed world!";
        let mut encoder = DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_ENCODING, "deflate".parse().unwrap());

        let resp = Response::new(StatusCode::OK, headers, Bytes::from(compressed)).unwrap();
        assert_eq!(resp.text().unwrap(), "Hello, deflate compressed world!");
    }

    // -- Decompression: zstd -----------------------------------------------

    #[test]
    fn decompress_zstd_roundtrip() {
        let original = b"Hello, zstd compressed world!";
        let compressed = zstd::stream::encode_all(&original[..], 3).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_ENCODING, "zstd".parse().unwrap());

        let resp = Response::new(StatusCode::OK, headers, Bytes::from(compressed)).unwrap();
        assert_eq!(resp.text().unwrap(), "Hello, zstd compressed world!");
    }

    // -- Decompression: invalid data --------------------------------------

    #[test]
    fn decompress_invalid_gzip_returns_body_error() {
        let bad_data = Bytes::from(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_ENCODING, "gzip".parse().unwrap());

        let err = Response::new(StatusCode::OK, headers, bad_data).unwrap_err();
        assert!(matches!(err, crate::error::Error::Body(_)));
        assert!(err.to_string().contains("decompression failed"));
    }

    // -- Decompression: identity/unknown encoding -------------------------

    #[test]
    fn decompress_identity_passes_through() {
        let body = Bytes::from("plain text");
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_ENCODING, "identity".parse().unwrap());

        let resp = Response::new(StatusCode::OK, headers, body.clone()).unwrap();
        assert_eq!(resp.bytes(), &body[..]);
    }

    #[test]
    fn decompress_unknown_encoding_passes_through() {
        let body = Bytes::from("data");
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_ENCODING, "lz4".parse().unwrap());

        let resp = Response::new(StatusCode::OK, headers, body.clone()).unwrap();
        assert_eq!(resp.bytes(), &body[..]);
    }

    // -- error_for_status --------------------------------------------------

    #[test]
    fn error_for_status_ok() {
        let mut resp = Response::new(StatusCode::OK, HeaderMap::new(), Bytes::new()).unwrap();
        resp.set_url("https://example.com".into());
        assert!(resp.error_for_status_ref().is_ok());
    }

    #[test]
    fn error_for_status_404() {
        let mut resp =
            Response::new(StatusCode::NOT_FOUND, HeaderMap::new(), Bytes::new()).unwrap();
        resp.set_url("https://example.com".into());
        assert!(resp.error_for_status_ref().is_err());
    }

    #[test]
    fn error_for_status_500() {
        let mut resp = Response::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            HeaderMap::new(),
            Bytes::new(),
        )
        .unwrap();
        resp.set_url("https://example.com".into());
        assert!(resp.error_for_status_ref().is_err());
    }

    // -- decompress_body (function-level) ------------------------------------

    #[test]
    fn decompress_body_no_encoding_is_identity() {
        let body = Bytes::from("raw data");
        let result = decompress_body(&HeaderMap::new(), body.clone()).unwrap();
        assert_eq!(result, body);
    }

    #[test]
    fn decompress_body_gzip_works() {
        use flate2::write::GzEncoder;
        use std::io::Write;

        let original = b"decompress_body gzip test";
        let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(original).unwrap();
        let compressed = enc.finish().unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_ENCODING, "gzip".parse().unwrap());

        let result = decompress_body(&headers, Bytes::from(compressed)).unwrap();
        assert_eq!(&result[..], original);
    }

    #[test]
    fn decompress_body_identity_encoding_passes_through() {
        let body = Bytes::from("identity");
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_ENCODING, "identity".parse().unwrap());
        let result = decompress_body(&headers, body.clone()).unwrap();
        assert_eq!(result, body);
    }

    // -- StreamDecoder: single-chunk roundtrip ---------------------------------

    fn compress_gzip(data: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use std::io::Write;
        let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn compress_brotli(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut buf = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut buf, 4096, 6, 22);
            writer.write_all(data).unwrap();
        }
        buf
    }

    fn compress_deflate(data: &[u8]) -> Vec<u8> {
        use flate2::write::DeflateEncoder;
        use std::io::Write;
        let mut enc = DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn compress_zstd(data: &[u8]) -> Vec<u8> {
        zstd::stream::encode_all(data, 3).unwrap()
    }

    /// Collect all decoded output from a StreamDecoder (decode + finish).
    fn decode_all(dec: &mut StreamDecoder, compressed: &[u8]) -> bytes::BytesMut {
        let mut out = bytes::BytesMut::new();
        out.extend_from_slice(&dec.decode_chunk(compressed).unwrap());
        out
    }

    fn finish_into(dec: StreamDecoder, buf: &mut bytes::BytesMut) {
        buf.extend_from_slice(&dec.finish().unwrap());
    }

    #[test]
    fn stream_decoder_gzip_single_chunk() {
        let original = b"Hello, streaming gzip world!";
        let compressed = compress_gzip(original);

        let mut dec = StreamDecoder::new("gzip").unwrap();
        let mut out = decode_all(&mut dec, &compressed);
        finish_into(dec, &mut out);
        assert_eq!(&out[..], &original[..]);
    }

    #[test]
    fn stream_decoder_brotli_single_chunk() {
        let original = b"Hello, streaming brotli world!";
        let compressed = compress_brotli(original);

        let mut dec = StreamDecoder::new("br").unwrap();
        let mut out = decode_all(&mut dec, &compressed);
        finish_into(dec, &mut out);
        assert_eq!(&out[..], &original[..]);
    }

    #[test]
    fn stream_decoder_deflate_single_chunk() {
        let original = b"Hello, streaming deflate world!";
        let compressed = compress_deflate(original);

        let mut dec = StreamDecoder::new("deflate").unwrap();
        let mut out = decode_all(&mut dec, &compressed);
        finish_into(dec, &mut out);
        assert_eq!(&out[..], &original[..]);
    }

    #[test]
    fn stream_decoder_zstd_single_chunk() {
        let original = b"Hello, streaming zstd world!";
        let compressed = compress_zstd(original);

        let mut dec = StreamDecoder::new("zstd").unwrap();
        let mut out = decode_all(&mut dec, &compressed);
        finish_into(dec, &mut out);
        assert_eq!(&out[..], &original[..]);
    }

    // -- StreamDecoder: multi-chunk roundtrip ----------------------------------

    /// Split data into chunks of the given size.
    fn split_chunks(data: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
        data.chunks(chunk_size).map(|c| c.to_vec()).collect()
    }

    #[test]
    fn stream_decoder_gzip_multi_chunk() {
        let original = "Streaming gzip multi-chunk test. ".repeat(100);
        let compressed = compress_gzip(original.as_bytes());
        let chunks = split_chunks(&compressed, 32);
        assert!(chunks.len() > 1, "test requires multiple chunks");

        let mut dec = StreamDecoder::new("gzip").unwrap();
        let mut out = bytes::BytesMut::new();
        for chunk in &chunks {
            out.extend_from_slice(&dec.decode_chunk(chunk).unwrap());
        }
        finish_into(dec, &mut out);
        assert_eq!(&out[..], original.as_bytes());
    }

    #[test]
    fn stream_decoder_brotli_multi_chunk() {
        let original = "Streaming brotli multi-chunk test. ".repeat(100);
        let compressed = compress_brotli(original.as_bytes());
        let chunks = split_chunks(&compressed, 32);
        assert!(chunks.len() > 1, "test requires multiple chunks");

        let mut dec = StreamDecoder::new("br").unwrap();
        let mut out = bytes::BytesMut::new();
        for chunk in &chunks {
            out.extend_from_slice(&dec.decode_chunk(chunk).unwrap());
        }
        finish_into(dec, &mut out);
        assert_eq!(&out[..], original.as_bytes());
    }

    #[test]
    fn stream_decoder_deflate_multi_chunk() {
        let original = "Streaming deflate multi-chunk test. ".repeat(100);
        let compressed = compress_deflate(original.as_bytes());
        let chunks = split_chunks(&compressed, 32);
        assert!(chunks.len() > 1, "test requires multiple chunks");

        let mut dec = StreamDecoder::new("deflate").unwrap();
        let mut out = bytes::BytesMut::new();
        for chunk in &chunks {
            out.extend_from_slice(&dec.decode_chunk(chunk).unwrap());
        }
        finish_into(dec, &mut out);
        assert_eq!(&out[..], original.as_bytes());
    }

    #[test]
    fn stream_decoder_zstd_multi_chunk() {
        let original = "Streaming zstd multi-chunk test. ".repeat(100);
        let compressed = compress_zstd(original.as_bytes());
        let chunks = split_chunks(&compressed, 32);
        assert!(chunks.len() > 1, "test requires multiple chunks");

        let mut dec = StreamDecoder::new("zstd").unwrap();
        let mut out = bytes::BytesMut::new();
        for chunk in &chunks {
            out.extend_from_slice(&dec.decode_chunk(chunk).unwrap());
        }
        finish_into(dec, &mut out);
        assert_eq!(&out[..], original.as_bytes());
    }

    // -- StreamDecoder: x-gzip alias ------------------------------------------

    #[test]
    fn stream_decoder_x_gzip_alias() {
        let original = b"x-gzip alias test";
        let compressed = compress_gzip(original);

        let mut dec = StreamDecoder::new("x-gzip").unwrap();
        let mut out = decode_all(&mut dec, &compressed);
        finish_into(dec, &mut out);
        assert_eq!(&out[..], &original[..]);
    }

    // -- StreamDecoder: unsupported encoding ----------------------------------

    #[test]
    fn stream_decoder_unsupported_encoding() {
        assert!(StreamDecoder::new("lz4").is_err());
    }

    // -- StreamDecoder: empty input -------------------------------------------

    #[test]
    fn stream_decoder_gzip_empty_finish_errors() {
        let dec = StreamDecoder::new("gzip").unwrap();
        // Finishing with no data is an invalid gzip stream.
        assert!(dec.finish().is_err());
    }

    #[test]
    fn stream_decoder_deflate_empty_finish_ok() {
        let dec = StreamDecoder::new("deflate").unwrap();
        let remaining = dec.finish().unwrap();
        assert!(remaining.is_empty());
    }
}
