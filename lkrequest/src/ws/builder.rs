//! WebSocket connection builder — configures and establishes a WS connection.

use http::header::HeaderName;
use http::HeaderMap;
use std::str::FromStr;
use url::Url;

use super::upgrade::ws_upgrade_h1;
use super::WsConnection;
use crate::error::{Error, Result};
use crate::session::Session;

/// Builder for configuring a WebSocket connection.
///
/// Created via [`Session::websocket(url)`](crate::session::Session).
pub struct WsBuilder {
    pub(crate) url: String,
    pub(crate) extra_headers: HeaderMap,
    pub(crate) protocols: Vec<String>,
    pub(crate) extensions: Vec<String>,
    session: Option<Session>,
}

impl WsBuilder {
    /// Create a new WebSocket builder for the given URL (standalone, no session).
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            extra_headers: HeaderMap::new(),
            protocols: Vec::new(),
            extensions: Vec::new(),
            session: None,
        }
    }

    /// Create a new WebSocket builder bound to a session.
    pub(crate) fn new_with_session(url: impl Into<String>, session: Session) -> Self {
        Self {
            url: url.into(),
            extra_headers: HeaderMap::new(),
            protocols: Vec::new(),
            extensions: Vec::new(),
            session: Some(session),
        }
    }

    /// Add a custom header to the WebSocket upgrade request.
    ///
    /// Common headers: `Origin`, `User-Agent`, `Cookie`, etc.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_str(name),
            http::HeaderValue::from_str(value),
        ) {
            self.extra_headers.insert(n, v);
        }
        self
    }

    /// Set the `Sec-WebSocket-Protocol` subprotocol(s).
    ///
    /// Multiple calls accumulate protocols.
    pub fn protocol(mut self, protocol: &str) -> Self {
        self.protocols.push(protocol.to_string());
        self
    }

    /// Set the `Sec-WebSocket-Extensions` extension(s).
    ///
    /// Multiple calls accumulate extensions.
    pub fn extension(mut self, extension: &str) -> Self {
        self.extensions.push(extension.to_string());
        self
    }

    /// Establish the WebSocket connection.
    ///
    /// Performs the full connection pipeline:
    /// 1. Parse the URL (wss:// or ws://)
    /// 2. TCP connection (with optional proxy and TCP fingerprint)
    /// 3. TLS handshake (with fingerprint-controlled ClientHello)
    /// 4. ALPN-based protocol selection:
    ///    - HTTP/1.1: sends Upgrade request (RFC 6455)
    ///    - HTTP/2: sends Extended CONNECT (RFC 8441)
    /// 5. Returns a `WsConnection` for bidirectional messaging
    ///
    /// Cookie, proxy, TLS fingerprint, and timeout settings are inherited
    /// from the session.
    ///
    /// The future is heap-allocated (`Pin<Box<…>>`) to prevent the ~28 KB
    /// async state machine from overflowing the stack in debug builds on
    /// platforms with small default stacks (e.g. 1 MB Windows main thread).
    #[allow(clippy::type_complexity)]
    pub fn connect(
        self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        WsConnection<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>>,
                    >,
                > + Send,
        >,
    > {
        Box::pin(async move {
            let session = self
                .session
                .as_ref()
                .ok_or_else(|| Error::Http("WebSocket builder requires a session".into()))?;

            let client = session.client();

            let parsed = Url::parse(&self.url).map_err(|e| Error::UrlParse(e.to_string()))?;

            let scheme = parsed.scheme();
            let is_tls = match scheme {
                "wss" | "https" => true,
                "ws" | "http" => false,
                _ => {
                    return Err(Error::UrlParse(format!(
                        "Unsupported WebSocket scheme: {scheme}"
                    )));
                }
            };

            let host = parsed
                .host_str()
                .ok_or_else(|| Error::UrlParse("Missing host in WebSocket URL".into()))?
                .to_string();

            let default_port = if is_tls { 443 } else { 80 };
            let port = parsed.port().unwrap_or(default_port);
            let path = if parsed.query().is_some() {
                format!("{}?{}", parsed.path(), parsed.query().unwrap())
            } else {
                parsed.path().to_string()
            };

            if !is_tls {
                return Err(Error::Http(
                    "Only wss:// (TLS) WebSocket connections are supported".into(),
                ));
            }

            // WebSocket uses H1-only ALPN (standard Upgrade requires HTTP/1.1)
            let mut tls_profile = client.tls_profile().clone();
            tls_profile.alpn_protocols =
                crate::session::pipeline::alpn_for_h1_only(&tls_profile.alpn_protocols);

            let connect_config = crate::connect::ConnectConfig::https(tls_profile, Vec::new());

            let conn = session
                .establish_connection(&host, port, session.inner.proxy.as_ref(), &connect_config)
                .await?;

            tracing::debug!(
                alpn = ?conn.negotiated_alpn(),
                "ws.alpn_negotiated",
            );

            let default_headers = client.default_headers();
            ws_upgrade_h1(
                conn.into_tcp_stream()?,
                &host,
                &path,
                &self,
                default_headers,
            )
            .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ====================================================================
    // WsBuilder — configuring a WebSocket before connecting
    // ====================================================================

    #[test]
    fn standalone_builder_stores_url() {
        let builder = WsBuilder::new("wss://echo.example.com/ws");
        assert_eq!(builder.url, "wss://echo.example.com/ws");
        assert!(builder.session.is_none());
    }

    #[test]
    fn add_custom_headers_for_auth() {
        let builder = WsBuilder::new("wss://api.example.com")
            .header("Authorization", "Bearer tok123")
            .header("Origin", "https://app.example.com");

        assert_eq!(builder.extra_headers.len(), 2);
        assert_eq!(
            builder.extra_headers.get("authorization").unwrap(),
            "Bearer tok123"
        );
        assert_eq!(
            builder.extra_headers.get("origin").unwrap(),
            "https://app.example.com"
        );
    }

    #[test]
    fn set_subprotocol_for_graphql() {
        let builder = WsBuilder::new("wss://api.example.com/graphql")
            .protocol("graphql-ws")
            .protocol("graphql-transport-ws");

        assert_eq!(builder.protocols.len(), 2);
        assert_eq!(builder.protocols[0], "graphql-ws");
        assert_eq!(builder.protocols[1], "graphql-transport-ws");
    }

    #[test]
    fn set_permessage_deflate_extension() {
        let builder = WsBuilder::new("wss://chat.example.com")
            .extension("permessage-deflate; client_max_window_bits");

        assert_eq!(builder.extensions.len(), 1);
        assert!(builder.extensions[0].contains("permessage-deflate"));
    }

    #[test]
    fn full_builder_chain() {
        let builder = WsBuilder::new("wss://realtime.example.com")
            .header("User-Agent", "MyApp/1.0")
            .header("Cookie", "session=abc")
            .protocol("chat")
            .extension("permessage-deflate");

        assert_eq!(builder.extra_headers.len(), 2);
        assert_eq!(builder.protocols, vec!["chat"]);
        assert_eq!(builder.extensions, vec!["permessage-deflate"]);
    }

    #[test]
    fn invalid_header_name_is_silently_skipped() {
        let builder = WsBuilder::new("wss://example.com")
            .header("valid-header", "ok")
            .header("invalid header name with spaces", "nope");

        assert_eq!(builder.extra_headers.len(), 1);
        assert!(builder.extra_headers.contains_key("valid-header"));
    }
}
