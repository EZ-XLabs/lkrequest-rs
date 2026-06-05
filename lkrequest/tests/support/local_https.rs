//! Embedded HTTPS server for Tier-0 integration tests (127.0.0.1 only).
//!
//! Uses rustls for TLS and `hyper` for HTTP/1 + HTTP/2 (ALPN).
//! Certificates are generated with `rcgen` (SAN: `127.0.0.1`, `localhost`).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{CertifiedKey, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

/// Running local HTTPS server. Drop to stop the accept loop.
pub struct LocalHttpsServer {
    /// Base URL without trailing slash, e.g. `https://127.0.0.1:54321`.
    pub base_url: String,
    shutdown: Option<oneshot::Sender<()>>,
    /// Shared request counter for retry/counting tests.
    pub request_counter: Arc<AtomicU32>,
}

/// DER-encoded CA certificate for the local server (for `add_ca_cert_der`).
pub fn local_server_ca_der(cert: &CertifiedKey<KeyPair>) -> Vec<u8> {
    cert.cert.der().to_vec()
}

impl Drop for LocalHttpsServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

fn build_certified_key() -> CertifiedKey<KeyPair> {
    rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string(), "localhost".to_string()])
        .expect("rcgen self-signed")
}

fn tls_acceptor(cert: &CertifiedKey<KeyPair>) -> TlsAcceptor {
    let cert_chain = vec![cert.cert.der().clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .expect("rustls protocol versions")
    .with_no_client_auth()
    .with_single_cert(cert_chain, key)
    .expect("rustls server certificate");
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(config))
}

fn parse_cookies(header: Option<&str>) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    let Some(raw) = header else {
        return serde_json::Value::Object(map);
    };
    for part in raw.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            map.insert(
                k.trim().to_string(),
                serde_json::Value::String(v.trim().to_string()),
            );
        }
    }
    serde_json::Value::Object(map)
}

fn json_headers_from_request(req: &Request<hyper::body::Incoming>) -> serde_json::Value {
    let mut headers = serde_json::Map::new();
    for (name, value) in req.headers().iter() {
        let v = value.to_str().unwrap_or("<binary>");
        headers.insert(
            name.as_str().to_string(),
            serde_json::Value::String(v.to_string()),
        );
    }
    serde_json::Value::Object(headers)
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    counter: Arc<AtomicU32>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();

    counter.fetch_add(1, Ordering::Relaxed);

    if let Some(rest) = path.strip_prefix("/redirect/") {
        if let Ok(n) = rest.parse::<u32>() {
            if n > 0 {
                let loc = format!("/redirect/{}", n - 1);
                return Ok(Response::builder()
                    .status(StatusCode::FOUND)
                    .header(hyper::header::LOCATION, loc)
                    .body(Full::new(Bytes::new()))
                    .unwrap());
            }
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "text/plain")
                .body(Full::new(Bytes::from("ok")))
                .unwrap());
        }
    }

    if path == "/redirect-to" {
        let mut target = String::from("/get");
        let mut code = 302u16;
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                match k {
                    "url" => {
                        target = urlencoding::decode(v)
                            .map(|c| c.into_owned())
                            .unwrap_or_else(|_| v.to_string());
                    }
                    "status_code" => {
                        if let Ok(c) = v.parse::<u16>() {
                            code = c;
                        }
                    }
                    _ => {}
                }
            }
        }
        return Ok(Response::builder()
            .status(StatusCode::from_u16(code).unwrap_or(StatusCode::FOUND))
            .header(hyper::header::LOCATION, target)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }

    if path == "/cookies/set" {
        let mut first_cookie: Option<(String, String)> = None;
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                let v_dec = urlencoding::decode(v)
                    .map(|c| c.into_owned())
                    .unwrap_or_else(|_| v.to_string());
                if first_cookie.is_none() {
                    first_cookie = Some((k.to_string(), v_dec));
                }
            }
        }
        let mut res = Response::builder()
            .status(StatusCode::TEMPORARY_REDIRECT)
            .header(hyper::header::LOCATION, "/cookies");
        if let Some((k, v)) = first_cookie {
            res = res.header(hyper::header::SET_COOKIE, format!("{k}={v}; Path=/"));
        }
        return Ok(res.body(Full::new(Bytes::new())).unwrap());
    }

    if path == "/cookies" && method == Method::GET {
        let cookie_hdrs: Vec<&str> = req
            .headers()
            .get_all(hyper::header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        let combined = if cookie_hdrs.is_empty() {
            None
        } else {
            Some(cookie_hdrs.join("; "))
        };
        let cookies = parse_cookies(combined.as_deref());
        let body = serde_json::json!({ "cookies": cookies });
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap());
    }

    if let Some(rest) = path.strip_prefix("/delay/") {
        if let Ok(secs) = rest.parse::<u64>() {
            tokio::time::sleep(Duration::from_secs(secs)).await;
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::from("delayed")))
                .unwrap());
        }
    }

    if let Some(rest) = path.strip_prefix("/bytes/") {
        if let Ok(n) = rest.parse::<usize>() {
            let n = n.min(16 * 1024 * 1024);
            let data = vec![b'x'; n];
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::from(data)))
                .unwrap());
        }
    }

    if let Some(rest) = path.strip_prefix("/status/") {
        if let Ok(code) = rest.parse::<u16>() {
            let st = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            return Ok(Response::builder()
                .status(st)
                .body(Full::new(Bytes::new()))
                .unwrap());
        }
    }

    if path == "/response-headers" && method == Method::GET {
        let mut count = 0usize;
        let mut size = 0usize;
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                match k {
                    "count" => {
                        count = v.parse().unwrap_or(0);
                    }
                    "size" => {
                        size = v.parse().unwrap_or(0);
                    }
                    _ => {}
                }
            }
        }
        let mut res = Response::builder().status(StatusCode::OK);
        for i in 0..count {
            let val = "x".repeat(size.max(1));
            res = res.header(format!("X-Test-{i}"), val);
        }
        return Ok(res.body(Full::new(Bytes::from("ok"))).unwrap());
    }

    if path == "/headers" && method == Method::GET {
        let headers = json_headers_from_request(&req);
        let body = serde_json::json!({ "headers": headers });
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap());
    }

    if path == "/get" && method == Method::GET {
        let body = serde_json::json!({
            "url": format!("https://127.0.0.1{}", path),
        });
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap());
    }

    if (path == "/post" || path == "/put" || path == "/patch" || path == "/delete")
        && (method == Method::POST
            || method == Method::PUT
            || method == Method::PATCH
            || method == Method::DELETE)
    {
        let ctype = req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let whole = req.collect().await?.to_bytes();
        let raw = String::from_utf8_lossy(&whole);

        let mut body = serde_json::json!({
            "data": raw.as_ref(),
        });

        if ctype.as_str().contains("application/json") {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                body["json"] = v;
            }
        }

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap());
    }

    // --- /compress/{encoding} — returns compressed body ---
    if let Some(encoding) = path.strip_prefix("/compress/") {
        let payload = "Hello, compressed world! ".repeat(20);
        let compressed = match encoding {
            "gzip" => {
                use flate2::write::GzEncoder;
                use std::io::Write;
                let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
                enc.write_all(payload.as_bytes()).ok();
                enc.finish().unwrap_or_default()
            }
            "br" => {
                use std::io::Write;
                let mut buf = Vec::new();
                {
                    let mut writer = brotli::CompressorWriter::new(&mut buf, 4096, 6, 22);
                    writer.write_all(payload.as_bytes()).ok();
                }
                buf
            }
            "zstd" => zstd::stream::encode_all(payload.as_bytes(), 3).unwrap_or_default(),
            "deflate" => {
                use flate2::write::DeflateEncoder;
                use std::io::Write;
                let mut enc = DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                enc.write_all(payload.as_bytes()).ok();
                enc.finish().unwrap_or_default()
            }
            _ => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from("unknown encoding")))
                    .unwrap());
            }
        };
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_ENCODING, encoding)
            .header(http::header::CONTENT_TYPE, "text/plain")
            .body(Full::new(Bytes::from(compressed)))
            .unwrap());
    }

    // --- /basic-auth/{user}/{pass} — HTTP Basic Auth ---
    if let Some(rest) = path.strip_prefix("/basic-auth/") {
        let parts: Vec<&str> = rest.splitn(2, '/').collect();
        if parts.len() == 2 {
            let expected_user = parts[0];
            let expected_pass = parts[1];
            let auth_header = req
                .headers()
                .get(hyper::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok());

            if let Some(auth) = auth_header {
                if let Some(encoded) = auth.strip_prefix("Basic ") {
                    use base64::Engine;
                    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                        let decoded_str = String::from_utf8_lossy(&decoded);
                        let expected = format!("{expected_user}:{expected_pass}");
                        if decoded_str == expected {
                            let body = serde_json::json!({
                                "authenticated": true,
                                "user": expected_user,
                            });
                            return Ok(Response::builder()
                                .status(StatusCode::OK)
                                .header(hyper::header::CONTENT_TYPE, "application/json")
                                .body(Full::new(Bytes::from(body.to_string())))
                                .unwrap());
                        }
                    }
                }
            }
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(hyper::header::WWW_AUTHENTICATE, "Basic realm=\"test\"")
                .body(Full::new(Bytes::new()))
                .unwrap());
        }
    }

    // --- /cookies/set-multi — set multiple cookies at once ---
    if path == "/cookies/set-multi" {
        let mut res = Response::builder()
            .status(StatusCode::TEMPORARY_REDIRECT)
            .header(hyper::header::LOCATION, "/cookies");
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                let v_dec = urlencoding::decode(v)
                    .map(|c| c.into_owned())
                    .unwrap_or_else(|_| v.to_string());
                res = res.header(hyper::header::SET_COOKIE, format!("{k}={v_dec}; Path=/"));
            }
        }
        return Ok(res.body(Full::new(Bytes::new())).unwrap());
    }

    // --- /redirect-loop — infinite redirect loop ---
    if path == "/redirect-loop" {
        return Ok(Response::builder()
            .status(StatusCode::FOUND)
            .header(hyper::header::LOCATION, "/redirect-loop")
            .body(Full::new(Bytes::new()))
            .unwrap());
    }

    // --- /redirect-307 — 307 redirect preserving method and body ---
    if path == "/redirect-307" {
        let target = {
            let mut t = String::from("/post");
            for pair in query.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    if k == "to" {
                        t = urlencoding::decode(v)
                            .map(|c| c.into_owned())
                            .unwrap_or_else(|_| v.to_string());
                    }
                }
            }
            t
        };
        return Ok(Response::builder()
            .status(StatusCode::TEMPORARY_REDIRECT)
            .header(hyper::header::LOCATION, target)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }

    // --- /redirect-308 — 308 redirect preserving method and body ---
    if path == "/redirect-308" {
        let target = {
            let mut t = String::from("/post");
            for pair in query.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    if k == "to" {
                        t = urlencoding::decode(v)
                            .map(|c| c.into_owned())
                            .unwrap_or_else(|_| v.to_string());
                    }
                }
            }
            t
        };
        return Ok(Response::builder()
            .status(StatusCode::PERMANENT_REDIRECT)
            .header(hyper::header::LOCATION, target)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }

    // --- /binary — returns non-UTF-8 binary bytes ---
    if path == "/binary" {
        let data: Vec<u8> = (0..=255).collect();
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/octet-stream")
            .body(Full::new(Bytes::from(data)))
            .unwrap());
    }

    // --- /json — returns a well-known JSON object ---
    if path == "/json" {
        let body = serde_json::json!({
            "message": "hello",
            "number": 42,
            "nested": { "key": "value" }
        });
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap());
    }

    // --- /text-plain — returns plain text ---
    if path == "/text-plain" {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "text/plain")
            .body(Full::new(Bytes::from("just plain text")))
            .unwrap());
    }

    // --- /counter — returns and resets the request counter ---
    if path == "/counter" {
        let count = counter.load(Ordering::Relaxed);
        let body = serde_json::json!({ "count": count });
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap());
    }

    // --- /status-body/{code} — status code with a body ---
    if let Some(rest) = path.strip_prefix("/status-body/") {
        if let Ok(code) = rest.parse::<u16>() {
            let st = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let body_text = format!("status {code}");
            return Ok(Response::builder()
                .status(st)
                .header(hyper::header::CONTENT_TYPE, "text/plain")
                .body(Full::new(Bytes::from(body_text)))
                .unwrap());
        }
    }

    // --- /echo-headers — returns request headers + method as JSON ---
    if path == "/echo-headers" {
        let headers = json_headers_from_request(&req);
        let body = serde_json::json!({
            "method": method.as_str(),
            "headers": headers,
            "path": path,
        });
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap());
    }

    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::from("not found")))
        .unwrap())
}

/// Start listening; returns once the accept loop is running.
pub async fn start_local_https_server() -> LocalHttpsServer {
    let certified = build_certified_key();
    let acceptor = tls_acceptor(&certified);
    let request_counter = Arc::new(AtomicU32::new(0));

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind 127.0.0.1");
    let addr = listener.local_addr().expect("local_addr");
    let base_url = format!("https://127.0.0.1:{}", addr.port());

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let counter = request_counter.clone();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { continue };
                    let acc = acceptor.clone();
                    let cnt = counter.clone();
                    tokio::spawn(async move {
                        let tls = match acc.accept(stream).await {
                            Ok(t) => t,
                            Err(_) => return,
                        };
                        let io = TokioIo::new(tls);
                        let svc = service_fn(move |req| {
                            let c = cnt.clone();
                            async move { handle_request(req, c).await }
                        });
                        let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                            .serve_connection_with_upgrades(io, svc)
                            .await;
                    });
                }
            }
        }
    });

    tokio::task::yield_now().await;

    LocalHttpsServer {
        base_url,
        shutdown: Some(shutdown_tx),
        request_counter,
    }
}

/// Build `https://127.0.0.1:port/path` from server base URL.
pub fn url_join(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    format!("{}{}", base, path)
}
