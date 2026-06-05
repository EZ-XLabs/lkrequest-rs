//! Middleware — local HTTPS server (Tier 0).
//!
//! Covers: on_request header injection, on_response modification,
//! multiple middleware chain, client+session onion model, error short-circuit.

#[macro_use]
mod support;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::middleware::{Middleware, MiddlewareRequest, MiddlewareResponse};
use lkrequest::Client;
use lktls::profile::presets;
use support::local_https::{start_local_https_server, url_join};

// --- Middleware implementations ---

struct AddHeaderMiddleware {
    name: String,
    value: String,
}

impl Middleware for AddHeaderMiddleware {
    fn on_request(
        &self,
        mut req: MiddlewareRequest,
    ) -> Result<MiddlewareRequest, lkrequest::error::Error> {
        req.headers.insert(
            http::header::HeaderName::from_bytes(self.name.as_bytes()).unwrap(),
            http::header::HeaderValue::from_str(&self.value).unwrap(),
        );
        Ok(req)
    }

    fn on_response(
        &self,
        resp: MiddlewareResponse,
    ) -> Result<MiddlewareResponse, lkrequest::error::Error> {
        Ok(resp)
    }
}

struct ResponseModifierMiddleware {
    inject_header_name: String,
    inject_header_value: String,
}

impl Middleware for ResponseModifierMiddleware {
    fn on_response(
        &self,
        mut resp: MiddlewareResponse,
    ) -> Result<MiddlewareResponse, lkrequest::error::Error> {
        resp.headers.insert(
            http::header::HeaderName::from_bytes(self.inject_header_name.as_bytes()).unwrap(),
            http::header::HeaderValue::from_str(&self.inject_header_value).unwrap(),
        );
        Ok(resp)
    }
}

struct CountingMiddleware {
    request_count: Arc<AtomicU32>,
    response_count: Arc<AtomicU32>,
}

impl CountingMiddleware {
    fn new() -> (Self, Arc<AtomicU32>, Arc<AtomicU32>) {
        let req = Arc::new(AtomicU32::new(0));
        let resp = Arc::new(AtomicU32::new(0));
        (
            Self {
                request_count: req.clone(),
                response_count: resp.clone(),
            },
            req,
            resp,
        )
    }
}

impl Middleware for CountingMiddleware {
    fn on_request(
        &self,
        req: MiddlewareRequest,
    ) -> Result<MiddlewareRequest, lkrequest::error::Error> {
        self.request_count.fetch_add(1, Ordering::Relaxed);
        Ok(req)
    }

    fn on_response(
        &self,
        resp: MiddlewareResponse,
    ) -> Result<MiddlewareResponse, lkrequest::error::Error> {
        self.response_count.fetch_add(1, Ordering::Relaxed);
        Ok(resp)
    }
}

struct ShortCircuitMiddleware;

impl Middleware for ShortCircuitMiddleware {
    fn on_request(
        &self,
        _req: MiddlewareRequest,
    ) -> Result<MiddlewareRequest, lkrequest::error::Error> {
        Err(lkrequest::error::Error::Http(
            "blocked by middleware".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// on_request: header injection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_middleware_adds_custom_header() {
    let srv = start_local_https_server().await;
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .middleware(AddHeaderMiddleware {
            name: "x-custom-test".into(),
            value: "middleware-works".into(),
        })
        .build();

    let session = client.session().build();
    let url = url_join(&srv.base_url, "/headers");
    let resp = session.get(&url).send().await.expect("request");

    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().expect("utf-8");
    let lower = body.to_lowercase();
    assert!(
        lower.contains("x-custom-test") && lower.contains("middleware-works"),
        "body={body}"
    );
}

// ---------------------------------------------------------------------------
// on_response: header injection in response
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_middleware_on_response_injects_header() {
    let srv = start_local_https_server().await;
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .middleware(ResponseModifierMiddleware {
            inject_header_name: "x-middleware-added".into(),
            inject_header_value: "response-modified".into(),
        })
        .build();

    let session = client.session().build();
    let url = url_join(&srv.base_url, "/get");
    let resp = session.get(&url).send().await.expect("request");

    assert_eq!(resp.status().as_u16(), 200);
    let hdr = resp
        .headers()
        .get("x-middleware-added")
        .and_then(|v| v.to_str().ok());
    assert_eq!(hdr, Some("response-modified"));
}

// ---------------------------------------------------------------------------
// Multiple middleware chain
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_middleware_multiple_chain_on_request() {
    let srv = start_local_https_server().await;
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .middleware(AddHeaderMiddleware {
            name: "x-first-mw".into(),
            value: "first".into(),
        })
        .middleware(AddHeaderMiddleware {
            name: "x-second-mw".into(),
            value: "second".into(),
        })
        .build();

    let session = client.session().build();
    let url = url_join(&srv.base_url, "/headers");
    let resp = session.get(&url).send().await.expect("request");

    let body = resp.text().expect("utf-8");
    let lower = body.to_lowercase();
    assert!(lower.contains("x-first-mw"), "missing first: {body}");
    assert!(lower.contains("x-second-mw"), "missing second: {body}");
}

// ---------------------------------------------------------------------------
// Client + Session middleware interaction (onion model)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_middleware_client_and_session_both_execute() {
    let srv = start_local_https_server().await;
    let (client_mw, client_req_count, client_resp_count) = CountingMiddleware::new();
    let (session_mw, session_req_count, session_resp_count) = CountingMiddleware::new();

    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .middleware(client_mw)
        .build();

    let session = client.session().middleware(session_mw).build();
    let url = url_join(&srv.base_url, "/get");
    let resp = session.get(&url).send().await.expect("request");
    assert_eq!(resp.status().as_u16(), 200);

    assert_eq!(client_req_count.load(Ordering::Relaxed), 1);
    assert_eq!(client_resp_count.load(Ordering::Relaxed), 1);
    assert_eq!(session_req_count.load(Ordering::Relaxed), 1);
    assert_eq!(session_resp_count.load(Ordering::Relaxed), 1);
}

// ---------------------------------------------------------------------------
// Error short-circuit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_middleware_short_circuit_aborts_request() {
    let srv = start_local_https_server().await;
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .middleware(ShortCircuitMiddleware)
        .build();

    let session = client.session().build();
    let url = url_join(&srv.base_url, "/get");
    let result = session.get(&url).send().await;

    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("blocked by middleware"),
        "error: {err_msg}"
    );
}

// ---------------------------------------------------------------------------
// Middleware called on every request (multiple requests)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_middleware_called_on_every_request() {
    let srv = start_local_https_server().await;
    let (mw, req_count, resp_count) = CountingMiddleware::new();

    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .middleware(mw)
        .build();

    let session = client.session().build();

    for _ in 0..3 {
        let resp = session
            .get(&url_join(&srv.base_url, "/get"))
            .send()
            .await
            .expect("request");
        assert_eq!(resp.status().as_u16(), 200);
    }

    assert_eq!(req_count.load(Ordering::Relaxed), 3);
    assert_eq!(resp_count.load(Ordering::Relaxed), 3);
}
