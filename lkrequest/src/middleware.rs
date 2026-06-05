//! Middleware / interceptor system for request and response processing.
//!
//! Middlewares form a chain that wraps every request sent through a Session.
//! They can inspect/modify requests before sending, and inspect/modify
//! responses after receiving.
//!
//! # Execution Order (Onion Model)
//!
//! ```text
//! Client middleware[0].on_request
//!   → Client middleware[1].on_request
//!     → Session middleware[0].on_request
//!       → actual HTTP send (TLS → H2/H1 → network)
//!     ← Session middleware[0].on_response
//!   ← Client middleware[1].on_response
//! ← Client middleware[0].on_response
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use lkrequest::middleware::{Middleware, MiddlewareRequest, MiddlewareResponse};
//! use lkrequest::Client;
//! use lktls::profile::presets;
//!
//! struct LoggingMiddleware;
//!
//! impl Middleware for LoggingMiddleware {
//!     fn on_request(&self, ctx: MiddlewareRequest) -> lkrequest::error::Result<MiddlewareRequest> {
//!         println!("{} {}", ctx.method, ctx.url);
//!         Ok(ctx)
//!     }
//!
//!     fn on_response(&self, ctx: MiddlewareResponse) -> lkrequest::error::Result<MiddlewareResponse> {
//!         println!("  → {}", ctx.status);
//!         Ok(ctx)
//!     }
//! }
//!
//! let client = Client::builder()
//!     .fingerprint(presets::chrome_144())
//!     .middleware(LoggingMiddleware)
//!     .build();
//! ```

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};

use crate::error::Result;

/// Request context passed through the middleware chain.
///
/// Middlewares can inspect and modify the method, URL, headers, and body
/// before the request is sent over the network.
#[derive(Debug)]
pub struct MiddlewareRequest {
    /// HTTP method (GET, POST, etc.).
    pub method: Method,
    /// Request URL.
    pub url: String,
    /// Request headers.
    pub headers: HeaderMap,
    /// Request body (if any).  Uses `Bytes` for zero-copy sharing.
    pub body: Option<Bytes>,
}

/// Response context passed through the middleware chain.
///
/// Middlewares can inspect the status code and headers.  The body is
/// available as raw bytes and can be replaced if needed.
#[derive(Debug)]
pub struct MiddlewareResponse {
    /// HTTP status code.
    pub status: StatusCode,
    /// Response headers.
    pub headers: HeaderMap,
    /// Response body bytes (already decompressed).  Uses `Bytes` for
    /// zero-copy sharing.
    pub body: Bytes,
}

/// Middleware trait for intercepting requests and responses.
///
/// Implement this trait to create custom middleware.  Both methods have
/// default implementations that pass through unchanged, so you only need
/// to override the ones you care about.
///
/// # Thread Safety
///
/// Middlewares must be `Send + Sync` because they are shared across
/// tasks via `Arc`.
///
/// # Short-Circuiting
///
/// Returning `Err(...)` from `on_request` aborts the request entirely.
/// Returning `Err(...)` from `on_response` replaces the response with
/// the error.
pub trait Middleware: Send + Sync {
    /// Called before the request is sent.
    ///
    /// Can modify the request context (headers, body, URL, method) or
    /// return `Err` to abort the request.
    fn on_request(&self, req: MiddlewareRequest) -> Result<MiddlewareRequest> {
        Ok(req)
    }

    /// Called after the response is received.
    ///
    /// Can inspect or modify the response (status, headers, body) or
    /// return `Err` to replace the response with an error.
    fn on_response(&self, resp: MiddlewareResponse) -> Result<MiddlewareResponse> {
        Ok(resp)
    }

    /// Human-readable name for this middleware (used in tracing/debug).
    fn name(&self) -> &str {
        std::any::type_name::<Self>()
    }
}

/// Ordered list of middleware, applied in sequence.
///
/// Used internally by `ClientInner` and `SessionInner` to store
/// the middleware chain.
pub(crate) type MiddlewareStack = Vec<std::sync::Arc<dyn Middleware>>;

/// Execute the `on_request` phase of a middleware stack.
///
/// Middlewares are executed in order (first added = first called).
pub(crate) fn apply_request_middlewares(
    stack: &[std::sync::Arc<dyn Middleware>],
    mut ctx: MiddlewareRequest,
) -> Result<MiddlewareRequest> {
    for mw in stack {
        ctx = mw.on_request(ctx)?;
    }
    Ok(ctx)
}

/// Execute the `on_response` phase of a middleware stack.
///
/// Middlewares are executed in **reverse** order (last added = first called
/// on response), forming an onion model.
pub(crate) fn apply_response_middlewares(
    stack: &[std::sync::Arc<dyn Middleware>],
    mut ctx: MiddlewareResponse,
) -> Result<MiddlewareResponse> {
    for mw in stack.iter().rev() {
        ctx = mw.on_response(ctx)?;
    }
    Ok(ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    struct CountingMiddleware {
        request_count: AtomicU32,
        response_count: AtomicU32,
    }

    impl CountingMiddleware {
        fn new() -> Self {
            Self {
                request_count: AtomicU32::new(0),
                response_count: AtomicU32::new(0),
            }
        }
    }

    impl Middleware for CountingMiddleware {
        fn on_request(&self, req: MiddlewareRequest) -> Result<MiddlewareRequest> {
            self.request_count.fetch_add(1, Ordering::Relaxed);
            Ok(req)
        }

        fn on_response(&self, resp: MiddlewareResponse) -> Result<MiddlewareResponse> {
            self.response_count.fetch_add(1, Ordering::Relaxed);
            Ok(resp)
        }

        fn name(&self) -> &str {
            "CountingMiddleware"
        }
    }

    struct HeaderInjector {
        name: String,
        value: String,
    }

    impl Middleware for HeaderInjector {
        fn on_request(&self, mut req: MiddlewareRequest) -> Result<MiddlewareRequest> {
            if let (Ok(n), Ok(v)) = (
                http::header::HeaderName::from_bytes(self.name.as_bytes()),
                http::header::HeaderValue::from_str(&self.value),
            ) {
                req.headers.insert(n, v);
            }
            Ok(req)
        }
    }

    struct ShortCircuit;

    impl Middleware for ShortCircuit {
        fn on_request(&self, _req: MiddlewareRequest) -> Result<MiddlewareRequest> {
            Err(crate::error::Error::Http("blocked by middleware".into()))
        }
    }

    fn make_request() -> MiddlewareRequest {
        MiddlewareRequest {
            method: Method::GET,
            url: "https://example.com".into(),
            headers: HeaderMap::new(),
            body: None,
        }
    }

    fn make_response() -> MiddlewareResponse {
        MiddlewareResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        }
    }

    #[test]
    fn test_middleware_passthrough() {
        let mw = CountingMiddleware::new();
        let stack: Vec<Arc<dyn Middleware>> = vec![Arc::new(mw)];

        let req = apply_request_middlewares(&stack, make_request()).unwrap();
        assert_eq!(req.url, "https://example.com");

        let resp = apply_response_middlewares(&stack, make_response()).unwrap();
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn test_middleware_modifies_request() {
        let injector = HeaderInjector {
            name: "x-custom".into(),
            value: "injected".into(),
        };
        let stack: Vec<Arc<dyn Middleware>> = vec![Arc::new(injector)];

        let req = apply_request_middlewares(&stack, make_request()).unwrap();
        assert_eq!(req.headers.get("x-custom").unwrap(), "injected");
    }

    #[test]
    fn test_middleware_short_circuit() {
        let stack: Vec<Arc<dyn Middleware>> = vec![Arc::new(ShortCircuit)];

        let result = apply_request_middlewares(&stack, make_request());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("blocked by middleware"));
    }

    #[test]
    fn test_middleware_chain_order() {
        let mw1 = HeaderInjector {
            name: "x-first".into(),
            value: "1".into(),
        };
        let mw2 = HeaderInjector {
            name: "x-second".into(),
            value: "2".into(),
        };
        let stack: Vec<Arc<dyn Middleware>> = vec![Arc::new(mw1), Arc::new(mw2)];

        let req = apply_request_middlewares(&stack, make_request()).unwrap();
        assert_eq!(req.headers.get("x-first").unwrap(), "1");
        assert_eq!(req.headers.get("x-second").unwrap(), "2");
    }

    #[test]
    fn test_response_middleware_reverse_order() {
        struct TagMiddleware(String);

        impl Middleware for TagMiddleware {
            fn on_response(&self, mut resp: MiddlewareResponse) -> Result<MiddlewareResponse> {
                // Append tag to body to track execution order.
                // Construct a new Bytes with the appended data.
                let mut buf = bytes::BytesMut::from(resp.body.as_ref());
                buf.extend_from_slice(self.0.as_bytes());
                buf.extend_from_slice(b",");
                resp.body = buf.freeze();
                Ok(resp)
            }
        }

        let stack: Vec<Arc<dyn Middleware>> = vec![
            Arc::new(TagMiddleware("first".into())),
            Arc::new(TagMiddleware("second".into())),
            Arc::new(TagMiddleware("third".into())),
        ];

        let resp = apply_response_middlewares(&stack, make_response()).unwrap();
        let order = String::from_utf8_lossy(&resp.body);
        // Reverse order: third, second, first (onion model)
        assert_eq!(order, "third,second,first,");
    }

    #[test]
    fn test_middleware_name() {
        let mw = CountingMiddleware::new();
        assert_eq!(mw.name(), "CountingMiddleware");

        let injector = HeaderInjector {
            name: "x".into(),
            value: "y".into(),
        };
        // Default name is the type name
        assert!(injector.name().contains("HeaderInjector"));
    }
}
