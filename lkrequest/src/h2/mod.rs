//! HTTP/2 backend — fingerprint-controlled HTTP/2 connections.
//!
//! This module re-exports types from the [`lkh2`] crate and provides
//! a thin error-mapping wrapper around its connection functions.
//!
//! HTTP/2 is provided by the native `lkh2` engine.

pub mod profile {
    pub use lkh2::profile::*;
}

pub use lkh2::{
    encode_alps_h2_settings, H2Profile, H2Setting, H2SettingId, HeadersPriority,
    ProfilePriorityFrame, PseudoHeaderId,
};

// Unified adapter types
pub use lkh2::{
    H2DriverConfig, H2FlowControl, H2ReadySender, H2RecvStream, H2ResponseFuture, H2SendError,
    H2SendStream, H2Sender, UnifiedH2Connection,
};

pub use lkh2::await_first_response;

use crate::error::{Error, Result};

/// Establish an HTTP/2 connection over a TLS stream with fingerprint control.
///
/// `first_request` — if provided, the
/// first HEADERS frame is written back-to-back with the connection preface
/// (matching Chrome's TLS record separation). The response can be obtained
/// via `UnifiedH2Connection::take_first_response()`.
pub async fn connect_h2<S>(
    tls_stream: S,
    h2_profile: &H2Profile,
    first_request: Option<http::Request<Option<bytes::Bytes>>>,
) -> Result<UnifiedH2Connection>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    connect_h2_with_config(tls_stream, h2_profile, first_request, None).await
}

pub(crate) async fn connect_h2_with_config<S>(
    tls_stream: S,
    h2_profile: &H2Profile,
    first_request: Option<http::Request<Option<bytes::Bytes>>>,
    max_pending_h2_requests: Option<usize>,
) -> Result<UnifiedH2Connection>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    lkh2::connect_h2_native_with_config(
        tls_stream,
        h2_profile,
        first_request,
        H2DriverConfig {
            max_pending_requests: max_pending_h2_requests,
        },
    )
    .await
    .map_err(|e| Error::Http(e.to_string()))
}
