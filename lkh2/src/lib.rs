//! # lkh2 — HTTP/2 Fingerprint-Controlled Connections
//!
//! Native HTTP/2 is implemented by a self-contained Sans-I/O engine with
//! frame-level control. It provides frame grouping, HPACK strategy, and
//! flow-control policy traits for advanced anti-fingerprinting scenarios.
//!
//! ## Core API
//!
//! - [`H2Profile`] — data structure describing the H2 fingerprint
//! - Built-in browser presets (Chrome, Firefox, Safari)
//! - Header order presets for HTTP request header ordering

// ─── Always available ────────────────────────────────────────────────────────

pub mod adapter;
pub mod error;
pub mod profile;
pub mod synthesis;

pub use error::{H2Error, Result};
pub use profile::ProfilePriorityFrame;
pub use profile::{
    encode_alps_h2_settings, H2Profile, H2Setting, H2SettingId, HeadersPriority, PriorityConfig,
    PseudoHeaderId, RequestPriority, StreamDepPolicy,
};
pub use synthesis::{validate as validate_h2_profile, H2Constraints, InvalidH2Spec};

pub use adapter::{
    H2FlowControl, H2ReadySender, H2RecvStream, H2ResponseFuture, H2SendError, H2SendStream,
    H2Sender, UnifiedH2Connection,
};

pub use adapter::await_first_response;

// ─── h2-native engine ───────────────────────────────────────────────────────

pub mod codec;
pub mod frame;

pub mod conn_state;
pub mod driver;
pub mod engine;
pub mod hpack;
mod hpack_enc;
pub mod policy;
pub mod stream;

pub const CONNECTION_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub use driver::{
    spawn_driver, DriverError, FirstRequest, FirstRequestResponse, H2DriverConfig,
    NativeResponseHeaders, NativeSendRequest,
};

pub use policy::{
    ChromeHpackPolicy, ChromeWritePolicy, ConfigurableWritePolicy, DefaultHpackPolicy,
    DefaultWritePolicy, FirefoxHpackPolicy, FirefoxWritePolicy, FlowControlPolicy,
    FrameWritePolicy, H2Behavior, HpackEncodePolicy, HpackFieldEncoding, ImmediateFlowControl,
    SafariHpackPolicy, SafariWritePolicy, ThresholdFlowControl,
};

pub async fn connect_h2_native<S>(
    tls_stream: S,
    h2_profile: &H2Profile,
    first_request: Option<http::Request<Option<bytes::Bytes>>>,
) -> Result<UnifiedH2Connection>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    connect_h2_native_with_config(
        tls_stream,
        h2_profile,
        first_request,
        H2DriverConfig::default(),
    )
    .await
}

pub async fn connect_h2_native_with_config<S>(
    tls_stream: S,
    h2_profile: &H2Profile,
    first_request: Option<http::Request<Option<bytes::Bytes>>>,
    config: H2DriverConfig,
) -> Result<UnifiedH2Connection>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let behavior = h2_profile.behavior();

    let (first_req, first_resp) = match first_request {
        Some(req) => {
            let (fr, fr_resp) = driver::FirstRequest::new(req);
            (Some(fr), Some(fr_resp))
        }
        None => (None, None),
    };

    let (sender, handle) = driver::spawn_driver_with_first_request_and_config(
        tls_stream,
        h2_profile,
        Some(behavior),
        first_req,
        config,
    )
    .await
    .map_err(|e| H2Error::Handshake(e.to_string()))?;

    match first_resp {
        Some(resp) => Ok(UnifiedH2Connection::from_native_with_first(
            sender, handle, resp,
        )),
        None => Ok(UnifiedH2Connection::from_native(sender, handle)),
    }
}
