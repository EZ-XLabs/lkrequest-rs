use bytes::Bytes;
use http::{Request, Response};

use crate::connection::{H3Error, H3RecvStream, LiveSendRequest};
use crate::profile::H3Profile;

/// Cloneable HTTP/3 sender backed by `h3` + `h3-quinn`.
#[derive(Clone)]
pub struct H3Sender {
    profile: H3Profile,
    inner: LiveSendRequest,
}

impl H3Sender {
    pub(crate) fn new(profile: H3Profile, inner: LiveSendRequest) -> Self {
        Self { profile, inner }
    }

    /// Returns the immutable fingerprint profile attached to this sender.
    pub fn profile(&self) -> &H3Profile {
        &self.profile
    }

    /// Indicates whether a concrete HTTP/3 backend is wired behind this sender.
    pub fn is_backend_wired(&self) -> bool {
        true
    }

    pub async fn send_request(
        &mut self,
        request: Request<Option<Bytes>>,
    ) -> Result<Response<H3RecvStream>, H3Error> {
        let method = request.method().clone();
        let uri = request.uri().clone();
        let body_len = request.body().as_ref().map_or(0, Bytes::len);
        tracing::debug!(
            method = %method,
            uri = %uri,
            body_len,
            pseudo_order = %self.profile.pseudo_header_order_token(),
            "h3.send_request_start"
        );
        let (parts, body) = request.into_parts();
        let request = Request::from_parts(parts, ());
        let mut stream = self.inner.send_request(request).await?;

        if let Some(body) = body {
            if !body.is_empty() {
                tracing::trace!(method = %method, uri = %uri, bytes = body.len(), "h3.send_request_body");
                stream.send_data(body).await?;
            }
        }
        stream.finish().await?;

        let response = stream.recv_response().await?;
        let (parts, _) = response.into_parts();
        tracing::debug!(
            method = %method,
            uri = %uri,
            status = parts.status.as_u16(),
            "h3.send_request_complete"
        );
        Ok(Response::from_parts(parts, H3RecvStream { inner: stream }))
    }
}
