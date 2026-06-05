//! `lkquic` — QUIC endpoint management with a pluggable transport backend.
//!
//! Keeps QUIC *policy* (connection-ID generation, endpoint strategy, transport
//! knobs) independent from the transport *implementation*. A
//! [`QuicEndpointManager`] owns endpoints and hands out connections through a
//! backend trait ([`QuicBackend`]), so the implementation can be swapped:
//!
//! - a real QUIC backend over the patched `quinn` (the `quinn-backend` feature,
//!   enabled by default in `lkrequest`), and
//! - a lightweight in-process [`StubQuicBackend`] for tests.
//!
//! Browser-exact QUIC fingerprinting (transport parameters, packetization, and
//! the connection-ID length via [`ChromeConnectionIdGenerator`]) is configured
//! from the profile carried by `lkh3` / `lktls-quic`; this crate is the
//! endpoint/connection plumbing that `lkrequest` builds HTTP/3 on top of.

mod backend;
mod cid;
mod endpoint;
#[cfg(feature = "quinn-backend")]
mod quinn_backend;

pub use backend::{
    BackendConnectRequest, EndpointBootstrap, QuicBackend, StubClientConfig, StubConnection,
    StubEndpoint, StubQuicBackend, StubQuicError,
};
pub use cid::{
    ChromeConnectionIdGenerator, ConnectionId, ConnectionIdError, ConnectionIdGenerator,
};
pub use endpoint::{
    ConnectRequest, QuicEndpointManager, QuicEndpointStrategy, QuicManagerError, StartedConnection,
};
#[cfg(feature = "quinn-backend")]
pub use quinn_backend::{QuinnBackend, QuinnBackendError, QuinnConnecting};
