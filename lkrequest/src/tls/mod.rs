//! TLS I/O layer — wraps lktls protocol engine with tokio async I/O.
//!
//! This module provides [`TlsConnector`] and [`TlsStream`] that bridge
//! the Sans-I/O protocol engine in `lktls` with tokio's async runtime.

mod connector;

pub use connector::{keylog_to_file, TlsConnector, TlsStream, TlsTransport};
pub use lktls::KeyLogCallback;
