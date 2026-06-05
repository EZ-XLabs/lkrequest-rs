//! `lkrequest-ffi` — stable C ABI for [`lkrequest`].
//!
//! Exposes the `lkrequest` object model (Client / Session / Request / Response /
//! StreamingResponse / ProxyPool / SessionPool / Multipart / Error / Op) as
//! opaque C handles behind a stable, `cbindgen`-generated header
//! (`include/lkrequest.h`). The Rust object graph lives behind the FFI boundary
//! in `handles_state`; callers hold handles and must pair every create with the
//! matching free.
//!
//! Optional features mirror the core crate: `quic-h3` (the HTTP/3 surface) and
//! `debug-registry` (handle-leak diagnostics).
//!
//! The header is regenerated from the export surface on every build by
//! `build.rs` via `cbindgen` and is not committed to the repository (it is
//! git-ignored); install `cbindgen` to produce it locally.

#![allow(non_camel_case_types)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

mod abi;
mod client;
mod conv;
mod diagnostics;
mod error;
mod handles;
mod handles_opaque;
mod handles_state;
mod logging;
mod multipart;
mod op;
mod panic;
mod preset;
mod proxy_pool;
mod proxy_probe;
mod request;
mod response;
mod runtime;
mod session;
mod session_pool;
mod streaming;
mod telemetry;
mod types;

pub use abi::*;
pub use client::*;
pub use error::*;
pub use handles::*;
pub use logging::*;
pub use multipart::*;
pub use op::*;
pub use preset::*;
pub use proxy_pool::*;
pub use proxy_probe::*;
pub use request::*;
pub use response::*;
pub use session::*;
pub use session_pool::*;
pub use streaming::*;
pub use telemetry::*;
pub use types::*;
