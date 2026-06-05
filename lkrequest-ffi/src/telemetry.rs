//! Aggregate operational telemetry over the C ABI.
//!
//! Mirrors `lkrequest::telemetry::metrics_snapshot()` so non-Rust hosts (Python,
//! Go, C) can scrape bandwidth / connection / request counters into their own
//! monitoring stack (a Prometheus exporter, an OTel meter, …).
//!
//! `lk_metrics_snapshot` is always present in the ABI; without the `telemetry`
//! build feature it reports all-zero counters.

use std::ptr;

use crate::abi::lk_status_t;
use crate::error::FfiError;
use crate::panic::catch_status;

/// Snapshot of the process-global operational counters.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct lk_metrics_snapshot_t {
    /// Total wire bytes received (includes TLS / HTTP framing overhead).
    pub bytes_in: u64,
    /// Total wire bytes sent.
    pub bytes_out: u64,
    /// Completed requests.
    pub requests_total: u64,
    /// Completed requests that ended in an error.
    pub requests_failed: u64,
    /// Currently-open transport connections.
    pub active_connections: u64,
    /// Cumulative connections opened.
    pub total_connections: u64,
}

/// Write the process-global telemetry snapshot into `out`.
///
/// Pull-only and near-free. Reports all-zero counters unless the library was
/// built with the `telemetry` feature.
#[no_mangle]
pub extern "C" fn lk_metrics_snapshot(out: *mut lk_metrics_snapshot_t) -> lk_status_t {
    catch_status(ptr::null_mut(), || {
        if out.is_null() {
            return Err(FfiError::invalid_argument("out is null"));
        }
        let snapshot = current_snapshot();
        // SAFETY: `out` is non-null (checked above); the caller guarantees it
        // points to writable storage for one `lk_metrics_snapshot_t`.
        unsafe { *out = snapshot };
        Ok(())
    })
}

#[cfg(feature = "telemetry")]
fn current_snapshot() -> lk_metrics_snapshot_t {
    let s = lkrequest::telemetry::metrics_snapshot();
    lk_metrics_snapshot_t {
        bytes_in: s.bytes_in,
        bytes_out: s.bytes_out,
        requests_total: s.requests_total,
        requests_failed: s.requests_failed,
        active_connections: s.active_connections,
        total_connections: s.total_connections,
    }
}

#[cfg(not(feature = "telemetry"))]
fn current_snapshot() -> lk_metrics_snapshot_t {
    lk_metrics_snapshot_t::default()
}
