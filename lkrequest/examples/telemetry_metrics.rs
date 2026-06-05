//! Operational telemetry demo — bandwidth, connection, and request counters.
//!
//! The core library only *produces* neutral numbers; a host wires them into its
//! own monitoring stack (a Prometheus exporter, OpenTelemetry, a custom
//! collector, …). This example just makes a few requests and prints the
//! pull-only [`telemetry::metrics_snapshot`].
//!
//! Requires the `telemetry` feature:
//!
//! ```sh
//! cargo run -p lkrequest --features telemetry --example telemetry_metrics
//! ```
//!
//! Note on bandwidth liveness: byte counts are accumulated per connection with
//! no atomics on the I/O hot path and flushed into the global counters when a
//! connection closes (or via `flush_telemetry()` at a request boundary). So the
//! first snapshot — taken while connections may still sit idle in the pool — can
//! show zero bytes; the second, after the session is dropped, reflects them.

use std::time::Duration;

use lkrequest::{telemetry, Client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder().build();
    let session = client.session().build();

    // A couple of successes plus one guaranteed failure (NXDOMAIN) so the
    // `requests_failed` counter is exercised too.
    let urls = [
        "https://example.com/",
        "https://example.org/",
        "https://this-host-does-not-exist.invalid/",
    ];

    for url in urls {
        match session.get(url).send().await {
            Ok(resp) => println!(
                "GET {url} -> {} ({} body bytes)",
                resp.status(),
                resp.bytes().len()
            ),
            Err(e) => println!("GET {url} -> error: {e}"),
        }
    }

    // Per-request diagnostics are opt-in per request (zero cost otherwise) and
    // attached to the Response: phase timings, negotiated protocol, remote addr.
    // Use a host not hit above so the connect phases (DNS/TCP/TLS) populate
    // rather than being skipped on a reused pooled connection.
    if let Ok(resp) = session
        .get("https://www.rust-lang.org/")
        .collect_diagnostics(true)
        .send()
        .await
    {
        if let Some(d) = resp.diagnostics() {
            println!("\n── per-request diagnostics (opt-in, fresh connection) ──");
            println!(
                "  dns={:?} tcp={:?} tls={:?} ttfb={:?} total={:?} (ms)",
                d.dns_ms, d.tcp_ms, d.tls_ms, d.ttfb_ms, d.total_ms
            );
            println!(
                "  protocol={:?} remote={:?} cipher={:?}",
                d.protocol, d.remote_addr, d.cipher_suite
            );
        }
    }

    // Requests and the active-connection gauge update live; byte counters are
    // buffered per connection, so they may still read zero here.
    println!("\n── snapshot while connections may still be pooled ──");
    print_snapshot(&telemetry::metrics_snapshot());

    // Dropping the session (and client) closes pooled connections; each one's
    // buffered byte counts flush into the global counters on drop.
    drop(session);
    drop(client);
    tokio::time::sleep(Duration::from_millis(200)).await;

    println!("\n── snapshot after closing connections (bytes flushed) ──");
    print_snapshot(&telemetry::metrics_snapshot());

    Ok(())
}

fn print_snapshot(s: &telemetry::MetricsSnapshot) {
    println!("  requests_total   = {}", s.requests_total);
    println!("  requests_failed  = {}", s.requests_failed);
    println!("  active_conns     = {}", s.active_connections);
    println!("  total_conns      = {}", s.total_connections);
    println!("  bytes_in         = {}", s.bytes_in);
    println!("  bytes_out        = {}", s.bytes_out);
}
