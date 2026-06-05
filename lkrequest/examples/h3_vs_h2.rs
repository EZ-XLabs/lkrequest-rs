//! Side-by-side H2 vs H3 comparison.
//!
//! Sends the same request over HTTP/2 (TCP+TLS) and HTTP/3 (QUIC) to
//! compare response timing, headers, and protocol negotiation.
//!
//! Run with:
//!   cargo run -p lkrequest --features quic-h3 --example h3_vs_h2

use std::time::Instant;

use lkrequest::Client;
use lktls::profile::presets;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("lkrequest=info")
        .init();

    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .build();

    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://cloudflare.com/cdn-cgi/trace".to_string());

    // H2 request (forced)
    let session_h2 = client.session().http2_only().build();
    let start_h2 = Instant::now();
    let resp_h2 = session_h2.get(&url).send().await?;
    let elapsed_h2 = start_h2.elapsed();
    let body_h2 = resp_h2.text()?;

    // H3 request (forced)
    let session_h3 = client.session().http3_only().build();
    let start_h3 = Instant::now();
    let resp_h3 = session_h3.get(&url).send().await?;
    let elapsed_h3 = start_h3.elapsed();
    let body_h3 = resp_h3.text()?;

    println!("=== Protocol Comparison: {url} ===\n");
    println!("{:<20} {:<20} {:<20}", "", "HTTP/2 (TCP)", "HTTP/3 (QUIC)");
    println!("{}", "-".repeat(60));
    println!(
        "{:<20} {:<20} {:<20}",
        "Version",
        resp_h2.version(),
        resp_h3.version()
    );
    println!(
        "{:<20} {:<20} {:<20}",
        "Status",
        resp_h2.status(),
        resp_h3.status()
    );
    println!(
        "{:<20} {:<20} {:<20}",
        "Time",
        format!("{:.1?}", elapsed_h2),
        format!("{:.1?}", elapsed_h3)
    );
    println!(
        "{:<20} {:<20} {:<20}",
        "Body size",
        format!("{} bytes", body_h2.len()),
        format!("{} bytes", body_h3.len())
    );

    if elapsed_h3 < elapsed_h2 {
        let pct = ((elapsed_h2.as_millis() as f64 - elapsed_h3.as_millis() as f64)
            / elapsed_h2.as_millis() as f64
            * 100.0) as i32;
        println!("\nH3 was ~{pct}% faster");
    } else {
        println!("\nH2 was faster (H3 may have cold-start overhead)");
    }

    if body_h2 == body_h3 {
        println!("Response bodies: identical");
    } else {
        println!("Response bodies: differ (expected for dynamic content)");
    }

    Ok(())
}
