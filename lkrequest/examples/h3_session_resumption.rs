//! HTTP/3 session resumption (0-RTT) demonstration.
//!
//! Shows how QUIC 0-RTT works across connections:
//! 1. First connection: full handshake, server sends session ticket
//! 2. Second connection: 0-RTT resumption (faster handshake)
//!
//! The session store is shared across connections via the Client,
//! mirroring how real browsers cache QUIC session tickets.
//!
//! Run with:
//!   cargo run -p lkrequest --features quic-h3 --example h3_session_resumption

use std::time::Instant;

use lkrequest::{keylog_to_file, Client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("lkrequest=debug,lktls_quic=debug")
        .init();

    let mut builder = Client::builder()
        .preset(lkrequest::preset::chrome_146())
        .quic_profile(lkh3::chrome_146_quic())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        );
    if let Ok(path) = std::env::var("LKREQUEST_KEYLOG_FILE") {
        builder = builder.keylog(keylog_to_file(path)?);
    }
    let client = builder.build();

    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://cloudflare.com/cdn-cgi/trace".to_string());

    // Connection 1: full QUIC handshake
    println!("=== Connection 1: Full QUIC handshake ===");
    let session1 = client.session().http3_only().build();
    let start1 = Instant::now();
    let resp1 = session1.get(&url).send().await?;
    let elapsed1 = start1.elapsed();
    println!("Status:  {}", resp1.status());
    println!("Version: {}", resp1.version());
    println!("Time:    {elapsed1:.1?}");
    let _ = resp1.text()?;

    // Wait for session ticket to be processed
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    drop(session1);

    // Connection 2: should use 0-RTT if the server supports it
    println!("\n=== Connection 2: Resumption (0-RTT if supported) ===");
    let session2 = client.session().http3_only().build();
    let start2 = Instant::now();
    let resp2 = session2.get(&url).send().await?;
    let elapsed2 = start2.elapsed();
    println!("Status:  {}", resp2.status());
    println!("Version: {}", resp2.version());
    println!("Time:    {elapsed2:.1?}");
    let _ = resp2.text()?;

    println!("\n=== Summary ===");
    println!("First connection:  {elapsed1:.1?}");
    println!("Second connection: {elapsed2:.1?}");
    if elapsed2 < elapsed1 {
        let savings = elapsed1.as_millis() as i64 - elapsed2.as_millis() as i64;
        println!("Resumption saved ~{savings}ms");
    }

    Ok(())
}
