//! Custom headers and cookie management example.
//!
//! Demonstrates:
//! - Setting default headers on the Client (sent with every request)
//! - Setting per-request custom headers
//! - Automatic cookie persistence within a Session
//!
//! Run with:
//!   cargo run -p lkrequest --example custom_headers

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::Client;
use lktls::profile::presets;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create a Client with default headers (sent on every request)
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .default_header("accept", "application/json")
        .default_header("accept-language", "en-US,en;q=0.9,zh-CN;q=0.8")
        .default_header("accept-encoding", "gzip, deflate, br")
        .build();

    let session = client.session().build();

    // 2. Send a request with additional per-request headers
    println!("=== Request with custom headers ===\n");
    let resp = session
        .get("https://httpbin.org/headers")
        .header("x-custom-id", "lkrequest-demo-12345")
        .header("x-request-source", "example-code")
        .send()
        .await?;

    println!("Status: {}", resp.status());
    let body: serde_json::Value = resp.json()?;
    println!("Server received headers:");
    if let Some(headers) = body.get("headers") {
        println!("{}", serde_json::to_string_pretty(headers)?);
    }

    // 3. Demonstrate cookie persistence
    println!("\n=== Cookie persistence demo ===\n");

    // First request: set a cookie via httpbin
    println!("Setting cookie 'session_id=abc123'...");
    let _ = session
        .get("https://httpbin.org/cookies/set/session_id/abc123")
        .send()
        .await?;

    // Second request: the cookie should be automatically included
    println!("Checking cookies...");
    let resp = session.get("https://httpbin.org/cookies").send().await?;

    let body: serde_json::Value = resp.json()?;
    println!("Cookies sent in second request:");
    if let Some(cookies) = body.get("cookies") {
        println!("{}", serde_json::to_string_pretty(cookies)?);
    }

    println!("\nDone! Cookies are automatically managed per-session.");

    Ok(())
}
