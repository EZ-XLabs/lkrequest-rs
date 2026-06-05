//! Basic GET request example.
//!
//! This is the simplest possible lkrequest usage: create a Client with a
//! Chrome 144 TLS + H2 fingerprint, build a Session, and send a GET request.
//!
//! Run with:
//!   cargo run -p lkrequest --example basic_get

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::Client;
use lktls::profile::presets;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create a Client with Chrome 144 fingerprint
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .default_header("accept", "text/html,application/xhtml+xml,*/*;q=0.8")
        .default_header("accept-language", "en-US,en;q=0.9")
        .build();

    // 2. Create a Session (represents a "virtual browser user")
    let session = client.session().build();

    // 3. Send a GET request
    println!("Sending GET request to https://httpbin.org/get ...");
    let resp = session.get("https://httpbin.org/get").send().await?;

    // 4. Read the response
    println!("Status: {}", resp.status());
    println!("Headers:");
    for (name, value) in resp.headers() {
        println!("  {}: {}", name, value.to_str().unwrap_or("<binary>"));
    }

    let body = resp.text()?;
    println!("\nBody:\n{body}");

    Ok(())
}
