//! Chrome 146 example.com example.
//!
//! Sends a GET request to example.com using Chrome 146 TLS + H2 fingerprint,
//! mimicking a real browser navigation.
//!
//! Run with:
//!   cargo run -p lkrequest --example chrome146_signup

use std::time::Duration;

use lkrequest::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "lkrequest=info,lktls=info".parse().unwrap()),
        )
        .init();

    let client = Client::builder()
        .preset(lkrequest::preset::chrome_146())
        .total_timeout(Duration::from_secs(30))
        .build();

    let session = client.session().max_redirects(0).build();

    println!("Requesting https://example.com/?lic=1 with Chrome 146 fingerprint...\n");

    let resp = session
        .get("https://example.com/?lic=1")
        .header(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        )
        .header(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,\
             image/avif,image/webp,image/apng,*/*;q=0.8",
        )
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("Accept-Encoding", "gzip, deflate, br")
        .header("Sec-Fetch-Site", "none")
        .header("Sec-Fetch-Mode", "navigate")
        .header("Sec-Fetch-User", "?1")
        .header("Sec-Fetch-Dest", "document")
        .header("Upgrade-Insecure-Requests", "1")
        .send()
        .await?;

    let status = resp.status();
    println!("Status: {status}");

    let body = resp.bytes();
    println!("Body length: {}", body.len());

    let text = String::from_utf8_lossy(body);
    if text.len() > 500 {
        println!("Body preview: {}...", &text[..500]);
    } else {
        println!("Body: {text}");
    }

    if status.as_u16() == 0 {
        eprintln!("Got status 0, request likely failed");
        std::process::exit(1);
    }

    Ok(())
}
