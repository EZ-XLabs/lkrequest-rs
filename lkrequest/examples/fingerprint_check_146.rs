//! Chrome 146 fingerprint verification example.
//!
//! Sends a request to tls.browserleaks.com/json using the built-in Chrome 146
//! TLS + H2 fingerprint and prints the detected values.
//!
//! Run with:
//!   cargo run -p lkrequest --example fingerprint_check_146

use lkrequest::h2::profile::chrome_146_h2;
use lkrequest::Client;
use lktls::profile::presets;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder()
        .fingerprint(presets::chrome_146())
        .h2_profile(chrome_146_h2())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        )
        .default_header("accept", "application/json,text/plain,*/*")
        .default_header("accept-language", "en-US,en;q=0.9")
        .build();

    let session = client.session().build();

    println!("Requesting https://tls.browserleaks.com/json with Chrome 146 fingerprint...\n");

    let resp = session
        .get("https://tls.browserleaks.com/json")
        .send()
        .await?;

    println!("Status: {}", resp.status());

    if resp.status().as_u16() != 200 {
        eprintln!("Non-200 response from browserleaks");
        return Ok(());
    }

    let json: serde_json::Value = resp.json()?;

    println!(
        "TLS Version: {}",
        json["tls_version"].as_str().unwrap_or("N/A")
    );
    println!(
        "JA3 Hash:    {}",
        json["ja3_hash"].as_str().unwrap_or("N/A")
    );
    println!("JA4:         {}", json["ja4"].as_str().unwrap_or("N/A"));
    println!(
        "Akamai:      {}",
        json["akamai_hash"].as_str().unwrap_or("N/A")
    );
    println!();
    println!("Full response:");
    println!("{}", serde_json::to_string_pretty(&json)?);

    Ok(())
}
