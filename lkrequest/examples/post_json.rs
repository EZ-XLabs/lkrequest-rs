//! POST request with JSON body example.
//!
//! Demonstrates sending a POST request with a JSON payload using the
//! `.json()` builder method, and reading the echoed JSON response.
//!
//! Run with:
//!   cargo run -p lkrequest --example post_json

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::Client;
use lktls::profile::presets;
use serde::{Deserialize, Serialize};

/// Request payload — will be serialized to JSON automatically.
#[derive(Serialize)]
struct CreateUser {
    name: String,
    email: String,
    age: u32,
}

/// Response structure from httpbin.org/post — echoes back our data.
#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct HttpbinPostResponse {
    json: Option<serde_json::Value>,
    headers: serde_json::Value,
    url: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create client with Chrome 144 fingerprint
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .build();

    let session = client.session().build();

    // Build our JSON payload
    let user = CreateUser {
        name: "Alice".to_string(),
        email: "alice@example.com".to_string(),
        age: 30,
    };

    // Send POST with JSON body
    println!("Sending POST with JSON body to https://httpbin.org/post ...");
    let resp = session
        .post("https://httpbin.org/post")
        .json(&user) // Automatically serializes + sets Content-Type: application/json
        .send()
        .await?;

    println!("Status: {}", resp.status());

    // Deserialize the echo response
    let echo: HttpbinPostResponse = resp.json()?;
    println!("\nEchoed URL: {}", echo.url);

    if let Some(json) = echo.json {
        println!("Echoed JSON payload:");
        println!("  name:  {}", json["name"].as_str().unwrap_or("?"));
        println!("  email: {}", json["email"].as_str().unwrap_or("?"));
        println!("  age:   {}", json["age"].as_u64().unwrap_or(0));
    }

    Ok(())
}
