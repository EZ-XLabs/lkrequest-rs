//! Fingerprint verification example.
//!
//! Demonstrates how to check your TLS + H2 fingerprint against online
//! detection services. This is useful for verifying that your fingerprint
//! matches a real browser before deploying.
//!
//! The example connects to tls.browserleaks.com and prints the detected
//! JA3, JA4, and Akamai H2 fingerprints alongside the expected values
//! for Chrome 144.
//!
//! Run with:
//!   cargo run -p lkrequest --example fingerprint_check

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::Client;
use lktls::profile::presets;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a Client with Chrome 144 TLS + H2 fingerprint
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

    println!("Checking fingerprint against tls.browserleaks.com...\n");

    let resp = session
        .get("https://tls.browserleaks.com/json")
        .send()
        .await?;

    if resp.status().as_u16() != 200 {
        eprintln!("Error: got status {}", resp.status());
        return Ok(());
    }

    let json: serde_json::Value = resp.json()?;

    // --- TLS Fingerprint ---
    println!("========== TLS Fingerprint ==========");

    let ja3_hash = json["ja3_hash"].as_str().unwrap_or("N/A");
    let ja4 = json["ja4"].as_str().unwrap_or("N/A");
    let tls_version = json["tls_version"].as_str().unwrap_or("N/A");

    println!("TLS Version:  {tls_version}");
    println!("JA3 Hash:     {ja3_hash}");
    println!("JA4:          {ja4}");

    // Expected Chrome 144 values
    let expected_ja3 = "991d71ee69967b7325077b71bad10393";
    let expected_ja4_prefix = "t13d1516h2";

    let ja3_match = ja3_hash == expected_ja3;
    let ja4_match = ja4.starts_with(expected_ja4_prefix);

    println!();
    println!(
        "JA3 match:    {} (expected: {})",
        if ja3_match { "PASS" } else { "FAIL" },
        expected_ja3
    );
    println!(
        "JA4 match:    {} (expected prefix: {})",
        if ja4_match { "PASS" } else { "FAIL" },
        expected_ja4_prefix
    );

    // --- H2 Fingerprint ---
    println!();
    println!("========== H2 Fingerprint ===========");

    let akamai_text = json["akamai_text"].as_str().unwrap_or("N/A");
    let akamai_hash = json["akamai_hash"].as_str().unwrap_or("N/A");

    println!("Akamai FP:    {akamai_text}");
    println!("Akamai Hash:  {akamai_hash}");

    let expected_akamai_fp = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p";
    let expected_akamai_hash = "52d84b11737d980aef856699f885ca86";

    let akamai_fp_match = akamai_text == expected_akamai_fp;
    let akamai_hash_match = akamai_hash == expected_akamai_hash;

    println!();
    println!(
        "Akamai FP:    {} (expected: {})",
        if akamai_fp_match { "PASS" } else { "FAIL" },
        expected_akamai_fp
    );
    println!(
        "Akamai Hash:  {} (expected: {})",
        if akamai_hash_match { "PASS" } else { "FAIL" },
        expected_akamai_hash
    );

    // --- Summary ---
    println!();
    println!("=====================================");
    let all_pass = ja3_match && ja4_match && akamai_fp_match && akamai_hash_match;
    if all_pass {
        println!("Result: ALL CHECKS PASSED");
        println!("Your fingerprint matches real Chrome 144!");
    } else {
        println!("Result: SOME CHECKS FAILED");
        println!("Review the mismatches above.");
    }

    // Print JA3 full text for debugging if needed
    if let Some(ja3_text) = json["ja3_text"].as_str() {
        println!();
        println!("JA3 Full Text (for debugging):");
        println!("  {ja3_text}");
    }

    Ok(())
}
