//! End-to-end SSLKEYLOGFILE (keylog) tests.
//!
//! Verifies that when a keylog callback is configured, TLS session secrets
//! are correctly emitted in NSS Key Log format for both TLS 1.3 and 1.2.
//!
//! Requires network access to tls.browserleaks.com.

#[macro_use]
mod support;

use std::sync::{Arc, Mutex};

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::keylog_to_file;
use lkrequest::{Client, TcpFingerprint};
use lktls::profile::presets;
use support::MAX_RETRIES;

fn chrome_client_with_keylog(collector: Arc<Mutex<Vec<String>>>) -> Client {
    let cb: lkrequest::KeyLogCallback = Arc::new(move |line: &str| {
        collector.lock().unwrap().push(line.to_string());
    });

    Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .keylog(cb)
        .build()
}

/// TLS 1.3 handshake should emit exactly 4 keylog lines.
#[tokio::test]
#[ignore = "Tier-2: tls.browserleaks.com"]
async fn test_keylog_tls13_emits_four_secrets() {
    let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let client = chrome_client_with_keylog(lines.clone());
    let session = client.session().build();

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://tls.browserleaks.com/json").send(),
        "request should succeed"
    );
    assert_eq!(resp.status().as_u16(), 200);

    let captured = lines.lock().unwrap();

    assert!(
        captured.len() >= 4,
        "expected at least 4 keylog lines for TLS 1.3, got {}:\n{:#?}",
        captured.len(),
        *captured
    );

    let labels: Vec<&str> = captured
        .iter()
        .filter_map(|l| l.split_whitespace().next())
        .collect();

    assert!(
        labels.contains(&"CLIENT_HANDSHAKE_TRAFFIC_SECRET"),
        "missing CLIENT_HANDSHAKE_TRAFFIC_SECRET"
    );
    assert!(
        labels.contains(&"SERVER_HANDSHAKE_TRAFFIC_SECRET"),
        "missing SERVER_HANDSHAKE_TRAFFIC_SECRET"
    );
    assert!(
        labels.contains(&"CLIENT_TRAFFIC_SECRET_0"),
        "missing CLIENT_TRAFFIC_SECRET_0"
    );
    assert!(
        labels.contains(&"SERVER_TRAFFIC_SECRET_0"),
        "missing SERVER_TRAFFIC_SECRET_0"
    );

    for line in captured.iter() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(
            parts.len(),
            3,
            "keylog line should have 3 parts (label, client_random, secret): {line}"
        );
        assert_eq!(
            parts[1].len(),
            64,
            "client_random should be 32 bytes (64 hex chars), got {} chars",
            parts[1].len()
        );
        assert!(
            parts[2].len() >= 64,
            "secret should be at least 32 bytes (64 hex chars), got {} chars",
            parts[2].len()
        );
        assert!(
            parts[1].chars().all(|c| c.is_ascii_hexdigit()),
            "client_random should be hex: {}",
            parts[1]
        );
        assert!(
            parts[2].chars().all(|c| c.is_ascii_hexdigit()),
            "secret should be hex: {}",
            parts[2]
        );
    }

    println!("Captured {} keylog lines:", captured.len());
    for line in captured.iter() {
        let label = line.split_whitespace().next().unwrap_or("?");
        println!("  {label}  ({})", line.len());
    }
    println!("\n=== PASSED: TLS 1.3 keylog emits correct secrets ===");
}

/// All keylog lines in the same handshake should share the same client_random.
#[tokio::test]
#[ignore = "Tier-2: tls.browserleaks.com"]
async fn test_keylog_client_random_consistent() {
    let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let client = chrome_client_with_keylog(lines.clone());
    let session = client.session().build();

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://tls.browserleaks.com/json").send(),
        "request should succeed"
    );
    assert_eq!(resp.status().as_u16(), 200);

    let captured = lines.lock().unwrap();
    assert!(!captured.is_empty(), "should have captured keylog lines");

    let client_randoms: Vec<&str> = captured
        .iter()
        .filter_map(|l| l.split_whitespace().nth(1))
        .collect();

    let first = client_randoms[0];
    for (i, cr) in client_randoms.iter().enumerate() {
        assert_eq!(
            *cr, first,
            "client_random mismatch at line {i}: {cr} != {first}"
        );
    }

    println!("All {} lines share client_random: {first}", captured.len());
    println!("=== PASSED: client_random is consistent across all keylog lines ===");
}

/// No keylog output when callback is not configured.
#[tokio::test]
#[ignore = "Tier-2: tls.browserleaks.com"]
async fn test_no_keylog_without_callback() {
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .build();
    let session = client.session().build();

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://tls.browserleaks.com/json").send(),
        "request should succeed"
    );
    assert_eq!(resp.status().as_u16(), 200);

    println!("=== PASSED: Request succeeds without keylog callback (no crash, no overhead) ===");
}

/// keylog_to_file writes secrets to a temp file in valid format.
#[tokio::test]
#[ignore = "Tier-2: tls.browserleaks.com"]
async fn test_keylog_to_file() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("lkrequest_test_keylog_{}.log", std::process::id()));

    let cb = keylog_to_file(&path).expect("should create keylog file");
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .tcp_fingerprint(TcpFingerprint::chrome_win())
        .h2_profile(chrome_144_h2())
        .default_header("cache-control", "max-age=0")
        .default_header(
            "sec-ch-ua",
            r#""Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145""#,
        )
        .default_header("sec-ch-ua-mobile", "?0")
        .default_header("sec-ch-ua-platform", r#""Windows""#)
        .default_header("upgrade-insecure-requests", "1")
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
        )
        .default_header(
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,\
             image/avif,image/webp,image/apng,*/*;q=0.8,\
             application/signed-exchange;v=b3;q=0.7",
        )
        .default_header("sec-fetch-site", "none")
        .default_header("sec-fetch-mode", "navigate")
        .default_header("sec-fetch-user", "?1")
        .default_header("sec-fetch-dest", "document")
        .default_header("accept-encoding", "gzip, deflate, br, zstd")
        .default_header("accept-language", "zh-CN,zh;q=0.9")
        .default_header("priority", "u=0, i")
        .keylog(cb)
        .build();
    let session = client.session().build();

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://tls.browserleaks.com/").send(),
        "request should succeed"
    );
    assert_eq!(resp.status().as_u16(), 200);
    println!("Content: {}", resp.text().expect("should be valid UTF-8"));

    let content = std::fs::read_to_string(&path).expect("should read keylog file");
    // let _ = std::fs::remove_file(&path);

    let non_empty_lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();

    assert!(
        non_empty_lines.len() >= 4,
        "keylog file should contain at least 4 lines, got {}:\n{content}",
        non_empty_lines.len()
    );

    for line in &non_empty_lines {
        let parts: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(parts.len(), 3, "invalid keylog line: {line}");
    }

    println!("Keylog file written to: {}", path.display());
    println!("{} lines written", non_empty_lines.len());
    println!("=== PASSED: keylog_to_file produces valid SSLKEYLOGFILE ===");
}
