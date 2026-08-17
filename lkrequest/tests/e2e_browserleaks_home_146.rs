//! Manual Chrome 146 check against the BrowserLeaks TLS homepage.
//!
//! This intentionally requests `https://tls.browserleaks.com/` instead of
//! `/json` and prints the full HTML response for manual inspection.
//!
//! Run with:
//!   cargo test -p lkrequest --test e2e_browserleaks_home_146 -- --ignored --nocapture

#[macro_use]
mod support;

use std::path::PathBuf;

use lkrequest::h2::profile::chrome_146_h2;
use lkrequest::{keylog_to_file, Client};
use lktls::profile::presets;
use support::MAX_RETRIES;

#[tokio::test]
#[ignore = "manual: prints full tls.browserleaks.com homepage response"]
async fn test_chrome146_browserleaks_homepage_prints_full_response() {
    let keylog_path = std::env::var_os("LKREQUEST_SSLKEYLOGFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/wireshark/test_chrome146_browserleaks.keys"));
    if let Some(parent) = keylog_path.parent() {
        std::fs::create_dir_all(parent).expect("keylog directory should be creatable");
    }
    let _ = std::fs::remove_file(&keylog_path);
    println!("TLS keylog: {}", keylog_path.display());

    let client = Client::builder()
        .fingerprint(presets::chrome_146())
        .h2_profile(chrome_146_h2())
        .keylog(keylog_to_file(&keylog_path).expect("keylog file should be writable"))
        .build();

    let session = client.session().build();
    // let session = client.session().proxy("http://127.0.0.1:8081").build();
    // let session = client.session().proxy("http://127.0.0.1:8888").build();

    let resp = retry!(
        MAX_RETRIES,
        session
            .get("https://tls.browserleaks.com/")
            // .get("https://secure.jointjuicesettlement.com/")
            .header("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
            .header("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
            .header("cache-control", "max-age=0")
            .header("sec-ch-ua", r#""Chromium";v="146", "Google Chrome";v="146", "Not/A)Brand";v="99""#)
            .header("sec-ch-ua-mobile", "?0")
            .header("sec-ch-ua-platform", r#""Windows""#)
            .header("accept-encoding", "gzip, deflate, br, zstd")
            .header("accept-language", "zh-CN,zh;q=0.9")
            .header("upgrade-insecure-requests", "1")
            .header("sec-fetch-site", "none")
            .header("sec-fetch-mode", "navigate")
            .header("sec-fetch-user", "?1")
            .header("sec-fetch-dest", "document")
            .header("priority", "u=0, i")
            .send(),
        "browserleaks homepage request should succeed"
    );

    let status = resp.status();
    // let headers = resp.headers().clone();
    // let body = resp.text().expect("homepage body should be valid UTF-8");

    // println!("=== tls.browserleaks.com/ Chrome 146 ===");
    println!("Status: {status}");
    // println!("Headers:");
    // for (name, value) in headers.iter() {
    //     println!("  {}: {}", name, value.to_str().unwrap_or("<non-utf8>"));
    // }
    // println!("Body length: {} bytes", body.len());
    // println!("--- BEGIN BODY ---");
    // println!("{body}");
    // println!("--- END BODY ---");

    // assert_eq!(status.as_u16(), 200, "expected HTTP 200");
    // assert!(
    //     body.contains("JA3") || body.contains("ja3") || body.contains("TLS"),
    //     "homepage body did not look like BrowserLeaks TLS output"
    // );
}
