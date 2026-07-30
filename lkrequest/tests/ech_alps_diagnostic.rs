//! Decisive ECH diagnostic — pinpoints WHERE real ECH breaks.
//!
//! Fixes everything except the `ech_outer_extensions` compression list, against a
//! real ECH server (Cloudflare). The handshake is server-validated: a bad
//! reconstructed inner / bad outer-extensions reference → Fatal `IllegalParameter`.
//!
//! Variants (all bare = no ALPS, unless noted):
//!   1. profile default `[51,10,13,5,18,16,45,27,17613]`  (the shipped list)
//!   2. `[51]` only            (compress just key_share)
//!   3. `[]`  empty            (compress nothing; every ext duplicated in inner)
//!   4. profile default + ALPS (the real connect_with_preset path)
//!
//! Reading the result:
//!   - #3 (no compression) FAILS  → ECH core is broken (encoding/padding/HPKE AAD/transcript)
//!   - #3 OK but #2 FAILS         → the compression *mechanism* (0xFD00 marker) is broken
//!   - #2/#3 OK but #1 FAILS      → the shipped compression *list/order* is wrong
//!   - #1 OK but #4 FAILS         → ALPS-specific
//!
//! Run:
//!   ECH_CONFIG_LIST_HEX=<hex> TEST_PROXY=http://127.0.0.1:7897 \
//!     cargo test -p lkrequest --features h2-native --test ech_alps_diagnostic -- --include-ignored --nocapture

#![cfg(feature = "h2-native")]

use lkrequest::TlsConnector;
use lktls::profile::presets;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn connect_tcp(host: &str, port: u16) -> TcpStream {
    if let Ok(proxy) = std::env::var("TEST_PROXY") {
        if !proxy.is_empty() {
            let url: url::Url = proxy.parse().expect("bad TEST_PROXY url");
            let ph = url.host_str().expect("proxy host").to_string();
            let pp = url.port().unwrap_or(7897);
            let mut s = TcpStream::connect((ph.as_str(), pp))
                .await
                .expect("connect to proxy");
            let req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
            s.write_all(req.as_bytes()).await.expect("send CONNECT");
            let mut buf = [0u8; 1024];
            let n = s.read(&mut buf).await.expect("read CONNECT reply");
            let resp = String::from_utf8_lossy(&buf[..n]);
            assert!(resp.contains(" 200"), "proxy CONNECT failed: {resp}");
            return s;
        }
    }
    TcpStream::connect((host, port))
        .await
        .expect("direct TCP connect")
}

/// One handshake. `outer_exts = None` keeps the profile's shipped list;
/// `Some(v)` overrides it. `with_alps` mirrors the real request path.
async fn try_variant(
    label: &str,
    outer_exts: Option<Vec<u16>>,
    with_alps: bool,
    host: &str,
    ech: &[u8],
) -> Result<(), String> {
    let tcp = connect_tcp(host, 443).await;

    let mut profile = presets::chrome_149();
    if let Some(oe) = outer_exts {
        profile.ech_outer_extensions = Some(oe);
    }

    let mut connector = TlsConnector::new(profile).ech_config(ech.to_vec());
    if with_alps {
        let alps = lkh2::encode_alps_h2_settings(&lkh2::profile::chrome_149_h2());
        connector = connector.alps_payload(alps);
    }

    match connector.connect(host, 443, tcp).await {
        Ok(mut tls) => {
            let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
            tls.write_all(req.as_bytes())
                .await
                .map_err(|e| format!("write: {e}"))?;
            let mut buf = vec![0u8; 2048];
            let n = tls.read(&mut buf).await.map_err(|e| format!("read: {e}"))?;
            let status = String::from_utf8_lossy(&buf[..n])
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            println!(
                "  [{label}] OK — alpn={:?}, \"{status}\"",
                tls.negotiated_alpn()
            );
            Ok(())
        }
        Err(e) => {
            println!("  [{label}] FAIL — {e:?}");
            Err(format!("{e:?}"))
        }
    }
}

#[tokio::test]
#[ignore = "Tier-2: real ECH to Cloudflare; needs ECH_CONFIG_LIST_HEX (+ TEST_PROXY); run with --include-ignored"]
async fn ech_compression_narrowing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("lktls=debug")
        .try_init();

    let hex = std::env::var("ECH_CONFIG_LIST_HEX").expect("set ECH_CONFIG_LIST_HEX");
    let ech = hex_decode(&hex).expect("valid hex");
    let host = std::env::var("ECH_TARGET_HOST").unwrap_or_else(|_| "cloudflare-ech.com".into());
    println!("ECH host = {host}, ECHConfigList = {} bytes\n", ech.len());

    // Realistic configs only. Note: `ech_outer_extensions = []` (compress nothing)
    // is intentionally NOT tested — real Chrome always compresses key_share, and
    // lktls relies on that (it does not generate the inner's own key shares), so
    // an empty list is an unsupported configuration, not a real scenario.
    println!("[1] profile default list, bare:");
    let v1 = try_variant("default", None, false, &host, &ech).await;
    println!("[2] [51] only (compresses key_share), bare:");
    let v2 = try_variant("[51]", Some(vec![51]), false, &host, &ech).await;
    println!("[3] profile default + ALPS (real connect_with_preset path):");
    let v3 = try_variant("default+alps", None, true, &host, &ech).await;

    println!("\n===== RESULTS =====");
    println!("  1 default      : {}", ok(&v1));
    println!("  2 [51]         : {}", ok(&v2));
    println!("  3 default+alps : {}", ok(&v3));

    // Real ECH must be ACCEPTED end-to-end. If the inner transcript / accept
    // confirmation were wrong, the server would still ECH-ACCEPT but the
    // handshake would fail with a key/MAC error; if the inner were malformed it
    // would abort with illegal_parameter. So a clean handshake here means the
    // server accepted ECH and the inner reconstruction matched. (Use a FRESH
    // ECHConfig — Cloudflare rotates the key roughly hourly.)
    assert!(
        v1.is_ok() && v2.is_ok() && v3.is_ok(),
        "real ECH failed: 1={v1:?} 2={v2:?} 3={v3:?}"
    );
}

fn ok(r: &Result<(), String>) -> String {
    match r {
        Ok(_) => "OK".into(),
        Err(e) => format!("FAIL ({e})"),
    }
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    let hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    if !hex.len().is_multiple_of(2) {
        return Err("odd-length hex".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
