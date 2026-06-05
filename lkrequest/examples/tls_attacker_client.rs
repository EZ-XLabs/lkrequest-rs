//! TLS client for TLS-Attacker security testing.
//!
//! Connects to a TLS-Attacker server and attempts a handshake.
//! Exit code 0 = handshake succeeded, non-zero = failed.
//!
//! Usage:
//!   cargo run -p lkrequest --example tls_attacker_client -- <host> <port> [insecure|secure]

use lkrequest::TlsConnector;
use lktls::profile::presets;
use std::process;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    let host = args.get(1).map(|s| s.as_str()).unwrap_or("localhost");
    let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(4433);
    let insecure = args.get(3).map(|s| s == "insecure").unwrap_or(false);

    eprintln!(
        "[tls_attacker_client] connecting to {}:{} (insecure={})",
        host, port, insecure
    );

    let profile = presets::chrome_144();
    let connector = TlsConnector::new(profile).insecure_skip_verify(insecure);

    let tcp = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect(format!("{host}:{port}")),
    )
    .await
    {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(e)) => {
            eprintln!("[tls_attacker_client] TCP connect failed: {e}");
            process::exit(1);
        }
        Err(_) => {
            eprintln!("[tls_attacker_client] TCP connect timed out");
            process::exit(1);
        }
    };

    let mut tls = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        connector.connect(host, port, tcp),
    )
    .await
    {
        Ok(Ok(tls)) => {
            eprintln!("[tls_attacker_client] TLS handshake succeeded");
            tls
        }
        Ok(Err(e)) => {
            eprintln!("[tls_attacker_client] TLS handshake failed: {e}");
            process::exit(2);
        }
        Err(_) => {
            eprintln!("[tls_attacker_client] TLS handshake timed out");
            process::exit(3);
        }
    };

    // Try a simple write/read to verify the connection is usable
    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    match tls.write_all(request).await {
        Ok(()) => eprintln!("[tls_attacker_client] data sent OK"),
        Err(e) => {
            eprintln!("[tls_attacker_client] write failed: {e}");
            process::exit(0); // handshake succeeded, write failure is expected
        }
    }

    let mut buf = [0u8; 4096];
    match tokio::time::timeout(std::time::Duration::from_secs(3), tls.read(&mut buf)).await {
        Ok(Ok(n)) => eprintln!("[tls_attacker_client] received {n} bytes"),
        Ok(Err(e)) => eprintln!("[tls_attacker_client] read error (expected): {e}"),
        Err(_) => eprintln!("[tls_attacker_client] read timeout (expected)"),
    }

    eprintln!("[tls_attacker_client] done");
    process::exit(0);
}
