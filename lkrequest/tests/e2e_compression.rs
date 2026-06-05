//! Compression / auto-decompression tests — local HTTPS server (Tier 0).
//!
//! Covers: gzip, brotli, deflate, zstd auto-decompression via the
//! local server's /compress/{encoding} endpoint.

mod support;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::Client;
use lktls::profile::presets;
use support::local_https::{start_local_https_server, url_join};

fn chrome_client() -> Client {
    Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .build()
}

const EXPECTED_PAYLOAD: &str = "Hello, compressed world! ";

// ---------------------------------------------------------------------------
// gzip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_auto_decompress_gzip() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/compress/gzip"))
        .send()
        .await
        .expect("gzip request");

    assert_eq!(resp.status().as_u16(), 200);
    let text = resp.text().expect("utf-8 text");
    assert!(
        text.contains(EXPECTED_PAYLOAD),
        "gzip decompression failed: body len={}",
        text.len()
    );
}

// ---------------------------------------------------------------------------
// brotli
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_auto_decompress_brotli() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/compress/br"))
        .send()
        .await
        .expect("brotli request");

    assert_eq!(resp.status().as_u16(), 200);
    let text = resp.text().expect("utf-8 text");
    assert!(
        text.contains(EXPECTED_PAYLOAD),
        "brotli decompression failed: body len={}",
        text.len()
    );
}

// ---------------------------------------------------------------------------
// deflate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_auto_decompress_deflate() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/compress/deflate"))
        .send()
        .await
        .expect("deflate request");

    assert_eq!(resp.status().as_u16(), 200);
    let text = resp.text().expect("utf-8 text");
    assert!(
        text.contains(EXPECTED_PAYLOAD),
        "deflate decompression failed: body len={}",
        text.len()
    );
}

// ---------------------------------------------------------------------------
// zstd
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_auto_decompress_zstd() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/compress/zstd"))
        .send()
        .await
        .expect("zstd request");

    assert_eq!(resp.status().as_u16(), 200);
    let text = resp.text().expect("utf-8 text");
    assert!(
        text.contains(EXPECTED_PAYLOAD),
        "zstd decompression failed: body len={}",
        text.len()
    );
}

// ---------------------------------------------------------------------------
// no_auto_decompress returns raw compressed bytes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_no_auto_decompress_returns_raw() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/compress/gzip"))
        .no_auto_decompress()
        .send()
        .await
        .expect("raw gzip request");

    assert_eq!(resp.status().as_u16(), 200);
    let raw = resp.bytes();
    // Gzip magic bytes: 0x1f 0x8b
    assert!(
        raw.len() >= 2 && raw[0] == 0x1f && raw[1] == 0x8b,
        "expected raw gzip bytes, got {} bytes starting with {:02x?}",
        raw.len(),
        &raw[..raw.len().min(4)]
    );
}

// ---------------------------------------------------------------------------
// unknown encoding endpoint returns 400
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_compress_unknown_encoding() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/compress/lz4"))
        .send()
        .await
        .expect("unknown encoding request");

    assert_eq!(resp.status().as_u16(), 400);
}

// ---------------------------------------------------------------------------
// streaming chunk_decoded — incremental decompression
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_streaming_chunk_decoded_gzip() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let mut resp = session
        .get(&url_join(&srv.base_url, "/compress/gzip"))
        .send_streaming()
        .await
        .expect("streaming gzip request");

    assert_eq!(resp.status().as_u16(), 200);

    let mut total = 0;
    let mut chunks = 0;
    while let Some(chunk) = resp.chunk_decoded().await.expect("chunk_decoded") {
        total += chunk.len();
        chunks += 1;
    }

    assert!(total > 0, "should receive decompressed data");
    let expected_payload = EXPECTED_PAYLOAD;
    // Re-read via buffered to verify same content
    let resp2 = session
        .get(&url_join(&srv.base_url, "/compress/gzip"))
        .send()
        .await
        .expect("buffered gzip request");
    let buffered_text = resp2.text().expect("utf-8");
    assert_eq!(
        total,
        buffered_text.len(),
        "streaming and buffered should produce same length"
    );
    println!("streaming chunk_decoded gzip: {chunks} chunks, {total} bytes");
    // Verify the payload contains expected content
    assert!(
        buffered_text.contains(expected_payload),
        "decompressed content mismatch"
    );
}

#[tokio::test]
async fn test_streaming_chunk_decoded_brotli() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let mut resp = session
        .get(&url_join(&srv.base_url, "/compress/br"))
        .send_streaming()
        .await
        .expect("streaming brotli request");

    assert_eq!(resp.status().as_u16(), 200);

    let mut decoded_body = Vec::new();
    while let Some(chunk) = resp.chunk_decoded().await.expect("chunk_decoded") {
        decoded_body.extend_from_slice(&chunk);
    }

    let text = String::from_utf8(decoded_body).expect("utf-8");
    assert!(
        text.contains(EXPECTED_PAYLOAD),
        "streaming brotli decompression failed: body len={}",
        text.len()
    );
}

#[tokio::test]
async fn test_streaming_chunk_decoded_deflate() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let mut resp = session
        .get(&url_join(&srv.base_url, "/compress/deflate"))
        .send_streaming()
        .await
        .expect("streaming deflate request");

    assert_eq!(resp.status().as_u16(), 200);

    let mut decoded_body = Vec::new();
    while let Some(chunk) = resp.chunk_decoded().await.expect("chunk_decoded") {
        decoded_body.extend_from_slice(&chunk);
    }

    let text = String::from_utf8(decoded_body).expect("utf-8");
    assert!(
        text.contains(EXPECTED_PAYLOAD),
        "streaming deflate decompression failed: body len={}",
        text.len()
    );
}

#[tokio::test]
async fn test_streaming_chunk_decoded_zstd() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let mut resp = session
        .get(&url_join(&srv.base_url, "/compress/zstd"))
        .send_streaming()
        .await
        .expect("streaming zstd request");

    assert_eq!(resp.status().as_u16(), 200);

    let mut decoded_body = Vec::new();
    while let Some(chunk) = resp.chunk_decoded().await.expect("chunk_decoded") {
        decoded_body.extend_from_slice(&chunk);
    }

    let text = String::from_utf8(decoded_body).expect("utf-8");
    assert!(
        text.contains(EXPECTED_PAYLOAD),
        "streaming zstd decompression failed: body len={}",
        text.len()
    );
}

// ---------------------------------------------------------------------------
// streaming chunk_decoded — identity passthrough
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_streaming_chunk_decoded_identity_passthrough() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let mut resp = session
        .get(&url_join(&srv.base_url, "/text-plain"))
        .send_streaming()
        .await
        .expect("streaming plain request");

    assert_eq!(resp.status().as_u16(), 200);

    let mut total = 0;
    while let Some(chunk) = resp.chunk_decoded().await.expect("chunk_decoded") {
        total += chunk.len();
    }

    assert!(total > 0, "should receive passthrough data");
}

// ---------------------------------------------------------------------------
// streaming bytes() — full buffered decompression (regression)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_streaming_bytes_decompresses_all_encodings() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    for encoding in &["gzip", "br", "deflate", "zstd"] {
        let resp = session
            .get(&url_join(&srv.base_url, &format!("/compress/{encoding}")))
            .send_streaming()
            .await
            .unwrap_or_else(|_| panic!("streaming {encoding} request"));

        assert_eq!(resp.status().as_u16(), 200);

        let body = resp
            .bytes()
            .await
            .unwrap_or_else(|_| panic!("bytes() {encoding}"));
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains(EXPECTED_PAYLOAD),
            "streaming bytes() {encoding} decompression failed"
        );
    }
}

// ---------------------------------------------------------------------------
// no_auto_decompress
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_streaming_no_auto_decompress_returns_raw() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/compress/gzip"))
        .no_auto_decompress()
        .send_streaming()
        .await
        .expect("raw gzip streaming request");

    assert_eq!(resp.status().as_u16(), 200);
    let raw = resp.bytes().await.expect("raw streaming bytes");
    assert!(
        raw.len() >= 2 && raw[0] == 0x1f && raw[1] == 0x8b,
        "expected raw gzip bytes from streaming response, got {} bytes starting with {:02x?}",
        raw.len(),
        &raw[..raw.len().min(4)]
    );
}
