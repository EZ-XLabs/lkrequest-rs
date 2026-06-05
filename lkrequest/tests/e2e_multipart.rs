//! Multipart uploads — local HTTPS server (Tier 0).
//! Single test runs both scenarios sequentially to avoid flaky parallel TLS to the embedded server.

mod support;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::multipart::{Multipart, Part};
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

#[tokio::test]
async fn test_multipart_text_and_file() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/post");

    let form = Multipart::new()
        .text("field1", "value1")
        .text("field2", "value2");

    let resp = session
        .post(&url)
        .multipart(form)
        .send()
        .await
        .expect("multipart POST");

    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().expect("utf-8");
    assert!(body.contains("value1"), "body={body}");
    assert!(body.contains("value2"), "body={body}");

    let form2 = Multipart::new().text("description", "test file").part(
        Part::new("file", "Hello from lkrequest multipart test!")
            .filename("test.txt")
            .content_type("text/plain"),
    );

    let resp2 = session
        .post(&url)
        .multipart(form2)
        .send()
        .await
        .expect("multipart file");

    assert_eq!(resp2.status().as_u16(), 200);
    let body2 = resp2.text().expect("utf-8");
    assert!(
        body2.contains("test.txt") || body2.contains("Hello from lkrequest"),
        "body={body2}"
    );
}

#[tokio::test]
async fn test_multipart_large_file() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/post");

    let large_content = "x".repeat(1_048_576); // 1 MB "file"
    let form = Multipart::new()
        .text("description", "large file upload test")
        .part(
            Part::new("bigfile", large_content)
                .filename("big.bin")
                .content_type("application/octet-stream"),
        );

    let resp = session
        .post(&url)
        .multipart(form)
        .send()
        .await
        .expect("large multipart POST");
    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn test_multipart_many_fields() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/post");

    let mut form = Multipart::new();
    for i in 0..50 {
        form = form.text(&format!("field_{i}"), &format!("value_{i}"));
    }

    let resp = session
        .post(&url)
        .multipart(form)
        .send()
        .await
        .expect("many-field multipart");
    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().expect("utf-8");
    assert!(body.contains("field_0"), "body={body}");
    assert!(body.contains("field_49"), "body={body}");
}

#[tokio::test]
async fn test_multipart_empty_part() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/post");

    let form = Multipart::new()
        .text("nonempty", "has-value")
        .text("empty", "");

    let resp = session
        .post(&url)
        .multipart(form)
        .send()
        .await
        .expect("empty-part multipart");
    assert_eq!(resp.status().as_u16(), 200);
}
