//! Offline benchmark suite for lkrequest.
//!
//! Pure CPU benchmarks — no network access required.
//! Measures internal processing performance via public API.
//!
//! Run with:
//!   cargo bench -p lkrequest --bench offline_bench

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use lkrequest::proxy::ProxyConfig;

// ---------------------------------------------------------------------------
// Proxy URL parsing
// ---------------------------------------------------------------------------

fn bench_proxy_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("proxy_parse");

    let urls = [
        ("http_simple", "http://proxy.example.com:8080"),
        ("http_auth", "http://user:pass@proxy.example.com:3128"),
        ("socks5", "socks5://proxy.example.com:1080"),
        ("socks5h_auth", "socks5h://user:pass@proxy.example.com:1080"),
    ];

    for (name, url) in &urls {
        group.bench_function(*name, |b| {
            b.iter(|| {
                ProxyConfig::parse(url).expect("parse");
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Client and Session construction
// ---------------------------------------------------------------------------

fn bench_client_construction(c: &mut Criterion) {
    use lkrequest::h2::profile::chrome_144_h2;
    use lkrequest::Client;
    use lktls::profile::presets;

    c.bench_function("client_build", |b| {
        b.iter(|| {
            Client::builder()
                .fingerprint(presets::chrome_144())
                .h2_profile(chrome_144_h2())
                .default_header("user-agent", "Test/1.0")
                .build()
        });
    });
}

fn bench_session_construction(c: &mut Criterion) {
    use lkrequest::h2::profile::chrome_144_h2;
    use lkrequest::Client;
    use lktls::profile::presets;

    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .build();

    c.bench_function("session_build", |b| {
        b.iter(|| client.session().build());
    });
}

// ---------------------------------------------------------------------------
// Profile presets loading
// ---------------------------------------------------------------------------

fn bench_profile_presets(c: &mut Criterion) {
    use lktls::profile::presets;

    let mut group = c.benchmark_group("profile_preset");

    group.bench_function("chrome_144", |b| {
        b.iter(presets::chrome_144);
    });

    group.bench_function("firefox_147", |b| {
        b.iter(presets::firefox_147);
    });

    group.bench_function("safari_26", |b| {
        b.iter(presets::safari_26);
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// JSON profile loading
// ---------------------------------------------------------------------------

fn bench_json_profile_load(c: &mut Criterion) {
    use lktls::profile::loader;

    let profiles = [
        (
            "chrome_144",
            include_str!("../../lktls/profiles/chrome_144.json"),
        ),
        (
            "firefox_147",
            include_str!("../../lktls/profiles/firefox_147.json"),
        ),
        (
            "safari_26",
            include_str!("../../lktls/profiles/safari_26.json"),
        ),
    ];

    let mut group = c.benchmark_group("json_profile_load");

    for (name, json) in &profiles {
        group.bench_function(*name, |b| {
            b.iter(|| {
                loader::from_json_str(json).expect("load");
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Multipart body construction (via public API — build request)
// ---------------------------------------------------------------------------

fn bench_multipart_request(c: &mut Criterion) {
    use lkrequest::h2::profile::chrome_144_h2;
    use lkrequest::multipart::{Multipart, Part};
    use lkrequest::Client;
    use lktls::profile::presets;

    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .build();
    let session = client.session().build();

    let mut group = c.benchmark_group("multipart_build");

    for &size in &[1024, 16384, 65536] {
        let file_data = vec![0xAAu8; size];
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let form = Multipart::new().text("field", "value").part(
                    Part::new("file", file_data.clone())
                        .filename("test.bin")
                        .content_type("application/octet-stream"),
                );
                // Build the request but don't send it
                let _rb = session.post("https://example.com/upload").multipart(form);
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion configuration
// ---------------------------------------------------------------------------

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(100)
        .measurement_time(std::time::Duration::from_secs(5));
    targets =
        bench_proxy_parse,
        bench_client_construction,
        bench_session_construction,
        bench_profile_presets,
        bench_json_profile_load,
        bench_multipart_request
}

criterion_main!(benches);
