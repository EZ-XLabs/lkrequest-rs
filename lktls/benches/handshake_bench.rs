//! Benchmark suite for lktls handshake operations.
//!
//! Measures ClientHello building performance for different browser profiles.
//! Pure CPU benchmarks — no network access required.
//!
//! Run with:
//!   cargo bench -p lktls --bench handshake_bench

use criterion::{criterion_group, criterion_main, Criterion};

use lktls::handshake::client_hello::ClientHelloBuilder;
use lktls::profile::presets;

// ---------------------------------------------------------------------------
// ClientHello building
// ---------------------------------------------------------------------------

fn bench_client_hello_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("client_hello_build");

    let profiles = vec![
        ("Chrome 144", presets::chrome_144()),
        ("Firefox 147", presets::firefox_147()),
        ("Safari 26", presets::safari_26()),
        ("Chrome 131", presets::chrome_131()),
    ];

    for (name, profile) in &profiles {
        group.bench_function(*name, |b| {
            b.iter(|| {
                let builder = ClientHelloBuilder::new(profile, "www.example.com");
                builder.build().expect("ClientHello build");
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// ServerHello parsing
// ---------------------------------------------------------------------------

fn bench_server_hello_parse(c: &mut Criterion) {
    // A minimal TLS 1.3 ServerHello (pre-recorded bytes)
    let server_hello_bytes: Vec<u8> = {
        let mut buf = Vec::new();
        // Protocol version (TLS 1.2 legacy)
        buf.extend_from_slice(&[0x03, 0x03]);
        // Server random (32 bytes)
        buf.extend_from_slice(&[0x42u8; 32]);
        // Session ID length + session ID (32 bytes matching typical CH)
        buf.push(32);
        buf.extend_from_slice(&[0x00u8; 32]);
        // Cipher suite (TLS_AES_128_GCM_SHA256 = 0x1301)
        buf.extend_from_slice(&[0x13, 0x01]);
        // Compression method (null)
        buf.push(0x00);
        // Extensions length
        let ext_len_pos = buf.len();
        buf.extend_from_slice(&[0x00, 0x00]); // placeholder

        // supported_versions extension (type=0x002B, len=2, version=0x0304)
        buf.extend_from_slice(&[0x00, 0x2B, 0x00, 0x02, 0x03, 0x04]);

        // key_share extension (type=0x0033, len=36, group=0x001D, key_len=32)
        buf.extend_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1D, 0x00, 0x20]);
        buf.extend_from_slice(&[0x55u8; 32]); // server public key

        let ext_len = (buf.len() - ext_len_pos - 2) as u16;
        buf[ext_len_pos] = (ext_len >> 8) as u8;
        buf[ext_len_pos + 1] = ext_len as u8;
        buf
    };

    c.bench_function("server_hello_parse", |b| {
        b.iter(|| {
            let _ = lktls::handshake::server_hello::parse_server_hello(&server_hello_bytes);
        });
    });
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
        bench_client_hello_build,
        bench_server_hello_parse
}

criterion_main!(benches);
