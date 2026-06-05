//! Benchmark suite for lktls cryptographic primitives.
//!
//! Pure CPU benchmarks with no network access required.
//!
//! Run with:
//!   cargo bench -p lktls --bench crypto_bench

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use lktls::crypto::aead::{Aead, AeadAlgorithm};
use lktls::crypto::hkdf::{self, HkdfAlgorithm};
use lktls::crypto::kx::{self, KxGroup};
use lktls::crypto::prf::{self, PrfAlgorithm};

// ---------------------------------------------------------------------------
// AEAD encrypt/decrypt
// ---------------------------------------------------------------------------

fn bench_aead_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead_encrypt");

    let algorithms = [
        ("AES-128-GCM", AeadAlgorithm::Aes128Gcm),
        ("AES-256-GCM", AeadAlgorithm::Aes256Gcm),
        ("ChaCha20-Poly1305", AeadAlgorithm::Chacha20Poly1305),
    ];
    let sizes = [1024, 16384, 65536];

    for (name, algo) in &algorithms {
        let key = vec![0x42u8; algo.key_len()];
        let iv = vec![0x00u8; algo.nonce_len()];
        let aead = Aead::new(*algo, &key, &iv).expect("AEAD init");

        for &size in &sizes {
            let plaintext = vec![0xAAu8; size];
            let aad = b"benchmark";

            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(BenchmarkId::new(*name, size), &size, |b, _| {
                let mut seq = 0u64;
                b.iter(|| {
                    aead.encrypt(seq, aad, &plaintext).expect("encrypt");
                    seq += 1;
                });
            });
        }
    }

    group.finish();
}

fn bench_aead_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead_decrypt");

    let algo = AeadAlgorithm::Aes128Gcm;
    let key = vec![0x42u8; algo.key_len()];
    let iv = vec![0x00u8; algo.nonce_len()];
    let aead = Aead::new(algo, &key, &iv).expect("AEAD init");
    let aad = b"benchmark";

    for &size in &[1024, 16384, 65536] {
        let plaintext = vec![0xAAu8; size];
        let ciphertext = aead.encrypt(0, aad, &plaintext).expect("encrypt");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                aead.decrypt(0, aad, &ciphertext).expect("decrypt");
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// HKDF
// ---------------------------------------------------------------------------

fn bench_hkdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("hkdf");

    let salt = vec![0x00u8; 32];
    let ikm = vec![0xAAu8; 48];

    group.bench_function("extract_sha256", |b| {
        b.iter(|| {
            hkdf::hkdf_extract(HkdfAlgorithm::Sha256, &salt, &ikm).expect("extract");
        });
    });

    group.bench_function("extract_sha384", |b| {
        b.iter(|| {
            hkdf::hkdf_extract(HkdfAlgorithm::Sha384, &salt, &ikm).expect("extract");
        });
    });

    group.bench_function("expand_label_sha256", |b| {
        b.iter(|| {
            hkdf::hkdf_expand_label(HkdfAlgorithm::Sha256, &ikm, "derived", b"context", 32)
                .expect("expand");
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// PRF (TLS 1.2)
// ---------------------------------------------------------------------------

fn bench_prf(c: &mut Criterion) {
    let mut group = c.benchmark_group("prf");

    let pre_master_secret = vec![0x42u8; 48];
    let client_random = [0x01u8; 32];
    let server_random = [0x02u8; 32];

    group.bench_function("compute_master_secret", |b| {
        b.iter(|| {
            prf::compute_master_secret(
                PrfAlgorithm::Sha256,
                &pre_master_secret,
                &client_random,
                &server_random,
            )
            .expect("master secret");
        });
    });

    let master_secret = prf::compute_master_secret(
        PrfAlgorithm::Sha256,
        &pre_master_secret,
        &client_random,
        &server_random,
    )
    .expect("master secret");

    group.bench_function("expand_key_block", |b| {
        b.iter(|| {
            prf::expand_key_block(
                PrfAlgorithm::Sha256,
                &master_secret,
                &server_random,
                &client_random,
                0,
                16,
                4,
            )
            .expect("key block");
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Key Exchange
// ---------------------------------------------------------------------------

fn bench_key_exchange(c: &mut Criterion) {
    let mut group = c.benchmark_group("kx");

    group.bench_function("x25519_generate", |b| {
        b.iter(|| {
            kx::generate_key_pair(KxGroup::X25519).expect("generate");
        });
    });

    group.bench_function("p256_generate", |b| {
        b.iter(|| {
            kx::generate_key_pair(KxGroup::Secp256r1).expect("generate");
        });
    });

    group.bench_function("x25519_shared_secret", |b| {
        let bob = kx::generate_key_pair(KxGroup::X25519).expect("generate");
        let bob_pub = bob.public_key.clone();

        b.iter(|| {
            let alice = kx::generate_key_pair(KxGroup::X25519).expect("generate");
            kx::compute_shared_secret(alice, &bob_pub).expect("shared secret");
        });
    });

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
        bench_aead_encrypt,
        bench_aead_decrypt,
        bench_hkdf,
        bench_prf,
        bench_key_exchange
}

criterion_main!(benches);
