//! Cryptographic Primitives Benchmarks
//!
//! Measures X25519 ECDH key exchange and ChaCha20-Poly1305 encrypt / decrypt
//! performance under representative payload sizes.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

fn bench_x25519_keypair_generation(c: &mut Criterion) {
    c.bench_function("x25519_keypair_generation", |b| {
        b.iter(|| {
            let secret = EphemeralSecret::random_from_rng(OsRng);
            let public = PublicKey::from(&secret);
            black_box((secret, public))
        })
    });
}

fn bench_x25519_diffie_hellman(c: &mut Criterion) {
    c.bench_function("x25519_diffie_hellman", |b| {
        // Pre-generate Bob's public key outside the timed region.
        let bob_secret = EphemeralSecret::random_from_rng(OsRng);
        let bob_public = PublicKey::from(&bob_secret);

        b.iter(|| {
            let alice_secret = EphemeralSecret::random_from_rng(OsRng);
            let shared = alice_secret.diffie_hellman(black_box(&bob_public));
            black_box(shared)
        })
    });
}

fn bench_chacha20_encrypt(c: &mut Criterion) {
    let key = Key::from([0x42u8; 32]);
    let nonce = Nonce::from([0u8; 12]);
    let cipher = ChaCha20Poly1305::new(&key);

    let mut group = c.benchmark_group("chacha20_encrypt");
    for size in [16usize, 64, 256, 1024] {
        let plaintext = vec![0xABu8; size];
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| {
                cipher
                    .encrypt(black_box(&nonce), black_box(pt.as_ref()))
                    .expect("encrypt")
            })
        });
    }
    group.finish();
}

fn bench_chacha20_decrypt(c: &mut Criterion) {
    let key = Key::from([0x42u8; 32]);
    let nonce = Nonce::from([0u8; 12]);
    let cipher = ChaCha20Poly1305::new(&key);

    let mut group = c.benchmark_group("chacha20_decrypt");
    for size in [16usize, 64, 256, 1024] {
        let plaintext = vec![0xABu8; size];
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .expect("pre-encrypt");
        group.bench_with_input(BenchmarkId::from_parameter(size), &ciphertext, |b, ct| {
            b.iter(|| {
                cipher
                    .decrypt(black_box(&nonce), black_box(ct.as_ref()))
                    .expect("decrypt")
            })
        });
    }
    group.finish();
}

/// Full session-establishment heuristic: keygen + ECDH + cipher construction.
fn bench_session_establishment_heuristic(c: &mut Criterion) {
    c.bench_function("session_establishment_heuristic", |b| {
        b.iter(|| {
            let alice_secret = EphemeralSecret::random_from_rng(OsRng);
            let alice_public = PublicKey::from(&alice_secret);

            let bob_secret = EphemeralSecret::random_from_rng(OsRng);
            let bob_public = PublicKey::from(&bob_secret);

            let alice_shared = alice_secret.diffie_hellman(black_box(&bob_public));
            let _bob_shared = bob_secret.diffie_hellman(black_box(&alice_public));

            let cipher = ChaCha20Poly1305::new(Key::from_slice(alice_shared.as_bytes()));
            let nonce = Nonce::from([1u8; 12]);
            let ct = cipher
                .encrypt(&nonce, black_box(b"session init".as_ref()))
                .expect("encrypt");
            black_box(ct)
        })
    });
}

criterion_group!(
    crypto_benches,
    bench_x25519_keypair_generation,
    bench_x25519_diffie_hellman,
    bench_chacha20_encrypt,
    bench_chacha20_decrypt,
    bench_session_establishment_heuristic,
);
criterion_main!(crypto_benches);
