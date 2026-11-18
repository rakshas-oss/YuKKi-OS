//! Cryptographic primitive microbenchmarks.
//!
//! All keys, nonce values, payload sizes and message bytes are loaded from
//! benches/datasets/native-v1.json. Values are deterministic test fixtures,
//! not production key material or nonce-generation guidance.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use serde_json::Value;
use std::hint::black_box;
use x25519_dalek::{PublicKey, StaticSecret};

fn dataset() -> Value {
    serde_json::from_str(include_str!("datasets/native-v1.json"))
        .expect("parse native benchmark dataset")
}

fn hex_bytes<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2, "hex fixture length");
    let mut output = [0u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).expect("valid hex fixture");
    }
    output
}

fn bench_x25519_keypair_generation(c: &mut Criterion) {
    let data = dataset();
    let crypto = &data["crypto"];
    let secret_bytes = hex_bytes::<32>(
        crypto["keypair_secret_hex"]
            .as_str()
            .expect("keypair secret"),
    );
    c.bench_function("x25519_keypair_generation", |b| {
        b.iter(|| {
            let secret = StaticSecret::from(black_box(secret_bytes));
            let public = PublicKey::from(&secret);
            black_box((secret, public))
        })
    });
}

fn bench_x25519_diffie_hellman(c: &mut Criterion) {
    let data = dataset();
    let crypto = &data["crypto"];
    let alice_secret = StaticSecret::from(hex_bytes::<32>(
        crypto["dh_alice_secret_hex"]
            .as_str()
            .expect("Alice secret"),
    ));
    let bob_secret = StaticSecret::from(hex_bytes::<32>(
        crypto["dh_bob_secret_hex"].as_str().expect("Bob secret"),
    ));
    let bob_public = PublicKey::from(&bob_secret);
    c.bench_function("x25519_diffie_hellman", |b| {
        b.iter(|| {
            let shared = alice_secret.diffie_hellman(black_box(&bob_public));
            black_box(shared)
        })
    });
}

fn bench_chacha20_encrypt(c: &mut Criterion) {
    let data = dataset();
    let crypto = &data["crypto"];
    let key = Key::from(hex_bytes::<32>(
        crypto["chacha_key_hex"].as_str().expect("ChaCha key"),
    ));
    let nonce = Nonce::from(hex_bytes::<12>(
        crypto["chacha_nonce_hex"].as_str().expect("ChaCha nonce"),
    ));
    let cipher = ChaCha20Poly1305::new(&key);
    let payload_byte = crypto["payload_byte"].as_u64().expect("payload byte") as u8;

    let mut group = c.benchmark_group("chacha20_encrypt");
    for size in crypto["payload_sizes_bytes"]
        .as_array()
        .expect("payload size list")
    {
        let size = size.as_u64().expect("payload size") as usize;
        let plaintext = vec![payload_byte; size];
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
    let data = dataset();
    let crypto = &data["crypto"];
    let key = Key::from(hex_bytes::<32>(
        crypto["chacha_key_hex"].as_str().expect("ChaCha key"),
    ));
    let nonce = Nonce::from(hex_bytes::<12>(
        crypto["chacha_nonce_hex"].as_str().expect("ChaCha nonce"),
    ));
    let cipher = ChaCha20Poly1305::new(&key);
    let payload_byte = crypto["payload_byte"].as_u64().expect("payload byte") as u8;

    let mut group = c.benchmark_group("chacha20_decrypt");
    for size in crypto["payload_sizes_bytes"]
        .as_array()
        .expect("payload size list")
    {
        let size = size.as_u64().expect("payload size") as usize;
        let plaintext = vec![payload_byte; size];
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .expect("pre-encrypt fixture");
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

fn bench_session_establishment_heuristic(c: &mut Criterion) {
    let data = dataset();
    let crypto = &data["crypto"];
    let alice_secret_bytes = hex_bytes::<32>(
        crypto["session_alice_secret_hex"]
            .as_str()
            .expect("session Alice secret"),
    );
    let bob_secret_bytes = hex_bytes::<32>(
        crypto["session_bob_secret_hex"]
            .as_str()
            .expect("session Bob secret"),
    );
    let nonce = Nonce::from(hex_bytes::<12>(
        crypto["session_nonce_hex"].as_str().expect("session nonce"),
    ));
    let message = crypto["session_message"]
        .as_str()
        .expect("session message")
        .as_bytes();

    c.bench_function("session_establishment_heuristic", |b| {
        b.iter(|| {
            let alice_secret = StaticSecret::from(black_box(alice_secret_bytes));
            let alice_public = PublicKey::from(&alice_secret);
            let bob_secret = StaticSecret::from(black_box(bob_secret_bytes));
            let bob_public = PublicKey::from(&bob_secret);
            let alice_shared = alice_secret.diffie_hellman(black_box(&bob_public));
            let _bob_shared = bob_secret.diffie_hellman(black_box(&alice_public));
            let cipher = ChaCha20Poly1305::new(&Key::from(*alice_shared.as_bytes()));
            let ciphertext = cipher.encrypt(&nonce, black_box(message)).expect("encrypt");
            black_box(ciphertext)
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
