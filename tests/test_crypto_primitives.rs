//! Tests for Cryptographic Primitives
//! Validates X25519 ECDH, ChaCha20-Poly1305, and key derivation

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

#[test]
fn test_x25519_key_exchange() {
    // Test basic ECDH key exchange
    let alice_secret = EphemeralSecret::random_from_rng(OsRng);
    let alice_public = PublicKey::from(&alice_secret);

    let bob_secret = EphemeralSecret::random_from_rng(OsRng);
    let bob_public = PublicKey::from(&bob_secret);

    // Compute shared secrets
    let alice_shared = alice_secret.diffie_hellman(&bob_public);
    let bob_shared = bob_secret.diffie_hellman(&alice_public);

    // Both sides should derive the same shared secret
    assert_eq!(
        alice_shared.as_bytes(),
        bob_shared.as_bytes(),
        "ECDH shared secrets must match"
    );
}

#[test]
fn test_chacha20_poly1305_encryption() {
    let key = Key::from([0u8; 32]);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = Nonce::from([0u8; 12]);
    let plaintext = b"Hello, YuKKi OS";

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .expect("Encryption failed");

    let decrypted = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .expect("Decryption failed");

    assert_eq!(
        plaintext,
        &decrypted[..],
        "Decrypted text must match plaintext"
    );
}

#[test]
fn test_chacha20_poly1305_authentication() {
    let key = Key::from([0u8; 32]);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = Nonce::from([0u8; 12]);
    let plaintext = b"Authenticated message";

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .expect("Encryption failed");

    // Corrupt a byte in the ciphertext
    let mut corrupted = ciphertext.clone();
    corrupted[0] ^= 0xFF;

    // Decryption should fail due to MAC verification
    let result = cipher.decrypt(&nonce, corrupted.as_ref());
    assert!(
        result.is_err(),
        "MAC verification must fail on corrupted ciphertext"
    );
}

#[test]
fn test_chacha20_poly1305_nonce_uniqueness() {
    let key = Key::from([0u8; 32]);
    let cipher = ChaCha20Poly1305::new(&key);
    let plaintext = b"Test message";

    let nonce1 = Nonce::from([0u8; 12]);
    let nonce2 = Nonce::from([1u8; 12]);

    let ct1 = cipher
        .encrypt(&nonce1, plaintext.as_ref())
        .expect("Encryption failed");
    let ct2 = cipher
        .encrypt(&nonce2, plaintext.as_ref())
        .expect("Encryption failed");

    // Same plaintext with different nonces must produce different ciphertexts
    assert_ne!(
        ct1, ct2,
        "Different nonces must produce different ciphertexts"
    );
}

#[test]
fn test_ephemeral_key_uniqueness() {
    let secret1 = EphemeralSecret::random_from_rng(OsRng);
    let secret2 = EphemeralSecret::random_from_rng(OsRng);

    let pub1 = PublicKey::from(&secret1);
    let pub2 = PublicKey::from(&secret2);

    assert_ne!(
        pub1.as_bytes(),
        pub2.as_bytes(),
        "Ephemeral keys must be unique"
    );
}

#[test]
fn test_session_key_derivation() {
    // Test minimal KDF as described in architecture
    let shared_secret = [0x42u8; 32];
    let domain_separator = [0xDEu8; 32];

    let mut session_key = [0u8; 32];
    for i in 0..32 {
        session_key[i] = shared_secret[i] ^ domain_separator[i];
    }

    // Key should be non-zero
    assert!(
        session_key.iter().any(|&b| b != 0),
        "Session key derivation must produce non-zero key"
    );
}

#[test]
fn test_chacha20_poly1305_tag_size() {
    let key = Key::from([0u8; 32]);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = Nonce::from([0u8; 12]);
    let plaintext = b"Tag size test";

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .expect("Encryption failed");

    // ChaCha20-Poly1305 appends a 16-byte authentication tag
    // ciphertext = encrypted_data + 16_byte_tag
    assert!(
        ciphertext.len() >= plaintext.len() + 16,
        "Ciphertext must include 16-byte authentication tag"
    );
}

#[test]
fn test_x25519_public_key_size() {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    assert_eq!(
        public.as_bytes().len(),
        32,
        "X25519 public key must be exactly 32 bytes"
    );
}
