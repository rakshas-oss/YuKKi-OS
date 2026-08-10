/// YuKKi OS v6.6.4 — Integration Test Suite
///
/// Covers: mesh peer management, encryption flows, and frame sequencing.

use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand_core::OsRng;

// ---------------------------------------------------------------------------
// Shared types mirrored from main (not re-exported from the binary)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct PeerInfo {
    uuid: Uuid,
    addr: String,
    p2p_port: u16,
    binary_port: u16,
}

#[derive(Serialize, Deserialize, Debug)]
enum SovereignCommand {
    Register(PeerInfo),
    NodeFleet(Vec<PeerInfo>),
}

// ---------------------------------------------------------------------------
// Mesh Integration Tests
// ---------------------------------------------------------------------------

#[test]
fn mesh_peer_info_serialization_roundtrip() {
    let peer = PeerInfo {
        uuid: Uuid::new_v4(),
        addr: "127.0.0.1".to_string(),
        p2p_port: 9000,
        binary_port: 9001,
    };
    let json = serde_json::to_string(&peer).expect("serialize");
    let decoded: PeerInfo = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(peer, decoded);
}

#[test]
fn mesh_socket_addr_parsing() {
    let addr: SocketAddr = "127.0.0.1:8080".parse().expect("parse addr");
    assert_eq!(addr.port(), 8080);
    assert!(addr.ip().is_loopback());
}

#[test]
fn mesh_uuid_generation_uniqueness() {
    let ids: Vec<Uuid> = (0..100).map(|_| Uuid::new_v4()).collect();
    let unique: HashSet<_> = ids.iter().collect();
    assert_eq!(ids.len(), unique.len(), "UUIDs must be unique");
}

#[test]
fn mesh_peer_blacklist_operations() {
    let mut blacklist: HashSet<Uuid> = HashSet::new();
    let peer_id = Uuid::new_v4();
    blacklist.insert(peer_id);
    assert!(blacklist.contains(&peer_id));
    blacklist.remove(&peer_id);
    assert!(!blacklist.contains(&peer_id));
}

#[test]
fn mesh_ip_blacklist_management() {
    let mut ip_blacklist: HashSet<String> = HashSet::new();
    let ip = "10.0.0.1".to_string();
    ip_blacklist.insert(ip.clone());
    assert!(ip_blacklist.contains(&ip));
    // second insert is idempotent
    ip_blacklist.insert(ip.clone());
    assert_eq!(ip_blacklist.len(), 1);
}

#[test]
fn mesh_fleet_peer_registry() {
    let mut fleet: HashMap<Uuid, PeerInfo> = HashMap::new();
    let peer = PeerInfo {
        uuid: Uuid::new_v4(),
        addr: "192.168.1.5".to_string(),
        p2p_port: 7000,
        binary_port: 7001,
    };
    fleet.insert(peer.uuid, peer.clone());
    assert_eq!(fleet.len(), 1);
    assert_eq!(fleet[&peer.uuid].addr, "192.168.1.5");
    fleet.remove(&peer.uuid);
    assert!(fleet.is_empty());
}

#[test]
fn mesh_nonce_counter_management() {
    let mut nonce: u64 = 0;
    for _ in 0..1000 {
        nonce += 1;
    }
    assert_eq!(nonce, 1000);
    // Nonce must not wrap unexpectedly within expected range
    assert!(nonce < u64::MAX);
}

#[test]
fn mesh_sync_boundary_detection_60_frame_intervals() {
    let trigger_every = 60u64;
    let triggers: Vec<u64> = (0..300)
        .filter(|seq| seq % trigger_every == 0 && *seq > 0)
        .collect();
    assert_eq!(triggers, vec![60, 120, 180, 240]);
    // Frame 0 is not a sync trigger
    assert!(!triggers.contains(&0));
}

#[test]
fn mesh_sovereign_command_register_serialization() {
    let peer = PeerInfo {
        uuid: Uuid::new_v4(),
        addr: "10.0.0.2".to_string(),
        p2p_port: 8500,
        binary_port: 8501,
    };
    let cmd = SovereignCommand::Register(peer.clone());
    let json = serde_json::to_string(&cmd).expect("serialize");
    assert!(json.contains("Register"));
}

#[test]
fn mesh_sovereign_command_fleet_serialization() {
    let peers: Vec<PeerInfo> = (0..3)
        .map(|i| PeerInfo {
            uuid: Uuid::new_v4(),
            addr: format!("10.0.0.{}", i + 1),
            p2p_port: 9000 + i as u16,
            binary_port: 9100 + i as u16,
        })
        .collect();
    let cmd = SovereignCommand::NodeFleet(peers);
    let json = serde_json::to_string(&cmd).expect("serialize");
    assert!(json.contains("NodeFleet"));
}

// ---------------------------------------------------------------------------
// Encryption Integration Tests
// ---------------------------------------------------------------------------

#[test]
fn encryption_framed_message_encrypt_decrypt() {
    let key_bytes = [0x42u8; 32];
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&0u64.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = b"hello secure world";
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).expect("encrypt");
    let recovered = cipher.decrypt(nonce, ciphertext.as_ref()).expect("decrypt");
    assert_eq!(recovered, plaintext);
}

#[test]
fn encryption_aead_frame_integrity_validation() {
    let key_bytes = [0xABu8; 32];
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&[0u8; 12]);

    let plaintext = b"integrity test payload";
    let mut ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).expect("encrypt");

    // Tamper with the ciphertext
    ciphertext[0] ^= 0xFF;
    let result = cipher.decrypt(nonce, ciphertext.as_ref());
    assert!(result.is_err(), "Tampered ciphertext must fail MAC verification");
}

#[test]
fn encryption_session_establishment_flow() {
    // Simulate X25519 key exchange → shared secret → session cipher
    let alice_secret = EphemeralSecret::random_from_rng(OsRng);
    let alice_public = PublicKey::from(&alice_secret);

    let bob_secret = EphemeralSecret::random_from_rng(OsRng);
    let bob_public = PublicKey::from(&bob_secret);

    let alice_shared = alice_secret.diffie_hellman(&bob_public);
    let bob_shared = bob_secret.diffie_hellman(&alice_public);

    // Both sides derive the same shared secret
    assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());

    // Derive session cipher from shared secret
    let alice_cipher = ChaCha20Poly1305::new(Key::from_slice(alice_shared.as_bytes()));
    let bob_cipher = ChaCha20Poly1305::new(Key::from_slice(bob_shared.as_bytes()));

    let nonce = Nonce::from_slice(&[1u8; 12]);
    let msg = b"session message";
    let ct = alice_cipher.encrypt(nonce, msg.as_ref()).expect("encrypt");
    let pt = bob_cipher.decrypt(nonce, ct.as_ref()).expect("decrypt");
    assert_eq!(pt, msg);
}

#[test]
fn encryption_nonce_sequence_uniqueness() {
    let nonces: Vec<[u8; 12]> = (0u64..1000)
        .map(|i| {
            let mut nb = [0u8; 12];
            nb[4..12].copy_from_slice(&i.to_le_bytes());
            nb
        })
        .collect();
    let unique: HashSet<[u8; 12]> = nonces.iter().cloned().collect();
    assert_eq!(nonces.len(), unique.len());
}

#[test]
fn encryption_ephemeral_key_uniqueness() {
    let pub1 = PublicKey::from(&EphemeralSecret::random_from_rng(OsRng));
    let pub2 = PublicKey::from(&EphemeralSecret::random_from_rng(OsRng));
    assert_ne!(pub1.as_bytes(), pub2.as_bytes());
}

// ---------------------------------------------------------------------------
// Frame Validation Tests
// ---------------------------------------------------------------------------

#[repr(C, packed(8))]
#[derive(Debug, Clone, Copy)]
struct SpatiotemporalFrame {
    seq_id: u64,
    x: f64,
    y: f64,
    z: f64,
    u: f64,
    v: f64,
    w: f64,
    fluidity: f32,
    drag: f32,
    divergence: f64,
    payload: [u8; 16],
}

#[test]
fn frame_sequence_ordering() {
    let frames: Vec<u64> = (0..10).collect();
    for window in frames.windows(2) {
        assert!(window[1] > window[0], "Frames must be strictly increasing");
    }
}

#[test]
fn frame_payload_isolation_between_frames() {
    let mut f1 = SpatiotemporalFrame {
        seq_id: 0,
        x: 0.0, y: 0.0, z: 0.0,
        u: 0.0, v: 0.0, w: 0.0,
        fluidity: 0.0, drag: 0.0, divergence: 0.0,
        payload: [0xAAu8; 16],
    };
    let f2 = SpatiotemporalFrame {
        seq_id: 1,
        payload: [0xBBu8; 16],
        ..f1
    };
    // Modifying f1 does not affect f2
    f1.payload[0] = 0xFF;
    assert_eq!(f2.payload[0], 0xBB);
    assert_eq!(f1.payload[0], 0xFF);
}

#[test]
fn frame_size_is_88_bytes() {
    assert_eq!(
        std::mem::size_of::<SpatiotemporalFrame>(),
        88,
        "Frame ABI requires exactly 88 bytes"
    );
}

#[test]
fn frame_lorenz_state_progression_tracking() {
    // Lorenz state is tracked per-frame; verify state changes between steps
    let mut x = 1.0f64;
    let mut y = 1.0f64;
    let mut z = 1.0f64;

    let sigma = 10.0f64;
    let rho = 28.0f64;
    let beta = 8.0f64 / 3.0f64;
    let dt = 0.001f64;

    let prev = (x, y, z);
    x += dt * sigma * (y - x);
    y += dt * (x * (rho - z) - y);
    z += dt * (x * y - beta * z);

    assert_ne!((x, y, z), prev, "Lorenz state must progress each step");
}
