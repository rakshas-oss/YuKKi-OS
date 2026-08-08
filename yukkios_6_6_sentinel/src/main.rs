// YuKKi OS v6.6.0 — Sentinel Mesh Edition
// Architect: Aditya Muralidhar (Rakshas International Unlimited)
// License: GPL-3.0
//
// Architecture:
//   Control Plane  — JSON messages over TCP, AEAD encrypted with ChaCha20-Poly1305
//                    after an X25519 ECDH handshake.
//   Data Plane     — Binary SpatiotemporalFrame stream driven by the Lorenz attractor
//                    (via C FFI, chaos_weave.c).
//   Integrity Sync — Dual-layer sentinel quarantine (soft / hard) managed in C.
//   Polymorphic Weave — ChaCha20 payload weaving mixed with current Lorenz state.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    ffi::CString,
    net::SocketAddr,
    sync::Arc,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use uuid::Uuid;
use anyhow::anyhow;
use x25519_dalek::{EphemeralSecret, PublicKey};

const VERSION: &str = "v6.6.0";
const FRAME_SIZE: usize = 88;
const AEAD_NONCE_SIZE: usize = 12;
const AEAD_TAG_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// FFI bindings — chaos_weave.c (C99 compatible)
// ---------------------------------------------------------------------------

#[repr(C, packed)]
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

extern "C" {
    fn chaos_engine_reseed(sigma: f64, rho: f64, beta: f64, x0: f64, y0: f64, z0: f64);
    fn weave_spatiotemporal_frame(
        seq: u64,
        payload_src: *const u8,
        out_frame: *mut SpatiotemporalFrame,
    );
    fn chacha_weave_payload(
        nonce12: *const u8,
        shared_key32: *const u8,
        plaintext: *const u8,
        len: usize,
        out: *mut u8,
    ) -> i32;
    fn sentinel_quarantine_node(node_uuid: *const std::ffi::c_char);
    fn sentinel_release_node(node_uuid: *const std::ffi::c_char);
    fn sentinel_is_quarantined(node_uuid: *const std::ffi::c_char) -> i32;
    fn sentinel_quarantine_level(node_uuid: *const std::ffi::c_char) -> i32;
}

// ---------------------------------------------------------------------------
// ChaosController
// ---------------------------------------------------------------------------

struct ChaosController;

impl ChaosController {
    fn init() {
        unsafe { chaos_engine_reseed(10.0, 28.0, 8.333_333_333_333, 0.1, 0.0, 0.0) };
    }

    fn next_frame(seq: u64, payload: Option<&[u8]>) -> SpatiotemporalFrame {
        let mut frame = SpatiotemporalFrame {
            seq_id: 0,
            x: 0.0,
            y: 0.0,
            z: 0.0,
            u: 0.0,
            v: 0.0,
            w: 0.0,
            fluidity: 0.0,
            drag: 0.0,
            divergence: 0.0,
            payload: [0u8; 16],
        };
        let src_ptr = payload.map(|p| p.as_ptr()).unwrap_or(std::ptr::null());
        unsafe { weave_spatiotemporal_frame(seq, src_ptr, &mut frame) };
        frame
    }

    fn frame_to_bytes(frame: &SpatiotemporalFrame) -> [u8; FRAME_SIZE] {
        unsafe { std::mem::transmute_copy(frame) }
    }
}

// ---------------------------------------------------------------------------
// Sentinel quarantine safe wrappers
// ---------------------------------------------------------------------------

fn quarantine_node(id: &str) {
    let cs = CString::new(id).unwrap_or_default();
    unsafe { sentinel_quarantine_node(cs.as_ptr()) };
}

fn release_node(id: &str) {
    let cs = CString::new(id).unwrap_or_default();
    unsafe { sentinel_release_node(cs.as_ptr()) };
}

fn is_quarantined(id: &str) -> bool {
    let cs = CString::new(id).unwrap_or_default();
    unsafe { sentinel_is_quarantined(cs.as_ptr()) != 0 }
}

fn quarantine_level(id: &str) -> i32 {
    let cs = CString::new(id).unwrap_or_default();
    unsafe { sentinel_quarantine_level(cs.as_ptr()) }
}

// ---------------------------------------------------------------------------
// ChaCha polymorphic weave safe wrapper
// ---------------------------------------------------------------------------

fn polymorphic_weave(nonce: &[u8; AEAD_NONCE_SIZE], key32: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let rc = unsafe {
        chacha_weave_payload(
            nonce.as_ptr(),
            key32.as_ptr(),
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
        )
    };
    if rc != 0 {
        eprintln!("[WARN] chacha_weave_payload returned {rc}");
    }
    out
}

// ---------------------------------------------------------------------------
// Control-plane message types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ControlMessage {
    Handshake {
        node_id: String,
        pub_key_hex: String,
    },
    HandshakeAck {
        node_id: String,
        pub_key_hex: String,
    },
    FluidMessage {
        from: String,
        to: String,
        body: String,
        seq: u64,
        frame_hash: String,
    },
    WeaveAnnounce {
        from: String,
        weave_hex: String,
        seq: u64,
    },
    PeerList {
        peers: Vec<String>,
    },
    Quarantine {
        target: String,
        level: i32,
        issuer: String,
    },
    Release {
        target: String,
        issuer: String,
    },
}

// ---------------------------------------------------------------------------
// AEAD framing helpers
// ---------------------------------------------------------------------------

fn aead_encrypt(cipher: &ChaCha20Poly1305, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; AEAD_NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("AEAD encrypt: {e}"))?;
    // Wire format: [12-byte nonce][ciphertext+tag]
    let mut out = Vec::with_capacity(AEAD_NONCE_SIZE + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn aead_decrypt(cipher: &ChaCha20Poly1305, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    if data.len() < AEAD_NONCE_SIZE + AEAD_TAG_SIZE {
        return Err(anyhow!("AEAD frame too short"));
    }
    let nonce = Nonce::from_slice(&data[..AEAD_NONCE_SIZE]);
    let pt = cipher
        .decrypt(nonce, &data[AEAD_NONCE_SIZE..])
        .map_err(|e| anyhow!("AEAD decrypt: {e}"))?;
    Ok(pt)
}

/// Write a length-prefixed AEAD frame.
async fn send_frame(
    stream: &mut TcpStream,
    cipher: &ChaCha20Poly1305,
    msg: &ControlMessage,
) -> anyhow::Result<()> {
    let json = serde_json::to_vec(msg)?;
    let ct = aead_encrypt(cipher, &json)?;
    let len = ct.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&ct).await?;
    Ok(())
}

/// Read a length-prefixed AEAD frame.
async fn recv_frame(
    stream: &mut TcpStream,
    cipher: &ChaCha20Poly1305,
) -> anyhow::Result<ControlMessage> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1_048_576 {
        return Err(anyhow!("Frame too large: {len}"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    let pt = aead_decrypt(cipher, &buf)?;
    Ok(serde_json::from_slice(&pt)?)
}

// ---------------------------------------------------------------------------
// X25519 handshake — derive ChaCha20-Poly1305 key from shared secret
// ---------------------------------------------------------------------------

fn derive_cipher(shared: &[u8; 32]) -> ChaCha20Poly1305 {
    // Simple KDF: BLAKE-like mixing via XOR + rotate (demo — use HKDF in production)
    let mut key_bytes = *shared;
    let lorenz_salt = b"yukki_sentinel_v660_kdf_lorenz\0\0";
    for i in 0..32 {
        key_bytes[i] ^= lorenz_salt[i];
        key_bytes[i] = key_bytes[i].rotate_left(3);
    }
    ChaCha20Poly1305::new(Key::from_slice(&key_bytes))
}

// ---------------------------------------------------------------------------
// Shared node state
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct NodeInfo {
    id: String,
    addr: SocketAddr,
}

type NodeMap = Arc<Mutex<HashMap<String, NodeInfo>>>;

// ---------------------------------------------------------------------------
// Bootstrap server — listens for inbound connections
// ---------------------------------------------------------------------------

async fn run_bootstrap(bind_addr: &str, node_id: String) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    let nodes: NodeMap = Arc::new(Mutex::new(HashMap::new()));

    println!("[{VERSION}] Bootstrap node {node_id} listening on {bind_addr}");
    ChaosController::init();

    // Spawn CLI
    let nodes_cli = Arc::clone(&nodes);
    let my_id = node_id.clone();
    tokio::spawn(async move {
        run_cli(my_id, nodes_cli).await;
    });

    loop {
        let (mut stream, peer_addr) = listener.accept().await?;
        let nodes = Arc::clone(&nodes);
        let my_id = node_id.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_inbound(&mut stream, peer_addr, my_id, nodes).await {
                eprintln!("[ERROR] Inbound {peer_addr}: {e}");
            }
        });
    }
}

async fn handle_inbound(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    my_id: String,
    nodes: NodeMap,
) -> anyhow::Result<()> {
    // Step 1: Read peer's public key
    let mut peer_pub_bytes = [0u8; 32];
    stream.read_exact(&mut peer_pub_bytes).await?;

    // Step 2: Generate our ephemeral keypair, send our public key
    let my_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let my_pub = PublicKey::from(&my_secret);
    stream.write_all(my_pub.as_bytes()).await?;

    // Step 3: Derive shared secret → cipher
    let peer_pub = PublicKey::from(peer_pub_bytes);
    let shared = my_secret.diffie_hellman(&peer_pub);
    let cipher = derive_cipher(shared.as_bytes());

    // Step 4: Receive handshake message
    let msg = recv_frame(stream, &cipher).await?;
    let peer_id = match &msg {
        ControlMessage::Handshake { node_id, .. } => node_id.clone(),
        _ => return Err(anyhow!("Expected Handshake, got {msg:?}")),
    };

    println!("[{my_id}] Handshake from {peer_id} ({peer_addr})");

    // Send ack
    let ack = ControlMessage::HandshakeAck {
        node_id: my_id.clone(),
        pub_key_hex: hex::encode(my_pub.as_bytes()),
    };
    send_frame(stream, &cipher, &ack).await?;

    if is_quarantined(&peer_id) {
        let ql = quarantine_level(&peer_id);
        println!("[{my_id}] Node {peer_id} is quarantined (level {ql}), dropping connection.");
        return Ok(());
    }

    nodes.lock().await.insert(
        peer_id.clone(),
        NodeInfo { id: peer_id.clone(), addr: peer_addr },
    );

    // Message loop
    loop {
        match recv_frame(stream, &cipher).await {
            Ok(msg) => handle_control_message(&my_id, msg, &nodes).await,
            Err(e) => {
                eprintln!("[{my_id}] Peer {peer_id} disconnected: {e}");
                break;
            }
        }
    }

    nodes.lock().await.remove(&peer_id);
    Ok(())
}

// ---------------------------------------------------------------------------
// Node (outbound) — connects to bootstrap
// ---------------------------------------------------------------------------

async fn run_node(bootstrap_addr: &str, node_id: String) -> anyhow::Result<()> {
    ChaosController::init();
    let nodes: NodeMap = Arc::new(Mutex::new(HashMap::new()));

    let mut stream = TcpStream::connect(bootstrap_addr).await?;
    println!("[{VERSION}] Node {node_id} connecting to {bootstrap_addr}");

    // Step 1: Generate keypair, send our public key first
    let my_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let my_pub = PublicKey::from(&my_secret);
    stream.write_all(my_pub.as_bytes()).await?;

    // Step 2: Read peer's public key
    let mut peer_pub_bytes = [0u8; 32];
    stream.read_exact(&mut peer_pub_bytes).await?;

    // Step 3: Derive shared secret → cipher
    let peer_pub = PublicKey::from(peer_pub_bytes);
    let shared = my_secret.diffie_hellman(&peer_pub);
    let cipher = derive_cipher(shared.as_bytes());

    // Step 4: Send handshake
    let hs = ControlMessage::Handshake {
        node_id: node_id.clone(),
        pub_key_hex: hex::encode(my_pub.as_bytes()),
    };
    send_frame(&mut stream, &cipher, &hs).await?;

    // Step 5: Receive ack
    let ack = recv_frame(&mut stream, &cipher).await?;
    match &ack {
        ControlMessage::HandshakeAck { node_id: peer_id, .. } => {
            println!("[{node_id}] Connected to bootstrap {peer_id}");
            nodes.lock().await.insert(
                peer_id.clone(),
                NodeInfo {
                    id: peer_id.clone(),
                    addr: stream.peer_addr()?,
                },
            );
        }
        _ => return Err(anyhow!("Expected HandshakeAck")),
    }

    // Split stream for concurrent read + CLI
    let (rh, wh) = stream.into_split();
    let rh = Arc::new(Mutex::new(rh));
    let wh = Arc::new(Mutex::new(wh));

    // Reader task
    let my_id2 = node_id.clone();
    let nodes2 = Arc::clone(&nodes);
    let cipher2 = cipher.clone();
    let rh2 = Arc::clone(&rh);
    tokio::spawn(async move {
        loop {
            let msg_result: anyhow::Result<ControlMessage> = {
                let mut r = rh2.lock().await;
                async {
                    let mut len_buf = [0u8; 4];
                    r.read_exact(&mut len_buf).await?;
                    let len = u32::from_be_bytes(len_buf) as usize;
                    let mut buf = vec![0u8; len];
                    r.read_exact(&mut buf).await?;
                    let pt = aead_decrypt(&cipher2, &buf)?;
                    let msg: ControlMessage = serde_json::from_slice(&pt)?;
                    Ok(msg)
                }
                .await
            };
            match msg_result {
                Ok(msg) => handle_control_message(&my_id2, msg, &nodes2).await,
                Err(e) => {
                    eprintln!("[{my_id2}] Bootstrap disconnected: {e}");
                    break;
                }
            }
        }
    });

    // CLI task
    let wh_cli = Arc::clone(&wh);
    let cipher_cli = cipher.clone();
    let my_id3 = node_id.clone();
    run_cli_outbound(my_id3, nodes, wh_cli, cipher_cli).await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Control message handler
// ---------------------------------------------------------------------------

async fn handle_control_message(
    my_id: &str,
    msg: ControlMessage,
    nodes: &NodeMap,
) {
    match msg {
        ControlMessage::FluidMessage { from, body, seq, frame_hash, .. } => {
            if is_quarantined(&from) {
                println!("[{my_id}] Dropping message from quarantined node {from}");
                return;
            }
            let frame = ChaosController::next_frame(seq, Some(body.as_bytes()));
            let fh = simple_hash(&ChaosController::frame_to_bytes(&frame));
            let expected = format!("{fh:016x}");
            if expected != frame_hash {
                println!("[{my_id}] Integrity mismatch from {from} at seq {seq} — soft quarantine");
                quarantine_node(&from);
            } else {
                println!("[{my_id}] msg from {from} [seq={seq}]: {body}");
            }
        }
        ControlMessage::WeaveAnnounce { from, weave_hex, seq } => {
            println!("[{my_id}] weave from {from} [seq={seq}]: {weave_hex}");
        }
        ControlMessage::PeerList { peers } => {
            println!("[{my_id}] fleet/peers: {}", peers.join(", "));
        }
        ControlMessage::Quarantine { target, level, issuer } => {
            println!("[{my_id}] Quarantine issued by {issuer}: target={target} level={level}");
            quarantine_node(&target);
            if level >= 2 {
                // Escalate to hard quarantine
                quarantine_node(&target);
            }
        }
        ControlMessage::Release { target, issuer } => {
            println!("[{my_id}] Release issued by {issuer}: target={target}");
            release_node(&target);
        }
        ControlMessage::HandshakeAck { node_id, .. } => {
            println!("[{my_id}] Unexpected HandshakeAck from {node_id}");
        }
        ControlMessage::Handshake { node_id, .. } => {
            println!("[{my_id}] Unexpected Handshake from {node_id}");
        }
    }
}

// ---------------------------------------------------------------------------
// Simple FNV-1a hash for frame integrity check
// ---------------------------------------------------------------------------

fn simple_hash(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

// ---------------------------------------------------------------------------
// CLI — bootstrap mode (full access to NodeMap directly)
// ---------------------------------------------------------------------------

async fn run_cli(my_id: String, nodes: NodeMap) {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();

    print_help(&my_id);

    loop {
        print!("> ");
        // flush stdout (best-effort, ignore errors)
        let _ = std::io::Write::flush(&mut std::io::stdout());

        let line = match reader.next_line().await {
            Ok(Some(l)) => l,
            _ => break,
        };
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        match parts[0] {
            "fleet" if parts.get(1) == Some(&"peers") => {
                let guard = nodes.lock().await;
                if guard.is_empty() {
                    println!("  (no peers connected)");
                } else {
                    for (id, info) in guard.iter() {
                        let ql = quarantine_level(id);
                        println!("  {} @ {} [q={}]", id, info.addr, ql);
                    }
                }
            }
            "exit" | "quit" => {
                println!("Exiting...");
                std::process::exit(0);
            }
            _ => {
                println!("  Unknown command. Type 'fleet peers' or 'exit'.");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CLI — node mode (sends messages over the established stream)
// ---------------------------------------------------------------------------

async fn run_cli_outbound(
    my_id: String,
    nodes: NodeMap,
    wh: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    cipher: ChaCha20Poly1305,
) {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();
    let mut seq: u64 = 0;

    print_help(&my_id);

    loop {
        print!("> ");
        let _ = std::io::Write::flush(&mut std::io::stdout());

        let line = match reader.next_line().await {
            Ok(Some(l)) => l,
            _ => break,
        };
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        match parts[0] {
            "fleet" if parts.get(1) == Some(&"peers") => {
                let guard = nodes.lock().await;
                if guard.is_empty() {
                    println!("  (no peers)");
                } else {
                    for (id, info) in guard.iter() {
                        println!("  {} @ {}", id, info.addr);
                    }
                }
            }
            "msg" => {
                // msg <to> <body>
                let to = parts.get(1).unwrap_or(&"all").to_string();
                let body = parts.get(2).unwrap_or(&"").to_string();
                seq += 1;
                let frame = ChaosController::next_frame(seq, Some(body.as_bytes()));
                let fh = simple_hash(&ChaosController::frame_to_bytes(&frame));
                let msg = ControlMessage::FluidMessage {
                    from: my_id.clone(),
                    to,
                    body,
                    seq,
                    frame_hash: format!("{fh:016x}"),
                };
                if let Err(e) = send_outbound(&wh, &cipher, &msg).await {
                    eprintln!("[ERROR] msg send: {e}");
                }
            }
            "weave" => {
                // weave <data>
                let data = parts.get(1).map(|s| s.as_bytes()).unwrap_or(b"sentinel");
                seq += 1;
                let mut nonce = [0u8; AEAD_NONCE_SIZE];
                rand::thread_rng().fill_bytes(&mut nonce);
                let dummy_key = [0u8; 32];
                let woven = polymorphic_weave(&nonce, &dummy_key, data);
                let msg = ControlMessage::WeaveAnnounce {
                    from: my_id.clone(),
                    weave_hex: hex::encode(&woven),
                    seq,
                };
                if let Err(e) = send_outbound(&wh, &cipher, &msg).await {
                    eprintln!("[ERROR] weave send: {e}");
                }
            }
            "exit" | "quit" => {
                println!("Exiting...");
                std::process::exit(0);
            }
            _ => {
                println!("  Unknown command.");
                print_help(&my_id);
            }
        }
    }
}

async fn send_outbound(
    wh: &Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    cipher: &ChaCha20Poly1305,
    msg: &ControlMessage,
) -> anyhow::Result<()> {
    let json = serde_json::to_vec(msg)?;
    let ct = aead_encrypt(cipher, &json)?;
    let len = ct.len() as u32;
    let mut guard = wh.lock().await;
    guard.write_all(&len.to_be_bytes()).await?;
    guard.write_all(&ct).await?;
    Ok(())
}

fn print_help(id: &str) {
    println!("=== YuKKi OS {VERSION} Sentinel Mesh — node: {id} ===");
    println!("  fleet peers      — list connected peers");
    println!("  msg <to> <text>  — send FluidMessage (AEAD encrypted)");
    println!("  weave <data>     — announce polymorphic weave payload");
    println!("  exit             — shut down node");
}

// ---------------------------------------------------------------------------
// Hex encoding (no external dep for small blobs)
// ---------------------------------------------------------------------------

mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Usage:
    //   yukki_sentinel bootstrap [bind_addr]
    //   yukki_sentinel node      [bootstrap_addr]
    let role = args.get(1).map(|s| s.as_str()).unwrap_or("bootstrap");
    let node_id = format!("node-{}", Uuid::new_v4());

    match role {
        "bootstrap" => {
            let addr = args.get(2).map(|s| s.as_str()).unwrap_or("0.0.0.0:7660");
            if let Err(e) = run_bootstrap(addr, node_id).await {
                eprintln!("Bootstrap error: {e}");
                std::process::exit(1);
            }
        }
        "node" => {
            let addr = args
                .get(2)
                .map(|s| s.as_str())
                .unwrap_or("127.0.0.1:7660");
            if let Err(e) = run_node(addr, node_id).await {
                eprintln!("Node error: {e}");
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("Usage: yukki_sentinel <bootstrap|node> [addr]");
            std::process::exit(1);
        }
    }
}
