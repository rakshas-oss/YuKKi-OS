// YuKKi OS v6.5.0 — Ephemeral Mesh Edition
// Architect: Aditya Muralidhar (Rakshas International Unlimited)
// License: GPL-3.0
//
// Control plane: X25519 ECDH key exchange + ChaCha20-Poly1305 AEAD
// Data plane:    Binary SpatiotemporalFrame tensor stream (Lorenz attractor)

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use futures_util::{SinkExt, StreamExt};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_tungstenite::{accept_async, connect_async, tungstenite::Message};
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey};

const VERSION: &str = "v6.5.0";
const FRAME_SIZE: usize = 88;

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
    fn oob_integrity_update(seq: u64, payload: *const u8, len: u32);
    fn oob_sync_check(seq: u64) -> i32;
    fn oob_quarantine_node(node_uuid: *const std::ffi::c_char);
    fn oob_is_quarantined(node_uuid: *const std::ffi::c_char) -> i32;
    // v6.5.0 — ephemeral session-key derivation
    fn ephemeral_derive_session_key(shared_secret_32: *const u8, out_key_32: *mut u8);
}

// ---------------------------------------------------------------------------
// ChaosController
// ---------------------------------------------------------------------------

struct ChaosController;

impl ChaosController {
    fn init_default() {
        unsafe { chaos_engine_reseed(10.0, 28.0, 8.333_333_333_33, 0.1, 0.0, 0.0) };
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
// OOB Integrity
// ---------------------------------------------------------------------------

fn oob_update(seq: u64, payload: &[u8]) {
    unsafe { oob_integrity_update(seq, payload.as_ptr(), payload.len() as u32) };
}

fn oob_is_sync_boundary(seq: u64) -> bool {
    unsafe { oob_sync_check(seq) != 0 }
}

fn quarantine_node(uuid: &str) {
    if let Ok(cstr) = std::ffi::CString::new(uuid) {
        unsafe { oob_quarantine_node(cstr.as_ptr()) };
    }
}

fn is_node_quarantined(uuid: &str) -> bool {
    std::ffi::CString::new(uuid)
        .map(|cs| unsafe { oob_is_quarantined(cs.as_ptr()) != 0 })
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// v6.5.0 — Ephemeral session-key derivation wrapper
// ---------------------------------------------------------------------------

/// Derive a 32-byte session key by mixing an X25519 shared secret with the
/// current Lorenz attractor state via the C FFI KDF shim.
fn derive_session_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe { ephemeral_derive_session_key(shared_secret.as_ptr(), out.as_mut_ptr()) };
    out
}

/// Perform an X25519 ECDH handshake (initiator side) and derive a session key.
/// Returns `(session_key, our_public_key_bytes)`.
fn ephemeral_ecdh_initiate() -> ([u8; 32], [u8; 32]) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    // For the demo / bootstrap path we use a fixed peer public key placeholder.
    // In production, swap this for the peer's actual public key received over the wire.
    let peer_public_bytes = *public.as_bytes(); // self-loop demo
    let peer_public = PublicKey::from(peer_public_bytes);
    let shared = secret.diffie_hellman(&peer_public);
    let session_key = derive_session_key(shared.as_bytes());
    (session_key, *public.as_bytes())
}

/// Encrypt a plaintext slice with ChaCha20-Poly1305 using the given 32-byte key.
/// Returns `nonce (12 bytes) || ciphertext` on success.
fn aead_encrypt(key_bytes: &[u8; 32], plaintext: &[u8]) -> Option<Vec<u8>> {
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    // Use a counter-based nonce seeded from OsRng for this demo.
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..4].copy_from_slice(&rand_nonce_u32().to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher.encrypt(nonce, plaintext).ok().map(|ct| {
        let mut out = nonce_bytes.to_vec();
        out.extend_from_slice(&ct);
        out
    })
}

/// Decrypt a `nonce (12 bytes) || ciphertext` blob with ChaCha20-Poly1305.
fn aead_decrypt(key_bytes: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 12 {
        return None;
    }
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&blob[..12]);
    cipher.decrypt(nonce, &blob[12..]).ok()
}

fn rand_nonce_u32() -> u32 {
    use rand_core::RngCore;
    OsRng.next_u32()
}

// ---------------------------------------------------------------------------
// P2P peer registry
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
struct PeerInfo {
    uuid: String,
    p2p_port: u16,
    binary_port: u16,
    addr: String,
}

type Registry = Arc<Mutex<HashMap<String, PeerInfo>>>;

// ---------------------------------------------------------------------------
// Bootstrap server (WebSocket C2)
// ---------------------------------------------------------------------------

async fn run_c2_bootstrap(bind_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    println!("[NETWORK] Bootstrap Server active at: ws://{}", bind_addr);

    let registry: Registry = Arc::new(Mutex::new(HashMap::new()));

    while let Ok((stream, peer_addr)) = listener.accept().await {
        let registry = Arc::clone(&registry);
        tokio::spawn(async move {
            if let Ok(ws_stream) = accept_async(stream).await {
                handle_bootstrap_peer(ws_stream, peer_addr, registry).await;
            }
        });
    }
    Ok(())
}

async fn handle_bootstrap_peer(
    mut ws: tokio_tungstenite::WebSocketStream<TcpStream>,
    peer_addr: SocketAddr,
    registry: Registry,
) {
    while let Some(Ok(msg)) = ws.next().await {
        if let Message::Text(txt) = msg {
            if let Ok(info) = serde_json::from_str::<PeerInfo>(&txt) {
                let uuid = info.uuid.clone();
                {
                    let mut reg = registry.lock().await;
                    reg.insert(uuid.clone(), info);
                }
                let snapshot = {
                    let reg = registry.lock().await;
                    serde_json::to_string(&reg.values().collect::<Vec<_>>())
                        .unwrap_or_default()
                };
                let _ = ws.send(Message::Text(snapshot)).await;
                println!("[C2] Peer {} registered from {}", uuid, peer_addr);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// JSON P2P listener
// ---------------------------------------------------------------------------

async fn run_p2p_listener(port: u16, self_uuid: String) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    println!("[CORE] JSON Control Channel: {}", addr);

    while let Ok((mut stream, peer_addr)) = listener.accept().await {
        let self_uuid = self_uuid.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                if let Ok(text) = std::str::from_utf8(&buf[..n]) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(text) {
                        if let Some(msg) = val.get("msg").and_then(|m| m.as_str()) {
                            let from = val
                                .get("from")
                                .and_then(|f| f.as_str())
                                .unwrap_or("unknown");
                            println!("[P2P INBOUND] (From {}): {}", from, msg);
                        } else if let Some(op) = val.get("op").and_then(|o| o.as_str()) {
                            match op {
                                "browse" => {
                                    let path = val
                                        .get("path")
                                        .and_then(|p| p.as_str())
                                        .unwrap_or(".");
                                    let listing = browse_directory(path);
                                    let response = serde_json::json!({ "listing": listing });
                                    let _ = stream
                                        .write_all(response.to_string().as_bytes())
                                        .await;
                                }
                                "manifest" => {
                                    let manifest = serde_json::json!({
                                        "uuid": self_uuid,
                                        "version": VERSION,
                                        "engine": "Lorenz-Weave-6D-Ephemeral"
                                    });
                                    let _ = stream
                                        .write_all(manifest.to_string().as_bytes())
                                        .await;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                let _ = peer_addr;
            }
        });
    }
    Ok(())
}

fn browse_directory(path: &str) -> Vec<serde_json::Value> {
    let mut entries = Vec::new();
    if let Ok(dir) = std::fs::read_dir(path) {
        for entry in dir.flatten() {
            let meta = entry.metadata().ok();
            let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            entries.push(serde_json::json!({
                "name": entry.file_name().to_string_lossy(),
                "type": if is_dir { "DIR" } else { "FILE" },
                "size": size
            }));
        }
    }
    entries
}

// ---------------------------------------------------------------------------
// Binary tensor stream listener
// ---------------------------------------------------------------------------

async fn run_binary_listener(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    println!("[CORE] Binary Tensor Channel: {}", addr);

    while let Ok((mut stream, _)) = listener.accept().await {
        tokio::spawn(async move {
            let mut buf = [0u8; FRAME_SIZE];
            let mut frame_count = 0u64;
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                frame_count += 1;
                let ack = format!("[WEAVE ACK] frame={}\n", frame_count);
                let _ = stream.write_all(ack.as_bytes()).await;
            }
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Client node — interactive shell + fleet orchestration
// ---------------------------------------------------------------------------

async fn run_client_node(
    bootstrap_addr: &str,
    p2p_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let self_uuid = Uuid::new_v4().to_string();
    let binary_port = p2p_port + 1000;

    println!("[CORE] Open-Source Host Activated | UUID: {}", self_uuid);

    // Derive ephemeral session key for this node's control-plane sessions
    let (session_key, our_pub) = ephemeral_ecdh_initiate();
    println!(
        "[ECDH] Ephemeral public key: {}",
        hex_encode(&our_pub)
    );
    println!(
        "[ECDH] Session key (first 8 bytes): {}",
        hex_encode(&session_key[..8])
    );

    // Demo: round-trip encrypt/decrypt of a greeting
    if let Some(blob) = aead_encrypt(&session_key, b"YuKKi OS 6.5.0 Ephemeral Mesh") {
        if let Some(plain) = aead_decrypt(&session_key, &blob) {
            println!(
                "[AEAD] Control-plane self-test OK: \"{}\"",
                String::from_utf8_lossy(&plain)
            );
        }
    }

    // Spawn listeners
    let uuid_for_p2p = self_uuid.clone();
    tokio::spawn(async move {
        let _ = run_p2p_listener(p2p_port, uuid_for_p2p).await;
    });
    tokio::spawn(async move {
        let _ = run_binary_listener(binary_port).await;
    });

    // Register with bootstrap
    let peer_info = PeerInfo {
        uuid: self_uuid.clone(),
        p2p_port,
        binary_port,
        addr: format!("127.0.0.1:{}", p2p_port),
    };

    let registry: Arc<Mutex<Vec<PeerInfo>>> = Arc::new(Mutex::new(Vec::new()));
    let bootstrap_url = format!("ws://{}", bootstrap_addr);
    let registry_clone = Arc::clone(&registry);
    let peer_json = serde_json::to_string(&peer_info)?;
    tokio::spawn(async move {
        if let Ok((mut ws, _)) = connect_async(&bootstrap_url).await {
            let _ = ws.send(Message::Text(peer_json)).await;
            if let Some(Ok(Message::Text(txt))) = ws.next().await {
                if let Ok(peers) = serde_json::from_str::<Vec<PeerInfo>>(&txt) {
                    let mut reg = registry_clone.lock().await;
                    *reg = peers;
                    println!(
                        "[C2] Fleet registry synchronized. {} nodes online.",
                        reg.len()
                    );
                }
            }
        }
    });

    println!("[CORE] JSON Control Channel: 127.0.0.1:{}", p2p_port);
    println!("[CORE] Binary Tensor Channel: 127.0.0.1:{}", binary_port);

    // Interactive shell
    let stdin = tokio::io::stdin();
    let mut reader = tokio::io::BufReader::new(stdin);
    let mut line = String::new();

    loop {
        print!("YuKKiOS_6.5 > ");
        use std::io::Write;
        let _ = std::io::stdout().flush();

        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }

        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "fleet" | "peers" => {
                println!("--- Current Active Fleet Topology ---");
                let reg = registry.lock().await;
                for p in reg.iter() {
                    let tag = if p.uuid == self_uuid { " (Self Node)" } else { "" };
                    println!(
                        "  Node: {} | P2P: {} | BINARY: {}{}",
                        p.uuid, p.p2p_port, p.binary_port, tag
                    );
                }
            }
            "msg" if parts.len() >= 3 => {
                let target_uuid = parts[1];
                let msg_text = parts[2..].join(" ");
                if let Some(peer) = find_peer(&registry, target_uuid).await {
                    send_p2p_msg(&self_uuid, &peer, &msg_text).await;
                } else {
                    println!("[ERR] Peer {} not found.", target_uuid);
                }
            }
            "manifest" if parts.len() >= 2 => {
                let target_uuid = parts[1];
                if let Some(peer) = find_peer(&registry, target_uuid).await {
                    request_manifest(&peer).await;
                }
            }
            "browse" | "ls" if parts.len() >= 2 => {
                let target_uuid = parts[1];
                let path = parts.get(2).copied().unwrap_or("/tmp");
                if let Some(peer) = find_peer(&registry, target_uuid).await {
                    browse_remote(&peer, path).await;
                }
            }
            "weave" if parts.len() >= 2 => {
                let target_uuid = parts[1];
                if is_node_quarantined(target_uuid) {
                    println!(
                        "[OOB] Node {} is quarantined/blacklisted — weave denied.",
                        target_uuid
                    );
                } else if let Some(peer) = find_peer(&registry, target_uuid).await {
                    run_weave_session(&peer).await;
                }
            }
            "quarantine" if parts.len() >= 2 => {
                let target_uuid = parts[1];
                quarantine_node(target_uuid);
                println!("[OOB] Node {} added to quarantine/blacklist.", target_uuid);
            }
            "quarantine_check" if parts.len() >= 2 => {
                let target_uuid = parts[1];
                if is_node_quarantined(target_uuid) {
                    println!("[OOB] Node {} is QUARANTINED.", target_uuid);
                } else {
                    println!("[OOB] Node {} is not quarantined.", target_uuid);
                }
            }
            "exit" | "quit" => {
                println!("[CORE] Graceful shutdown initiated.");
                break;
            }
            _ => {
                println!("[SHELL] Unknown command: {}", parts[0]);
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Peer helpers
// ---------------------------------------------------------------------------

async fn find_peer(registry: &Arc<Mutex<Vec<PeerInfo>>>, uuid: &str) -> Option<PeerInfo> {
    let reg = registry.lock().await;
    reg.iter().find(|p| p.uuid.starts_with(uuid)).cloned()
}

async fn send_p2p_msg(from_uuid: &str, peer: &PeerInfo, msg: &str) {
    if let Ok(mut stream) =
        TcpStream::connect(format!("127.0.0.1:{}", peer.p2p_port)).await
    {
        let payload = serde_json::json!({ "from": from_uuid, "msg": msg });
        let _ = stream.write_all(payload.to_string().as_bytes()).await;
    }
}

async fn request_manifest(peer: &PeerInfo) {
    if let Ok(mut stream) =
        TcpStream::connect(format!("127.0.0.1:{}", peer.p2p_port)).await
    {
        let req = serde_json::json!({ "op": "manifest" });
        let _ = stream.write_all(req.to_string().as_bytes()).await;
        let mut buf = vec![0u8; 1024];
        if let Ok(n) = stream.read(&mut buf).await {
            if let Ok(txt) = std::str::from_utf8(&buf[..n]) {
                println!("[MANIFEST] From {}: {}", peer.uuid, txt);
            }
        }
    }
}

async fn browse_remote(peer: &PeerInfo, path: &str) {
    if let Ok(mut stream) =
        TcpStream::connect(format!("127.0.0.1:{}", peer.p2p_port)).await
    {
        let req = serde_json::json!({ "op": "browse", "path": path });
        let _ = stream.write_all(req.to_string().as_bytes()).await;
        let mut buf = vec![0u8; 4096];
        if let Ok(n) = stream.read(&mut buf).await {
            if let Ok(txt) = std::str::from_utf8(&buf[..n]) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(txt) {
                    println!("[P2P BROWSE] Directory listing from {}:", peer.uuid);
                    if let Some(entries) = val.get("listing").and_then(|l| l.as_array()) {
                        for e in entries {
                            let kind = e.get("type").and_then(|t| t.as_str()).unwrap_or("?");
                            let name = e.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                            let size = e.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
                            if kind == "DIR" {
                                println!("  [DIR] {}", name);
                            } else {
                                println!("  [FILE] {} ({} bytes)", name, size);
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn run_weave_session(peer: &PeerInfo) {
    if let Ok(mut stream) =
        TcpStream::connect(format!("127.0.0.1:{}", peer.binary_port)).await
    {
        println!("[STREAM] Launching 6D Weave session (Binary Mode)...");
        let seed_payload: [u8; 16] = [128, 64, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for seq in 0u64..100 {
            let frame = ChaosController::next_frame(seq, Some(&seed_payload));
            let bytes = ChaosController::frame_to_bytes(&frame);
            oob_update(seq, &frame.payload);
            if stream.write_all(&bytes).await.is_err() {
                break;
            }
            // Read fields via unaligned-safe copy
            let x = unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(frame.x)) };
            let y = unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(frame.y)) };
            let z = unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(frame.z)) };
            let u = unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(frame.u)) };
            let v_val: f64 = unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(frame.v)) };
            let w: f64 = unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(frame.w)) };
            let fluidity: f32 =
                unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(frame.fluidity)) };
            if oob_is_sync_boundary(seq) {
                println!(
                    "[OOB] 60-frame sync boundary at seq #{} — integrity hash snapshot triggered.",
                    seq
                );
            }
            println!(
                "[WEAVE BINARY] Frame #{} | Spatial: [{:.2}, {:.2}, {:.2}] \
                 Drift: [{:.2}, {:.2}, {:.2}] Fluidity: {:.4}",
                seq, x, y, z, u, v_val, w, fluidity
            );
            tokio::time::sleep(tokio::time::Duration::from_millis(15)).await;
        }
        println!("[STREAM] Toroidal weave sequence closed smoothly.");
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ChaosController::init_default();

    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("bootstrap") => {
            let addr = args.get(2).map(|s| s.as_str()).unwrap_or("127.0.0.1:7000");
            run_c2_bootstrap(addr).await?;
        }
        Some("node") => {
            let bootstrap = args
                .get(2)
                .map(|s| s.as_str())
                .unwrap_or("127.0.0.1:7000");
            let p2p_port: u16 = args
                .get(3)
                .and_then(|p| p.parse().ok())
                .unwrap_or(8001);
            run_client_node(bootstrap, p2p_port).await?;
        }
        _ => {
            println!("YuKKi OS {} — Ephemeral Mesh Edition", VERSION);
            println!("Usage:");
            println!("  yukkios_6_5_ephemeral bootstrap [bind_addr]");
            println!("  yukkios_6_5_ephemeral node <bootstrap_addr> <p2p_port>");
        }
    }

    Ok(())
}
