// YuKKi OS v6.4.2 — Interim-Crypt Edition
// Architect: Aditya Muralidhar (Rakshas International Unlimited)
// License: GPL-3.0

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_tungstenite::{accept_async, connect_async, tungstenite::Message};
use uuid::Uuid;

const VERSION: &str = "v6.4.2";
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
}

// ---------------------------------------------------------------------------
// ChaosController — FFI frame extraction wrapper
// ---------------------------------------------------------------------------

struct ChaosController;

impl ChaosController {
    fn init_default() {
        // Initialize with default Lorenz parameters using the reseed path
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
                    serde_json::to_string(&reg.values().collect::<Vec<_>>()).unwrap_or_default()
                };
                let _ = ws.send(Message::Text(snapshot)).await;
                println!(
                    "[C2] Peer {} registered from {}",
                    uuid,
                    peer_addr
                );
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
                                    let path =
                                        val.get("path").and_then(|p| p.as_str()).unwrap_or(".");
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
                                        "engine": "Lorenz-Weave-6D"
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
            let _ = tokio::fs::create_dir_all("./yukkios_transfers").await;
            let mut buf = [0u8; FRAME_SIZE];
            let mut frame_count = 0u64;
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                frame_count += 1;
                // Acknowledge with a simple counter response
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

    println!(
        "[CORE] Open-Source Host Activated | UUID: {}",
        self_uuid
    );

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
                    println!("[C2] Fleet registry synchronized. {} nodes online.", reg.len());
                }
            }
        }
    });

    // Interactive shell
    println!("[CORE] JSON Control Channel: 127.0.0.1:{}", p2p_port);
    println!("[CORE] Binary Tensor Channel: 127.0.0.1:{}", binary_port);

    let stdin = tokio::io::stdin();
    let mut reader = tokio::io::BufReader::new(stdin);
    let mut line = String::new();

    loop {
        print!("YuKKiOS_6.4 > ");
        use std::io::Write;
        let _ = std::io::stdout().flush();

        line.clear();
        use tokio::io::AsyncBufReadExt;
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
            "get" if parts.len() >= 4 => {
                let target_uuid = parts[1];
                let remote_path = parts[2];
                let local_path = parts[3];
                if let Some(peer) = find_peer(&registry, target_uuid).await {
                    pull_file(&peer, remote_path, local_path).await;
                }
            }
            "weave" if parts.len() >= 2 => {
                let target_uuid = parts[1];
                if let Some(peer) = find_peer(&registry, target_uuid).await {
                    run_weave_session(&peer).await;
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

async fn find_peer(
    registry: &Arc<Mutex<Vec<PeerInfo>>>,
    uuid: &str,
) -> Option<PeerInfo> {
    let reg = registry.lock().await;
    reg.iter().find(|p| p.uuid.starts_with(uuid)).cloned()
}

async fn send_p2p_msg(from_uuid: &str, peer: &PeerInfo, msg: &str) {
    if let Ok(mut stream) = TcpStream::connect(format!("127.0.0.1:{}", peer.p2p_port)).await {
        let payload = serde_json::json!({ "from": from_uuid, "msg": msg });
        let _ = stream.write_all(payload.to_string().as_bytes()).await;
    }
}

async fn request_manifest(peer: &PeerInfo) {
    if let Ok(mut stream) = TcpStream::connect(format!("127.0.0.1:{}", peer.p2p_port)).await {
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
    if let Ok(mut stream) = TcpStream::connect(format!("127.0.0.1:{}", peer.p2p_port)).await {
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

async fn pull_file(peer: &PeerInfo, remote_path: &str, local_path: &str) {
    if let Ok(mut stream) =
        TcpStream::connect(format!("127.0.0.1:{}", peer.binary_port)).await
    {
        let header = format!("GET {}\n", remote_path);
        let _ = stream.write_all(header.as_bytes()).await;
        let mut buf = vec![0u8; 65536];
        let mut total = 0usize;
        if let Ok(mut file) = tokio::fs::File::create(local_path).await {
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                let _ = file.write_all(&buf[..n]).await;
                total += n;
            }
        }
        println!("[P2P FILE] Transfer complete. {} bytes received.", total);
    }
}

async fn run_weave_session(peer: &PeerInfo) {
    if let Ok(mut stream) =
        TcpStream::connect(format!("127.0.0.1:{}", peer.binary_port)).await
    {
        println!("[STREAM] Launching 6D Weave session (Binary Mode)...");
        let seed_payload: [u8; 16] = [
            128, 64, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        for seq in 0u64..100 {
            let frame = ChaosController::next_frame(seq, Some(&seed_payload));
            let bytes = ChaosController::frame_to_bytes(&frame);
            if stream.write_all(&bytes).await.is_err() {
                break;
            }
            // Print frame info (read fields via copy to avoid unaligned access)
            let x = { let v: f64 = unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(frame.x)) }; v };
            let y = { let v: f64 = unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(frame.y)) }; v };
            let z = { let v: f64 = unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(frame.z)) }; v };
            let u = { let v: f64 = unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(frame.u)) }; v };
            let v_val = { let v: f64 = unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(frame.v)) }; v };
            let w = { let v: f64 = unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(frame.w)) }; v };
            let fluidity = { let v: f32 = unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(frame.fluidity)) }; v };
            println!(
                "[WEAVE BINARY] Frame #{} | Spatial: [{:.2}, {:.2}, {:.2}] Drift: [{:.2}, {:.2}, {:.2}] Fluidity: {:.4}",
                seq, x, y, z, u, v_val, w, fluidity
            );
            tokio::time::sleep(tokio::time::Duration::from_millis(15)).await;
        }
        println!("[STREAM] Toroidal weave sequence closed smoothly.");
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize Lorenz engine using the reseed path with default parameters
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
            println!("YuKKi OS {} — Interim-Crypt Edition", VERSION);
            println!("Usage:");
            println!("  yukkios_6_4_interim bootstrap [bind_addr]");
            println!("  yukkios_6_4_interim node <bootstrap_addr> <p2p_port>");
        }
    }

    Ok(())
}
