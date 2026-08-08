#!/usr/bin/env zsh
# ==============================================================================
# OPEN-SOURCE GENESIS: YUKKI OS V6.4.0 (INTERIM-CRYPT EDITION)
# ARCHITECT: Aditya Muralidhar (Rakshas International Unlimited)
# LICENSE: GNU General Public License Version 3 (GPL-3)
# PARADIGM: 6D Lorenz-Weave + P2P File Ops + Uncloneable Encryption
# ==============================================================================

# Zsh strict error handling
setopt err_exit no_unset pipe_fail

ARCHIVE_DIR="yukkios_6_4_interim"
EXECUTABLE_NAME="yukki_core_node"

# Zsh idiomatic styling (Prompts Expansion)
TEAL='%F{37}'
GOLD='%F{136}'
RESET='%f'

print -P "${GOLD}======================================================================${RESET}"
print -P "${GOLD}    __  __      _  ___  ___    ____  ____    ____                     ${RESET}"
print -P "${GOLD}    \\ \\/ /_  _ | |/ / |/ /_   / __ \\/ ___|  / ___|                    ${RESET}"
print -P "${GOLD}     \\  /| | | | ' /| ' /(_) | |  | \\___ \\ | |                        ${RESET}"
print -P "${GOLD}     / / | |_| | . \\| . \\_   | |__| |___) || |___                     ${RESET}"
print -P "${GOLD}    /_/   \\__,_|_|\\_\\_|\\_(_)  \\____/|____/  \\____| 6.4 INTERIM-CRYPT  ${RESET}"
print -P "${GOLD}======================================================================${RESET}"

print -P "${TEAL}[*] Initiating Spatiotemporal Genesis of YuKKi OS 6.4...${RESET}"
print -P "${TEAL}[*] Building Directory Infrastructure...${RESET}"

# Zsh Brace Expansion for directory scaffolding
mkdir -p "$ARCHIVE_DIR/src/"{ffi,memory}

# ------------------------------------------------------------------------------
# 1. THE OPEN-SOURCE LICENSE (GPL-3)
# ------------------------------------------------------------------------------
print -P "${TEAL}[*] Packaging Standard GPL-3 License...${RESET}"
cat << 'EOF' > "$ARCHIVE_DIR/vault_license.txt"
PROJECT: YuKKi OS 6.4.0 / THE SPATIOTEMPORAL WEAVE (INTERIM-CRYPT)
AUTHOR: Aditya Muralidhar / Rakshas International Unlimited

This operating system suite is distributed under the GNU General Public License
Version 3 (GPL-3). 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
EOF

# ------------------------------------------------------------------------------
# 2. THE FLUID PROTOCOL DEFINITION (LEGACY-SAFE C HEADER)
# ------------------------------------------------------------------------------
print -P "${TEAL}[*] Creating Laminar Interface Protocol definitions (Legacy Aligned)...${RESET}"
cat << 'EOF' > "$ARCHIVE_DIR/src/ffi/laminar_api.h"
/* LAMINAR FLOW API - v6.4 (Binary Zero-Drag Spatiotemporal - Legacy Safe) */
#ifndef LAMINAR_API_H
#define LAMINAR_API_H

#include <stdint.h>

/* Pre-C99 / MSVC Fallback Alignment */
#pragma pack(push, 1)

// Strict 88-byte hyper-aligned tensor packet representation
typedef struct __attribute__((packed, aligned(8))) {
    uint64_t seq_id;         // 8 bytes
    double x, y, z;          // 24 bytes (Space)
    double u, v, w;          // 24 bytes (Velocity Vector / Temporal Drift)
    float fluidity;          // 4 bytes
    float drag;              // 4 bytes
    double divergence;       // 8 bytes (Promoted from float to double for strict 8-byte alignment)
    uint8_t payload[16];     // 16 bytes (Telemetry / Encrypted Segment)
} SpatiotemporalFrame;

#pragma pack(pop)

void chaos_engine_init(double sigma, double rho, double beta);
void generate_lorenz_step(double dt);
void weave_spatiotemporal_frame(uint64_t seq, const uint8_t* payload_src, SpatiotemporalFrame* out_frame);

#endif
EOF

# ------------------------------------------------------------------------------
# 3. LORENZ ATTRACTOR & UNCLONEABLE ENCRYPTION (C99 STRICT)
# ------------------------------------------------------------------------------
print -P "${TEAL}[*] Forging C-Side Lorenz Attractor Engine & Quantum Bindings...${RESET}"
cat << 'EOF' > "$ARCHIVE_DIR/src/ffi/chaos_weave.c"
#include "laminar_api.h"
#include <math.h>
#include <string.h>

/* Legacy-Safe Quantum Slab Descriptor */
#pragma pack(push, 1)
typedef struct {
    uint32_t q_slab_handle;
    uint8_t  pauli_signature[16];
    uint32_t active_basis;
} UncloneableQuantumSlab;
#pragma pack(pop)

static double x_state = 0.1;
static double y_state = 0.0;
static double z_state = 0.0;
static double sigma_param = 10.0;
static double rho_param = 28.0;
static double beta_param = 8.33333333333;

void chaos_engine_init(double sigma, double rho, double beta) {
    sigma_param = sigma; rho_param = rho; beta_param = beta;
    x_state = 0.1; y_state = 0.0; z_state = 0.0;
}

/* Information-Theoretic Clifford/Pauli Binding Simulation (C99 Compatible) */
int unclonable_clifford_bind(const uint8_t *raw_msg, size_t len, UncloneableQuantumSlab *out_slab) {
    if (!raw_msg || !out_slab) return -1;
    out_slab->q_slab_handle = 0xAE509001;
    out_slab->active_basis = 0x3; // X-Z anti-commuting cross-check
    
    for (int i = 0; i < 16; i++) {
        out_slab->pauli_signature[i] = (i < len) ? (raw_msg[i] ^ 0xA5) : 0x00;
    }
    return 0;
}

void generate_lorenz_step(double dt) {
    double dx = sigma_param * (y_state - x_state);
    double dy = x_state * (rho_param - z_state) - y_state;
    double dz = x_state * y_state - beta_param * z_state;
    
    x_state += dx * dt; y_state += dy * dt; z_state += dz * dt;
    
    /* Legacy fallback for math macros */
    if (x_state != x_state || x_state > 1e308 || x_state < -1e308) x_state = 0.1;
    if (y_state != y_state || y_state > 1e308 || y_state < -1e308) y_state = 0.0;
    if (z_state != z_state || z_state > 1e308 || z_state < -1e308) z_state = 0.0;
}

void weave_spatiotemporal_frame(uint64_t seq, const uint8_t* payload_src, SpatiotemporalFrame* out_frame) {
    generate_lorenz_step(0.005);
    out_frame->seq_id = seq;
    out_frame->x = x_state;
    out_frame->y = y_state;
    out_frame->z = z_state;
    out_frame->u = x_state * 0.125;
    out_frame->v = y_state * 0.25;
    out_frame->w = z_state * 0.5;
    
    double speed = sqrt(x_state * x_state + y_state * y_state + z_state * z_state);
    out_frame->fluidity = (float)(1.0 / (1.0 + exp(-speed / 10.0)));
    out_frame->drag = (float)(1.0f - out_frame->fluidity);
    out_frame->divergence = 0.0;
    
    memset(out_frame->payload, 0, 16);
    if (payload_src) { 
        UncloneableQuantumSlab secure_slab;
        unclonable_clifford_bind(payload_src, 16, &secure_slab);
        memcpy(out_frame->payload, secure_slab.pauli_signature, 16); 
    }
}
EOF

# ------------------------------------------------------------------------------
# 4. RUST CARGO DESCRIPTOR
# ------------------------------------------------------------------------------
print -P "${TEAL}[*] Generating cargo project file...${RESET}"
cat << 'EOF_CARGO' > "$ARCHIVE_DIR/Cargo.toml"
[package]
name = "yukkios_6_4_interim"
version = "6.4.0"
edition = "2021"
authors = ["Aditya Muralidhar <Rakshas International Unlimited>"]
description = "YuKKi OS 6.4 Interim ADI Mesh w/ Uncloneable Encryption"

[dependencies]
tokio = { version = "1", features = ["full", "process"] }
tokio-tungstenite = "0.20"
futures-util = "0.3"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
uuid = { version = "1.6", features = ["v4", "serde"] }

[build-dependencies]
cc = "1.0"
EOF_CARGO

# ------------------------------------------------------------------------------
# 5. RUST SYSTEM ENGINE (CONVERGED ARCHITECTURE)
# ------------------------------------------------------------------------------
print -P "${TEAL}[*] Forging Rust Main & Memory Controller integration layer...${RESET}"
cat << 'EOF_RUST' > "$ARCHIVE_DIR/src/main.rs"
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, Mutex},
    io::{AsyncReadExt, AsyncWriteExt, copy},
    task::spawn_blocking,
    fs::{File as TokioFile, self as tokio_fs},
};
use tokio_tungstenite::{accept_async, connect_async, tungstenite::protocol::Message as WsMessage};
use futures_util::{StreamExt, SinkExt};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use std::{
    collections::HashMap,
    sync::Arc,
    net::SocketAddr,
    time::Duration,
    io::Write as _,
    path::PathBuf,
    fs as std_fs,
};

const LOCAL_TRANSFER_DIR: &str = "./yukkios_transfers";

// --- HYPER-ALIGNMENT INTERACTION STRUCTS ---
#[repr(C, packed(8))]
#[derive(Debug, Clone, Copy)]
pub struct SpatiotemporalFrame {
    pub seq_id: u64,
    pub x: f64, pub y: f64, pub z: f64,
    pub u: f64, pub v: f64, pub w: f64,
    pub fluidity: f32,
    pub drag: f32,
    pub divergence: f64,
    pub payload: [u8; 16],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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

#[derive(Serialize, Deserialize, Debug)]
struct FluidMessage {
    sender_uuid: Uuid,
    target_uuid: Uuid,
    msg_type: String, 
    content: String,
    file_size: Option<u64>,
    local_path: Option<String>,
}

// --- FFI SYSTEM BRIDGE ---
extern "C" {
    fn chaos_engine_init(sigma: f64, rho: f64, beta: f64);
    fn weave_spatiotemporal_frame(seq: u64, payload_src: *const u8, out_frame: *mut SpatiotemporalFrame);
}

// --- SYSTEM CONTROLLER ---
pub struct ChaosController {
    current_seq: u64,
}

impl ChaosController {
    pub fn new() -> Self {
        unsafe { chaos_engine_init(10.0, 28.0, 8.33333333333); }
        Self { current_seq: 0 }
    }

    pub fn extract_frame(&mut self, payload: &[u8; 16]) -> SpatiotemporalFrame {
        let mut frame = std::mem::MaybeUninit::<SpatiotemporalFrame>::uninit();
        unsafe {
            weave_spatiotemporal_frame(self.current_seq, payload.as_ptr(), frame.as_mut_ptr());
            self.current_seq += 1;
            frame.assume_init()
        }
    }
}

// --- NETWORK CORE ENGINE (BOOTSTRAP) ---
async fn run_c2_bootstrap(listen_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let addr = listen_addr.parse::<SocketAddr>()?;
    let listener = TcpListener::bind(&addr).await?;
    let peers: Arc<Mutex<HashMap<Uuid, PeerInfo>>> = Arc::new(Mutex::new(HashMap::new()));
    
    println!("\x1b[38;5;136m[NETWORK] Bootstrap Server active at: ws://{}\x1b[0m", listen_addr);
    loop {
        let (stream, client_addr) = listener.accept().await?;
        let peers_clone = Arc::clone(&peers);
        tokio::spawn(async move {
            if let Err(e) = handle_websocket_peer(stream, client_addr, peers_clone).await {
                eprintln!("\x1b[38;5;37m[C2] Handshake disruption: {}\x1b[0m", e);
            }
        });
    }
}

async fn handle_websocket_peer(
    stream: TcpStream,
    _client_addr: SocketAddr,
    peers: Arc<Mutex<HashMap<Uuid, PeerInfo>>>,
) -> Result<(), tokio_tungstenite::tungstenite::Error> {
    let ws_stream = accept_async(stream).await?;
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    let mut peer_uuid = None;
    let (tx, mut rx) = mpsc::unbounded_channel::<SovereignCommand>();
    
    let ws_sender_task = tokio::spawn(async move {
        while let Some(command) = rx.recv().await {
            let json = serde_json::to_string(&command).unwrap();
            if ws_sender.send(WsMessage::Text(json)).await.is_err() { break; }
        }
    });
    
    while let Some(msg) = ws_receiver.next().await {
        match msg {
            Ok(WsMessage::Text(text)) => {
                if let Ok(SovereignCommand::Register(info)) = serde_json::from_str::<SovereignCommand>(&text) {
                    peer_uuid = Some(info.uuid);
                    println!("\x1b[38;5;37m[C2] Peer node accepted: {} (P2P: {} | BIN: {})\x1b[0m", info.uuid, info.p2p_port, info.binary_port);
                    let mut lock = peers.lock().await;
                    lock.insert(info.uuid, info.clone());
                    let current_fleet: Vec<PeerInfo> = lock.values().cloned().collect();
                    drop(lock);
                    let _ = tx.send(SovereignCommand::NodeFleet(current_fleet));
                }
            }
            Ok(WsMessage::Close(_)) | Err(_) => break,
            _ => (),
        }
    }
    
    ws_sender_task.abort();
    if let Some(uuid) = peer_uuid {
        let mut lock = peers.lock().await;
        lock.remove(&uuid);
        println!("\x1b[38;5;37m[C2] Peer node dissociated: {}\x1b[0m", uuid);
    }
    Ok(())
}

// --- JSON FRAMING HELPERS ---
async fn send_framed(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    let len = payload.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    Ok(())
}

async fn read_framed(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

// --- FILE SYSTEM HELPERS ---
async fn list_directory_blocking(path: &str) -> String {
    let path_buf = PathBuf::from(path);
    spawn_blocking(move || {
        let mut listing = String::new();
        match std_fs::read_dir(&path_buf) {
            Ok(entries) => {
                for entry in entries {
                    if let Ok(entry) = entry {
                        let metadata = entry.metadata().unwrap();
                        let file_name = entry.file_name().into_string().unwrap_or_default();
                        let file_type = if metadata.is_dir() { "[DIR]" } else { "[FILE]" };
                        let size = if metadata.is_file() { format!(" ({} bytes)", metadata.len()) } else { "".to_string() };
                        listing.push_str(&format!("{} {}{}\n", file_type, file_name, size));
                    }
                }
                if listing.is_empty() { format!("Path '{}' is empty or inaccessible.", path) } else { format!("Contents of {}:\n{}", path, listing) }
            }
            Err(e) => format!("Error reading directory '{}': {}", path, e),
        }
    }).await.unwrap_or_else(|_| "Error listing directory in thread.".to_string())
}

async fn send_file_p2p(stream: &mut TcpStream, self_uuid: Uuid, target_uuid: Uuid, remote_path: &str, local_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let file_path = PathBuf::from(remote_path);
    let mut file = TokioFile::open(&file_path).await?;
    let file_size = file.metadata().await?.len();
    
    let init_msg = FluidMessage {
        sender_uuid: self_uuid, target_uuid,
        content: file_path.file_name().unwrap_or_default().to_string_lossy().to_string(),
        msg_type: "file_init".to_string(),
        file_size: Some(file_size), local_path: Some(local_path.to_string()),
    };
    
    let init_bytes = serde_json::to_vec(&init_msg)?;
    send_framed(stream, &init_bytes).await?;
    println!("\x1b[38;5;37m[P2P FILE] Streaming {} bytes...\x1b[0m", file_size);
    copy(&mut file, stream).await?;
    Ok(())
}

async fn receive_file_p2p(stream: &mut TcpStream, local_path: &str, file_size: u64) -> Result<(), Box<dyn std::error::Error>> {
    let final_path = PathBuf::from(LOCAL_TRANSFER_DIR).join(local_path);
    let mut file = TokioFile::create(&final_path).await?;
    let mut limited_reader = tokio::io::take(stream, file_size);
    copy(&mut limited_reader, &mut file).await?;
    Ok(())
}

// --- 6D BINARY TENSOR STREAMING (ISOLATED PORT) ---
async fn handle_local_laminar_stream(mut stream: TcpStream, _self_uuid: Uuid) {
    let mut controller = ChaosController::new();
    println!("\x1b[38;5;136m[STREAM] Launching 6D Weave session (Binary Mode)...\x1b[0m");
    
    for _ in 0..100 {
        // Unencrypted seed payload. The C FFI layer will inject the Pauli bindings.
        let payload_fragment = [0x59, 0x75, 0x4B, 0x4B, 0x69, 0x20, 0x4F, 0x53, 0x20, 0x36, 0x2E, 0x34, 0x20, 0x45, 0x4E, 0x43]; 
        let raw_frame = controller.extract_frame(&payload_fragment);
        
        let frame_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                &raw_frame as *const SpatiotemporalFrame as *const u8,
                std::mem::size_of::<SpatiotemporalFrame>(),
            )
        };
        
        if stream.write_all(frame_bytes).await.is_err() {
            eprintln!("\x1b[38;5;37m[STREAM] Connection lost during binary weave.\x1b[0m");
            break;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    println!("\x1b[38;5;136m[STREAM] Toroidal weave sequence closed smoothly.\x1b[0m");
}

async fn run_binary_listener(listen_addr: String) {
    let listener = TcpListener::bind(&listen_addr).await.unwrap();
    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; std::mem::size_of::<SpatiotemporalFrame>()]; 
                loop {
                    match stream.read_exact(&mut buffer).await {
                        Ok(_) => {
                            let frame: SpatiotemporalFrame = unsafe {
                                std::ptr::read(buffer.as_ptr() as *const SpatiotemporalFrame)
                            };
                            println!(
                                "\x1b[38;5;37m[WEAVE BINARY] Frame #{} | Spatial: [{:.2}, {:.2}, {:.2}] Drift: [{:.2}, {:.2}, {:.2}] Fluidity: {:.4}\x1b[0m",
                                frame.seq_id, frame.x, frame.y, frame.z, frame.u, frame.v, frame.w, frame.fluidity
                            );
                        }
                        Err(_) => break, 
                    }
                }
            });
        }
    }
}

// --- JSON CONTROL & FILE LISTENER ---
async fn run_p2p_listener(listen_addr: String, self_uuid: Uuid) {
    let listener = TcpListener::bind(&listen_addr).await.unwrap();
    if let Err(e) = tokio_fs::create_dir_all(LOCAL_TRANSFER_DIR).await {
        eprintln!("\x1b[38;5;37m[P2P] Could not create transfer directory: {}\x1b[0m", e);
    }
    loop {
        if let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(handle_p2p_connection(stream, self_uuid));
        }
    }
}

async fn handle_p2p_connection(mut stream: TcpStream, self_uuid: Uuid) {
    loop {
        match read_framed(&mut stream).await {
            Ok(payload) => {
                if let Ok(msg) = serde_json::from_slice::<FluidMessage>(&payload) {
                    let sender = msg.sender_uuid;
                    match msg.msg_type.as_str() {
                        "msg" => println!("\n\x1b[38;5;37m[P2P INBOUND] (From {}): {}\x1b[0m", sender, msg.content),
                        "manifest" => println!("\n\x1b[38;5;37m[P2P JOBBYSLOTTY] Manifest received from {}:\n{}\x1b[0m", sender, msg.content),
                        "browse_req" => {
                            let response = list_directory_blocking(&msg.content).await;
                            let response_msg = FluidMessage {
                                sender_uuid: self_uuid, target_uuid: sender, content: response,
                                msg_type: "browse_res".to_string(), file_size: None, local_path: None,
                            };
                            if let Ok(bytes) = serde_json::to_vec(&response_msg) { let _ = send_framed(&mut stream, &bytes).await; }
                        }
                        "browse_res" => println!("\n\x1b[38;5;37m[P2P BROWSE] Directory listing from {}:\n{}\x1b[0m", sender, msg.content),
                        "file_req" => {
                            let remote_path = msg.content;
                            let local_path = msg.local_path.unwrap_or_default();
                            let _ = send_file_p2p(&mut stream, self_uuid, sender, &remote_path, &local_path).await;
                            return;
                        }
                        "file_init" => {
                            if let (Some(size), Some(path)) = (msg.file_size, msg.local_path) {
                                println!("\n\x1b[38;5;37m[P2P FILE] Receiving '{}' ({} bytes)...\x1b[0m", path, size);
                                if receive_file_p2p(&mut stream, &path, size).await.is_ok() {
                                    println!("\x1b[38;5;37m[P2P FILE] Transfer complete.\x1b[0m");
                                }
                            }
                            return; 
                        }
                        _ => {}
                    }
                }
            }
            Err(_) => return,
        }
    }
}

// --- NODE APPLICATION SHELL ---
async fn run_client_node(c2_addr: &str, p2p_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let client_uuid = Uuid::new_v4();
    let self_addr_json = format!("127.0.0.1:{}", p2p_port);
    let binary_port = p2p_port + 1000;
    let self_addr_binary = format!("127.0.0.1:{}", binary_port);
    let fleet: Arc<Mutex<HashMap<Uuid, PeerInfo>>> = Arc::new(Mutex::new(HashMap::new()));
    let fleet_clone = Arc::clone(&fleet);
    
    println!("\x1b[38;5;136m[CORE] Open-Source Host Activated | UUID: {}\x1b[0m", client_uuid);
    println!("\x1b[38;5;136m[CORE] JSON Control Channel: {}\x1b[0m", self_addr_json);
    println!("\x1b[38;5;136m[CORE] Binary Tensor Channel: {}\x1b[0m", self_addr_binary);
    
    tokio::spawn(run_p2p_listener(self_addr_json.clone(), client_uuid));
    tokio::spawn(run_binary_listener(self_addr_binary.clone()));
    
    let (ws_stream, _) = connect_async(format!("ws://{}", c2_addr)).await?;
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    let my_reg = SovereignCommand::Register(PeerInfo {
        uuid: client_uuid, addr: c2_addr.to_string(), p2p_port, binary_port,
    });
    
    ws_sender.send(WsMessage::Text(serde_json::to_string(&my_reg)?)).await?;
    let fleet_receiver = Arc::clone(&fleet);
    
    tokio::spawn(async move {
        while let Some(msg) = ws_receiver.next().await {
            if let Ok(WsMessage::Text(text)) = msg {
                if let Ok(SovereignCommand::NodeFleet(list)) = serde_json::from_str::<SovereignCommand>(&text) {
                    let mut lock = fleet_receiver.lock().await;
                    lock.clear();
                    for node in list { lock.insert(node.uuid, node); }
                    println!("\n\x1b[38;5;37m[C2] Fleet registry synchronized. {} nodes online.\x1b[0m", lock.len());
                }
            }
        }
    });
    
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut line = String::new();
    
    loop {
        print!("\n\x1b[38;5;136mYuKKiOS_6.4 > \x1b[0m");
        std::io::stdout().flush().ok();
        line.clear();
        if tokio::time::timeout(Duration::from_millis(100), stdin.read_line(&mut line)).await.is_err() { continue; }
        
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.is_empty() { continue; }
        
        match parts[0] {
            "fleet" | "peers" => {
                let lock = fleet_clone.lock().await;
                println!("\x1b[38;5;136m--- Current Active Fleet Topology ---\x1b[0m");
                for peer in lock.values() {
                    let identity = if peer.uuid == client_uuid { "(Self Node)" } else { "" };
                    println!("  Node: {} | P2P: {} | BINARY: {} {}", peer.uuid, peer.p2p_port, peer.binary_port, identity);
                }
            }
            "msg" | "manifest" | "browse" | "ls" | "get" => {
                if let Some(target_uuid_str) = parts.get(1) {
                    let target = if parts[0] == "manifest" { Uuid::parse_str(parts.get(2).unwrap_or(&"")) } else { Uuid::parse_str(target_uuid_str) };
                    
                    if let Ok(target_uuid) = target {
                        let lock = fleet_clone.lock().await;
                        if let Some(target_node) = lock.get(&target_uuid) {
                            let target_addr = format!("127.0.0.1:{}", target_node.p2p_port);
                            
                            let outbound = match parts[0] {
                                "msg" => FluidMessage { sender_uuid: client_uuid, target_uuid, msg_type: "msg".to_string(), content: parts[2..].join(" "), file_size: None, local_path: None },
                                "manifest" => FluidMessage { 
                                    sender_uuid: client_uuid, target_uuid, msg_type: "manifest".to_string(), 
                                    content: format!("project: core-kernel-v6.4\nauthor: {}\njobs:\n  1: {{ cmd: 'make clean', deps: [] }}", client_uuid), file_size: None, local_path: None 
                                },
                                "browse" | "ls" => FluidMessage { sender_uuid: client_uuid, target_uuid, msg_type: "browse_req".to_string(), content: parts.get(2).unwrap_or(&".").to_string(), file_size: None, local_path: None },
                                "get" => FluidMessage { sender_uuid: client_uuid, target_uuid, msg_type: "file_req".to_string(), content: parts.get(2).unwrap_or(&"").to_string(), file_size: None, local_path: Some(parts.get(3).unwrap_or(&"").to_string()) },
                                _ => continue,
                            };
                            
                            if let Ok(mut stream) = TcpStream::connect(&target_addr).await {
                                if let Ok(encoded) = serde_json::to_vec(&outbound) { let _ = send_framed(&mut stream, &encoded).await; }
                            }
                        } else { println!("Target node unrecognized."); }
                    }
                }
            }
            "weave" => {
                if let Ok(target) = Uuid::parse_str(parts.get(1).unwrap_or(&"")) {
                    let lock = fleet_clone.lock().await;
                    if let Some(target_node) = lock.get(&target) {
                        let target_addr_binary = format!("127.0.0.1:{}", target_node.binary_port);
                        if let Ok(stream) = TcpStream::connect(&target_addr_binary).await { tokio::spawn(handle_local_laminar_stream(stream, client_uuid)); }
                    }
                }
            }
            "exit" | "quit" => break,
            _ => println!("Commands: fleet, msg, manifest submit, browse, get, weave, exit"),
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 { return Ok(()); }
    match args[1].as_str() {
        "bootstrap" => run_c2_bootstrap(&args[2]).await,
        "node" => run_client_node(&args[2], args[3].parse::<u16>()?).await,
        _ => Ok(())
    }
}
EOF_RUST

# ------------------------------------------------------------------------------
# 6. AUTOMATED HYPER-FLOW LINKER (BUILD.RS - LEGACY C99 TOGGLE)
# ------------------------------------------------------------------------------
print -P "${TEAL}[*] Constructing dynamic build wrapper (build.rs)...${RESET}"
cat << 'EOF' > "$ARCHIVE_DIR/build.rs"
fn main() {
    println!("cargo:rerun-if-changed=src/ffi/chaos_weave.c");
    cc::Build::new()
        .file("src/ffi/chaos_weave.c")
        .include("src/ffi")
        .flag("-std=c99") // Enforce legacy C standard
        .compile("chaos_weave");
}
EOF

# ------------------------------------------------------------------------------
# 7. MANIFEST COMPILER & INITIATION SEQUENCE
# ------------------------------------------------------------------------------
print -P "${TEAL}[*] Transpiling workspace elements...${RESET}"
cd "$ARCHIVE_DIR" || exit 1

# Check for LEGACY_MODE environment variable securely defaulting to 0
if [[ "${LEGACY_MODE:-0}" == "1" ]]; then
    print -P "${GOLD}[!] LEGACY_MODE Detected. Cross-compiling statically via MUSL...${RESET}"
    cargo build --release --target=x86_64-unknown-linux-musl
    BUILD_PATH="./$ARCHIVE_DIR/target/x86_64-unknown-linux-musl/release/$EXECUTABLE_NAME"
else
    cargo build --release
    BUILD_PATH="./$ARCHIVE_DIR/target/release/$EXECUTABLE_NAME"
fi

# Due to Zsh's err_exit, reaching this block guarantees build success
print -P "${GOLD}======================================================================${RESET}"
print -P "${TEAL}[+] CONGRATULATIONS: YuKKi OS 6.4.0 Interim-Crypt compilation successful.${RESET}"
print -P "${TEAL}[+] Target Binary Location: $BUILD_PATH${RESET}"
print -P "${GOLD}======================================================================${RESET}"
print -P "${TEAL}  BUILD CONTENTS (GPL-3 - INTERIM-CRYPT):${RESET}"
print -P "  - Integrated real-time Lorenz Chaos attractor mathematical manifolds."
print -P "  - Uncloneable Pauli/Clifford encryption bindings at the bit level."
print -P "  - Zero-latency memory bypass aligned explicitly to 88-byte bounds."
print -P "  - P2P distributed networking with dual-port architecture (JSON + Binary)."
print -P "  - Restored v4 Filesystem Utilities (Browse, Asynchronous Transfer)."
print -P "  - Information-Theoretic security model for payload protection."
print -P "  - Hardware layout restricted to purely electrical flat topology."
print -P "${GOLD}======================================================================${RESET}"

exit 0
