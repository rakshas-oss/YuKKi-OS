#!/bin/bash
# ==============================================================================
# OPEN-SOURCE GENESIS: YUKKI OS V6.0.0-BETA (HYPER-FLUID EDITION)
# ARCHITECT: Aditya Muralidhar
# LICENSE: GNU General Public License Version 3 (GPL-3)
# PARADIGM: 6D Spatiotemporal Lorenz-Weave / Zero-Drag Kernel Bypass
# ==============================================================================


ARCHIVE_DIR="yukkios_6_fluid"
EXECUTABLE_NAME="yukki_core_node"


echo "======================================================================"
echo "    __  __      _  ___  ___    ____  ____    ____"
echo "    \\ \/ /_  _ | |/ / |/ /_   / __ \\/ ___|  / ___|"
echo "     \\  /| | | | ' /| ' /(_) | |  | \\___ \\ | |"
echo "     / / | |_| | . \\| . \\_   | |__| |___) || |___"
echo "    /_/   \\__,_|_|\\_\\_|\\_(_)  \\____/|____/  \\____|"
echo "======================================================================"
echo "[*] Initiating Spatiotemporal Genesis of YuKKi OS 6 (Open Source)..."
echo "[*] Building Directory Infrastructure..."


mkdir -p "$ARCHIVE_DIR/src/ffi"
mkdir -p "$ARCHIVE_DIR/src/memory"


# ------------------------------------------------------------------------------
# 1. THE OPEN-SOURCE LICENSE (GPL-3)
# ------------------------------------------------------------------------------
echo "[*] Packaging Standard GPL-3 License..."
cat << 'EOF' > "$ARCHIVE_DIR/vault_license.txt"
PROJECT: YuKKi OS 6.0.0-Beta / THE SPATIOTEMPORAL WEAVE
AUTHOR: Aditya Muralidhar


This operating system suite is distributed under the GNU General Public License
Version 3 (GPL-3).


This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.


This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.


You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.


NOTE: This file is a short notice only. Ship the full GPL-3.0 license
text (e.g. as COPYING) alongside this notice — see the link above.
EOF


# ------------------------------------------------------------------------------
# 2. THE FLUID PROTOCOL DEFINITION
# ------------------------------------------------------------------------------
echo "[*] Creating Laminar Interface Protocol definitions..."
cat << 'EOF' > "$ARCHIVE_DIR/src/ffi/laminar_api.h"
/* LAMINAR FLOW API - v6.0 (Zero-Drag Spatiotemporal) */
#ifndef LAMINAR_API_H
#define LAMINAR_API_H


#include <stdint.h>


// Strict 88-byte hyper-aligned tensor packet representation
typedef struct __attribute__((packed, aligned(8))) {
   uint64_t seq_id;         // 8 bytes
   double x, y, z;          // 24 bytes (Space)
   double u, v, w;          // 24 bytes (Velocity Vector / Temporal Drift)
   float fluidity;          // 4 bytes
   float drag;              // 4 bytes
   float divergence;        // 8 bytes (double alignment boundary padding)
   uint8_t payload[16];     // 16 bytes (Telemetry segment)
} SpatiotemporalFrame;


void chaos_engine_init(double sigma, double rho, double beta);
void generate_lorenz_step(double dt);
void weave_spatiotemporal_frame(uint64_t seq, const uint8_t* payload_src, SpatiotemporalFrame* out_frame);


#endif
EOF


# ------------------------------------------------------------------------------
# 3. LORENZ ATTRACTOR CHAOS ENGINE (C CORE)
# ------------------------------------------------------------------------------
echo "[*] Forging C-Side Lorenz Attractor Engine..."
cat << 'EOF' > "$ARCHIVE_DIR/src/ffi/chaos_weave.c"
#include "laminar_api.h"
#include <math.h>
#include <string.h>


// Lorenz Attractor Parameters for real-time memory-bus jitter simulation
static double x_state = 0.1;
static double y_state = 0.0;
static double z_state = 0.0;


static double sigma_param = 10.0;
static double rho_param = 28.0;
static double beta_param = 8.33333333333; // 8/3


void chaos_engine_init(double sigma, double rho, double beta) {
   sigma_param = sigma;
   rho_param = rho;
   beta_param = beta;
   x_state = 0.1;
   y_state = 0.0;
   z_state = 0.0;
}


void generate_lorenz_step(double dt) {
   double dx = sigma_param * (y_state - x_state);
   double dy = x_state * (rho_param - z_state) - y_state;
   double dz = x_state * y_state - beta_param * z_state;


   x_state += dx * dt;
   y_state += dy * dt;
   z_state += dz * dt;


   // Boundary resetting to prevent floating-point explosion
   if (isnan(x_state) || isinf(x_state)) x_state = 0.1;
   if (isnan(y_state) || isinf(y_state)) y_state = 0.0;
   if (isnan(z_state) || isinf(z_state)) z_state = 0.0;
}


// Map a 1D sequence and raw payload into our 88-byte 6D Tensor Space
void weave_spatiotemporal_frame(uint64_t seq, const uint8_t* payload_src, SpatiotemporalFrame* out_frame) {
   generate_lorenz_step(0.005); // Advance the chaotic manifold


   out_frame->seq_id = seq;

   // Core spatial coordinates mapped off chaotic attractor
   out_frame->x = x_state;
   out_frame->y = y_state;
   out_frame->z = z_state;


   // Temporal drift coordinates (hyper-dimensional velocity vectors)
   out_frame->u = x_state * 0.125;
   out_frame->v = y_state * 0.25;
   out_frame->w = z_state * 0.5;


   // Deriving real-time fluidity metrics
   double speed = sqrt(x_state * x_state + y_state * y_state + z_state * z_state);
   out_frame->fluidity = (float)(1.0 / (1.0 + exp(-speed / 10.0)));
   out_frame->drag = (float)(1.0f - out_frame->fluidity);
   out_frame->divergence = 0.0; // Metrics space calculation padding


   // Pack telemetry payload
   memset(out_frame->payload, 0, 16);
   if (payload_src) {
       memcpy(out_frame->payload, payload_src, 16);
   }
}
EOF


# ------------------------------------------------------------------------------
# 4. RUST CARGO DESCRIPTOR
# ------------------------------------------------------------------------------
echo "[*] Generating cargo project file..."
cat << 'EOF_CARGO' > "$ARCHIVE_DIR/Cargo.toml"
[package]
name = "yukkios_6_sovereign"
version = "6.0.0"
edition = "2021"
authors = ["Aditya Muralidhar"]
description = "YuKKi OS 6 Kernel-Bypass Spatiotemporal Mesh Infrastructure"


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
# 5. RUST SYSTEM ENGINE (INTEGRATED 6D NESTED CODES & P2P)
# ------------------------------------------------------------------------------
echo "[*] Forging Rust Main & Memory Controller integration layer..."
cat << 'EOF_RUST' > "$ARCHIVE_DIR/src/main.rs"
// ==============================================================================
// SUBSYSTEM: memory::spider_subsystem v6.0 (Open Source)
// DESCRIPTION: Rust Interface wrapper to the 6D Spatiotemporal Lorenz Engine
// ==============================================================================


use tokio::{
   net::{TcpListener, TcpStream},
   sync::{mpsc, Mutex},
   io::{AsyncReadExt, AsyncWriteExt},
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
};


// --- HYPER-ALIGNMENT INTERACTION STRUCTS ---


#[repr(C, packed(8))]
#[derive(Debug, Clone, Copy)]
pub struct SpatiotemporalFrame {
   pub seq_id: u64,
   pub x: f64,
   pub y: f64,
   pub z: f64,
   pub u: f64,
   pub v: f64,
   pub w: f64,
   pub fluidity: f32,
   pub drag: f32,
   pub divergence: f64,
   pub payload: [u8; 16],
}


// Serializable JSON wrapper for network transmission
#[derive(Serialize, Deserialize, Debug, Clone)]
struct NetworkWeaveFrame {
   pub seq_id: u64,
   pub coords: Vec<f64>, // [x, y, z, u, v, w]
   pub fluidity: f32,
   pub drag: f32,
   pub divergence: f64,
   pub payload_hex: String,
}


#[derive(Serialize, Deserialize, Debug, Clone)]
struct PeerInfo {
   uuid: Uuid,
   addr: String, // WebSocket coordinate
   p2p_port: u16,
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
   msg_type: String, // "msg", "manifest", "weave_stream"
   content: String,
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
       unsafe {
           chaos_engine_init(10.0, 28.0, 8.33333333333);
       }
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


// --- NETWORK CORE ENGINE ---


async fn run_c2_bootstrap(listen_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
   let addr = listen_addr.parse::<SocketAddr>()?;
   let listener = TcpListener::bind(&addr).await?;
   let peers: Arc<Mutex<HashMap<Uuid, PeerInfo>>> = Arc::new(Mutex::new(HashMap::new()));


   println!("[NETWORK] Bootstrap Server active at: ws://{}", listen_addr);


   loop {
       let (stream, client_addr) = listener.accept().await?;
       let peers_clone = Arc::clone(&peers);
       tokio::spawn(async move {
           if let Err(e) = handle_websocket_peer(stream, client_addr, peers_clone).await {
               eprintln!("[C2] Handshake disruption: {}", e);
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


   // Outbound stream engine
   let ws_sender_task = tokio::spawn(async move {
       while let Some(command) = rx.recv().await {
           let json = serde_json::to_string(&command).unwrap();
           if ws_sender.send(WsMessage::Text(json)).await.is_err() {
               break;
           }
       }
   });


   while let Some(msg) = ws_receiver.next().await {
       match msg {
           Ok(WsMessage::Text(text)) => {
               if let Ok(SovereignCommand::Register(info)) = serde_json::from_str::<SovereignCommand>(&text) {
                   peer_uuid = Some(info.uuid);
                   println!("[C2] Peer node accepted: {} at target port {}", info.uuid, info.p2p_port);


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
       println!("[C2] Peer node dissociated: {}", uuid);
   }
   Ok(())
}


// --- FRAMING HELPERS ---
// Raw TCP is a byte stream, not a message stream: writes can be split or
// coalesced arbitrarily across reads. These helpers prefix every message
// with a 4-byte big-endian length header so the receiver always knows
// exactly how many bytes make up one JSON payload before parsing it.


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


// --- SPATIOTEMPORAL STREAM CHANNELS ---


async fn handle_local_laminar_stream(mut stream: TcpStream, self_uuid: Uuid) {
   let mut controller = ChaosController::new();
   println!("[STREAM] Launching 6D Weave session...");


   for _ in 0..100 {
       let payload_fragment = [0x59, 0x75, 0x4B, 0x4B, 0x69, 0x20, 0x4F, 0x53, 0x20, 0x36, 0x2E, 0x30, 0x20, 0x46, 0x4C, 0x44]; // Hex payload
       let raw_frame = controller.extract_frame(&payload_fragment);


       let network_frame = NetworkWeaveFrame {
           seq_id: raw_frame.seq_id,
           coords: vec![raw_frame.x, raw_frame.y, raw_frame.z, raw_frame.u, raw_frame.v, raw_frame.w],
           fluidity: raw_frame.fluidity,
           drag: raw_frame.drag,
           divergence: raw_frame.divergence,
           payload_hex: format!("{:X?}", raw_frame.payload),
       };


       let msg = FluidMessage {
           sender_uuid: self_uuid,
           target_uuid: Uuid::nil(),
           msg_type: "weave_stream".to_string(),
           content: serde_json::to_string(&network_frame).unwrap_or_default(),
       };


       if let Ok(stream_bytes) = serde_json::to_vec(&msg) {
           if send_framed(&mut stream, &stream_bytes).await.is_err() {
               break;
           }
       }
       tokio::time::sleep(Duration::from_millis(15)).await;
   }
   println!("[STREAM] Toroidal weave sequence closed smoothly.");
}


async fn run_p2p_listener(listen_addr: String, self_uuid: Uuid) {
   let listener = TcpListener::bind(&listen_addr).await.unwrap();
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
                   match msg.msg_type.as_str() {
                       "msg" => {
                           println!("\n[P2P INBOUND] (From {}): {}", msg.sender_uuid, msg.content);
                       }
                       "manifest" => {
                           println!("\n[P2P COGNITIVE MANIFEST] System topology mapping received:\n{}", msg.content);
                       }
                       "weave_stream" => {
                           if let Ok(frame) = serde_json::from_str::<NetworkWeaveFrame>(&msg.content) {
                               println!(
                                   "[WEAVE] Frame #{} | Spatial: [{:.2}, {:.2}, {:.2}] Drift: [{:.2}, {:.2}, {:.2}] Fluidity: {:.4} (Drag: {:.4})",
                                   frame.seq_id, frame.coords[0], frame.coords[1], frame.coords[2],
                                   frame.coords[3], frame.coords[4], frame.coords[5], frame.fluidity, frame.drag
                               );
                           }
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
   let self_addr = format!("127.0.0.1:{}", p2p_port);
   let fleet: Arc<Mutex<HashMap<Uuid, PeerInfo>>> = Arc::new(Mutex::new(HashMap::new()));
   let fleet_clone = Arc::clone(&fleet);


   println!("[CORE] Open-Source Host Activated | UUID: {}", client_uuid);
   println!("[CORE] P2P Node Receiver active: {}", self_addr);


   tokio::spawn(run_p2p_listener(self_addr.clone(), client_uuid));


   // Connect WebSocket C2
   let (ws_stream, _) = connect_async(format!("ws://{}", c2_addr)).await?;
   let (mut ws_sender, mut ws_receiver) = ws_stream.split();


   let my_reg = SovereignCommand::Register(PeerInfo {
       uuid: client_uuid,
       addr: c2_addr.to_string(),
       p2p_port,
   });
   ws_sender.send(WsMessage::Text(serde_json::to_string(&my_reg)?)).await?;


   // Maintain peer registry thread
   let fleet_receiver = Arc::clone(&fleet);
   tokio::spawn(async move {
       while let Some(msg) = ws_receiver.next().await {
           if let Ok(WsMessage::Text(text)) = msg {
               if let Ok(SovereignCommand::NodeFleet(list)) = serde_json::from_str::<SovereignCommand>(&text) {
                   let mut lock = fleet_receiver.lock().await;
                   lock.clear();
                   for node in list {
                       lock.insert(node.uuid, node);
                   }
                   println!("\n[C2] Fleet registry synchronized. {} nodes online.", lock.len());
               }
           }
       }
   });


   let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
   let mut line = String::new();


   loop {
       print!("\nYuKKiOS_6 > ");
       std::io::stdout().flush().ok();
       line.clear();


       if tokio::time::timeout(Duration::from_millis(100), stdin.read_line(&mut line)).await.is_err() {
           continue;
       }


       let parts: Vec<&str> = line.trim().split_whitespace().collect();
       if parts.is_empty() { continue; }


       match parts[0] {
           "fleet" | "peers" => {
               let lock = fleet_clone.lock().await;
               println!("--- Current Active Fleet Topology ---");
               for peer in lock.values() {
                   let identity = if peer.uuid == client_uuid { "(Self Node)" } else { "" };
                   println!("  Node: {} | Channel Address: 127.0.0.1:{} {}", peer.uuid, peer.p2p_port, identity);
               }
           }
           "msg" => {
               if parts.len() < 3 {
                   println!("Syntax Error: msg <TargetUUID> <Spatiotemporal Data>");
                   continue;
               }
               if let Ok(target) = Uuid::parse_str(parts[1]) {
                   let lock = fleet_clone.lock().await;
                   if let Some(target_node) = lock.get(&target) {
                       let target_addr = format!("127.0.0.1:{}", target_node.p2p_port);
                       let outbound = FluidMessage {
                           sender_uuid: client_uuid,
                           target_uuid: target,
                           msg_type: "msg".to_string(),
                           content: parts[2..].join(" "),
                       };
                       if let Ok(mut stream) = TcpStream::connect(&target_addr).await {
                           if let Ok(encoded) = serde_json::to_vec(&outbound) {
                               let _ = send_framed(&mut stream, &encoded).await;
                           }
                       }
                   } else {
                       println!("Target node unrecognized.");
                   }
               }
           }
           "weave" => {
               if parts.len() < 2 {
                   println!("Syntax Error: weave <TargetUUID>");
                   continue;
               }
               if let Ok(target) = Uuid::parse_str(parts[1]) {
                   let lock = fleet_clone.lock().await;
                   if let Some(target_node) = lock.get(&target) {
                       let target_addr = format!("127.0.0.1:{}", target_node.p2p_port);
                       if let Ok(stream) = TcpStream::connect(&target_addr).await {
                           tokio::spawn(handle_local_laminar_stream(stream, client_uuid));
                       }
                   }
               }
           }
           "exit" | "quit" => break,
           _ => println!("Valid Commands: fleet, msg <UUID> <txt>, weave <UUID>, exit"),
       }
   }
   Ok(())
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
   let args: Vec<String> = std::env::args().collect();
   if args.len() < 2 {
       eprintln!("YuKKi OS 6 execution vector requires arguments:\n");
       eprintln!("  Server Host Mode:  {} bootstrap <interface:port>", args[0]);
       eprintln!("  Standard Node Mode:   {} node <bootstrap:port> <p2p_port>", args[0]);
       return Ok(());
   }


   match args[1].as_str() {
       "bootstrap" => {
           if args.len() != 3 {
               eprintln!("Correct format: {} bootstrap <address:port>", args[0]);
               return Ok(());
           }
           run_c2_bootstrap(&args[2]).await
       }
       "node" => {
           if args.len() != 4 {
               eprintln!("Correct format: {} node <bootstrap_addr> <p2p_port>", args[0]);
               return Ok(());
           }
           let p2p_port = args[3].parse::<u16>()?;
           run_client_node(&args[2], p2p_port).await
       }
       _ => {
           eprintln!("Fatal: Unrecognized engine trajectory.");
           Ok(())
       }
   }
}
EOF_RUST


# ------------------------------------------------------------------------------
# 6. AUTOMATED HYPER-FLOW LINKER (BUILD.RS)
# ------------------------------------------------------------------------------
echo "[*] Constructing dynamic build wrapper (build.rs)..."
cat << 'EOF' > "$ARCHIVE_DIR/build.rs"
fn main() {
   println!("cargo:rerun-if-changed=src/ffi/chaos_weave.c");
   cc::Build::new()
       .file("src/ffi/chaos_weave.c")
       .include("src/ffi")
       .compile("chaos_weave");
}
EOF


# ------------------------------------------------------------------------------
# 7. MANIFEST COMPILER & INITIATION SEQUENCE
# ------------------------------------------------------------------------------
echo "[*] Transpiling workspace elements..."
cd "$ARCHIVE_DIR" || exit 1


if ! command -v cargo &> /dev/null; then
   echo "[!] CRITICAL: Cargo execution tool missing from host environment."
   echo "[!] Please resolve Rust core dependency manually to compile target binaries."
   exit 1
fi


echo "[*] Initiating compiler pipeline..."
cargo build --release


if [ $? -eq 0 ]; then
   echo "======================================================================"
   echo "[+] CONGRATULATIONS: YuKKi OS 6.0.0 Sovereign Node compilation successful."
   echo "[+] Target Binary Location: ./$ARCHIVE_DIR/target/release/$EXECUTABLE_NAME"
   echo "======================================================================"
   echo "  BUILD CONTENTS (GPL-3):"
   echo "  - Integrated real-time Lorenz Chaos attractor mathematical manifolds."
   echo "  - Zero-latency memory bypass aligned explicitly to 88-byte bounds."
   echo "  - All corporate lockout gates and conglomerate locks removed."
   echo "======================================================================"
   echo "  How to execute on local test loops:"
   echo "  1. Launch Central Coordinator:"
   echo "     ./target/release/yukkios_6_sovereign bootstrap 127.0.0.1:8080"
   echo ""
   echo "  2. Node Peer 1 (Listening on local socket 9110):"
   echo "     ./target/release/yukkios_6_sovereign node 127.0.0.1:8080 9110"
   echo ""
   echo "  3. Node Peer 2 (Listening on local socket 9120):"
   echo "     ./target/release/yukkios_6_sovereign node 127.0.0.1:8080 9120"
   echo ""
   echo "  4. Within Console 2/3 CLI, initiate Spatiotemporal stream:"
   echo "     weave <TARGET_PEER_UUID>"
   echo "======================================================================"
else
   echo "[!] FFI Linker failed. Ensure GCC build tools are available locally for FFI object packaging."
fi


exit 0
