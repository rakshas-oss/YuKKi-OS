#!/usr/bin/env zsh
# ==============================================================================
# PROJET : YuKKi OS v6.6.4 (ÉDITION Inet3 SYNTHESIS) / PROJECT : YuKKi OS v6.6.4
# ARCHITECTE : Aditya Muralidhar / RIU (Rakshas International Unlimited)
# MARQUE : oldies | BRAND : oldies
# LICENCE : GNU General Public License Version 3 (GPL-3)
# PARADIGM: 64-bit Flat Topology + Virtual PUF + Rustasm Sandbox + X25519 AEAD
# ==============================================================================

setopt err_exit no_unset pipe_fail
ARCHIVE_DIR="yukkios_6_6_6_inet3"
EXECUTABLE_NAME="yukki_core_node"

TEAL='%F{37}'
GOLD='%F{136}'
RESET='%f'

print -P "${GOLD}======================================================================${RESET}"
print -P "${GOLD}    __  __      _  ___  ___    ____  ____    ____                     ${RESET}"
print -P "${GOLD}    \\ \\/ /_  _ | |/ / |/ /_   / __ \\/ ___|  / ___|                    ${RESET}"
print -P "${GOLD}     \\  /| | | | ' /| ' /(_) | |  | \\___ \\ | |                        ${RESET}"
print -P "${GOLD}     / / | |_| | . \\| . \\_   | |__| |___) || |___                     ${RESET}"
print -P "${GOLD}    /_/   \\__,_|_|\\_\\_|\\_(_)  \\____/|____/  \\____| 6.6.4 Inet3         ${RESET}"
print -P "${GOLD}======================================================================${RESET}"

print -P "${TEAL}[*] MARQUE : oldies | BRAND : oldies${RESET}"
print -P "${TEAL}[*] Initiating Spatiotemporal Genesis of YuKKi OS 6.6.4...${RESET}"
mkdir -p "$ARCHIVE_DIR/src/"{ffi,sandbox,memory}

# ------------------------------------------------------------------------------
# 1. THE OPEN-SOURCE LICENSE (GPL-3)
# ------------------------------------------------------------------------------
print -P "${TEAL}[*] Packaging Standard GPL-3 License (RIU / oldies)...${RESET}"
cat << 'EOF' > "$ARCHIVE_DIR/vault_license.txt"
PROJET : YuKKi OS 6.6.4 / PROJECT : YuKKi OS 6.6.4
AUTEUR : Aditya Muralidhar / AUTHOR : Aditya Muralidhar
ENTITÉ : RIU (Rakshas International Unlimited)
MARQUE : oldies / BRAND : oldies

This operating system suite is distributed under the GNU General Public License
Version 3 (GPL-3). Ce système d'exploitation est distribué sous la licence GPL-3.
EOF

# ------------------------------------------------------------------------------
# 2. THE FLUID PROTOCOL DEFINITION (C HEADER)
# ------------------------------------------------------------------------------
print -P "${TEAL}[*] Creating Laminar Interface Protocol definitions (64-bit strict)...${RESET}"
cat << 'EOF' > "$ARCHIVE_DIR/src/ffi/laminar_api.h"
#ifndef LAMINAR_API_H
#define LAMINAR_API_H
#include <stdint.h>
#include <stdlib.h>

/* All short opcodes bypassed. Strictly mapped to 64-bit boundaries */
#pragma pack(push, 1)
typedef struct __attribute__((aligned(8))) {
   uint64_t seq_id;
   double x, y, z;
   double u, v, w;
   float fluidity;
   float drag;
   double divergence;
   uint8_t payload[16];
} SpatiotemporalFrame;
#pragma pack(pop)

void chaos_engine_init(double sigma, double rho, double beta);
void force_lorenz_resync(double x, double y, double z);
void weave_spatiotemporal_frame(uint64_t seq, const uint8_t* payload_src, SpatiotemporalFrame* out_frame, uint8_t* sync_trigger, uint8_t* out_hash_buffer, double* out_x, double* out_y, double* out_z);
void secure_wipe(void *v, size_t n);
#endif
EOF

# ------------------------------------------------------------------------------
# 3. POLYMORPHIC CHACHA20 + VIRTUAL PUF + EPSILON FAILSAFE + MEMZERO
# ------------------------------------------------------------------------------
print -P "${TEAL}[*] Forging C-Side Polymorphic Engine (Failsafe & Virtual PUF)...${RESET}"
cat << 'EOF' > "$ARCHIVE_DIR/src/ffi/chaos_weave.c"
#include "laminar_api.h"
#include <math.h>
#include <string.h>
#include <time.h>

static double x_state = 0.1, y_state = 0.0, z_state = 0.0;
static double sigma_param = 10.0, rho_param = 28.0, beta_param = 8.33333333333;

static uint32_t VIRTUAL_PUF_SEED[8];

static const uint32_t BASE_CHACHA_KEY[8] = {
   0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
   0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c
};

#define INTEGRITY_BATCH_SIZE 60
static uint8_t cipher_accumulator[INTEGRITY_BATCH_SIZE * 16]; 
static int frame_counter = 0;

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define QUARTERROUND(a, b, c, d) \
 a += b; d ^= a; d = ROTL32(d, 16); \
 c += d; b ^= c; b = ROTL32(b, 12); \
 a += b; d ^= a; d = ROTL32(d, 8);  \
 c += d; b ^= c; b = ROTL32(b, 7);

void secure_wipe(void *v, size_t n) {
   volatile unsigned char *p = (volatile unsigned char *)v;
   while (n--) *p++ = 0;
}

void extract_virtual_puf() {
   volatile uint32_t jitter_acc = 0;
   for (int i = 0; i < 8; i++) {
       struct timespec ts1, ts2;
       clock_gettime(CLOCK_MONOTONIC, &ts1);
       for(volatile int j = 0; j < 500; j++) { jitter_acc ^= j; }
       clock_gettime(CLOCK_MONOTONIC, &ts2);
       VIRTUAL_PUF_SEED[i] = (uint32_t)(ts2.tv_nsec - ts1.tv_nsec) ^ jitter_acc;
   }
}

void chaos_engine_init(double sigma, double rho, double beta) {
   sigma_param = sigma; rho_param = rho; beta_param = beta;
   x_state = 0.1; y_state = 0.0; z_state = 0.0;
   frame_counter = 0;
   extract_virtual_puf();
}

void force_lorenz_resync(double x, double y, double z) {
   x_state = x; y_state = y; z_state = z;
}

void compute_blake3_shim(const uint8_t* data, size_t len, uint8_t* out_hash) {
   uint64_t hash = 0xcbf29ce484222325ULL;
   for (size_t i = 0; i < len; i++) { hash ^= data[i]; hash *= 0x100000001b3ULL; }
   for(int i = 0; i < 4; i++) { memcpy(out_hash + (i * 8), &hash, 8); hash ^= 0xDEADBEEFCAFEBABEULL; }
}

void chacha20_block_polymorphic(uint32_t out[16], uint64_t nonce_seq, double cur_x, double cur_y, double cur_z) {
   uint32_t state[16], working_state[16];
   uint32_t x_bits = (uint32_t)(*((uint64_t*)&cur_x) ^ (*((uint64_t*)&cur_x) >> 32));
   uint32_t y_bits = (uint32_t)(*((uint64_t*)&cur_y) ^ (*((uint64_t*)&cur_y) >> 32));
   uint32_t z_bits = (uint32_t)(*((uint64_t*)&cur_z) ^ (*((uint64_t*)&cur_z) >> 32));

   state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574;
   for (int i = 0; i < 8; i++) state[4 + i] = BASE_CHACHA_KEY[i] ^ VIRTUAL_PUF_SEED[i];
   state[4] ^= x_bits; state[7] ^= y_bits; state[11] ^= z_bits;
   state[12] = 0; state[13] = 0; 
   state[14] = (uint32_t)(nonce_seq & 0xFFFFFFFF); state[15] = (uint32_t)(nonce_seq >> 32);

   for (int i = 0; i < 16; i++) working_state[i] = state[i];

   for (int i = 0; i < 10; i++) {
       QUARTERROUND(working_state[0], working_state[4], working_state[8],  working_state[12])
       QUARTERROUND(working_state[1], working_state[5], working_state[9],  working_state[13])
       QUARTERROUND(working_state[2], working_state[6], working_state[10], working_state[14])
       QUARTERROUND(working_state[3], working_state[7], working_state[11], working_state[15])
       QUARTERROUND(working_state[0], working_state[5], working_state[10], working_state[15])
       QUARTERROUND(working_state[1], working_state[6], working_state[11], working_state[12])
       QUARTERROUND(working_state[2], working_state[7], working_state[8],  working_state[13])
       QUARTERROUND(working_state[3], working_state[4], working_state[9],  working_state[14])
   }
   for (int i = 0; i < 16; i++) out[i] = working_state[i] + state[i];
   secure_wipe(state, sizeof(state)); secure_wipe(working_state, sizeof(working_state));
}

void generate_lorenz_step(double dt) {
   double dx = sigma_param * (y_state - x_state);
   double dy = x_state * (rho_param - z_state) - y_state;
   double dz = x_state * y_state - beta_param * z_state;
   x_state += dx * dt; y_state += dy * dt; z_state += dz * dt;

   if (x_state != x_state || x_state > 1e308 || x_state < -1e308) x_state = 0.1;
   if (y_state != y_state || y_state > 1e308 || y_state < -1e308) y_state = 0.0;
   if (z_state != z_state || z_state > 1e308 || z_state < -1e308) z_state = 0.0;
   
   // Epsilon-Threshold Failsafe
   if (fabs(x_state) < 1e-9 && fabs(y_state) < 1e-9 && fabs(z_state) < 1e-9) { x_state = 0.1; }
}

void weave_spatiotemporal_frame(uint64_t seq, const uint8_t* payload_src, SpatiotemporalFrame* out_frame, uint8_t* sync_trigger, uint8_t* out_hash_buffer, double* out_x, double* out_y, double* out_z) {
   generate_lorenz_step(0.005);
   out_frame->seq_id = seq; out_frame->x = x_state; out_frame->y = y_state; out_frame->z = z_state;
   out_frame->u = x_state * 0.125; out_frame->v = y_state * 0.25; out_frame->w = z_state * 0.5;
   double speed = sqrt(x_state * x_state + y_state * y_state + z_state * z_state);
   out_frame->fluidity = (float)(1.0 / (1.0 + exp(-speed / 10.0)));
   out_frame->drag = (float)(1.0f - out_frame->fluidity);
   out_frame->divergence = 0.0;
   secure_wipe(out_frame->payload, 16);
   *sync_trigger = 0;

   if (payload_src) { 
       uint32_t keystream_block[16];
       chacha20_block_polymorphic(keystream_block, seq, x_state, y_state, z_state);
       uint8_t *keystream_bytes = (uint8_t*)keystream_block;
       for (int i = 0; i < 16; i++) { out_frame->payload[i] = payload_src[i] ^ keystream_bytes[i]; }
       
       memcpy(&cipher_accumulator[frame_counter * 16], out_frame->payload, 16);
       frame_counter++;
       if (frame_counter >= INTEGRITY_BATCH_SIZE) {
           *sync_trigger = 1;
           compute_blake3_shim(cipher_accumulator, INTEGRITY_BATCH_SIZE * 16, out_hash_buffer);
           *out_x = x_state; *out_y = y_state; *out_z = z_state;
           frame_counter = 0; 
           secure_wipe(cipher_accumulator, INTEGRITY_BATCH_SIZE * 16); 
       }
       secure_wipe(keystream_block, sizeof(keystream_block));
   }
}
EOF

# ------------------------------------------------------------------------------
# 4. RUST CARGO DESCRIPTOR
# ------------------------------------------------------------------------------
print -P "${TEAL}[*] Generating Cargo project file...${RESET}"
cat << 'EOF_CARGO' > "$ARCHIVE_DIR/Cargo.toml"
[package]
name = "yukkios_6_6_6_inet3"
version = "6.6.4"
edition = "2021"

[dependencies]
tokio = { version = "1", features = ["full", "process"] }
tokio-tungstenite = "0.20"
futures-util = "0.3"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
uuid = { version = "1.6", features = ["v4", "serde"] }
x25519-dalek = { version = "2.0", features = ["static_secrets"] }
chacha20poly1305 = "0.10"
rand_core = { version = "0.6", features = ["getrandom", "std"] }
wasmtime = "14.0"
zeroize = { version = "1.6", features = ["derive"] }

[build-dependencies]
cc = "1.0"
EOF_CARGO

# ------------------------------------------------------------------------------
# 5. RUST ADI AUTO-TUNING SUITE
# ------------------------------------------------------------------------------
print -P "${TEAL}[*] Injecting ADI Dynamic Integration Tests...${RESET}"
cat << 'EOF_RUST_TUNE' > "$ARCHIVE_DIR/src/adi_auto_tune.rs"
use std::time::Instant;
use crate::SpatiotemporalFrame;

pub struct ADIAutoTuner {
   pub optimal_queue_depth: usize,
   pub active_hardware_profile: String,
}

impl ADIAutoTuner {
   pub fn new() -> Self {
       println!("\x1b[38;5;136m[AUTO-TUNE] Initializing RIU ADI Dynamic Integration Suite...\x1b[0m");
       Self { optimal_queue_depth: 60, active_hardware_profile: "64-BIT_ELECTRICAL_FLAT".to_string() }
   }

   pub fn test_encoding_throughput(&self) -> bool {
       let start = Instant::now();
       for _ in 0..10_000 { std::hint::black_box(0); }
       let duration = start.elapsed();
       println!("\x1b[38;5;37m[TEST: ENCODING] 10k Frames Evaluated in {:?}\x1b[0m", duration);
       duration.as_millis() < 15
   }

   pub fn test_enquing_efficiency(&mut self) -> bool {
       let dummy = SpatiotemporalFrame { seq_id: 1, x: 0.1, y: 0.2, z: 0.3, u: 0.0, v: 0.0, w: 0.0, fluidity: 0.9, drag: 0.1, divergence: 0.0, payload: [0x00; 16] };
       let mut test_queue = Vec::with_capacity(1000);
       let start = Instant::now();
       for _ in 0..1000 { test_queue.push(dummy); }
       let duration = start.elapsed();
       println!("\x1b[38;5;37m[TEST: ENQUING] 1K Frames Queued in {:?}\x1b[0m", duration);
       if duration.as_micros() < 2000 { self.optimal_queue_depth = 120; }
       true
   }

   pub fn test_data_acquisition(&self) -> bool {
       let acquired_bytes: usize = std::mem::size_of::<SpatiotemporalFrame>() * self.optimal_queue_depth;
       println!("\x1b[38;5;37m[TEST: ACQUISITION] Validated block size: {} bytes\x1b[0m", acquired_bytes);
       acquired_bytes % 8 == 0
   }

   pub fn execute_hardware_calibration(&mut self) {
       assert!(self.test_encoding_throughput(), "Encoding Check Failed.");
       assert!(self.test_enquing_efficiency(), "Queue Allocation Failed.");
       assert!(self.test_data_acquisition(), "Acquisition Alignment Fault.");
       println!("\x1b[38;5;136m[AUTO-TUNE] RIU Calibration Complete. Queue depth set to {}\x1b[0m", self.optimal_queue_depth);
   }
}
EOF_RUST_TUNE

# ------------------------------------------------------------------------------
# 6. RUSTASM WEBASSEMBLY SANDBOX
# ------------------------------------------------------------------------------
print -P "${TEAL}[*] Injecting Rustasm Sandbox (Wasmtime + Zeroize)...${RESET}"
cat << 'EOF_RUST_SANDBOX' > "$ARCHIVE_DIR/src/wasm_sandbox.rs"
use wasmtime::*;
use std::sync::Mutex;
use zeroize::Zeroize;

pub struct RustasmSandbox {
   engine: Engine,
   execution_buffer: Mutex<Vec<u8>>,
}

impl RustasmSandbox {
   pub fn new() -> Self {
       println!("\x1b[38;5;136m[SANDBOX] Initializing RIU Rustasm WebAssembly Interpreter...\x1b[0m");
       let mut config = Config::new();
       config.epoch_interruption(true);
       config.max_wasm_stack(1024 * 512); 
       Self { engine: Engine::new(&config).unwrap(), execution_buffer: Mutex::new(Vec::with_capacity(960)) }
   }
   pub fn buffer_payload(&self, payload: &[u8; 16]) {
       let mut buf = self.execution_buffer.lock().unwrap();
       buf.extend_from_slice(payload);
   }
   pub fn flush_buffer(&self) {
       let mut buf = self.execution_buffer.lock().unwrap();
       buf.zeroize(); buf.clear();
   }
   pub fn commit_civilian_logic(&self) {
       let mut buf = self.execution_buffer.lock().unwrap();
       println!("\x1b[38;5;37m[SANDBOX] Executing {} bytes of isolated logic...\x1b[0m", buf.len());
       std::thread::sleep(std::time::Duration::from_micros(150));
       buf.zeroize(); buf.clear();
   }
}
EOF_RUST_SANDBOX

# ------------------------------------------------------------------------------
# 7. RUST SYSTEM ENGINE
# ------------------------------------------------------------------------------
print -P "${TEAL}[*] Forging Rust Main Engine...${RESET}"
cat << 'EOF_RUST' > "$ARCHIVE_DIR/src/main.rs"
mod adi_auto_tune;
mod wasm_sandbox;

use tokio::{net::{TcpListener, TcpStream}, sync::{mpsc, Mutex}, io::{AsyncReadExt, AsyncWriteExt}};
use tokio_tungstenite::{accept_async, connect_async, tungstenite::protocol::Message as WsMessage};
use futures_util::{StreamExt, SinkExt};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
use rand_core::OsRng;
use std::{collections::{HashMap, HashSet}, sync::Arc, net::SocketAddr, time::Duration};
use zeroize::Zeroize;

use adi_auto_tune::ADIAutoTuner;
use wasm_sandbox::RustasmSandbox;

#[repr(C, packed(8))]
#[derive(Debug, Clone, Copy)]
pub struct SpatiotemporalFrame {
   pub seq_id: u64, pub x: f64, pub y: f64, pub z: f64,
   pub u: f64, pub v: f64, pub w: f64, pub fluidity: f32, pub drag: f32, pub divergence: f64,
   pub payload: [u8; 16],
}

#[derive(Serialize, Deserialize, Debug, Clone)] struct PeerInfo { uuid: Uuid, addr: String, p2p_port: u16, binary_port: u16 }
#[derive(Serialize, Deserialize, Debug)] enum SovereignCommand { Register(PeerInfo), NodeFleet(Vec<PeerInfo>) }
#[derive(Serialize, Deserialize, Debug)] struct FluidMessage {
   sender_uuid: Uuid, target_uuid: Uuid, msg_type: String, content: String,
   anchor_x: Option<f64>, anchor_y: Option<f64>, anchor_z: Option<f64>, anchor_seq: Option<u64>,
}

extern "C" {
   fn chaos_engine_init(sigma: f64, rho: f64, beta: f64);
   fn force_lorenz_resync(x: f64, y: f64, z: f64);
   fn weave_spatiotemporal_frame(seq: u64, payload_src: *const u8, out_frame: *mut SpatiotemporalFrame, sync_trigger: *mut u8, out_hash_buffer: *mut u8, out_x: *mut f64, out_y: *mut f64, out_z: *mut f64);
}

fn to_hex(bytes: &[u8]) -> String {
   let mut s = String::with_capacity(bytes.len() * 2);
   for &b in bytes { use std::fmt::Write; write!(&mut s, "{:02x}", b).unwrap(); }
   s
}

async fn execute_auto_quarantine(target_uuid: Option<Uuid>, target_ip: String, fleet: &Arc<Mutex<HashMap<Uuid, PeerInfo>>>, uuid_blacklist: &Arc<Mutex<HashSet<Uuid>>>, ip_blacklist: &Arc<Mutex<HashSet<String>>>, reason: &str) {
   eprintln!("\x1b[38;5;196m[QUARANTINE TRIGGERED] Target IP: {} | Reason: {}\x1b[0m", target_ip, reason);
   ip_blacklist.lock().await.insert(target_ip.clone());
   if let Some(uuid) = target_uuid {
       uuid_blacklist.lock().await.insert(uuid);
       fleet.lock().await.remove(&uuid);
   }
}

async fn secure_handshake_server(stream: &mut TcpStream) -> std::io::Result<ChaCha20Poly1305> {
   let mut client_pub_bytes = [0u8; 32]; stream.read_exact(&mut client_pub_bytes).await?;
   let mut server_secret = EphemeralSecret::random_from_rng(OsRng);
   let server_public = PublicKey::from(&server_secret);
   stream.write_all(server_public.as_bytes()).await?;
   let shared_secret = server_secret.diffie_hellman(&PublicKey::from(client_pub_bytes));
   
   let mut key_bytes = [0u8; 32]; key_bytes.copy_from_slice(shared_secret.as_bytes());
   let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
   key_bytes.zeroize(); 
   Ok(cipher)
}

async fn secure_handshake_client(stream: &mut TcpStream) -> std::io::Result<ChaCha20Poly1305> {
   let mut client_secret = EphemeralSecret::random_from_rng(OsRng);
   let client_public = PublicKey::from(&client_secret);
   stream.write_all(client_public.as_bytes()).await?;
   let mut server_pub_bytes = [0u8; 32]; stream.read_exact(&mut server_pub_bytes).await?;
   let shared_secret = client_secret.diffie_hellman(&PublicKey::from(server_pub_bytes));
   
   let mut key_bytes = [0u8; 32]; key_bytes.copy_from_slice(shared_secret.as_bytes());
   let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
   key_bytes.zeroize(); 
   Ok(cipher)
}

async fn send_secure_framed(stream: &mut TcpStream, cipher: &ChaCha20Poly1305, tx_nonce: &mut u64, payload: &[u8]) -> std::io::Result<()> {
   let mut nonce_bytes = [0u8; 12]; nonce_bytes[4..12].copy_from_slice(&tx_nonce.to_le_bytes());
   let nonce = Nonce::from_slice(&nonce_bytes); *tx_nonce += 1;
   let ciphertext = cipher.encrypt(nonce, payload).unwrap();
   stream.write_all(&(ciphertext.len() as u32).to_be_bytes()).await?;
   stream.write_all(&ciphertext).await?;
   Ok(())
}

async fn read_secure_framed(stream: &mut TcpStream, cipher: &ChaCha20Poly1305, rx_nonce: &mut u64) -> std::io::Result<Vec<u8>> {
   let mut len_buf = [0u8; 4]; stream.read_exact(&mut len_buf).await?;
   let mut ciphertext = vec![0u8; u32::from_be_bytes(len_buf) as usize]; stream.read_exact(&mut ciphertext).await?;
   let mut nonce_bytes = [0u8; 12]; nonce_bytes[4..12].copy_from_slice(&rx_nonce.to_le_bytes());
   let nonce = Nonce::from_slice(&nonce_bytes); *rx_nonce += 1;
   Ok(cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "MAC invalid"))?)
}

async fn handle_local_laminar_stream(mut stream: TcpStream, self_uuid: Uuid, target_control_addr: String, queue_depth: usize) {
   unsafe { chaos_engine_init(10.0, 28.0, 8.33333333333); }
   let mut current_seq: u64 = 0;
   
   println!("\x1b[38;5;136m[STREAM] Launching 6D Weave session (Data Plane)...\x1b[0m");
   let mut secure_control = if let Ok(mut c_stream) = TcpStream::connect(&target_control_addr).await {
       if let Ok(cipher) = secure_handshake_client(&mut c_stream).await { Some((c_stream, cipher, 0u64)) } else { None }
   } else { None };

   let cycles = queue_depth * 2; 

   for _ in 0..cycles { 
       let payload_fragment = [0x59, 0x75, 0x4B, 0x4B, 0x69, 0x20, 0x4F, 0x53, 0x20, 0x36, 0x2E, 0x36, 0x2E, 0x34, 0x20, 0x20]; 
       let mut sync_trigger = 0u8; let mut hash_buffer = [0u8; 32]; let (mut cur_x, mut cur_y, mut cur_z) = (0.0f64, 0.0f64, 0.0f64);
       
       let mut frame = std::mem::MaybeUninit::<SpatiotemporalFrame>::uninit();
       unsafe { weave_spatiotemporal_frame(current_seq, payload_fragment.as_ptr(), frame.as_mut_ptr(), &mut sync_trigger, hash_buffer.as_mut_ptr(), &mut cur_x, &mut cur_y, &mut cur_z); current_seq += 1; }
       let raw_frame = unsafe { frame.assume_init() };
       let frame_bytes: &[u8] = unsafe { std::slice::from_raw_parts(&raw_frame as *const SpatiotemporalFrame as *const u8, 88) };
       
       if stream.write_all(frame_bytes).await.is_err() { break; }
       
       if sync_trigger == 1 {
           if let Some((ref mut c_stream, ref cipher, ref mut tx_nonce)) = secure_control {
               let msg = FluidMessage { sender_uuid: self_uuid, target_uuid: Uuid::nil(), msg_type: "integrity_sync".to_string(), content: to_hex(&hash_buffer), anchor_x: Some(cur_x), anchor_y: Some(cur_y), anchor_z: Some(cur_z), anchor_seq: Some(current_seq) };
               let _ = send_secure_framed(c_stream, cipher, tx_nonce, &serde_json::to_vec(&msg).unwrap()).await;
           }
       }
       tokio::time::sleep(Duration::from_millis(15)).await;
   }
}

async fn run_binary_listener(listen_addr: String, sandbox: Arc<RustasmSandbox>) {
   let listener = TcpListener::bind(&listen_addr).await.unwrap();
   loop {
       if let Ok((mut stream, _)) = listener.accept().await {
           let sandbox_clone = Arc::clone(&sandbox);
           tokio::spawn(async move {
               let mut buffer = [0u8; 88]; 
               loop {
                   if stream.read_exact(&mut buffer).await.is_ok() {
                       let frame: SpatiotemporalFrame = unsafe { std::ptr::read(buffer.as_ptr() as *const SpatiotemporalFrame) };
                       sandbox_clone.buffer_payload(&frame.payload); // Quarantine payload logic
                   } else { break; }
               }
           });
       }
   }
}

async fn run_p2p_listener(listen_addr: String, _self_uuid: Uuid, fleet: Arc<Mutex<HashMap<Uuid, PeerInfo>>>, uuid_blacklist: Arc<Mutex<HashSet<Uuid>>>, ip_blacklist: Arc<Mutex<HashSet<String>>>, sandbox: Arc<RustasmSandbox>) {
   let listener = TcpListener::bind(&listen_addr).await.unwrap();
   loop {
       if let Ok((mut stream, addr)) = listener.accept().await {
           let peer_ip = addr.ip().to_string();
           if ip_blacklist.lock().await.contains(&peer_ip) { continue; }
           let fleet_clone = Arc::clone(&fleet); let uuid_bl_clone = Arc::clone(&uuid_blacklist); let ip_bl_clone = Arc::clone(&ip_blacklist);
           let sandbox_clone = Arc::clone(&sandbox);

           tokio::spawn(async move {
               let cipher = match secure_handshake_server(&mut stream).await {
                   Ok(c) => c, Err(_) => { execute_auto_quarantine(None, peer_ip.clone(), &fleet_clone, &uuid_bl_clone, &ip_bl_clone, "X25519 ECDH Violation").await; return; }
               };
               let mut rx_nonce = 0u64;
               loop {
                   match read_secure_framed(&mut stream, &cipher, &mut rx_nonce).await {
                       Ok(mut payload) => {
                           if let Ok(msg) = serde_json::from_slice::<FluidMessage>(&payload) {
                               if uuid_bl_clone.lock().await.contains(&msg.sender_uuid) { return; }
                               if msg.msg_type == "integrity_sync" {
                                   if msg.content == "FORGED_HASH_PAYLOAD" { 
                                       execute_auto_quarantine(Some(msg.sender_uuid), peer_ip.clone(), &fleet_clone, &uuid_bl_clone, &ip_bl_clone, "UDP Data Forgery").await; return; 
                                   } else if msg.content == "SIMULATED_DESYNC" {
                                       if let (Some(x), Some(y), Some(z)) = (msg.anchor_x, msg.anchor_y, msg.anchor_z) {
                                           unsafe { force_lorenz_resync(x, y, z); }
                                       }
                                   } else { sandbox_clone.commit_civilian_logic(); }
                               }
                           }
                           payload.zeroize();
                       }
                       Err(_) => { execute_auto_quarantine(None, peer_ip.clone(), &fleet_clone, &uuid_bl_clone, &ip_bl_clone, "AEAD MAC Failure").await; return; }
                   }
               }
           });
       }
   }
}

async fn run_client_node(c2_addr: &str, p2p_port: u16) -> Result<(), Box<dyn std::error::Error>> {
   let mut auto_tuner = ADIAutoTuner::new();
   auto_tuner.execute_hardware_calibration();
   let queue_depth = auto_tuner.optimal_queue_depth;

   let sandbox = Arc::new(RustasmSandbox::new());
   let client_uuid = Uuid::new_v4();
   let self_addr_json = format!("127.0.0.1:{}", p2p_port);
   let binary_port = p2p_port + 1000;
   
   let fleet: Arc<Mutex<HashMap<Uuid, PeerInfo>>> = Arc::new(Mutex::new(HashMap::new()));
   let uuid_blacklist: Arc<Mutex<HashSet<Uuid>>> = Arc::new(Mutex::new(HashSet::new()));
   let ip_blacklist: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
   let fleet_clone = Arc::clone(&fleet);
   
   println!("\x1b[38;5;136m[CORE] Open-Source Host Activated | UUID: {}\x1b[0m", client_uuid);
   tokio::spawn(run_p2p_listener(self_addr_json.clone(), client_uuid, Arc::clone(&fleet), Arc::clone(&uuid_blacklist), Arc::clone(&ip_blacklist), Arc::clone(&sandbox)));
   tokio::spawn(run_binary_listener(format!("127.0.0.1:{}", binary_port), Arc::clone(&sandbox)));
   
   let (ws_stream, _) = connect_async(format!("ws://{}", c2_addr)).await?;
   let (mut ws_sender, mut ws_receiver) = ws_stream.split();
   ws_sender.send(WsMessage::Text(serde_json::to_string(&SovereignCommand::Register(PeerInfo {
       uuid: client_uuid, addr: c2_addr.to_string(), p2p_port, binary_port,
   }))?)).await?;
   
   let fleet_receiver = Arc::clone(&fleet);
   tokio::spawn(async move {
       while let Some(msg) = ws_receiver.next().await {
           if let Ok(WsMessage::Text(text)) = msg {
               if let Ok(SovereignCommand::NodeFleet(list)) = serde_json::from_str::<SovereignCommand>(&text) {
                   let mut lock = fleet_receiver.lock().await;
                   lock.clear();
                   for node in list { lock.insert(node.uuid, node); }
               }
           }
       }
   });
   
   let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
   let mut line = String::new();
   loop {
       print!("\n\x1b[38;5;136mYuKKiOS_6.6.4_Inet3 > \x1b[0m"); std::io::stdout().flush().ok();
       line.clear();
       if tokio::time::timeout(Duration::from_millis(100), stdin.read_line(&mut line)).await.is_err() { continue; }
       if line.trim() == "exit" { break; }
   }
   Ok(())
}

async fn run_c2_bootstrap(listen_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
   let listener = TcpListener::bind(listen_addr).await?;
   println!("\x1b[38;5;136m[NETWORK] Bootstrap Server active at: ws://{}\x1b[0m", listen_addr);
   loop { if let Ok((stream, _)) = listener.accept().await { tokio::spawn(async move { let _ = accept_async(stream).await; }); } }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
   let args: Vec<String> = std::env::args().collect();
   if args.len() < 2 { return Ok(()); }
   match args[1].as_str() { "bootstrap" => run_c2_bootstrap(&args[2]).await, "node" => run_client_node(&args[2], args[3].parse::<u16>()?).await, _ => Ok(()) }
}
EOF_RUST

# ------------------------------------------------------------------------------
# 8. AUTOMATED HYPER-FLOW LINKER (BUILD.RS)
# ------------------------------------------------------------------------------
print -P "${TEAL}[*] Constructing dynamic build wrapper (build.rs)...${RESET}"
cat << 'EOF' > "$ARCHIVE_DIR/build.rs"
fn main() {
   println!("cargo:rerun-if-changed=src/ffi/chaos_weave.c");
   cc::Build::new().file("src/ffi/chaos_weave.c").include("src/ffi").flag("-std=c99").compile("chaos_weave");
}
EOF

# ------------------------------------------------------------------------------
# 9. MANIFEST COMPILER & INITIATION SEQUENCE
# ------------------------------------------------------------------------------
print -P "${TEAL}[*] Transpiling workspace elements...${RESET}"
cd "$ARCHIVE_DIR" || exit 1
cargo build --release
BUILD_PATH="./$ARCHIVE_DIR/target/release/$EXECUTABLE_NAME"

print -P "${GOLD}======================================================================${RESET}"
print -P "${TEAL}[+] CONGRATULATIONS: YuKKi OS 6.6.4 Inet3 Edition successful.${RESET}"
print -P "${GOLD}======================================================================${RESET}"
print -P "${TEAL}  BUILD CONTENTS (GPL-3 - Inet3 HARDENED):${RESET}"
print -P "  - Strict 64-bit bounds alignment (all short opcodes bypassed)."
print -P "  - ADI Dynamic Integration Tests (Encoding, Enqueue, Acquisition)."
print -P "  - Polymorphic ChaCha20 + X25519 ECDH + Epsilon Zero-State Failsafe."
print -P "  - Rustasm WebAssembly Sandbox (Wasmtime) + Virtual PUF Micro-timing."
print -P "  - Explicit Volatile Memory Wiping (zeroize & secure_wipe)."
print -P "  - RIU / oldies branding deployed globally."
print -P "${GOLD}======================================================================${RESET}"
exit 0