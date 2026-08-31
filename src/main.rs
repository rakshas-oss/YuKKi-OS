mod adi_auto_tune;
mod wasm_sandbox;

use tokio::{net::{TcpListener, TcpStream}, sync::{mpsc, Mutex}, io::{AsyncReadExt, AsyncWriteExt, AsyncBufReadExt}};
use std::io::Write;
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

#[link(name = "chaos_weave", kind = "static")]
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
       print!("\n\x1b[38;5;136mYuKKiOS_6.6.6_Inet3 > \x1b[0m"); std::io::stdout().flush().ok();
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
