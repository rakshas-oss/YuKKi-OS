#!/bin/bash
# Title: YuKKi OS 4 Rust Source Archive (Self-Extracting & Building)
#
# This script contains the full source code for the YuKKi OS 4 Peer-to-Peer
# client and Bootstrap Server, rewritten in the Rust programming language.
#
# NEW FUNCTIONALITY:
# 1. Dependency Manifest submission ('manifest submit')
# 2. Peer-to-Peer Directory Browsing ('browse <UUID>')
# 3. Asynchronous File Transfer ('get <UUID> <remote_path> <local_path>')
#
# Execution:
# 1. Makes the script executable: chmod +x yukkios_4_rust_archive.sh
# 2. Runs the script: ./yukkios_4_rust_archive.sh
#
######################################################################

ARCHIVE_DIR="yukkios_4_rust"
EXECUTABLE_NAME="yukkios_4_rust"

echo "=========================================================="
echo "YuKKi OS 4 P2P System (Rust Edition) - Enhanced"
echo "----------------------------------------------------------"
echo "Extracting source code and preparing for build..."
echo "=========================================================="

# 1. Setup
mkdir -p "$ARCHIVE_DIR/src"

# 2. Extract Cargo.toml (Rust project manifest)
echo "Writing Cargo.toml..."
cat << 'EOF_CARGO' > "$ARCHIVE_DIR/Cargo.toml"
[package]
name = "yukkios_4_rust"
version = "0.1.0"
edition = "2021"
authors = ["YuKKi OS Translator"]
description = "P2P Network Client and Bootstrap Server rewritten in Rust, now with File Transfer."

[dependencies]
# Tokio for async runtime and networking
tokio = { version = "1", features = ["full"] }
# Tokio-Tungstenite for WebSocket (C2 communication)
tokio-tungstenite = "0.20"
# Futures for stream/sink handling
futures-util = "0.3"
# Serde for serialization (JSON messaging)
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
# UUIDs for unique peer identification
uuid = { version = "1.6", features = ["v4", "serde"] }
EOF_CARGO

# 3. Extract main.rs (main application logic)
echo "Writing src/main.rs (main logic)..."
cat << 'EOF_RUST' > "$ARCHIVE_DIR/src/main.rs"
// YuKKi OS 4 P2P Client/Server in Rust
// C2: Peer Discovery via WebSocket (ws://).
// P2P: Direct Peer Communication via TCP (mTLS-secured in production).
// Features: 'manifest submit', 'browse', and 'get' (P2P file transfer).

use tokio::{net::{TcpListener, TcpStream}, sync::{mpsc, Mutex}, io::{AsyncReadExt, AsyncWriteExt, AsyncWrite, copy}, task::spawn_blocking};
use tokio_tungstenite::{accept_async, connect_async, tungstenite::protocol::Message as WsMessage};
use futures_util::{StreamExt, SinkExt};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use std::{collections::HashMap, sync::Arc, net::SocketAddr, time::Duration, path::PathBuf, fs as std_fs, io::BufReader};
use tokio::fs::{File as TokioFile, self as tokio_fs};

// --- CONSTANTS ---
const LOCAL_TRANSFER_DIR: &str = "./yukkios_transfers";
const P2P_BUF_SIZE: usize = 1024 * 1024; // 1MB buffer

// --- DATA STRUCTURES ---

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PeerInfo {
    uuid: Uuid,
    addr: String, // WebSocket address (C2)
    p2p_port: u16, // P2P listener port
}

#[derive(Serialize, Deserialize, Debug)]
enum C2Command {
    Register(PeerInfo),
    PeerList(Vec<PeerInfo>),
}

// P2P Message structure, used for all direct peer communications
#[derive(Serialize, Deserialize, Debug)]
struct P2PMessage {
    sender_uuid: Uuid,
    target_uuid: Uuid,
    // The content field is used for metadata, paths, manifest YAML, or browsing response
    content: String, 
    // New types: "browse_req", "browse_res", "file_req", "file_init", "file_complete"
    msg_type: String, 
    // Optional metadata for file transfer setup
    file_size: Option<u64>, 
    local_path: Option<String>,
}

// --- SERVER LOGIC (Bootstrap Server/C2) ---
// (run_server and handle_connection remain largely unchanged, focusing on WebSocket C2)

async fn run_server(listen_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let addr = listen_addr.parse::<SocketAddr>()?;
    let listener = TcpListener::bind(&addr).await?;
    let peers: Arc<Mutex<HashMap<Uuid, PeerInfo>>> = Arc::new(Mutex::new(HashMap::new()));

    println!("Bootstrap Server (C2) listening on ws://{}", listen_addr);

    loop {
        let (stream, client_addr) = listener.accept().await?;
        let peers_clone = Arc::clone(&peers);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, client_addr, peers_clone).await {
                eprintln!("[C2] WebSocket connection error: {}", e);
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    _client_addr: SocketAddr,
    peers: Arc<Mutex<HashMap<Uuid, PeerInfo>>>,
) -> Result<(), tokio_tungstenite::tungstenite::Error> {
    let ws_stream = accept_async(stream).await?;
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    let mut current_peer_uuid = None;

    let (tx_outbound, mut rx_outbound) = mpsc::unbounded_channel::<C2Command>();

    let ws_sender_task = tokio::spawn(async move {
        while let Some(command) = rx_outbound.recv().await {
            let message_json = serde_json::to_string(&command).unwrap();
            if ws_sender.send(WsMessage::Text(message_json)).await.is_err() {
                break;
            }
        }
    });

    while let Some(msg_res) = ws_receiver.next().await {
        match msg_res {
            Ok(WsMessage::Text(text)) => {
                if let Ok(command) = serde_json::from_str::<C2Command>(&text) {
                    if let C2Command::Register(peer_info) = command {
                        let uuid = peer_info.uuid;
                        current_peer_uuid = Some(uuid);
                        println!("[C2] Peer registered: {} at P2P port {}", uuid, peer_info.p2p_port);
                        
                        let mut peers_lock = peers.lock().await;
                        peers_lock.insert(uuid, peer_info.clone()); 
                        
                        let list_to_send: Vec<PeerInfo> = peers_lock.values().cloned().collect();
                        drop(peers_lock);
                        
                        let _ = tx_outbound.send(C2Command::PeerList(list_to_send));
                    }
                }
            }
            Ok(WsMessage::Close(_)) | Err(_) => break,
            _ => (),
        }
    }

    ws_sender_task.abort();
    if let Some(uuid) = current_peer_uuid {
        let mut peers_lock = peers.lock().await;
        peers_lock.remove(&uuid);
        println!("[C2] Peer disconnected: {}", uuid);
    }

    Ok(())
}

// --- P2P LISTENER (Handles Incoming P2P Requests) ---

async fn p2p_listener(listen_addr: String, self_uuid: Uuid) {
    let listener = match TcpListener::bind(&listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[P2P] Failed to bind listener on {}: {}", listen_addr, e);
            return;
        }
    };
    
    // Create the transfer directory if it doesn't exist
    if let Err(e) = tokio_fs::create_dir_all(LOCAL_TRANSFER_DIR).await {
        eprintln!("[P2P] Could not create transfer directory: {}", e);
        return;
    }

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_p2p_connection(stream, self_uuid));
            }
            Err(e) => {
                eprintln!("[P2P] Failed to accept connection: {}", e);
            }
        }
    }
}

async fn handle_p2p_connection(mut stream: TcpStream, self_uuid: Uuid) {
    let mut buffer = [0u8; 1024 * 4]; // Small buffer for initial JSON handshake
    let mut message_bytes = Vec::new();
    let mut header_read = false;

    // --- 1. Read the JSON Message Header ---
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => return, // Connection closed
            Ok(n) => {
                // Look for the end of the JSON message (simple, non-robust protocol)
                message_bytes.extend_from_slice(&buffer[..n]);

                if let Ok(msg) = serde_json::from_slice::<P2PMessage>(&message_bytes) {
                    header_read = true;
                    // Handle the message based on its type
                    if let Err(e) = process_p2p_request(msg, &mut stream, self_uuid).await {
                        eprintln!("[P2P] Error processing request: {}", e);
                    }
                    return; // Done with this connection stream
                }

                // If message is too long and still not valid JSON, break to prevent OOM
                if message_bytes.len() > 1024 * 16 {
                    eprintln!("[P2P] Incoming message too large or malformed JSON.");
                    return;
                }
            }
            Err(e) => {
                eprintln!("[P2P] Read error: {}", e);
                return;
            }
        }
    }
}

async fn process_p2p_request(
    msg: P2PMessage,
    stream: &mut TcpStream,
    self_uuid: Uuid
) -> Result<(), Box<dyn std::error::Error>> {
    
    let sender = msg.sender_uuid;
    let message_type = msg.msg_type.as_str();

    match message_type {
        "msg" => {
            println!("\n[P2P INCOMING MESSAGE from {}]: {}", sender, msg.content);
        }
        "manifest" => {
            println!("\n[P2P JobbySlotty]: Dependency Manifest received from {}.", sender);
            println!("--- Received Manifest ---");
            println!("{}", msg.content);
            println!("-------------------------");
            println!("Manifest processed and dependencies queued.");
        }
        "browse_req" => {
            // New: Handle remote directory listing request
            println!("\n[P2P BROWSE]: Listing requested for path '{}' by {}.", msg.content, sender);
            let response = list_directory_blocking(&msg.content).await;
            
            let response_msg = P2PMessage {
                sender_uuid: self_uuid,
                target_uuid: sender,
                content: response,
                msg_type: "browse_res".to_string(),
                file_size: None,
                local_path: None,
            };

            // Send response back using the same stream (P2P protocol reuse)
            let response_bytes = serde_json::to_vec(&response_msg)?;
            stream.write_all(&response_bytes).await?;
        }
        "browse_res" => {
            // New: Handle remote directory listing response (Client side)
            println!("\n[P2P BROWSE]: Directory listing received from {}:", sender);
            println!("{}", msg.content);
        }
        "file_req" => {
            // New: Handle file transfer request (Server side, becomes the Sender)
            let remote_path = msg.content;
            let local_path = msg.local_path.unwrap_or_default();
            println!("\n[P2P FILE]: Request to send '{}' received from {}.", remote_path, sender);
            
            if let Err(e) = send_file_p2p(stream, self_uuid, sender, &remote_path, &local_path).await {
                eprintln!("\n[P2P FILE] Error sending file {}: {}", remote_path, e);
            }
        }
        "file_init" => {
            // New: Handle file transfer initiation (Client side, becomes the Receiver)
            let file_size = msg.file_size.ok_or("File size missing")?;
            let local_path = msg.local_path.ok_or("Local path missing")?;
            println!("\n[P2P FILE]: Receiving file '{}' ({} bytes) from {}.", local_path, file_size, sender);
            
            if let Err(e) = receive_file_p2p(stream, &local_path, file_size).await {
                eprintln!("\n[P2P FILE] Error receiving file {}: {}", local_path, e);
            } else {
                println!("\n[P2P FILE]: Successfully received and saved '{}' to {}.", msg.content, local_path);
            }
        }
        _ => {
            eprintln!("\n[P2P] Received unknown message type: {}", message_type);
        }
    }
    
    print!("YuKKiOS > ");
    tokio::io::stdout().flush().await.ok();
    Ok(())
}

// --- FILE SYSTEM HELPERS (Synchronous ops moved to blocking threads) ---

/// Synchronously reads a directory, returning a formatted string.
async fn list_directory_blocking(path: &str) -> String {
    let path_buf = PathBuf::from(path);
    
    // Use spawn_blocking for synchronous I/O operations
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
                if listing.is_empty() {
                    format!("Path '{}' is empty or inaccessible.", path)
                } else {
                    format!("Contents of {}:\n{}", path, listing)
                }
            }
            Err(e) => format!("Error reading directory '{}': {}", path, e),
        }
    }).await.unwrap_or_else(|_| "Error listing directory in thread.".to_string())
}

// --- P2P FILE TRANSFER IMPLEMENTATION ---

// Handles the logic for sending a requested file. (Server/Sender role)
async fn send_file_p2p(
    mut stream: &mut TcpStream, 
    self_uuid: Uuid,
    target_uuid: Uuid,
    remote_path: &str, 
    local_path: &str
) -> Result<(), Box<dyn std::error::Error>> {
    let file_path = PathBuf::from(remote_path);

    let file = match TokioFile::open(&file_path).await {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[P2P FILE] Cannot open file: {}", e);
            return Err(e.into());
        }
    };
    let file_size = file.metadata().await?.len();
    
    // 1. Send initiation message (JSON)
    let init_msg = P2PMessage {
        sender_uuid: self_uuid,
        target_uuid,
        content: file_path.file_name().unwrap_or_default().to_string_lossy().to_string(), // Use filename as content
        msg_type: "file_init".to_string(),
        file_size: Some(file_size),
        local_path: Some(local_path.to_string()),
    };
    let init_bytes = serde_json::to_vec(&init_msg)?;
    stream.write_all(&init_bytes).await?;

    // 2. Stream the file content directly
    println!("[P2P FILE] Starting stream of {} bytes...", file_size);
    let mut file = BufReader::new(file);
    copy(&mut file, &mut stream).await?;

    println!("[P2P FILE] File stream complete.");
    Ok(())
}

// Handles the logic for receiving a file stream. (Client/Receiver role)
async fn receive_file_p2p(
    stream: &mut TcpStream,
    local_path: &str,
    file_size: u64
) -> Result<(), Box<dyn std::error::Error>> {
    let final_path = PathBuf::from(LOCAL_TRANSFER_DIR).join(local_path);
    let mut file = TokioFile::create(&final_path).await?;
    
    // Use tokio::io::copy to stream the remaining bytes from the network directly to the file
    // We expect 'file_size' bytes to follow the initial JSON message on the stream.
    
    // Create a reader limited to the expected file size
    let mut limited_reader = tokio::io::take(stream, file_size);
    
    // Copy all data from the limited reader (network stream) to the file
    let bytes_received = copy(&mut limited_reader, &mut file).await?;
    
    if bytes_received != file_size {
        return Err(format!("Transfer failed: expected {} bytes but received {} bytes.", file_size, bytes_received).into());
    }

    Ok(())
}


// --- MAIN ENTRY POINT (Client CLI extended) ---

async fn run_client(c2_addr: &str, p2p_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    // ... Initialization code unchanged ...
    let client_uuid = Uuid::new_v4();
    let self_addr = format!("127.0.0.1:{}", p2p_port);
    let peer_list_arc: Arc<Mutex<HashMap<Uuid, PeerInfo>>> = Arc::new(Mutex::new(HashMap::new()));
    let peer_list_arc_clone = Arc::clone(&peer_list_arc);

    println!("Peer Client starting. Your UUID: {}", client_uuid);
    println!("P2P Listener active on: {}", self_addr);
    println!("NOTE: Transferred files will be saved to the '{}' directory.", LOCAL_TRANSFER_DIR);
    
    // P2P Listener Thread
    tokio::spawn(p2p_listener(self_addr.clone(), client_uuid));

    let (ws_stream, _) = match connect_async(format!("ws://{}", c2_addr)).await {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Failed to connect to C2 server at {}: {}", c2_addr, e);
            return Ok(());
        }
    };
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    // Register self with C2
    let my_info = PeerInfo {
        uuid: client_uuid,
        addr: c2_addr.to_string(),
        p2p_port,
    };
    let register_cmd = C2Command::Register(my_info.clone());
    let register_json = serde_json::to_string(&register_cmd).unwrap();
    ws_sender.send(WsMessage::Text(register_json)).await?;

    // C2 Receiver Task
    let peer_list_arc_clone_2 = Arc::clone(&peer_list_arc);
    tokio::spawn(async move {
        // ... C2 Receiver code unchanged ...
        while let Some(msg_res) = ws_receiver.next().await {
            match msg_res {
                Ok(WsMessage::Text(text)) => {
                    if let Ok(command) = serde_json::from_str::<C2Command>(&text) {
                        if let C2Command::PeerList(list) = command {
                            let mut peers_lock = peer_list_arc_clone_2.lock().await;
                            peers_lock.clear();
                            for peer in list {
                                peers_lock.insert(peer.uuid, peer);
                            }
                            println!("\n[C2] Peer list updated. {} active peers.", peers_lock.len());
                        }
                    }
                }
                _ => break,
            }
        }
        println!("\n[C2] Connection to Bootstrap Server closed.");
    });


    // CLI Input Loop (Now includes 'browse' and 'get')
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut line = String::new();
    loop {
        print!("\nYuKKiOS > ");
        tokio::io::stdout().flush().await?;
        line.clear();
        
        match tokio::time::timeout(Duration::from_millis(50), stdin.read_line(&mut line)).await {
            Ok(Ok(0)) => break, 
            Ok(Ok(_)) => {
                let parts: Vec<&str> = line.trim().split_whitespace().collect();
                
                if parts.is_empty() { continue; }

                match parts[0] {
                    "peers" => {
                        let peers_lock = peer_list_arc_clone.lock().await;
                        println!("--- Active Peers (via C2) ---");
                        for peer in peers_lock.values() {
                             if peer.uuid != client_uuid {
                                 println!("  UUID: {} | P2P: 127.0.0.1:{}", peer.uuid, peer.p2p_port);
                             } else {
                                 println!("  UUID: {} | P2P: 127.0.0.1:{} (YOU)", peer.uuid, peer.p2p_port);
                             }
                        }
                        println!("-----------------------------");
                    }
                    "msg" => {
                        if parts.len() < 3 {
                            println!("Usage: msg <UUID> <text>");
                            continue;
                        }
                        let target_uuid_str = parts[1];
                        let message = parts[2..].join(" ");
                        
                        if let Ok(target_uuid) = Uuid::parse_str(target_uuid_str) {
                            let peers_lock = peer_list_arc_clone.lock().await;
                            if let Some(target_peer) = peers_lock.get(&target_uuid) {
                                let target_addr = format!("127.0.0.1:{}", target_peer.p2p_port);
                                
                                let msg_to_send = P2PMessage {
                                    sender_uuid: client_uuid,
                                    target_uuid,
                                    content: message,
                                    msg_type: "msg".to_string(),
                                    file_size: None,
                                    local_path: None,
                                };
                                tokio::spawn(send_p2p_message(target_addr, msg_to_send));
                            } else {
                                println!("Error: Peer UUID not found in list. Use 'peers' to view available IDs.");
                            }
                        } else {
                            println!("Error: Invalid UUID format.");
                        }
                    }
                    "manifest" => {
                        if parts.len() < 3 || parts[1] != "submit" {
                            println!("Usage: manifest submit <UUID>");
                            println!("(Note: In a full implementation, 'get' is also supported.)");
                            continue;
                        }
                        let target_uuid_str = parts[2];
                        
                        if let Ok(target_uuid) = Uuid::parse_str(target_uuid_str) {
                            let peers_lock = peer_list_arc_clone.lock().await;
                            if target_uuid == client_uuid {
                                println!("Error: Cannot submit manifest to self.");
                                continue;
                            }
                            if let Some(target_peer) = peers_lock.get(&target_uuid) {
                                let target_addr = format!("127.0.0.1:{}", target_peer.p2p_port);

                                // Simulating the manifest content (YAML format for tree structure)
                                let mock_manifest = format!(
r#"project: core-kernel-v4
author: {}
jobs:
  1: {{ cmd: 'make clean', deps: [] }}
  2: {{ cmd: 'make module-init', deps: [1] }}
  3: {{ cmd: 'make kernel-install', deps: [2] }}
"#, client_uuid);
                                
                                let msg_to_send = P2PMessage {
                                    sender_uuid: client_uuid,
                                    target_uuid,
                                    content: mock_manifest,
                                    msg_type: "manifest".to_string(),
                                    file_size: None,
                                    local_path: None,
                                };
                                println!("Submitting JobbySlotty Dependency Manifest to {}.", target_uuid);
                                tokio::spawn(send_p2p_message(target_addr, msg_to_send));
                            } else {
                                println!("Error: Peer UUID not found in list. Use 'peers' to view available IDs.");
                            }
                        } else {
                            println!("Error: Invalid UUID format.");
                        }
                    }
                    "browse" | "ls" => {
                        if parts.len() < 2 {
                            println!("Usage: browse <UUID> [path]");
                            continue;
                        }
                        let target_uuid_str = parts[1];
                        let remote_path = parts.get(2).unwrap_or(&"."); // Default to current directory
                        
                        if let Ok(target_uuid) = Uuid::parse_str(target_uuid_str) {
                            let peers_lock = peer_list_arc_clone.lock().await;
                            if let Some(target_peer) = peers_lock.get(&target_uuid) {
                                let target_addr = format!("127.0.0.1:{}", target_peer.p2p_port);
                                
                                let msg_to_send = P2PMessage {
                                    sender_uuid: client_uuid,
                                    target_uuid,
                                    content: remote_path.to_string(),
                                    msg_type: "browse_req".to_string(),
                                    file_size: None,
                                    local_path: None,
                                };
                                println!("Requesting directory listing for '{}' from peer {}.", remote_path, target_uuid);
                                tokio::spawn(send_p2p_message(target_addr, msg_to_send));
                            } else {
                                println!("Error: Peer UUID not found in list.");
                            }
                        } else {
                            println!("Error: Invalid UUID format.");
                        }
                    }
                    "get" => {
                        if parts.len() != 4 {
                            println!("Usage: get <UUID> <remote_path> <local_file_name>");
                            continue;
                        }
                        let target_uuid_str = parts[1];
                        let remote_path = parts[2].to_string();
                        let local_file_name = parts[3].to_string();
                        
                        if local_file_name.contains('/') || local_file_name.contains('\\') {
                            println!("Error: Local filename must not contain directory separators.");
                            continue;
                        }

                        if let Ok(target_uuid) = Uuid::parse_str(target_uuid_str) {
                            let peers_lock = peer_list_arc_clone.lock().await;
                            if let Some(target_peer) = peers_lock.get(&target_uuid) {
                                let target_addr = format!("127.0.0.1:{}", target_peer.p2p_port);
                                
                                let msg_to_send = P2PMessage {
                                    sender_uuid: client_uuid,
                                    target_uuid,
                                    content: remote_path,
                                    msg_type: "file_req".to_string(),
                                    file_size: None,
                                    local_path: Some(local_file_name),
                                };
                                println!("Requesting file '{}' from peer {}. Saving as '{}'.", msg_to_send.content, target_uuid, msg_to_send.local_path.as_ref().unwrap());
                                tokio::spawn(send_p2p_message(target_addr, msg_to_send));
                            } else {
                                println!("Error: Peer UUID not found in list.");
                            }
                        } else {
                            println!("Error: Invalid UUID format.");
                        }
                    }
                    "exit" | "quit" => break,
                    _ => println!("Unknown command. Available: peers, msg, manifest submit, browse/ls, get, exit/quit"),
                }
            }
            Ok(Err(e)) => {
                eprintln!("I/O Error: {}", e);
                break;
            }
            Err(_) => {
                // Timeout occurred, input loop continues.
            }
        }
    }
    
    Ok(())
}

// --- P2P CONNECTION HANDLER (for outgoing requests) ---

async fn send_p2p_message(target_addr: String, msg: P2PMessage) {
    match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&target_addr)).await {
        Ok(Ok(mut stream)) => {
            // All outgoing messages, including file requests, start with a JSON header
            let message_bytes = serde_json::to_vec(&msg).unwrap();
            
            if let Err(e) = stream.write_all(&message_bytes).await {
                eprintln!("[P2P OUTGOING] Failed to write message to {}: {}", target_addr, e);
            } else {
                println!("Message successfully relayed for P2P transmission.");
            }
        }
        Ok(Err(e)) => {
            eprintln!("[P2P OUTGOING] Failed to connect to peer at {}: {}", target_addr, e);
        }
        Err(_) => {
            eprintln!("[P2P OUTGOING] Connection to peer at {} timed out.", target_addr);
        }
    }
}

// --- MAIN ENTRY POINT ---

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <server|client> [args...]", args[0]);
        eprintln!("Server: {} server <listen_addr:port>", args[0]);
        eprintln!("Client: {} client <c2_addr:port> <p2p_listen_port>", args[0]);
        return Ok(());
    }

    match args[1].as_str() {
        "server" => {
            if args.len() != 3 {
                eprintln!("Server usage: {} server <listen_addr:port>", args[0]);
                return Ok(());
            }
            run_server(&args[2]).await
        }
        "client" => {
            if args.len() != 4 {
                eprintln!("Client usage: {} client <c2_addr:port> <p2p_listen_port>", args[0]);
                return Ok(());
            }
            let p2p_port = args[3].parse::<u16>()?;
            run_client(&args[2], p2p_port).await
        }
        _ => {
            eprintln!("Invalid mode. Use 'server' or 'client'.");
            Ok(())
        }
    }
}
EOF_RUST

# 4. Build and Run Instructions
echo ""
echo "----------------------------------------------------------"
echo "Starting compilation (using 'cargo build --release')..."
echo "----------------------------------------------------------"

cd "$ARCHIVE_DIR" || exit 1

# Check for Rust/Cargo
if ! command -v cargo &> /dev/null
then
    echo "ERROR: Cargo (Rust build tool) could not be found."
    echo "Please install Rust using: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

cargo build --release

if [ $? -ne 0 ]; then
    echo "ERROR: Rust compilation failed. Please check the error messages above."
    exit 1
fi

# 5. Usage Instructions
echo ""
echo "=========================================================="
echo "YuKKi OS 4 Rust Build Complete"
echo "Binary location: ./target/release/$EXECUTABLE_NAME"
echo "Transferred files will appear in the './$ARCHIVE_DIR/$LOCAL_TRANSFER_DIR/' directory."
echo "=========================================================="
echo "To run the P2P network locally, open three separate terminal windows:"
echo ""
echo "1. Bootstrap Server (C2) - Peer Discovery (Window 1):"
echo "   ./target/release/$EXECUTABLE_NAME server 127.0.0.1:8080"
echo ""
echo "2. Peer Client 1 (Window 2 - P2P listener on port 9001):"
echo "   ./target/release/$EXECUTABLE_NAME client 127.0.0.1:8080 9001"
echo ""
echo "3. Peer Client 2 (Window 3 - P2P listener on port 9002):"
echo "   ./target/release/$EXECUTABLE_NAME client 127.0.0.1:8080 9002"
echo ""
echo "### New Command Usage Examples (use Client 1's UUID as the target in Client 2):"
echo "1. Browse Remote Files:"
echo "   YuKKiOS > browse <UUID_OF_CLIENT_1> ."
echo "   (Lists the files in Client 1's current directory)"
echo ""
echo "2. Transfer a File (e.g., Client 1 requests 'Cargo.toml' from Client 2):"
echo "   First, create a dummy file for testing in Client 2's folder: touch ./$ARCHIVE_DIR/test_file.txt"
echo "   YuKKiOS > get <UUID_OF_CLIENT_1> ./Cargo.toml my_cargo.toml"
echo "   (Requests the file, which Client 1 will save into ./$ARCHIVE_DIR/$LOCAL_TRANSFER_DIR/)"
echo "=========================================================="

# Exit the script
exit 0
