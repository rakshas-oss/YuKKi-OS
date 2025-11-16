#!/bin/bash
# Title: YuKKi OS 4 Rust Source Archive (Self-Extracting & Building)
#
# This script contains the full source code for the YuKKi OS 4 Peer-to-Peer
# client and Bootstrap Server, rewritten in the Rust programming language.
#
# The code now includes support for the new "manifest submit" command, 
# allowing clients to share Dependency Manifest structures over the P2P channel.
#
# Execution:
# 1. Makes the script executable: chmod +x yukkios_4_rust_archive.sh
# 2. Runs the script: ./yukkios_4_rust_archive.sh
#
# The script will:
# 1. Create a directory named 'yukkios_4_rust'.
# 2. Extract Cargo.toml and src/main.rs into the directory.
# 3. Check for the 'cargo' build tool (Rust).
# 4. Compile the project using 'cargo build --release'.
# 5. Print final execution instructions.
#
######################################################################

ARCHIVE_DIR="yukkios_4_rust"

echo "=========================================================="
echo "YuKKi OS 4 P2P System (Rust Edition)"
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
description = "P2P Network Client and Bootstrap Server rewritten in Rust."

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
// This version includes the new 'manifest' command for dependency exchange.

use tokio::{net::{TcpListener, TcpStream}, sync::{mpsc, Mutex}, io::{AsyncReadExt, AsyncWriteExt}};
use tokio_tungstenite::{accept_async, connect_async, tungstenite::protocol::Message as WsMessage};
use futures_util::{StreamExt, SinkExt};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use std::{collections::HashMap, sync::Arc, net::SocketAddr, time::Duration};

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

// P2P Message structure, used for all direct peer communications (msg, manifest, file, job)
#[derive(Serialize, Deserialize, Debug)]
struct P2PMessage {
    sender_uuid: Uuid,
    target_uuid: Uuid, // For private messages
    content: String,
    msg_type: String, // "msg", "say", "file", "job", "manifest"
}

// --- SERVER LOGIC (Bootstrap Server/C2) ---

async fn run_server(listen_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let addr = listen_addr.parse::<SocketAddr>()?;
    let listener = TcpListener::bind(&addr).await?;
    // Hashmap to store active peers, protected by Arc and Mutex for concurrent access
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
    let mut current_peer_uuid = None; // Track the UUID of the connected peer

    // Channel for sending outbound C2 messages (like peer list updates)
    let (tx_outbound, mut rx_outbound) = mpsc::unbounded_channel::<C2Command>();

    // Sender task: forwards C2 commands from the channel to the WebSocket
    let ws_sender_task = tokio::spawn(async move {
        while let Some(command) = rx_outbound.recv().await {
            let message_json = serde_json::to_string(&command).unwrap();
            if ws_sender.send(WsMessage::Text(message_json)).await.is_err() {
                break;
            }
        }
    });

    // Receiver task: handles incoming commands (mainly Register)
    while let Some(msg_res) = ws_receiver.next().await {
        match msg_res {
            Ok(WsMessage::Text(text)) => {
                if let Ok(command) = serde_json::from_str::<C2Command>(&text) {
                    if let C2Command::Register(peer_info) = command {
                        let uuid = peer_info.uuid;
                        current_peer_uuid = Some(uuid);
                        println!("[C2] Peer registered: {} at P2P port {}", uuid, peer_info.p2p_port);
                        
                        let mut peers_lock = peers.lock().await;
                        peers_lock.insert(uuid, peer_info.clone()); // Store the new peer
                        
                        // Send the full list back to the newly registered peer
                        let list_to_send: Vec<PeerInfo> = peers_lock.values().cloned().collect();
                        drop(peers_lock);
                        
                        // Send the updated list to the new peer
                        let _ = tx_outbound.send(C2Command::PeerList(list_to_send));
                    }
                }
            }
            Ok(WsMessage::Close(_)) | Err(_) => break,
            _ => (), // Ignore Ping, Pong, Binary messages
        }
    }

    // Cleanup and termination
    ws_sender_task.abort();
    if let Some(uuid) = current_peer_uuid {
        let mut peers_lock = peers.lock().await;
        peers_lock.remove(&uuid);
        println!("[C2] Peer disconnected: {}", uuid);
    }

    Ok(())
}


// --- CLIENT LOGIC (Peer Client) ---

async fn run_client(c2_addr: &str, p2p_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let client_uuid = Uuid::new_v4();
    let self_addr = format!("127.0.0.1:{}", p2p_port);
    let peer_list_arc: Arc<Mutex<HashMap<Uuid, PeerInfo>>> = Arc::new(Mutex::new(HashMap::new()));
    let peer_list_arc_clone = Arc::clone(&peer_list_arc);

    println!("Peer Client starting. Your UUID: {}", client_uuid);
    println!("P2P Listener active on: {}", self_addr);
    
    // P2P Listener Thread
    tokio::spawn(p2p_listener(self_addr.clone(), client_uuid));

    // C2 Connection and Registration
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

    // C2 Receiver Task: Handles incoming PeerLists
    let peer_list_arc_clone_2 = Arc::clone(&peer_list_arc);
    tokio::spawn(async move {
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


    // CLI Input Loop (Simulates the command line interface)
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut line = String::new();
    loop {
        print!("\nYuKKiOS > ");
        tokio::io::stdout().flush().await?;
        line.clear();
        
        // Timeout allows the receiver task to process C2 updates asynchronously
        match tokio::time::timeout(Duration::from_millis(50), stdin.read_line(&mut line)).await {
            Ok(Ok(0)) => break, // EOF
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
                                };
                                // Spawn task to send message P2P
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
                                    msg_type: "manifest".to_string(), // The new manifest type
                                };
                                // Spawn task to send message P2P
                                println!("Submitting JobbySlotty Dependency Manifest to {}.", target_uuid);
                                tokio::spawn(send_p2p_message(target_addr, msg_to_send));
                            } else {
                                println!("Error: Peer UUID not found in list. Use 'peers' to view available IDs.");
                            }
                        } else {
                            println!("Error: Invalid UUID format.");
                        }
                    }
                    "exit" | "quit" => break,
                    _ => println!("Unknown command. Available: peers, msg <UUID> <text>, manifest submit <UUID>, exit/quit"),
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

// --- P2P LISTENER (TCP/mTLS Placeholder) ---

async fn p2p_listener(listen_addr: String, _self_uuid: Uuid) {
    // NOTE: In a production environment, this should be wrapped in mTLS (Mutual TLS)
    // using a crate like `tokio-rustls` to ensure compliance and security.
    // The current implementation is simple TCP for demonstration.
    let listener = match TcpListener::bind(&listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[P2P] Failed to bind listener on {}: {}", listen_addr, e);
            return;
        }
    };
    
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_p2p_connection(stream));
            }
            Err(e) => {
                eprintln!("[P2P] Failed to accept connection: {}", e);
            }
        }
    }
}

async fn handle_p2p_connection(mut stream: TcpStream) {
    // Read all bytes until EOF or connection close (simple stream protocol)
    let mut buffer = Vec::new();
    if let Ok(n) = stream.read_to_end(&mut buffer).await {
        if n > 0 {
            if let Ok(msg) = serde_json::from_slice::<P2PMessage>(&buffer) {
                
                match msg.msg_type.as_str() {
                    "msg" => {
                        // This simulates the client receiving a message
                        println!("\n[P2P INCOMING MESSAGE from {}]: {}", msg.sender_uuid, msg.content);
                    }
                    "manifest" => {
                        println!("\n[P2P JobbySlotty]: Dependency Manifest received from {}.", msg.sender_uuid);
                        println!("--- Received Manifest ---");
                        println!("{}", msg.content);
                        println!("-------------------------");
                        println!("Manifest processed and dependencies queued.");
                    }
                    _ => {
                        eprintln!("\n[P2P] Received unknown message type: {}", msg.msg_type);
                    }
                }
                
                print!("YuKKiOS > ");
                // Flush stdout to show the prompt again immediately
                tokio::io::stdout().flush().await.ok();
            } else {
                eprintln!("[P2P] Received malformed message.");
            }
        }
    }
}

async fn send_p2p_message(target_addr: String, msg: P2PMessage) {
    // NOTE: This connection should also use mTLS for security.
    match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&target_addr)).await {
        Ok(Ok(mut stream)) => {
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
echo "This may take a few minutes on the first run as dependencies are downloaded."
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
echo "Binary location: ./target/release/yukkios_4_rust"
echo "=========================================================="
echo "To run the P2P network locally, open three separate terminal windows:"
echo ""
echo "1. Bootstrap Server (C2) - Peer Discovery (Window 1):"
echo "   ./target/release/yukkios_4_rust server 127.0.0.1:8080"
echo ""
echo "2. Peer Client 1 (Window 2 - P2P listener on port 9001):"
echo "   ./target/release/yukkios_4_rust client 127.0.0.1:8080 9001"
echo ""
echo "3. Peer Client 2 (Window 3 - P2P listener on port 9002):"
echo "   ./target/release/yukkios_4_rust client 127.0.0.1:8080 9002"
echo ""
echo "In the Peer Client windows, use 'peers' to list known UUIDs,"
echo "use 'msg <UUID> <text>' to send a direct P2P message,"
echo "and use 'manifest submit <UUID>' to share a dependency tree."
echo "=========================================================="

# Exit the script
exit 0
