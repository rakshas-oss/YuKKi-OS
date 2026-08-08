mod crypto;

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs as std_fs,
    io::Write as _,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    fs::{self as tokio_fs, File as TokioFile},
    io::{copy, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Mutex},
    task::spawn_blocking,
};
use tokio_tungstenite::{
    accept_async, connect_async, tungstenite::protocol::Message as WsMessage,
};
use uuid::Uuid;

const LOCAL_TRANSFER_DIR: &str = "./yukkios_transfers";
const LORENZ_SIGMA: f64 = 10.0;
const LORENZ_RHO: f64 = 28.0;
const LORENZ_BETA: f64 = 8.33333333333;

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

unsafe extern "C" {
    fn chaos_engine_init(sigma: f64, rho: f64, beta: f64);
    fn weave_spatiotemporal_frame(
        seq: u64,
        payload_src: *const u8,
        out_frame: *mut SpatiotemporalFrame,
    );
}

pub struct ChaosController {
    current_seq: u64,
}

impl ChaosController {
    pub fn new() -> Self {
        unsafe { chaos_engine_init(LORENZ_SIGMA, LORENZ_RHO, LORENZ_BETA) };
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

async fn run_c2_bootstrap(listen_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let addr = listen_addr.parse::<SocketAddr>()?;
    let listener = TcpListener::bind(&addr).await?;
    let peers: Arc<Mutex<HashMap<Uuid, PeerInfo>>> = Arc::new(Mutex::new(HashMap::new()));
    println!(
        "\x1b[38;5;136m[NETWORK] Bootstrap Server active at: ws://{}\x1b[0m",
        listen_addr
    );

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
            if ws_sender.send(WsMessage::Text(json.into())).await.is_err() {
                break;
            }
        }
    });

    while let Some(msg) = ws_receiver.next().await {
        match msg {
            Ok(WsMessage::Text(text)) => {
                if let Ok(SovereignCommand::Register(info)) =
                    serde_json::from_str::<SovereignCommand>(&text)
                {
                    peer_uuid = Some(info.uuid);
                    println!(
                        "\x1b[38;5;37m[C2] Peer node accepted: {} (P2P: {} | BIN: {})\x1b[0m",
                        info.uuid, info.p2p_port, info.binary_port
                    );
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

async fn send_p2p_message(
    stream: &mut TcpStream,
    message: &FluidMessage,
) -> Result<(), Box<dyn std::error::Error>> {
    let encoded = serde_json::to_vec(message)?;
    let payload = crypto::encrypt_payload(&encoded)?;
    send_framed(stream, &payload).await?;
    Ok(())
}

async fn list_directory_blocking(path: &str) -> String {
    let path_buf = PathBuf::from(path);
    let path_display = path.to_string();
    spawn_blocking(move || {
        let mut listing = String::new();
        match std_fs::read_dir(&path_buf) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let Ok(metadata) = entry.metadata() else {
                        continue;
                    };
                    let file_name = entry.file_name().into_string().unwrap_or_default();
                    let file_type = if metadata.is_dir() { "[DIR]" } else { "[FILE]" };
                    let size = if metadata.is_file() {
                        format!(" ({} bytes)", metadata.len())
                    } else {
                        String::new()
                    };
                    listing.push_str(&format!("{} {}{}\n", file_type, file_name, size));
                }
                if listing.is_empty() {
                    format!("Path '{}' is empty or inaccessible.", path_display)
                } else {
                    format!("Contents of {}:\n{}", path_display, listing)
                }
            }
            Err(e) => format!("Error reading directory '{}': {}", path_display, e),
        }
    })
    .await
    .unwrap_or_else(|_| "Error listing directory in thread.".to_string())
}

async fn send_file_p2p(
    stream: &mut TcpStream,
    self_uuid: Uuid,
    target_uuid: Uuid,
    remote_path: &str,
    local_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_path = PathBuf::from(remote_path);
    let mut file = TokioFile::open(&file_path).await?;
    let file_size = file.metadata().await?.len();

    let init_msg = FluidMessage {
        sender_uuid: self_uuid,
        target_uuid,
        content: file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        msg_type: "file_init".to_string(),
        file_size: Some(file_size),
        local_path: Some(local_path.to_string()),
    };
    send_p2p_message(stream, &init_msg).await?;

    println!("\x1b[38;5;37m[P2P FILE] Streaming {} bytes...\x1b[0m", file_size);
    copy(&mut file, stream).await?;
    Ok(())
}

async fn receive_file_p2p(
    stream: &mut TcpStream,
    local_path: &str,
    file_size: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let final_path = PathBuf::from(LOCAL_TRANSFER_DIR).join(local_path);
    let mut file = TokioFile::create(&final_path).await?;
    let mut limited_reader = stream.take(file_size);
    copy(&mut limited_reader, &mut file).await?;
    Ok(())
}

async fn handle_local_laminar_stream(mut stream: TcpStream, _self_uuid: Uuid) {
    let mut controller = ChaosController::new();
    println!("\x1b[38;5;136m[STREAM] Launching 6D Weave session (Binary Mode)...\x1b[0m");

    for _ in 0..100 {
        let payload_fragment = [
            0x59, 0x75, 0x4B, 0x4B, 0x69, 0x20, 0x4F, 0x53, 0x20, 0x36, 0x2E, 0x30, 0x20, 0x46,
            0x4C, 0x44,
        ];
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
                                std::ptr::read_unaligned(
                                    buffer.as_ptr() as *const SpatiotemporalFrame
                                )
                            };
                            let seq_id = frame.seq_id;
                            let x = frame.x;
                            let y = frame.y;
                            let z = frame.z;
                            let u = frame.u;
                            let v = frame.v;
                            let w = frame.w;
                            let fluidity = frame.fluidity;
                            println!(
                                "\x1b[38;5;37m[WEAVE BINARY] Frame #{} | Spatial: [{:.2}, {:.2}, {:.2}] Drift: [{:.2}, {:.2}, {:.2}] Fluidity: {:.4}\x1b[0m",
                                seq_id, x, y, z, u, v, w, fluidity
                            );
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    }
}

async fn run_p2p_listener(listen_addr: String, self_uuid: Uuid) {
    let listener = TcpListener::bind(&listen_addr).await.unwrap();
    if let Err(e) = tokio_fs::create_dir_all(LOCAL_TRANSFER_DIR).await {
        eprintln!(
            "\x1b[38;5;37m[P2P] Could not create transfer directory: {}\x1b[0m",
            e
        );
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
                let Ok(payload) = crypto::decrypt_payload(&payload) else {
                    eprintln!("\x1b[38;5;37m[P2P] Discarded undecipherable frame.\x1b[0m");
                    continue;
                };
                if let Ok(msg) = serde_json::from_slice::<FluidMessage>(&payload) {
                    let sender = msg.sender_uuid;
                    match msg.msg_type.as_str() {
                        "msg" => println!(
                            "\n\x1b[38;5;37m[P2P INBOUND] (From {}): {}\x1b[0m",
                            sender, msg.content
                        ),
                        "manifest" => println!(
                            "\n\x1b[38;5;37m[P2P JOBBYSLOTTY] Manifest received from {}:\n{}\x1b[0m",
                            sender, msg.content
                        ),
                        "browse_req" => {
                            let response = list_directory_blocking(&msg.content).await;
                            let response_msg = FluidMessage {
                                sender_uuid: self_uuid,
                                target_uuid: sender,
                                content: response,
                                msg_type: "browse_res".to_string(),
                                file_size: None,
                                local_path: None,
                            };
                            let _ = send_p2p_message(&mut stream, &response_msg).await;
                        }
                        "browse_res" => println!(
                            "\n\x1b[38;5;37m[P2P BROWSE] Directory listing from {}:\n{}\x1b[0m",
                            sender, msg.content
                        ),
                        "file_req" => {
                            let remote_path = msg.content;
                            let local_path = msg.local_path.unwrap_or_default();
                            let _ = send_file_p2p(
                                &mut stream,
                                self_uuid,
                                sender,
                                &remote_path,
                                &local_path,
                            )
                            .await;
                            return;
                        }
                        "file_init" => {
                            if let (Some(size), Some(path)) = (msg.file_size, msg.local_path) {
                                println!(
                                    "\n\x1b[38;5;37m[P2P FILE] Receiving '{}' ({} bytes)...\x1b[0m",
                                    path, size
                                );
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

async fn run_client_node(
    c2_addr: &str,
    p2p_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let client_uuid = Uuid::new_v4();

    let self_addr_json = format!("127.0.0.1:{}", p2p_port);
    let binary_port = p2p_port + 1000;
    let self_addr_binary = format!("127.0.0.1:{}", binary_port);

    let fleet: Arc<Mutex<HashMap<Uuid, PeerInfo>>> = Arc::new(Mutex::new(HashMap::new()));
    let fleet_clone = Arc::clone(&fleet);

    println!(
        "\x1b[38;5;136m[CORE] Open-Source Host Activated | UUID: {}\x1b[0m",
        client_uuid
    );
    println!(
        "\x1b[38;5;136m[CORE] JSON Control Channel: {}\x1b[0m",
        self_addr_json
    );
    println!(
        "\x1b[38;5;136m[CORE] Binary Tensor Channel: {}\x1b[0m",
        self_addr_binary
    );
    if crypto::encryption_enabled() {
        println!("\x1b[38;5;136m[CORE] Interim-Crypt payload protection enabled.\x1b[0m");
    }

    tokio::spawn(run_p2p_listener(self_addr_json.clone(), client_uuid));
    tokio::spawn(run_binary_listener(self_addr_binary.clone()));

    let (ws_stream, _) = connect_async(format!("ws://{}", c2_addr)).await?;
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    let my_reg = SovereignCommand::Register(PeerInfo {
        uuid: client_uuid,
        addr: c2_addr.to_string(),
        p2p_port,
        binary_port,
    });
    ws_sender
        .send(WsMessage::Text(serde_json::to_string(&my_reg)?.into()))
        .await?;

    let fleet_receiver = Arc::clone(&fleet);
    tokio::spawn(async move {
        while let Some(msg) = ws_receiver.next().await {
            if let Ok(WsMessage::Text(text)) = msg {
                if let Ok(SovereignCommand::NodeFleet(list)) =
                    serde_json::from_str::<SovereignCommand>(&text)
                {
                    let mut lock = fleet_receiver.lock().await;
                    lock.clear();
                    for node in list {
                        lock.insert(node.uuid, node);
                    }
                    println!(
                        "\n\x1b[38;5;37m[C2] Fleet registry synchronized. {} nodes online.\x1b[0m",
                        lock.len()
                    );
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
        if tokio::time::timeout(Duration::from_millis(100), stdin.read_line(&mut line))
            .await
            .is_err()
        {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "fleet" | "peers" => {
                let lock = fleet_clone.lock().await;
                println!("\x1b[38;5;136m--- Current Active Fleet Topology ---\x1b[0m");
                for peer in lock.values() {
                    let identity = if peer.uuid == client_uuid {
                        "(Self Node)"
                    } else {
                        ""
                    };
                    println!(
                        "  Node: {} | P2P: {} | BINARY: {} {}",
                        peer.uuid, peer.p2p_port, peer.binary_port, identity
                    );
                }
            }
            "msg" | "manifest" | "browse" | "ls" | "get" => {
                if let Some(target_uuid_str) = parts.get(1) {
                    let target = if parts[0] == "manifest" {
                        Uuid::parse_str(parts.get(2).unwrap_or(&""))
                    } else {
                        Uuid::parse_str(target_uuid_str)
                    };

                    if let Ok(target_uuid) = target {
                        let lock = fleet_clone.lock().await;
                        if let Some(target_node) = lock.get(&target_uuid) {
                            let target_addr = format!("127.0.0.1:{}", target_node.p2p_port);

                            let outbound = match parts[0] {
                                "msg" => FluidMessage {
                                    sender_uuid: client_uuid,
                                    target_uuid,
                                    msg_type: "msg".to_string(),
                                    content: parts[2..].join(" "),
                                    file_size: None,
                                    local_path: None,
                                },
                                "manifest" => FluidMessage {
                                    sender_uuid: client_uuid,
                                    target_uuid,
                                    msg_type: "manifest".to_string(),
                                    content: format!(
                                        "project: core-kernel-v6.4\nauthor: {}\nsecurity:\n  mode: interim-crypt\njobs:\n  1: {{ cmd: 'cargo build --release', deps: [] }}",
                                        client_uuid
                                    ),
                                    file_size: None,
                                    local_path: None,
                                },
                                "browse" | "ls" => FluidMessage {
                                    sender_uuid: client_uuid,
                                    target_uuid,
                                    msg_type: "browse_req".to_string(),
                                    content: parts.get(2).unwrap_or(&".").to_string(),
                                    file_size: None,
                                    local_path: None,
                                },
                                "get" => FluidMessage {
                                    sender_uuid: client_uuid,
                                    target_uuid,
                                    msg_type: "file_req".to_string(),
                                    content: parts.get(2).unwrap_or(&"").to_string(),
                                    file_size: None,
                                    local_path: Some(parts.get(3).unwrap_or(&"").to_string()),
                                },
                                _ => continue,
                            };

                            if let Ok(mut stream) = TcpStream::connect(&target_addr).await {
                                let _ = send_p2p_message(&mut stream, &outbound).await;
                            }
                        } else {
                            println!("Target node unrecognized.");
                        }
                    }
                }
            }
            "weave" => {
                if let Ok(target) = Uuid::parse_str(parts.get(1).unwrap_or(&"")) {
                    let lock = fleet_clone.lock().await;
                    if let Some(target_node) = lock.get(&target) {
                        let target_addr_binary = format!("127.0.0.1:{}", target_node.binary_port);
                        if let Ok(stream) = TcpStream::connect(&target_addr_binary).await {
                            tokio::spawn(handle_local_laminar_stream(stream, client_uuid));
                        }
                    }
                }
            }
            "exit" | "quit" => break,
            _ => println!("Commands: fleet, msg, manifest, browse, get, weave, exit"),
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    crypto::configure(LORENZ_SIGMA, LORENZ_RHO, LORENZ_BETA);

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("bootstrap") if args.len() >= 3 => run_c2_bootstrap(&args[2]).await,
        Some("node") if args.len() >= 4 => run_client_node(&args[2], args[3].parse::<u16>()?).await,
        _ => {
            eprintln!("Usage: yukki_core_node bootstrap <host:port> | node <bootstrap_host:port> <p2p_port>");
            Ok(())
        }
    }
}
