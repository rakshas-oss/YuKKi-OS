use std::{
    collections::{HashMap, HashSet, VecDeque},
    env, io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use futures_util::{SinkExt, StreamExt};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    signal,
    sync::{mpsc, Mutex, Semaphore},
    time::timeout,
};
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest,
    http::{header::AUTHORIZATION, HeaderValue},
    Message,
};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use yukkios_6_8_0_inet3::{
    stream_gateway::{self, GatewayAuth},
    LiveMediaStreams, MediaStreamConfig, StreamAnnouncement, StreamDigestEntry, StreamRegistry,
};
use zeroize::Zeroize;

const MAX_FRAME_BYTES: usize = 64 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const ANTI_ENTROPY_INTERVAL: Duration = Duration::from_secs(30);
const PROTOCOL_CONTEXT: &[u8] = b"YuKKi-OS/control/v1";
const AUTH_CONFIRMATION: &[u8] = b"YuKKi-OS authenticated peer";

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PeerInfo {
    uuid: Uuid,
    addr: String,
}

#[derive(Serialize, Deserialize, Debug)]
enum SovereignCommand {
    Register(PeerInfo),
    NodeFleet(Vec<PeerInfo>),
    StreamAnnouncement(StreamAnnouncement),
    StreamDigest(Vec<StreamDigestEntry>),
}

struct Session {
    tx: ChaCha20Poly1305,
    rx: ChaCha20Poly1305,
    tx_direction: u32,
    rx_direction: u32,
    tx_nonce: u64,
    rx_nonce: u64,
}

fn parse_psk() -> io::Result<[u8; 32]> {
    let encoded = env::var("YUKKI_PSK_HEX").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "YUKKI_PSK_HEX must contain a 64-character hexadecimal pre-shared key",
        )
    })?;
    if encoded.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "YUKKI_PSK_HEX must be 64 hex characters",
        ));
    }
    let mut key = [0u8; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "YUKKI_PSK_HEX is not hexadecimal",
            )
        })?;
    }
    Ok(key)
}

fn derive_key(shared: &[u8], psk: &[u8; 32], label: &[u8]) -> io::Result<ChaCha20Poly1305> {
    let hkdf = Hkdf::<Sha256>::new(Some(psk), shared);
    let mut key = [0u8; 32];
    hkdf.expand(label, &mut key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "key derivation failed"))?;
    let cipher = ChaCha20Poly1305::new(&Key::from(key));
    key.zeroize();
    Ok(cipher)
}

async fn establish_session(
    stream: &mut TcpStream,
    psk: &[u8; 32],
    server: bool,
) -> io::Result<Session> {
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    let secret = StaticSecret::from(secret_bytes);
    secret_bytes.zeroize();
    let public = PublicKey::from(&secret);
    let mut peer_public = [0u8; 32];

    if server {
        stream.read_exact(&mut peer_public).await?;
        stream.write_all(public.as_bytes()).await?;
    } else {
        stream.write_all(public.as_bytes()).await?;
        stream.read_exact(&mut peer_public).await?;
    }

    let shared = secret.diffie_hellman(&PublicKey::from(peer_public));
    let mut shared_bytes = *shared.as_bytes();
    let (tx_label, rx_label, tx_direction, rx_direction) = if server {
        (
            b"YuKKi-OS/control/v1/server-to-client".as_slice(),
            b"YuKKi-OS/control/v1/client-to-server".as_slice(),
            2,
            1,
        )
    } else {
        (
            b"YuKKi-OS/control/v1/client-to-server".as_slice(),
            b"YuKKi-OS/control/v1/server-to-client".as_slice(),
            1,
            2,
        )
    };
    let mut session = Session {
        tx: derive_key(&shared_bytes, psk, tx_label)?,
        rx: derive_key(&shared_bytes, psk, rx_label)?,
        tx_direction,
        rx_direction,
        tx_nonce: 0,
        rx_nonce: 0,
    };
    shared_bytes.zeroize();

    if server {
        if read_frame(stream, &mut session).await? != AUTH_CONFIRMATION {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "peer authentication failed",
            ));
        }
        send_frame(stream, &mut session, AUTH_CONFIRMATION).await?;
    } else {
        send_frame(stream, &mut session, AUTH_CONFIRMATION).await?;
        if read_frame(stream, &mut session).await? != AUTH_CONFIRMATION {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "server authentication failed",
            ));
        }
    }
    Ok(session)
}

fn nonce(direction: u32, counter: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[..4].copy_from_slice(&direction.to_be_bytes());
    bytes[4..].copy_from_slice(&counter.to_be_bytes());
    Nonce::from(bytes)
}

async fn send_frame(
    stream: &mut TcpStream,
    session: &mut Session,
    plaintext: &[u8],
) -> io::Result<()> {
    if plaintext.len() > MAX_FRAME_BYTES || session.tx_nonce == u64::MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message too large or nonce exhausted",
        ));
    }
    let ciphertext = session
        .tx
        .encrypt(
            &nonce(session.tx_direction, session.tx_nonce),
            Payload {
                msg: plaintext,
                aad: PROTOCOL_CONTEXT,
            },
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "encryption failed"))?;
    session.tx_nonce += 1;
    stream
        .write_all(&(ciphertext.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&ciphertext).await
}

async fn read_frame(stream: &mut TcpStream, session: &mut Session) -> io::Result<Vec<u8>> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BYTES + 16 || session.rx_nonce == u64::MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length or nonce exhausted",
        ));
    }
    let mut ciphertext = vec![0u8; length];
    stream.read_exact(&mut ciphertext).await?;
    let plaintext = session
        .rx
        .decrypt(
            &nonce(session.rx_direction, session.rx_nonce),
            Payload {
                msg: &ciphertext,
                aad: PROTOCOL_CONTEXT,
            },
        )
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "authentication failed"))?;
    session.rx_nonce += 1;
    ciphertext.zeroize();
    Ok(plaintext)
}

async fn secured_session(
    stream: &mut TcpStream,
    psk: &[u8; 32],
    server: bool,
) -> io::Result<Session> {
    timeout(HANDSHAKE_TIMEOUT, establish_session(stream, psk, server))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))?
}

type Fleet = Arc<Mutex<HashMap<Uuid, PeerInfo>>>;
type Clients = Arc<Mutex<HashMap<Uuid, mpsc::Sender<Vec<u8>>>>>;
type SeenAnnouncements = Arc<Mutex<(HashSet<String>, VecDeque<String>)>>;

async fn relay_to_peers(message: Vec<u8>, except: Uuid, clients: &Clients) {
    let senders: Vec<_> = clients
        .lock()
        .await
        .iter()
        .filter(|(id, _)| **id != except)
        .map(|(_, sender)| sender.clone())
        .collect();
    for sender in senders {
        let _ = sender.send(message.clone()).await;
    }
}

async fn broadcast_fleet(fleet: &Fleet, clients: &Clients) {
    let message = match serde_json::to_vec(&SovereignCommand::NodeFleet(
        fleet.lock().await.values().cloned().collect(),
    )) {
        Ok(message) => message,
        Err(error) => {
            warn!(%error, "could not serialize fleet update");
            return;
        }
    };
    let senders: Vec<_> = clients.lock().await.values().cloned().collect();
    for sender in senders {
        let _ = sender.send(message.clone()).await;
    }
}

async fn handle_peer(
    mut stream: TcpStream,
    remote: SocketAddr,
    psk: Arc<[u8; 32]>,
    fleet: Fleet,
    clients: Clients,
    seen_announcements: SeenAnnouncements,
) {
    let mut session = match secured_session(&mut stream, &psk, true).await {
        Ok(session) => session,
        Err(error) => {
            warn!(%remote, %error, "rejected peer during handshake");
            return;
        }
    };
    let registration = match timeout(IO_TIMEOUT, read_frame(&mut stream, &mut session)).await {
        Ok(Ok(bytes)) => serde_json::from_slice::<SovereignCommand>(&bytes).ok(),
        _ => None,
    };
    let Some(SovereignCommand::Register(peer)) = registration else {
        warn!(%remote, "peer did not register");
        return;
    };
    let id = peer.uuid;
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(32);
    fleet.lock().await.insert(id, peer);
    clients.lock().await.insert(id, tx);
    info!(%remote, %id, "peer registered");
    broadcast_fleet(&fleet, &clients).await;

    loop {
        tokio::select! {
            Some(message) = rx.recv() => {
                if !matches!(
                    timeout(IO_TIMEOUT, send_frame(&mut stream, &mut session, &message)).await,
                    Ok(Ok(()))
                ) {
                    break;
                }
            }
            result = timeout(IO_TIMEOUT, read_frame(&mut stream, &mut session)) => {
                match result {
                    Ok(Ok(mut message)) => {
                        match serde_json::from_slice::<SovereignCommand>(&message) {
                            Ok(SovereignCommand::StreamAnnouncement(mut announcement))
                                if announcement.remaining_hops > 1
                                    && announcement.remaining_hops <= yukkios_6_8_0_inet3::STREAM_ANNOUNCEMENT_MAX_HOPS =>
                            {
                                let should_forward = {
                                    let mut seen = seen_announcements.lock().await;
                                    if seen.0.insert(announcement.message_id.clone()) {
                                        seen.1.push_back(announcement.message_id.clone());
                                        while seen.1.len() > 4096 {
                                            if let Some(oldest) = seen.1.pop_front() {
                                                seen.0.remove(&oldest);
                                            }
                                        }
                                        true
                                    } else {
                                        false
                                    }
                                };
                                if should_forward {
                                    announcement.remaining_hops -= 1;
                                    if let Ok(encoded) = serde_json::to_vec(
                                        &SovereignCommand::StreamAnnouncement(announcement),
                                    ) {
                                        relay_to_peers(encoded, id, &clients).await;
                                    }
                                }
                            }
                            Ok(SovereignCommand::StreamDigest(digest))
                                if digest.len() <= yukkios_6_8_0_inet3::STREAM_REGISTRY_MAX_STREAMS =>
                            {
                                relay_to_peers(message.clone(), id, &clients).await;
                            }
                            _ => {}
                        }
                        message.zeroize();
                    },
                    _ => break,
                }
            }
        }
    }
    fleet.lock().await.remove(&id);
    clients.lock().await.remove(&id);
    info!(%remote, %id, "peer disconnected");
    broadcast_fleet(&fleet, &clients).await;
}

async fn run_bootstrap(address: SocketAddr, psk: [u8; 32]) -> io::Result<()> {
    let listener = TcpListener::bind(address).await?;
    let fleet = Arc::new(Mutex::new(HashMap::new()));
    let clients = Arc::new(Mutex::new(HashMap::new()));
    let seen_announcements = Arc::new(Mutex::new((HashSet::new(), VecDeque::new())));
    let permits = Arc::new(Semaphore::new(128));
    let psk = Arc::new(psk);
    info!(%address, "bootstrap listening");

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, remote) = result?;
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    warn!(%remote, "connection limit reached");
                    continue;
                };
                let peer_psk = psk.clone();
                let peer_fleet = fleet.clone();
                let peer_clients = clients.clone();
                let peer_seen = seen_announcements.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    handle_peer(stream, remote, peer_psk, peer_fleet, peer_clients, peer_seen).await;
                });
            }
            result = signal::ctrl_c() => {
                result?;
                info!("shutdown requested");
                return Ok(());
            }
        }
    }
}

async fn run_node(bootstrap: SocketAddr, advertised: SocketAddr, psk: [u8; 32]) -> io::Result<()> {
    let mut stream = timeout(IO_TIMEOUT, TcpStream::connect(bootstrap))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "bootstrap connection timed out"))??;
    let mut session = secured_session(&mut stream, &psk, false).await?;
    let node_id = Uuid::new_v4();
    let streams = Arc::new(
        LiveMediaStreams::new(MediaStreamConfig::default())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
    );
    let registry = StreamRegistry::new(node_id.to_string(), streams.clone())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let registration = serde_json::to_vec(&SovereignCommand::Register(PeerInfo {
        uuid: node_id,
        addr: advertised.to_string(),
    }))
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    send_frame(&mut stream, &mut session, &registration).await?;
    send_gossip_digest(&mut stream, &mut session, &registry).await?;
    if env::var_os("YUKKI_GATEWAY_TOKEN").is_some() {
        let auth = gateway_auth(false)?;
        let address: SocketAddr = env::var("YUKKI_GATEWAY_LISTEN")
            .unwrap_or_else(|_| DEFAULT_GATEWAY_ADDRESS.to_string())
            .parse()
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid YUKKI_GATEWAY_LISTEN")
            })?;
        let listener = TcpListener::bind(address).await?;
        info!(%address, "node stream gateway listening");
        let gateway_streams = streams.clone();
        let gateway_registry = registry.clone();
        tokio::spawn(async move {
            if let Err(error) =
                stream_gateway::serve(listener, gateway_streams, gateway_registry, auth).await
            {
                warn!(%error, "node stream gateway stopped");
            }
        });
    }
    info!(%bootstrap, %advertised, "node registered; press Ctrl-C to stop");
    let mut last_digest = Instant::now();
    tokio::select! {
        result = async {
            loop {
                match timeout(IO_TIMEOUT, read_frame(&mut stream, &mut session)).await {
                    Ok(Ok(mut message)) => {
                        match serde_json::from_slice::<SovereignCommand>(&message) {
                            Ok(SovereignCommand::NodeFleet(fleet)) => {
                                info!(peers = fleet.len(), "received fleet update");
                            }
                            Ok(SovereignCommand::StreamAnnouncement(announcement)) => {
                                let now = SystemTime::now().duration_since(UNIX_EPOCH)
                                    .unwrap_or_default().as_secs();
                                if registry.accept_announcement(announcement, now).is_ok() {
                                    info!("received stream announcement");
                                }
                            }
                            Ok(SovereignCommand::StreamDigest(digest))
                                if digest.len() <= yukkios_6_8_0_inet3::STREAM_REGISTRY_MAX_STREAMS =>
                            {
                                for descriptor in registry.descriptors_for_digest(&digest)
                                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
                                {
                                    let announcement = StreamAnnouncement {
                                        message_id: Uuid::new_v4().to_string(),
                                        remaining_hops: yukkios_6_8_0_inet3::STREAM_ANNOUNCEMENT_MAX_HOPS,
                                        descriptor,
                                    };
                                    let bytes = serde_json::to_vec(
                                        &SovereignCommand::StreamAnnouncement(announcement),
                                    ).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                                    send_frame(&mut stream, &mut session, &bytes).await?;
                                }
                            }
                            _ => {}
                        }
                        message.zeroize();
                    }
                    Ok(Err(error)) => return Err(error),
                    Err(_) => {}
                }
                if last_digest.elapsed() >= ANTI_ENTROPY_INTERVAL {
                    send_gossip_digest(&mut stream, &mut session, &registry).await?;
                    last_digest = Instant::now();
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), io::Error>(())
        } => result,
        result = signal::ctrl_c() => {
            result?;
            info!("shutdown requested");
            Ok(())
        }
    }
}

async fn send_gossip_digest(
    stream: &mut TcpStream,
    session: &mut Session,
    registry: &StreamRegistry,
) -> io::Result<()> {
    let digest = registry
        .digest()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let message = serde_json::to_vec(&SovereignCommand::StreamDigest(digest))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    send_frame(stream, session, &message).await
}

fn usage() -> &'static str {
    "Usage: yukki_core_node bootstrap <bind-address> | node <bootstrap-address> <advertised-address> | gateway [listen-address] [--insecure-dev] | streams list [gateway-address] | streams tune <stream-id> [--from <seq>]\nSet YUKKI_PSK_HEX for mesh commands and YUKKI_GATEWAY_TOKEN for the gateway."
}

const DEFAULT_GATEWAY_ADDRESS: &str = "127.0.0.1:7670";
const MAX_GATEWAY_TOKEN_BYTES: usize = 4096;
const MAX_CLI_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

fn gateway_address() -> io::Result<SocketAddr> {
    env::var("YUKKI_GATEWAY_ENDPOINT")
        .unwrap_or_else(|_| DEFAULT_GATEWAY_ADDRESS.to_string())
        .parse()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "YUKKI_GATEWAY_ENDPOINT must be a socket address",
            )
        })
}

fn gateway_auth(insecure_dev: bool) -> io::Result<GatewayAuth> {
    match env::var("YUKKI_GATEWAY_TOKEN") {
        Ok(token)
            if !token.is_empty()
                && token.len() <= MAX_GATEWAY_TOKEN_BYTES
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/=".contains(&byte)) =>
        {
            Ok(GatewayAuth::Bearer(token))
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "YUKKI_GATEWAY_TOKEN must be 1..=4096 visible bearer-token characters",
        )),
        Err(_) if insecure_dev => Ok(GatewayAuth::InsecureDev),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "YUKKI_GATEWAY_TOKEN is required; use --insecure-dev only for local development",
        )),
    }
}

async fn run_gateway(address: SocketAddr, insecure_dev: bool) -> io::Result<()> {
    let auth = gateway_auth(insecure_dev)?;
    let streams = Arc::new(
        LiveMediaStreams::new(MediaStreamConfig::default())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
    );
    let registry = StreamRegistry::new("local", streams.clone())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let listener = TcpListener::bind(address).await?;
    info!(%address, "stream gateway listening");
    stream_gateway::serve(listener, streams, registry, auth).await
}

async fn gateway_get(address: SocketAddr, path: &str, token: &str) -> io::Result<(u16, Vec<u8>)> {
    let mut socket = timeout(Duration::from_secs(5), TcpStream::connect(address))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "gateway connection timed out"))??;
    let authorization = ["Authorization: Bearer ", token, "\r\n"].concat();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {address}\r\n{authorization}Connection: close\r\n\r\n"
    );
    socket.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    let read = timeout(
        Duration::from_secs(30),
        socket
            .take((MAX_CLI_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut response),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "gateway response timed out"))??;
    if read > MAX_CLI_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gateway response exceeds limit",
        ));
    }
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP response"))?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP headers"))?;
    let status = headers
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP status"))?;
    Ok((status, response[header_end + 4..].to_vec()))
}

fn gateway_token() -> io::Result<String> {
    let token = env::var("YUKKI_GATEWAY_TOKEN").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "YUKKI_GATEWAY_TOKEN is required to use the gateway",
        )
    })?;
    gateway_auth(false)?;
    Ok(token)
}

fn percent_encode_path(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(byte as char);
        } else {
            use std::fmt::Write;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

async fn run_streams_list(address: SocketAddr) -> io::Result<()> {
    let token = gateway_token()?;
    let (status, body) = gateway_get(address, "/v1/streams", &token).await?;
    if status != 200 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("gateway returned HTTP {status}"),
        ));
    }
    let streams: Vec<serde_json::Value> = serde_json::from_slice(&body)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    for stream in streams {
        println!(
            "{}\t{}\t{}\t{}",
            stream["id"].as_str().unwrap_or(""),
            stream["kind"].as_str().unwrap_or(""),
            stream["status"].as_str().unwrap_or(""),
            stream["name"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

async fn run_streams_tune(
    address: SocketAddr,
    stream_id: &str,
    from_sequence: u64,
) -> io::Result<()> {
    let token = gateway_token()?;
    let url = format!(
        "ws://{address}/v1/streams/{}/ws?from={from_sequence}",
        percent_encode_path(stream_id)
    );
    let mut request = url
        .into_client_request()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let authorization = HeaderValue::from_str(&["Bearer ", &token].concat())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    request.headers_mut().insert(AUTHORIZATION, authorization);
    let (mut socket, _) = tokio_tungstenite::connect_async(request)
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionRefused, error))?;
    let mut stdout = tokio::io::stdout();
    while let Some(message) = socket.next().await {
        match message.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))? {
            Message::Binary(frame) if frame.len() >= 8 => {
                let sequence = u64::from_be_bytes(frame[..8].try_into().unwrap());
                stdout.write_all(&frame[8..]).await?;
                stdout.flush().await?;
                let ack = serde_json::json!({"type": "ack", "sequence": sequence}).to_string();
                socket
                    .send(Message::Text(ack.into()))
                    .await
                    .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error))?;
            }
            Message::Text(text) if text.contains("\"lagged\"") => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "stream subscription was lagged",
                ));
            }
            Message::Ping(payload) => socket
                .send(Message::Pong(payload))
                .await
                .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error))?,
            Message::Close(_) => return Ok(()),
            _ => {}
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();
    let args: Vec<String> = env::args().collect();
    match args.as_slice() {
        [_, command, address] if command == "bootstrap" => {
            run_bootstrap(
                address
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, usage()))?,
                parse_psk()?,
            )
            .await
        }
        [_, command, bootstrap, advertised] if command == "node" => {
            run_node(
                bootstrap
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, usage()))?,
                advertised
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, usage()))?,
                parse_psk()?,
            )
            .await
        }
        [_, command] if command == "gateway" => {
            run_gateway(DEFAULT_GATEWAY_ADDRESS.parse().unwrap(), false).await
        }
        [_, command, flag] if command == "gateway" && flag == "--insecure-dev" => {
            run_gateway(DEFAULT_GATEWAY_ADDRESS.parse().unwrap(), true).await
        }
        [_, command, address] if command == "gateway" => {
            run_gateway(
                address
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, usage()))?,
                false,
            )
            .await
        }
        [_, command, address, flag] if command == "gateway" && flag == "--insecure-dev" => {
            run_gateway(
                address
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, usage()))?,
                true,
            )
            .await
        }
        [_, command, action] if command == "streams" && action == "list" => {
            run_streams_list(gateway_address()?).await
        }
        [_, command, action, address] if command == "streams" && action == "list" => {
            run_streams_list(
                address
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, usage()))?,
            )
            .await
        }
        [_, command, action, stream_id] if command == "streams" && action == "tune" => {
            run_streams_tune(gateway_address()?, stream_id, 0).await
        }
        [_, command, action, stream_id, flag, from]
            if command == "streams" && action == "tune" && flag == "--from" =>
        {
            let from_sequence = from
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, usage()))?;
            run_streams_tune(gateway_address()?, stream_id, from_sequence).await
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, usage())),
    }
}
