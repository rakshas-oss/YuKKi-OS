use std::{collections::HashMap, env, io, net::SocketAddr, sync::Arc, time::Duration};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    signal,
    sync::{mpsc, Mutex, Semaphore},
    time::timeout,
};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

const MAX_FRAME_BYTES: usize = 64 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(30);
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
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    key.zeroize();
    Ok(cipher)
}

async fn establish_session(
    stream: &mut TcpStream,
    psk: &[u8; 32],
    server: bool,
) -> io::Result<Session> {
    let secret = EphemeralSecret::random_from_rng(OsRng);
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
    *Nonce::from_slice(&bytes)
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
                    Ok(Ok(mut message)) => message.zeroize(),
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
                tokio::spawn(async move {
                    let _permit = permit;
                    handle_peer(stream, remote, peer_psk, peer_fleet, peer_clients).await;
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
    let registration = serde_json::to_vec(&SovereignCommand::Register(PeerInfo {
        uuid: Uuid::new_v4(),
        addr: advertised.to_string(),
    }))
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    send_frame(&mut stream, &mut session, &registration).await?;
    info!(%bootstrap, %advertised, "node registered; press Ctrl-C to stop");
    tokio::select! {
        result = async {
            loop {
                let mut message = timeout(IO_TIMEOUT, read_frame(&mut stream, &mut session)).await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "bootstrap idle timeout"))??;
                if let Ok(SovereignCommand::NodeFleet(fleet)) = serde_json::from_slice(&message) {
                    info!(peers = fleet.len(), "received fleet update");
                }
                message.zeroize();
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

fn usage() -> &'static str {
    "Usage: yukki_core_node bootstrap <bind-address> | node <bootstrap-address> <advertised-address>\nSet YUKKI_PSK_HEX to a 32-byte hexadecimal pre-shared key."
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
    let psk = parse_psk()?;
    match args.as_slice() {
        [_, command, address] if command == "bootstrap" => {
            run_bootstrap(
                address
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, usage()))?,
                psk,
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
                psk,
            )
            .await
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, usage())),
    }
}
