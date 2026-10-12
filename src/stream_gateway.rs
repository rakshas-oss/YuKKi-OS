use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::serve::Listener;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        DefaultBodyLimit, Path, Query, State,
    },
    http::{header, HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    time::{interval, timeout, MissedTickBehavior},
};
use tracing::warn;

use crate::{
    media_codec::{LiveMediaStreams, MediaChunk, MediaError},
    stream_registry::{RegistryError, StreamRegistry, Subscription, SubscriptionRead},
    stream_relay::{RelayError, StreamRelay},
};

const DASHBOARD_HTML: &str = include_str!("dashboard.html");
const MAX_HTTP_BODY_BYTES: usize = 1024;
const MAX_RANGE_CHUNKS: u64 = 8;
const MAX_CONNECTIONS: usize = 128;
const MAX_WS_FRAME_BYTES: usize = crate::media_codec::MEDIA_CHUNK_HEADER_LEN
    + crate::media_codec::MEDIA_MAX_STREAM_ID_BYTES
    + crate::media_codec::MEDIA_MAX_CODEC_BYTES
    + crate::media_codec::MEDIA_MAX_CHUNK_BYTES
    + 8;
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const PING_INTERVAL: Duration = Duration::from_secs(20);
const STREAM_POLL_INTERVAL: Duration = Duration::from_millis(25);
const DEFAULT_DRONE_DASHBOARD_MAX_CHUNKS: u64 = 256;

#[derive(Clone)]
pub enum GatewayAuth {
    Bearer(String),
    InsecureDev,
}

#[derive(Clone)]
struct GatewayState {
    streams: Arc<LiveMediaStreams>,
    registry: StreamRegistry,
    auth: GatewayAuth,
    relay: Option<Arc<StreamRelay>>,
}

#[derive(Deserialize)]
struct ChunkQuery {
    from: u64,
    limit: Option<u64>,
}

#[derive(Deserialize)]
struct StreamQuery {
    from: Option<u64>,
}

#[derive(Deserialize)]
struct ClientAck {
    r#type: String,
    sequence: u64,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

pub async fn serve(
    listener: TcpListener,
    streams: Arc<LiveMediaStreams>,
    registry: StreamRegistry,
    auth: GatewayAuth,
) -> std::io::Result<()> {
    serve_with_relay(listener, streams, registry, auth, None).await
}

/// Like [`serve`], but remote streams are mirrored and relayed via `relay`
/// instead of returning `501`.
pub async fn serve_with_relay(
    listener: TcpListener,
    streams: Arc<LiveMediaStreams>,
    registry: StreamRegistry,
    auth: GatewayAuth,
    relay: Option<Arc<StreamRelay>>,
) -> std::io::Result<()> {
    let state = GatewayState {
        streams,
        registry,
        auth,
        relay,
    };
    let app = Router::new()
        .route("/dashboard", get(dashboard))
        .route("/dashboard/drones", get(list_drones))
        .route("/dashboard/drones/{id}", get(describe_drone))
        .route("/v1/streams", get(list_streams))
        .route("/v1/streams/{id}", get(describe_stream))
        .route("/v1/streams/{id}/chunks", get(read_chunks))
        .route("/v1/streams/{id}/ws", get(websocket_tune_in))
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(MAX_HTTP_BODY_BYTES))
        .layer(middleware::from_fn_with_state(
            state,
            authenticate_and_limit,
        ));
    axum::serve(
        CappedListener {
            listener,
            permits: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        },
        app,
    )
    .await
}

fn drone_dashboard_enabled() -> bool {
    matches!(
        std::env::var("YUKKI_DRONE_DASHBOARD_ENABLED")
            .ok()
            .as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("True") | Some("yes") | Some("YES")
    )
}

fn drone_dashboard_max_chunks() -> u64 {
    std::env::var("YUKKI_DRONE_DASHBOARD_MAX_CHUNKS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_DRONE_DASHBOARD_MAX_CHUNKS)
}

async fn authenticate_and_limit(
    State(state): State<GatewayState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let drone_dashboard = path.starts_with("/dashboard/drones");
    if path != "/dashboard" && !drone_dashboard && !authorized(request.headers(), &state.auth) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "unauthorized",
            }),
        )
            .into_response();
    }
    if drone_dashboard && !drone_dashboard_enabled() {
        return StatusCode::NOT_FOUND.into_response();
    }
    match timeout(HTTP_REQUEST_TIMEOUT, next.run(request)).await {
        Ok(response) => response,
        Err(_) => StatusCode::GATEWAY_TIMEOUT.into_response(),
    }
}

fn authorized(headers: &HeaderMap, auth: &GatewayAuth) -> bool {
    match auth {
        GatewayAuth::InsecureDev => true,
        GatewayAuth::Bearer(token) => headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .is_some_and(|candidate| {
                constant_time_token_eq(token.as_bytes(), candidate.as_bytes())
            }),
    }
}

fn constant_time_token_eq(expected: &[u8], actual: &[u8]) -> bool {
    let expected_hash = Sha256::digest(expected);
    let actual_hash = Sha256::digest(actual);
    let mut difference = (expected.len() ^ actual.len()) as u64;
    for (left, right) in expected_hash.iter().zip(actual_hash.iter()) {
        difference |= u64::from(left ^ right);
    }
    difference == 0
}

async fn dashboard() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        DASHBOARD_HTML,
    )
        .into_response()
}

async fn list_drones(State(state): State<GatewayState>) -> Response {
    if !drone_dashboard_enabled() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let mut drones = Vec::new();
    let max_chunks = drone_dashboard_max_chunks();
    match state.registry.list_streams() {
        Ok(streams) => {
            for stream in streams {
                drones.push(serde_json::json!({
                    "id": stream.id,
                    "stream_id": stream.id,
                    "name": stream.name,
                    "kind": stream.kind,
                    "status": stream.status,
                    "max_chunks": max_chunks,
                    "source": "gateway"
                }));
            }
            Json(drones).into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn describe_drone(State(state): State<GatewayState>, Path(id): Path<String>) -> Response {
    if !drone_dashboard_enabled() {
        return StatusCode::NOT_FOUND.into_response();
    }

    match state.registry.describe(&id) {
        Ok(stream) => Json(serde_json::json!({
            "id": id,
            "stream_id": stream.id,
            "name": stream.name,
            "kind": stream.kind,
            "status": stream.status,
            "max_chunks": drone_dashboard_max_chunks(),
            "summary": "optional drone dashboard record"
        }))
        .into_response(),
        Err(RegistryError::StreamNotFound(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

async fn list_streams(State(state): State<GatewayState>) -> Response {
    match state.registry.list_streams() {
        Ok(streams) => Json(streams).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn describe_stream(State(state): State<GatewayState>, Path(id): Path<String>) -> Response {
    match state.registry.describe(&id) {
        Ok(stream) => Json(stream).into_response(),
        Err(RegistryError::StreamNotFound(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

async fn read_chunks(
    State(state): State<GatewayState>,
    Path(id): Path<String>,
    Query(query): Query<ChunkQuery>,
) -> Response {
    let limit = query.limit.unwrap_or(1);
    if limit == 0 || limit > MAX_RANGE_CHUNKS {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Some(last) = query.from.checked_add(limit - 1) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match state.streams.get_range(&id, query.from, last) {
        Ok(chunks) => Json(chunks).into_response(),
        Err(MediaError::StreamNotFound(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::RANGE_NOT_SATISFIABLE.into_response(),
    }
}

async fn websocket_tune_in(
    State(state): State<GatewayState>,
    Path(id): Path<String>,
    Query(query): Query<StreamQuery>,
    websocket: WebSocketUpgrade,
) -> Response {
    let from = query.from.unwrap_or(0);
    let result = match state.relay.clone() {
        Some(relay) => {
            let id = id.clone();
            match tokio::task::spawn_blocking(move || relay.tune_in(&id, from)).await {
                Ok(Ok(subscription)) => Ok(subscription),
                Ok(Err(RelayError::Registry(error))) => Err(error),
                Ok(Err(RelayError::Upstream(_))) => {
                    return StatusCode::BAD_GATEWAY.into_response();
                }
                _ => return StatusCode::BAD_REQUEST.into_response(),
            }
        }
        None => state.registry.tune_in(&id, from),
    };
    let subscription = match result {
        Ok(subscription) => subscription,
        Err(RegistryError::StreamNotFound(_)) => return StatusCode::NOT_FOUND.into_response(),
        Err(RegistryError::Invalid("remote stream subscription")) => {
            return StatusCode::NOT_IMPLEMENTED.into_response();
        }
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    websocket
        .max_frame_size(MAX_WS_FRAME_BYTES)
        .max_message_size(MAX_WS_FRAME_BYTES)
        .on_upgrade(move |socket| {
            websocket_session(socket, subscription, state.registry, state.relay, id)
        })
}

async fn websocket_session(
    socket: WebSocket,
    mut subscription: Subscription,
    registry: StreamRegistry,
    relay: Option<Arc<StreamRelay>>,
    stream_id: String,
) {
    let (mut sender, mut receiver) = futures_util::StreamExt::split(socket);
    let mut ping = interval(PING_INTERVAL);
    ping.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ping.tick().await;
    let mut poll = interval(STREAM_POLL_INTERVAL);
    poll.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut last_activity = Instant::now();
    let mut awaiting_ack = None;
    loop {
        tokio::select! {
            incoming = futures_util::StreamExt::next(&mut receiver) => {
                match incoming {
                    Some(Ok(Message::Text(text))) if text.len() <= 1024 => {
                        let ack = serde_json::from_str::<ClientAck>(&text);
                        match ack {
                            Ok(ack) if ack.r#type == "ack" && awaiting_ack == Some(ack.sequence) => {
                                if subscription.acknowledge_through(ack.sequence).is_err() {
                                    close_policy(&mut sender).await;
                                    break;
                                }
                                awaiting_ack = None;
                                last_activity = Instant::now();
                            }
                            _ => {
                                close_policy(&mut sender).await;
                                break;
                            }
                        }
                    }
                    Some(Ok(Message::Pong(_))) => last_activity = Instant::now(),
                    Some(Ok(Message::Ping(payload))) => {
                        if futures_util::SinkExt::send(&mut sender, Message::Pong(payload)).await.is_err() {
                            break;
                        }
                        last_activity = Instant::now();
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => {
                        close_policy(&mut sender).await;
                        break;
                    }
                }
            }
            _ = ping.tick() => {
                if last_activity.elapsed() >= IDLE_TIMEOUT {
                    let _ = futures_util::SinkExt::send(&mut sender, Message::Close(None)).await;
                    break;
                }
                if futures_util::SinkExt::send(&mut sender, Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }
            _ = poll.tick(), if awaiting_ack.is_none() => {
                match subscription.next_chunk() {
                    Ok(SubscriptionRead::Chunk(chunk)) => {
                        let sequence = chunk.sequence_no;
                        let Ok(frame) = websocket_chunk_frame(&chunk) else {
                            break;
                        };
                        match timeout(Duration::from_secs(30), futures_util::SinkExt::send(&mut sender, Message::Binary(frame.into()))).await {
                            Ok(Ok(())) => awaiting_ack = Some(sequence),
                            _ => break,
                        }
                    }
                    Ok(SubscriptionRead::Waiting) => {
                        if let Some(relay) = relay.clone().filter(|r| r.is_mirror(&stream_id)) {
                            let id = stream_id.clone();
                            let _ = tokio::task::spawn_blocking(move || relay.pump(&id)).await;
                        }
                    }
                    Ok(SubscriptionRead::Finished) => {
                        let _ = futures_util::SinkExt::send(&mut sender, Message::Close(None)).await;
                        break;
                    }
                    Ok(SubscriptionRead::Lagged) => {
                        let signal = serde_json::json!({
                            "type": "lagged",
                            "next_seq": subscription.next_sequence(),
                        }).to_string();
                        let _ = futures_util::SinkExt::send(&mut sender, Message::Text(signal.into())).await;
                        close_policy(&mut sender).await;
                        break;
                    }
                    Err(_) => break,
                }
            }
        }
    }
    let _ = registry.tune_out(&subscription);
}

fn websocket_chunk_frame(chunk: &MediaChunk) -> Result<Vec<u8>, MediaError> {
    let encoded = chunk.encode()?;
    let mut frame = Vec::with_capacity(8 + encoded.len());
    frame.extend_from_slice(&chunk.sequence_no.to_be_bytes());
    frame.extend_from_slice(&encoded);
    Ok(frame)
}

async fn close_policy<S>(sender: &mut S)
where
    S: futures_util::Sink<Message, Error = axum::Error> + Unpin,
{
    let close = Message::Close(Some(axum::extract::ws::CloseFrame {
        code: axum::extract::ws::close_code::POLICY,
        reason: "invalid stream control message".into(),
    }));
    let _ = futures_util::SinkExt::send(sender, close).await;
}

pub fn parse_listen_address(address: &str) -> Result<SocketAddr, std::net::AddrParseError> {
    address.parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_comparison_rejects_wrong_and_different_length_tokens() {
        let auth = GatewayAuth::Bearer("secret-token".into());
        let mut headers = HeaderMap::new();
        let correct = ["Bearer ", auth_token(&auth)].concat();
        headers.insert(header::AUTHORIZATION, correct.parse().unwrap());
        assert!(authorized(&headers, &auth));
        let incorrect = ["Bearer ", "wrong"].concat();
        headers.insert(header::AUTHORIZATION, incorrect.parse().unwrap());
        assert!(!authorized(&headers, &auth));
        headers.remove(header::AUTHORIZATION);
        assert!(!authorized(&headers, &auth));
        assert!(authorized(&HeaderMap::new(), &GatewayAuth::InsecureDev));
    }

    #[test]
    fn drone_dashboard_routes_are_disabled_until_enabled() {
        let original = std::env::var("YUKKI_DRONE_DASHBOARD_ENABLED").ok();
        std::env::remove_var("YUKKI_DRONE_DASHBOARD_ENABLED");
        assert!(!drone_dashboard_enabled());
        if let Some(value) = original {
            std::env::set_var("YUKKI_DRONE_DASHBOARD_ENABLED", value);
        }
    }

    fn auth_token(auth: &GatewayAuth) -> &str {
        match auth {
            GatewayAuth::Bearer(token) => token,
            GatewayAuth::InsecureDev => "",
        }
    }
}
