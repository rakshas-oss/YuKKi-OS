use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::extract::connect_info::Connected;
use axum::serve::{IncomingStream, Listener};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, DefaultBodyLimit, Path, Query, State,
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
// Bound synchronous origin socket operations across all websocket sessions.
const MAX_CONCURRENT_ORIGIN_PULLS: usize = 8;
static ORIGIN_PULL_PERMITS: Semaphore = Semaphore::const_new(MAX_CONCURRENT_ORIGIN_PULLS);
const DEFAULT_DRONE_DASHBOARD_MAX_CHUNKS: u64 = 256;

const MAX_TRACKED_CLIENTS: usize = 4096;
const REQUEST_BURST_PER_CLIENT: f64 = 40.0;
const REQUEST_RATE_PER_CLIENT_PER_SEC: f64 = 20.0;
const REQUEST_BURST_GLOBAL: f64 = 300.0;
const REQUEST_RATE_GLOBAL_PER_SEC: f64 = 100.0;
const MAX_WEBSOCKETS_GLOBAL: usize = 64;
const MAX_WEBSOCKETS_PER_CLIENT: usize = 4;
const EGRESS_BURST_GLOBAL_BYTES: f64 = 16.0 * 1024.0 * 1024.0;
const EGRESS_RATE_GLOBAL_BYTES_PER_SEC: f64 = 64.0 * 1024.0 * 1024.0;
const EGRESS_BURST_PER_CLIENT_BYTES: f64 = 4.0 * 1024.0 * 1024.0;
const EGRESS_RATE_PER_CLIENT_BYTES_PER_SEC: f64 = 8.0 * 1024.0 * 1024.0;
const WS_CONTROL_BURST: f64 = 40.0;
const WS_CONTROL_RATE_PER_SEC: f64 = 20.0;

struct ClientBudget {
    request_tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
    active_websockets: usize,
    egress_tokens: f64,
    egress_refill: Instant,
}

struct GatewayBudgetState {
    clients: HashMap<IpAddr, ClientBudget>,
    global_tokens: f64,
    global_refill: Instant,
    global_egress_tokens: f64,
    global_egress_refill: Instant,
    active_websockets: usize,
}

/// Admission controls for the read-only stream gateway. This intentionally
/// limits abusive access by network peer, not by publisher identity: untrusted
/// streams remain readable without being allowed to monopolize resources.
struct GatewayFloodLimiter {
    state: Mutex<GatewayBudgetState>,
}

impl GatewayFloodLimiter {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            state: Mutex::new(GatewayBudgetState {
                clients: HashMap::new(),
                global_tokens: REQUEST_BURST_GLOBAL,
                global_refill: now,
                global_egress_tokens: EGRESS_BURST_GLOBAL_BYTES,
                global_egress_refill: now,
                active_websockets: 0,
            }),
        }
    }

    fn ensure_client<'a>(
        state: &'a mut GatewayBudgetState,
        peer: IpAddr,
        now: Instant,
    ) -> Option<&'a mut ClientBudget> {
        state.clients.retain(|_, budget| {
            now.saturating_duration_since(budget.last_seen) <= Duration::from_secs(300)
                || budget.active_websockets != 0
        });
        if !state.clients.contains_key(&peer) {
            if state.clients.len() >= MAX_TRACKED_CLIENTS {
                return None;
            }
            state.clients.insert(
                peer,
                ClientBudget {
                    request_tokens: REQUEST_BURST_PER_CLIENT,
                    last_refill: now,
                    last_seen: now,
                    active_websockets: 0,
                    egress_tokens: EGRESS_BURST_PER_CLIENT_BYTES,
                    egress_refill: now,
                },
            );
        }
        state.clients.get_mut(&peer)
    }

    fn allow_request(&self, peer: IpAddr) -> bool {
        let now = Instant::now();
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let elapsed = now.saturating_duration_since(state.global_refill).as_secs_f64();
        state.global_tokens = (state.global_tokens
            + elapsed * REQUEST_RATE_GLOBAL_PER_SEC)
            .min(REQUEST_BURST_GLOBAL);
        state.global_refill = now;
        if state.global_tokens < 1.0 {
            return false;
        }
        let Some(client) = Self::ensure_client(&mut state, peer, now) else {
            return false;
        };
        let elapsed = now.saturating_duration_since(client.last_refill).as_secs_f64();
        client.request_tokens = (client.request_tokens
            + elapsed * REQUEST_RATE_PER_CLIENT_PER_SEC)
            .min(REQUEST_BURST_PER_CLIENT);
        client.last_refill = now;
        client.last_seen = now;
        if client.request_tokens < 1.0 {
            return false;
        }
        client.request_tokens -= 1.0;
        state.global_tokens -= 1.0;
        true
    }

    fn allow_egress_bytes(&self, peer: IpAddr, byte_cost: usize) -> bool {
        let now = Instant::now();
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let global_elapsed = now
            .saturating_duration_since(state.global_egress_refill)
            .as_secs_f64();
        state.global_egress_tokens = (state.global_egress_tokens
            + global_elapsed * EGRESS_RATE_GLOBAL_BYTES_PER_SEC)
            .min(EGRESS_BURST_GLOBAL_BYTES);
        state.global_egress_refill = now;
        if byte_cost as f64 > state.global_egress_tokens {
            return false;
        }
        let Some(client) = Self::ensure_client(&mut state, peer, now) else {
            return false;
        };
        let client_elapsed = now
            .saturating_duration_since(client.egress_refill)
            .as_secs_f64();
        client.egress_tokens = (client.egress_tokens
            + client_elapsed * EGRESS_RATE_PER_CLIENT_BYTES_PER_SEC)
            .min(EGRESS_BURST_PER_CLIENT_BYTES);
        client.egress_refill = now;
        client.last_seen = now;
        if byte_cost as f64 > client.egress_tokens {
            return false;
        }
        client.egress_tokens -= byte_cost as f64;
        state.global_egress_tokens -= byte_cost as f64;
        true
    }

    fn acquire_websocket(self: &Arc<Self>, peer: IpAddr) -> Option<WebSocketPermit> {
        let now = Instant::now();
        let mut state = self.state.lock().ok()?;
        if state.active_websockets >= MAX_WEBSOCKETS_GLOBAL {
            return None;
        }
        let client = Self::ensure_client(&mut state, peer, now)?;
        if client.active_websockets >= MAX_WEBSOCKETS_PER_CLIENT {
            return None;
        }
        client.active_websockets += 1;
        client.last_seen = now;
        state.active_websockets += 1;
        Some(WebSocketPermit {
            limiter: self.clone(),
            peer,
        })
    }
}

struct WebSocketPermit {
    limiter: Arc<GatewayFloodLimiter>,
    peer: IpAddr,
}

impl Drop for WebSocketPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.limiter.state.lock() {
            state.active_websockets = state.active_websockets.saturating_sub(1);
            if let Some(client) = state.clients.get_mut(&self.peer) {
                client.active_websockets = client.active_websockets.saturating_sub(1);
                client.last_seen = Instant::now();
            }
        }
    }
}
struct CappedListener {
    listener: TcpListener,
    permits: Arc<Semaphore>,
}

struct CappedStream {
    stream: TcpStream,
    // Keep the connection permit alive for the entire accepted connection.
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl AsyncRead for CappedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_read(cx, buffer)
    }
}

impl AsyncWrite for CappedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_write(cx, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

#[derive(Debug, Clone, Copy)]
struct PeerAddr(SocketAddr);

impl Connected<IncomingStream<'_, CappedListener>> for PeerAddr {
    fn connect_info(stream: IncomingStream<'_, CappedListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

impl Listener for CappedListener {
    type Io = CappedStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let permit = self.permits.clone().acquire_owned().await
            .expect("connection semaphore remains open");
        loop {
            match self.listener.accept().await {
                Ok((stream, address)) => {
                    return (CappedStream { stream, _permit: permit }, address);
                }
                Err(error) => {
                    warn!("stream gateway accept error: {error}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}


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
    flood_limiter: Arc<GatewayFloodLimiter>,
    #[cfg(feature = "mesh_dashboard")]
    mesh: Arc<MeshStore>,
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

#[cfg(feature = "mesh_dashboard")]
#[derive(Deserialize)]
struct MeshQuery {
    bbox: Option<String>,
    limit: Option<usize>,
    since: Option<u64>,
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
    #[cfg(feature = "mesh_dashboard")]
    let mesh = {
        let mesh = Arc::new(MeshStore::new());
        for node in demo_mesh_nodes() {
            mesh.upsert_node(node);
        }
        mesh
    };

    let state = GatewayState {
        streams,
        registry,
        auth,
        relay,
        flood_limiter: Arc::new(GatewayFloodLimiter::new()),
        #[cfg(feature = "mesh_dashboard")]
        mesh,
    };
    let app = Router::new()
        .route("/dashboard", get(dashboard))
        .route("/dashboard/drones", get(list_drones))
        .route("/dashboard/drones/{id}", get(describe_drone))
        .route("/v1/streams", get(list_streams))
        .route("/v1/streams/{id}", get(describe_stream))
        .route("/v1/streams/{id}/chunks", get(read_chunks))
        .route("/v1/streams/{id}/ws", get(websocket_tune_in));
    #[cfg(feature = "mesh_dashboard")]
    let app = app
        .route("/v1/mesh", get(mesh_state))
        .route("/v1/mesh/ws", get(mesh_ws));
    let app = app
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(MAX_HTTP_BODY_BYTES))
        .layer(middleware::from_fn_with_state(
            state,
            authenticate_and_limit,
        ))
        // Added outermost so browser CORS preflights are handled before bearer auth.
        .layer(middleware::from_fn(cors_preflight_and_headers));
    axum::serve(
        CappedListener {
            listener,
            permits: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        },
        app.into_make_service_with_connect_info::<PeerAddr>(),
    )
    .await
}

const GATEWAY_CORS_ORIGINS_ENV: &str = "YUKKI_GATEWAY_CORS_ORIGINS";

fn cors_origin_allowed(origin: &str, configured_origins: &str) -> bool {
    configured_origins.split(',').any(|candidate| {
        let candidate = candidate.trim();
        !candidate.is_empty() && candidate != "*" && candidate == origin
    })
}

fn apply_cors_headers(response: &mut Response, origin: &str) {
    if let Ok(origin) = origin.parse() {
        let headers = response.headers_mut();
        headers.insert("access-control-allow-origin", origin);
        headers.append("vary", "Origin".parse().expect("static header is valid"));
    }
}

async fn cors_preflight_and_headers(
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let origin = request
        .headers()
        .get("origin")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let Some(origin) = origin else {
        return next.run(request).await;
    };

    let configured = std::env::var(GATEWAY_CORS_ORIGINS_ENV).unwrap_or_default();
    if !cors_origin_allowed(&origin, &configured) {
        // Do not attach CORS permission to an unlisted origin. Leave ordinary
        // same-origin GET requests functional even when no cross-origin list
        // is configured; browsers still prevent cross-origin JS from reading
        // the response. Preflight is rejected before the protected GET.
        if request.method() == axum::http::Method::OPTIONS {
            return StatusCode::FORBIDDEN.into_response();
        }
        return next.run(request).await;
    }

    if request.method() == axum::http::Method::OPTIONS {
        let requested_method = request
            .headers()
            .get("access-control-request-method")
            .and_then(|value| value.to_str().ok());
        let requested_headers_allowed = request
            .headers()
            .get("access-control-request-headers")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .split(',')
            .all(|header| {
                matches!(
                    header.trim().to_ascii_lowercase().as_str(),
                    "" | "authorization" | "content-type"
                )
            });
        if !requested_method.is_some_and(|method| method.eq_ignore_ascii_case("GET"))
            || !requested_headers_allowed
        {
            return StatusCode::FORBIDDEN.into_response();
        }

        let mut response = StatusCode::NO_CONTENT.into_response();
        apply_cors_headers(&mut response, &origin);
        let headers = response.headers_mut();
        headers.insert(
            "access-control-allow-methods",
            "GET, OPTIONS".parse().expect("static header is valid"),
        );
        headers.insert(
            "access-control-allow-headers",
            "Authorization, Content-Type".parse().expect("static header is valid"),
        );
        headers.insert(
            "access-control-max-age",
            "300".parse().expect("static header is valid"),
        );
        return response;
    }

    let mut response = next.run(request).await;
    apply_cors_headers(&mut response, &origin);
    response
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
    let peer = request
        .extensions()
        .get::<ConnectInfo<PeerAddr>>()
        .map(|ConnectInfo(address)| address.0.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    if !state.flood_limiter.allow_request(peer) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
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

#[cfg(feature = "mesh_dashboard")]
async fn mesh_state(State(state): State<GatewayState>, Query(query): Query<MeshQuery>) -> Response {
    if let Some(bbox) = query.bbox {
        let mut parts = bbox.split(',');
        let (Some(min_lon), Some(min_lat), Some(max_lon), Some(max_lat)) = (
            parts.next().and_then(|v| v.parse::<f64>().ok()),
            parts.next().and_then(|v| v.parse::<f64>().ok()),
            parts.next().and_then(|v| v.parse::<f64>().ok()),
            parts.next().and_then(|v| v.parse::<f64>().ok()),
        ) else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        let limit = query.limit.unwrap_or(500).min(5000);
        let nodes = state.mesh.query_bbox(min_lon, min_lat, max_lon, max_lat, limit, query.since);
        return Json(MeshSnapshot {
            nodes,
            generated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
        .into_response();
    }
    Json(state.mesh.snapshot()).into_response()
}

#[cfg(feature = "mesh_dashboard")]
async fn mesh_ws(State(state): State<GatewayState>, websocket: WebSocketUpgrade) -> Response {
    let mesh = state.mesh.clone();
    websocket.on_upgrade(move |socket| mesh_ws_session(socket, mesh))
}

#[cfg(feature = "mesh_dashboard")]
async fn mesh_ws_session(mut socket: WebSocket, mesh: Arc<MeshStore>) {
    let mut tick = interval(Duration::from_secs(2));
    loop {
        tick.tick().await;
        let snapshot = mesh.snapshot();
        match serde_json::to_string(&snapshot) {
            Ok(payload) => {
                if futures_util::SinkExt::send(&mut socket, Message::Text(payload.into())).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
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
    ConnectInfo(peer): ConnectInfo<PeerAddr>,
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
        Ok(chunks) => {
            let egress_bytes = chunks.iter().fold(0usize, |total, chunk| {
                total.saturating_add(chunk.payload.len())
                    .saturating_add(chunk.stream_id.len())
                    .saturating_add(chunk.codec.len())
                    .saturating_add(96)
            });
            if !state.flood_limiter.allow_egress_bytes(peer.0.ip(), egress_bytes) {
                return StatusCode::TOO_MANY_REQUESTS.into_response();
            }
            Json(chunks).into_response()
        },
        Err(MediaError::StreamNotFound(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::RANGE_NOT_SATISFIABLE.into_response(),
    }
}

async fn websocket_tune_in(
    State(state): State<GatewayState>,
    ConnectInfo(peer): ConnectInfo<PeerAddr>,
    Path(id): Path<String>,
    Query(query): Query<StreamQuery>,
    websocket: WebSocketUpgrade,
) -> Response {
    let from = query.from.unwrap_or(0);
    let Some(ws_permit) = state.flood_limiter.acquire_websocket(peer.0.ip()) else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let result = match state.relay.clone() {
        Some(relay) => {
            let id = id.clone();
            let permit = match ORIGIN_PULL_PERMITS.acquire().await {
                Ok(permit) => permit,
                Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
            };
            match tokio::task::spawn_blocking(move || {
                let _permit = permit;
                relay.tune_in(&id, from)
            }).await {
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
            websocket_session(
                socket, subscription, state.registry, state.relay, id,
                state.flood_limiter, peer.0.ip(), ws_permit
            )
        })
}

async fn websocket_session(
    socket: WebSocket,
    mut subscription: Subscription,
    registry: StreamRegistry,
    relay: Option<Arc<StreamRelay>>,
    stream_id: String,
    flood_limiter: Arc<GatewayFloodLimiter>,
    peer: IpAddr,
    _permit: WebSocketPermit,
) {
    let (mut sender, mut receiver) = futures_util::StreamExt::split(socket);
    let mut ping = interval(PING_INTERVAL);
    ping.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ping.tick().await;
    let mut poll = interval(STREAM_POLL_INTERVAL);
    poll.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut last_activity = Instant::now();
    let mut awaiting_ack = None;
    let mut control_tokens = WS_CONTROL_BURST;
    let mut control_refill = Instant::now();
    loop {
        tokio::select! {
            incoming = futures_util::StreamExt::next(&mut receiver) => {
                let now = Instant::now();
                let elapsed = now.saturating_duration_since(control_refill).as_secs_f64();
                control_tokens = (control_tokens + elapsed * WS_CONTROL_RATE_PER_SEC)
                    .min(WS_CONTROL_BURST);
                control_refill = now;
                if control_tokens < 1.0 {
                    close_policy(&mut sender).await;
                    break;
                }
                control_tokens -= 1.0;
                match incoming {
                    Some(Ok(Message::Text(text))) if text.len() <= 1024 => {
                        let ack = crate::ingress::from_slice::<ClientAck>(text.as_bytes(), crate::ingress::IngressLimits::CONTROL);
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
                        if !flood_limiter.allow_egress_bytes(peer, frame.len()) {
                            close_policy(&mut sender).await;
                            break;
                        }
                        match timeout(Duration::from_secs(30), futures_util::SinkExt::send(&mut sender, Message::Binary(frame.into()))).await {
                            Ok(Ok(())) => awaiting_ack = Some(sequence),
                            _ => break,
                        }
                    }
                    Ok(SubscriptionRead::Waiting) => {
                        if let Some(relay) = relay.clone().filter(|r| r.is_mirror(&stream_id)) {
                            let id = stream_id.clone();
                            // Do not create more blocking work when the shared
                            // origin budget is exhausted; the next poll can retry.
                            if let Ok(permit) = ORIGIN_PULL_PERMITS.try_acquire() {
                                let _ = tokio::task::spawn_blocking(move || {
                                    let _permit = permit;
                                    relay.pump(&id)
                                }).await;
                            }
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
    fn cors_allowlist_requires_an_exact_origin_and_rejects_wildcards() {
        let allowed = "https://dashboard.example,https://ops.example:8443";
        assert!(cors_origin_allowed("https://dashboard.example", allowed));
        assert!(cors_origin_allowed("https://ops.example:8443", allowed));
        assert!(!cors_origin_allowed("https://dashboard.example.evil", allowed));
        assert!(!cors_origin_allowed("https://dashboard.example/", allowed));
        assert!(!cors_origin_allowed("https://dashboard.example", "*"));
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

    #[tokio::test]
    async fn origin_pull_budget_is_bounded_and_recovers_after_saturation() {
        let permits = ORIGIN_PULL_PERMITS
            .try_acquire_many(MAX_CONCURRENT_ORIGIN_PULLS as u32)
            .expect("test must acquire the complete origin-pull budget");
        assert!(ORIGIN_PULL_PERMITS.try_acquire().is_err());

        let waiting = tokio::spawn(async {
            ORIGIN_PULL_PERMITS.acquire().await.map(|_| ())
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished(), "ninth origin pull must wait at capacity");

        drop(permits);
        timeout(Duration::from_secs(1), waiting)
            .await
            .expect("origin-pull waiter must resume after capacity is released")
            .expect("origin-pull waiter task must not panic")
            .expect("origin-pull semaphore must remain open");
    }

    fn auth_token(auth: &GatewayAuth) -> &str {
        match auth {
            GatewayAuth::Bearer(token) => token,
            GatewayAuth::InsecureDev => "",
        }
    }
}

#[cfg(test)]
mod flood_control_tests {
    use super::*;

    #[test]
    fn per_peer_request_bucket_rejects_bursts_and_refills() {
        let limiter = GatewayFloodLimiter::new();
        let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        for _ in 0..(REQUEST_BURST_PER_CLIENT as usize) {
            assert!(limiter.allow_request(peer));
        }
        assert!(!limiter.allow_request(peer));
        std::thread::sleep(Duration::from_millis(100));
        assert!(limiter.allow_request(peer));
    }

    #[test]
    fn websocket_concurrency_is_bounded_per_peer_and_globally() {
        let limiter = Arc::new(GatewayFloodLimiter::new());
        let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
        let mut permits = Vec::new();
        for _ in 0..MAX_WEBSOCKETS_PER_CLIENT {
            permits.push(limiter.acquire_websocket(peer).expect("within per-peer limit"));
        }
        assert!(limiter.acquire_websocket(peer).is_none());
        drop(permits);
        assert!(limiter.acquire_websocket(peer).is_some());
    }

    #[test]
    fn global_and_per_peer_egress_byte_buckets_cap_stream_downloads() {
        let limiter = GatewayFloodLimiter::new();
        let peer_a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
        let peer_b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 21));
        assert!(limiter.allow_egress_bytes(peer_a, EGRESS_BURST_PER_CLIENT_BYTES as usize));
        assert!(!limiter.allow_egress_bytes(peer_a, 1));
        assert!(limiter.allow_egress_bytes(peer_b, EGRESS_BURST_PER_CLIENT_BYTES as usize));
    }

    #[test]
    fn global_request_bucket_caps_aggregate_flooding() {
        let limiter = GatewayFloodLimiter::new();
        for value in 1..=(REQUEST_BURST_GLOBAL as u32) {
            let peer = IpAddr::V4(Ipv4Addr::from(value));
            assert!(limiter.allow_request(peer));
        }
        let extra_peer = IpAddr::V4(Ipv4Addr::from(REQUEST_BURST_GLOBAL as u32 + 1));
        assert!(!limiter.allow_request(extra_peer));
    }

    #[test]
    fn client_budget_table_is_hard_bounded() {
        let limiter = GatewayFloodLimiter::new();
        let mut state = limiter.state.lock().unwrap();
        let now = Instant::now();
        for value in 1..=(MAX_TRACKED_CLIENTS + 8) {
            let peer = IpAddr::V4(Ipv4Addr::from(value as u32));
            let _ = GatewayFloodLimiter::ensure_client(&mut state, peer, now);
        }
        assert!(state.clients.len() <= MAX_TRACKED_CLIENTS);
    }
}
