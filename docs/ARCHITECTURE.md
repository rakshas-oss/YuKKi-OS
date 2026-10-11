# YuKKi OS v6.9.0 — Architecture

## Scope

This document describes the architecture implemented in the current repository state.

## Runtime topology

YuKKi-OS runs as a control-plane mesh with two process roles:

- `bootstrap <bind-address>`: accepts peer registrations and broadcasts fleet updates
- `node <bootstrap-address> <advertised-address>`: registers to bootstrap and receives fleet updates

The CLI also provides an authenticated stream gateway and `streams list` /
`streams tune` clients. When `YUKKI_GATEWAY_TOKEN` is set, a node starts a
loopback HTTP/WebSocket gateway sharing its in-process stream registry.

## Control-plane transport

- Transport: TCP
- Framing: 4-byte big-endian length prefix
- Max plaintext frame: 64 KiB
- Session setup:
  1. X25519 ephemeral key exchange
  2. HKDF-SHA256 using shared secret + `YUKKI_PSK_HEX`
  3. ChaCha20-Poly1305 directional ciphers (`client->server`, `server->client`)
  4. Auth confirmation frame exchange
- Timeouts:
  - handshake timeout: 10s
  - I/O timeout: 30s
- Bootstrap inbound concurrency cap: 128 connections

## Peer registry behavior

- Peer registration payload is JSON:
  - `Register(PeerInfo { uuid, addr })`
- Fleet update payload is JSON:
  - `NodeFleet(Vec<PeerInfo>)`
- Peer state is in-memory only.

Stream announcements and SHA-256 descriptor digests are additional encrypted
`SovereignCommand` messages on the same authenticated TCP session. Bootstrap
relays each bounded, deduplicated announcement to the other connected nodes.
Nodes exchange a compact digest every 30 seconds while idle and announce full
descriptors for mismatches. Announcements expire after 120 seconds, have at
most eight hops, are limited to 16 KiB, and are deduplicated using a 4096-entry
cache. Fan-out is bounded by the existing 128-connection bootstrap limit.

## C FFI frame engine

- Header: `src/ffi/laminar_api.h`
- C implementation: `src/ffi/chaos_weave.c`
- Rust ABI struct: `SpatiotemporalFrame` (`88` bytes, packed/aligned for C interop)

C exports include:

- Lorenz/chaos functions (`chaos_engine_init`, `chaos_engine_reseed`, `generate_lorenz_step`, `weave_spatiotemporal_frame`)
- OOB helper functions (`oob_fnv1a_rolling_hash`, `oob_integrity_update`, `oob_sync_check`, `oob_quarantine_node`, `oob_is_quarantined`)

These FFI APIs are currently library-side primitives; the node CLI path does not expose direct runtime commands for OOB quarantine management.

## Broker integration boundary

`src/broker_client.rs` is intentionally isolated from peer-mesh transport:

- One TCP connection per broker submission
- Length-prefixed JSON request/response
- Independent request and connect timeout controls
- Request/response shape validation before/after I/O

Security note: broker transport auth is outside YuKKi-OS today.

## Geospatial and live media codecs

`src/arcgis.rs` represents avenue/road-network line geometry as GeoJSON
LineString Features with WGS84 longitude/latitude coordinates and optional
`route_id`/`avenue_name` metadata. It does not reinterpret the legacy `NXR1`
fluid/numeric fields and does not claim compatibility with proprietary
ArcGIS feature-service formats. GeoJSON Features can cross the existing
`BrokerTask` JSON boundary under `geospatial.arcgis.avenue.v1`.

`src/media_codec.rs` frames opaque codec payloads in YKMC v1 chunks and offers
the synchronized, in-process `LiveMediaStreams` collection. Audio/video
codec bitstreams are pass-through only; no transcoding occurs. Stream
appenders must supply contiguous sequence numbers beginning at zero. The
default store limits are 64 streams, 64 chunks per stream, 256 chunks total,
and 256 KiB per chunk; exhausted capacity reports backpressure instead of
discarding data. Consumers reclaim storage with `acknowledge_through` or
`remove_stream`. A chunk can be wrapped in the existing BrokerTask JSON
envelope, but its JSON byte-array expansion remains subject to the broker
client's configured frame-size limit.

`src/stream_registry.rs` derives local stream descriptors from store snapshots
and merges remote descriptors. Subscriptions have independent sequence cursors
and aggregate acknowledgements; per-stream and per-node subscriber ceilings
avoid per-consumer unbounded buffering. `src/stream_gateway.rs` exposes
authenticated HTTP list/describe/range endpoints and an ack-driven WebSocket
binary stream. The gateway caps accepted TCP connections at 128 and HTTP
request handling at 30 seconds; WebSockets use 60-second idle timeouts with
20-second pings. It does not provide TLS.

The mesh currently distributes discovery metadata only. Remote chunk fetching,
relay/fan-out trees, and shared upstream pulls are not implemented; the gateway
returns `501` for remote WebSocket tune-in. The standalone `gateway` command
owns a separate in-memory store, while the optional node gateway shares that
node's store and registry.

WASM stream selection remains host mediated: `wasm_ingest` validates guest
memory ranges before copying one bounded encoded chunk through
`env::yukki_select_stream`. No raw pointers or direct store handles are exposed.
Applications must still protect broker TCP links with an authenticated proxy
or equivalent deployment boundary.

## WebAssembly sandbox and GPU interop

`src/wasm_sandbox.rs` provides a Wasmtime-based execution sandbox:

- max linear memory: 16 MiB
- default fuel budget: 10,000,000
- optional fuel override: `YUKKI_WASM_MAX_FUEL` (must be positive)
- isolated memory: no direct host or CUDA memory pointers exposed to WASM guests

`src/gpu_adapter.rs` provides the GPU task offloading adapter and module lifecycle manager targeting `rakshas-oss/overhauled`:

- **Isolation Preservation**: Sandboxes communicate with GPU acceleration via host-mediated calls (`submit_gpu_task`). The host validates buffer sizes (capped at 64 KiB execution buffers) and generates high-level `BufferDescriptor`s. Sandboxes cannot bypass the runtime to touch CUDA APIs or device memory.
- **Protocol Version Negotiation**: Version exchange (`overhauled.wasm.gpu.v1`) ensures mutual compatibility prior to workload dispatch.
- **Retry and Idempotency**: Network failures or transient broker rejections (`retryable: true`) are retried automatically with backoff, preserving `task_id` for deduplication.
- **Safe Module Hotswapping**:
  1. *Prepare*: Compile and validate replacement module bytecode in the background.
  2. *State Handoff*: Optional structured application state migration via `StateHandoffHook`. Live WASM linear memory and arbitrary GPU VRAM/streams are explicitly **not** migrated.
  3. *Rollback on Failure*: Any validation or state handoff error aborts the swap, keeping the existing version actively serving.
  4. *Atomic Routing*: Routing tables update atomically to redirect new submissions.
  5. *Quiesce and Drain*: The old module version stops receiving new tasks while in-flight GPU tasks complete.
  6. *Drain-Before-Release*: Resources tied to superseded versions are deallocated strictly after in-flight operations drop to zero.
- **Configurable / Optional**: Disabled by default (`YUKKI_GPU_ADAPTER_ENABLED=false`), allowing standard node operations on systems without GPUs or overhauled brokers.

## Known implementation limitations

- Shared PSK trust model; no per-peer identity or rotation protocol
- No built-in TLS/mTLS transport wrapping for peer or broker sockets
- No persistent runtime state store
- No HTTP health endpoint; health is log- and process-state based
- No remote stream media relay or upstream sharing
