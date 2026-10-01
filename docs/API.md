# YuKKi OS v6.8.0 — API and ABI Reference

## CLI API (`src/main.rs`)

### Command forms

```text
yukki_core_node bootstrap <bind-address>
yukki_core_node node <bootstrap-address> <advertised-address>
```

### Required environment

- `YUKKI_PSK_HEX`: 64-character hex string (32-byte PSK)

### Optional environment

- `RUST_LOG`: tracing filter (default `info`)

## Peer mesh message schema

```rust
enum SovereignCommand {
    Register(PeerInfo),
    NodeFleet(Vec<PeerInfo>),
}

struct PeerInfo {
    uuid: uuid::Uuid,
    addr: String,
}
```

Messages are JSON encoded and encrypted after session establishment.

## Broker client API (`src/broker_client.rs`)

### Environment variables

- `YUKKI_BROKER_ENDPOINT`
- `YUKKI_BROKER_CONNECT_TIMEOUT_MS` (must be > 0 and <= 600000 / 10 minutes)
- `YUKKI_BROKER_REQUEST_TIMEOUT_MS` (must be > 0 and <= 600000 / 10 minutes)
- `YUKKI_BROKER_MAX_FRAME_BYTES`
- `YUKKI_BROKER_TRANSPORT_SECURITY` (`plaintext-boundary` | `authenticated-proxy`)

### Request schema (`BrokerTask`)

- `task_id: String` (required, non-empty)
- `source: String` (required, non-empty)
- `destination: String` (required, non-empty)
- `kind: String` (required, non-empty)
- `priority: u8`
- `timeout_ms: u32` (required, `1..=300000` i.e. up to 5 minutes; zero or
  oversized values are rejected by `validate()`. Callers that cannot guarantee
  an in-range value can use `BrokerTask::effective_timeout_ms()`, which falls
  back to a heuristic timeout derived from the payload size instead of
  trusting a raw out-of-range value.)
- `payload: serde_json::Value` (required, non-null)

### Response schema (`BrokerResult`)

- `task_id: String` (must match request task_id)
- `status: String` (required, non-empty)
- `gpu_id: Option<i32>`
- `execution_ms: Option<u64>`
- `result: Option<serde_json::Value>`

## NXR1 geospatial frame interop (`src/nxr1.rs`)

Wire-compatible `geospatial.frame.v1` codec shared with `rakshas-oss/overhauled`.
See the module-level docs in `src/nxr1.rs` for the full rationale; summary:

### NXR1 wire format

Fixed 81-byte big-endian header followed by an opaque, length-prefixed
payload:

| Field        | Type      | Bytes |
|--------------|-----------|-------|
| magic        | `u32`     | 4     |
| version      | `u8`      | 1     |
| seq_id       | `u64`     | 8     |
| x, y, z      | `f64` ×3  | 24    |
| u, v, w      | `f64` ×3  | 24    |
| fluidity     | `f32`     | 4     |
| drag         | `f32`     | 4     |
| divergence   | `f64`     | 8     |
| payload_len  | `u32`     | 4     |
| payload      | `[u8; N]` | N     |

- `magic` must equal `0x4E58_5231` (ASCII `"NXR1"`).
- `version` must equal `1`.
- All float fields must be finite (`NaN`/`±Infinity` rejected).
- `payload_len` is bounded by `NXR1_MAX_PAYLOAD_BYTES` (currently equal to
  `DEFAULT_BROKER_MAX_FRAME_BYTES`, 64 KiB).
- Decoding requires the input to be exactly `81 + payload_len` bytes: both
  truncated input and trailing bytes are rejected.

### Broker adapter

`to_broker_task`/`from_broker_task` convert an `Nxr1Frame` to/from the
existing `BrokerTask` envelope (kind `"geospatial.frame.v1"`, encoded NXR1
bytes carried as a JSON byte array under the `"nxr1"` payload key). This
reuses `BrokerClient`'s existing 4-byte length-prefixed JSON transport — no
second, parallel binary transport is introduced.

### Errors (`Nxr1Error`)

`Truncated`, `TrailingBytes`, `InvalidMagic`, `UnsupportedVersion`,
`NonFiniteValue`, `PayloadTooLarge`, `UnexpectedKind`,
`MissingBrokerPayload`, `MalformedBrokerPayload`.

NXR1 remains the legacy numeric frame format; its `x/y/z`, vector, and fluid
fields are not mapped to geographic coordinates. New avenue and road-network
data should use the explicit GeoJSON representation below.

## ArcGIS-oriented avenue GeoJSON (`src/arcgis.rs`)

Public symbols exported from the crate root:
`ArcGisAvenue`, `Wgs84Coordinate`, `ArcGisError`, `ARCGIS_AVENUE_KIND`, and
`ARCGIS_AVENUE_MAX_BYTES`, `ARCGIS_AVENUE_MAX_COORDINATES`.

`ArcGisAvenue::encode` and `decode` use an interoperable RFC 7946 GeoJSON
`Feature` containing a `LineString`, not a proprietary ArcGIS binary format.
The encoded shape is:

```json
{
  "type": "Feature",
  "id": "avenue-42",
  "geometry": {
    "type": "LineString",
    "coordinates": [[-122.4194, 37.7749], [-122.418, 37.7755]]
  },
  "properties": { "route_id": "route-7", "avenue_name": "Main Avenue" }
}
```

Each position is `[longitude, latitude]` in WGS84 (EPSG:4326); coordinates
must be finite, longitude must be in `[-180, 180]`, and latitude in `[-90, 90]`.
A LineString requires at least two positions. `feature_id` is required;
`route_id` and `avenue_name` are optional, non-empty strings limited to 256
UTF-8 bytes. Features are limited to 10,000 positions and 64 KiB. Elevation,
measures, arbitrary ArcGIS attributes, and proprietary feature-service
formats are not modeled.

`ArcGisAvenue::to_broker_task` and `from_broker_task` use kind
`geospatial.arcgis.avenue.v1`, placing the GeoJSON Feature under the
`arcgis_avenue` key of the existing `BrokerTask.payload`. This is the
repository's JSON broker envelope, not an ArcGIS service client. The broker's
configured frame-size limit still applies to the complete JSON task.

## Chunked audio/video (`src/media_codec.rs`)

Public symbols exported from the crate root:
`MediaType`, `MediaStreamMetadata`, `MediaChunk`, `MediaStreamConfig`,
`LiveMediaStreams`, `MediaError`, `MEDIA_MAX_CHUNK_BYTES`,
`MEDIA_MAX_STREAM_ID_BYTES`, `MEDIA_MAX_CODEC_BYTES`,
`MEDIA_CHUNK_HEADER_LEN`, `MEDIA_CHUNK_KIND`, and `MEDIA_CHUNK_BROKER_KEY`.

This is a codec-agnostic pass-through library. It does not encode or decode
H.264, Opus, or other codec bitstreams. `MediaChunk::encode`/`decode` frame
opaque payload bytes using YKMC v1. All integers are unsigned big-endian:

| Field | Type | Bytes |
|---|---:|---:|
| magic (`YKMC`) | `u32` | 4 |
| version | `u8` | 1 |
| media type (`0` audio, `1` video) | `u8` | 1 |
| flags (bit 0 is keyframe; other bits reserved) | `u8` | 1 |
| stream ID UTF-8 byte length | `u16` | 2 |
| codec label UTF-8 byte length | `u16` | 2 |
| sequence number | `u64` | 8 |
| timestamp in milliseconds | `u64` | 8 |
| payload byte length | `u32` | 4 |
| stream ID, codec label, payload | variable | declared lengths |

The fixed header is 31 bytes. The stream ID is limited to 128 bytes, codec
label to 64 bytes, and payload to 256 KiB. Decoding rejects invalid magic,
version, media type, flags, UTF-8, lengths, truncation, and trailing bytes.
`MediaChunk::to_broker_task`/`from_broker_task` use kind `media.chunk.v1`
with an encoded byte array under `media_chunk`. JSON arrays expand binary
data; the configured `BrokerClient` frame-size limit still applies.

`LiveMediaStreams::new(config)` returns a synchronized in-memory collection:

```rust,ignore
let streams = LiveMediaStreams::new(MediaStreamConfig::default())?;
streams.open_stream(MediaStreamMetadata {
    stream_id: "camera-1".into(),
    media_type: MediaType::Video,
    codec: "example-codec".into(),
})?;
let chunk = MediaChunk {
    stream_id: "camera-1".into(),
    media_type: MediaType::Video,
    codec: "example-codec".into(),
    sequence_no: 0,
    timestamp_ms: 0,
    is_keyframe: true,
    payload: vec![0x01, 0x02],
};
streams.ingest_chunk(&chunk.encode()?)?;
let frame = streams.get_chunk("camera-1", 0)?;
let frames = streams.get_range("camera-1", 0, 10)?;
streams.close_stream("camera-1")?;
```

`append_chunk` and `ingest_chunk` require contiguous sequence numbers starting
at zero; duplicates and gaps/out-of-order input return distinct
`MediaError`s. Reads distinguish future/missing chunks from acknowledged and
no-longer-retained chunks. Ranges are inclusive and may not exceed
`max_chunks_per_stream`. `MediaStreamConfig` configures `max_streams`,
`max_chunks_per_stream`, `max_total_chunks`, and `max_chunk_bytes`; defaults
are 64 streams, 64 chunks per stream, 256 total retained chunks, and 256 KiB
per chunk (at most 64 MiB of retained payloads). Full capacity returns
`MediaError::Backpressure`; no chunks are silently evicted.
`acknowledge_through` releases a prefix of retained chunks, `close_stream`
prevents more appends but keeps chunks readable, `stream_metadata` retrieves
the immutable stream metadata, and `remove_stream` deletes the stream and
frees all its retained data. These APIs are in-process storage; they do not
provide network transport, persistence, codec transcoding, or media-clock
synchronization.

## C ABI (`src/ffi/laminar_api.h`)

### `SpatiotemporalFrame`

Packed/aligned C-compatible struct, 88 bytes:

- `seq_id: uint64_t`
- `x, y, z: double`
- `u, v, w: double`
- `fluidity: float`
- `drag: float`
- `divergence: double`
- `payload[16]: uint8_t`

### Exported C functions

- `chaos_engine_init(double sigma, double rho, double beta)`
- `chaos_engine_reseed(double sigma, double rho, double beta, double x0, double y0, double z0)`
- `generate_lorenz_step(double dt)`
- `weave_spatiotemporal_frame(uint64_t seq, const uint8_t* payload_src, SpatiotemporalFrame* out_frame)`
- `oob_fnv1a_rolling_hash(uint64_t seed, const uint8_t *data, uint32_t len)`
- `oob_integrity_update(uint64_t seq, const uint8_t *payload, uint32_t len)`
- `oob_sync_check(uint64_t seq)`
- `oob_quarantine_node(const char *node_uuid)`
- `oob_is_quarantined(const char *node_uuid)`

## Rust library exports (`src/lib.rs`)

- `adi_auto_tune`
- `broker_client`
- `gpu_adapter`
- `nxr1`
- `wasm_sandbox`
- `SpatiotemporalFrame`

## GPU WASM Broker Interop API (`src/gpu_adapter.rs`)

Interoperability adapter for scheduling GPU compute tasks on `rakshas-oss/overhauled` from WASM sandboxes.

### Wire Protocol Contract

- **Transport**: Raw TCP with 4-byte big-endian length-prefixed JSON.
- **Protocol Version**: `overhauled.wasm.gpu.v1`.
- **Framing**:
  - 4 bytes: `uint32_t` payload length in network byte order (big-endian).
  - N bytes: UTF-8 encoded JSON `BrokerMessage`.

### Message Types (`BrokerMessage`)

Tagged union with `"type"` and `"payload"`:

1. **`handshake_request` (`ProtocolHandshakeRequest`)**:
   - `magic: String` (`"OVERHAULED_WASM_GPU"`)
   - `supported_versions: Vec<String>` (e.g. `["overhauled.wasm.gpu.v1"]`)
   - `client_id: String`
2. **`handshake_response` (`ProtocolHandshakeResponse`)**:
   - `status: String` (`"ok"` or `"incompatible_version"`)
   - `negotiated_version: Option<String>`
   - `capabilities: Vec<String>` (e.g. `["nvlink_placement", "cancellation", "batching"]`)
   - `error_message: Option<String>`
3. **`task_request` (`GpuTaskRequest`)**:
   - `protocol_version: String` (`"overhauled.wasm.gpu.v1"`)
   - `task_id: String` (UUID or unique string)
   - `idempotency_key: Option<String>` (for deduplication during retries; defaults to `task_id`)
   - `sandbox_id: String` (originating sandbox identity)
   - `module_id: String`
   - `module_version: String`
   - `priority: u8` (0-255, higher = higher scheduling priority)
   - `deadline_ms: Option<u64>` (epoch millisecond deadline)
   - `timeout_ms: u32` (`1..=300000`, i.e. up to 5 minutes; zero or oversized
     values are rejected by `validate()`. `GpuTaskRequest::effective_timeout_ms()`
     returns a heuristic, payload-size-derived timeout as a safe fallback when
     the raw value is out of range instead of trusting it blindly.)
   - `buffers: Vec<BufferDescriptor>` (input and output descriptors)
   - `metadata: Option<Value>`
4. **`task_response` (`GpuTaskResponse`)**:
   - `protocol_version: String`
   - `task_id: String` (matches request)
   - `status: GpuTaskStatus` (`"completed"`, `"failed"`, `"cancelled"`, `"rejected"`)
   - `gpu_id: Option<i32>` (assigned GPU ID)
   - `execution_ms: Option<u64>`
   - `output_buffers: Vec<BufferDescriptor>`
   - `error: Option<BrokerTaskError>` (`code`, `message`, `retryable`)
5. **`cancel_request` (`CancelTaskRequest`)**:
   - `protocol_version: String`
   - `task_id: String`
   - `sandbox_id: String`
   - `reason: String`
6. **`cancel_response` (`CancelTaskResponse`)**:
   - `task_id: String`
   - `cancelled: bool`
   - `message: Option<String>`

### Buffer Descriptors (`BufferDescriptor`)

- `buffer_id: String`
- `kind: BufferKind` (`"host_memory"`, `"shared_memory"`, `"inline_bytes"`, `"gpu_buffer"`)
- `size_bytes: usize`
- `offset: usize`
- `access: BufferAccess` (`"read_only"`, `"write_only"`, `"read_write"`)
- `inline_data: Option<Vec<u8>>`

### Module Lifecycle & Safe Hotswapping

Managed by `ModuleLifecycleManager`:
1. **Prepare**: Background bytecode compilation and validation (`prepare_version`).
2. **State Handoff**: If hooks are registered on both versions, `export_state()` on old and `import_state()` on new version.
3. **Rollback on Failure**: If preparation or state handoff fails, activation is aborted and the previous version remains active and serving without disruption.
4. **Atomic Switch**: Active routing table is atomically updated.
5. **Quiesce & Drain**: Old version enters `Quiescing` state and stops receiving new tasks.
6. **Drain-Before-Release Ordering**: Resources belonging to the old version are only deallocated after its in-flight GPU task count reaches zero.

**State Migration Note**: Live WASM linear memory pages and arbitrary CUDA device pointers are **never** migrated across module versions. Hotswapping strictly relies on quiescing plus application-level structured state handoff hooks.

### Environment Configuration

- `YUKKI_GPU_ADAPTER_ENABLED`: `"true"` | `"false"` (default `false`)
- `YUKKI_GPU_BROKER_ENDPOINT`: endpoint address (default `127.0.0.1:9000`)
- `YUKKI_GPU_CONNECT_TIMEOUT_MS`: connect timeout in ms (default `3000`; must be > 0 and <= 600000 / 10 minutes)
- `YUKKI_GPU_REQUEST_TIMEOUT_MS`: request timeout in ms (default `5000`; must be > 0 and <= 600000 / 10 minutes)
- `YUKKI_GPU_QUIESCE_TIMEOUT_MS`: quiesce timeout in ms (default `5000`; must be > 0 and <= 600000 / 10 minutes)
- `YUKKI_GPU_MAX_RETRIES`: maximum retry attempts for retryable errors (default `3`)
- `YUKKI_GPU_MAX_FRAME_BYTES`: maximum message frame size in bytes (default `65536`)

### Paired overhauled PR Compatibility Notes

- The companion `overhauled` PR must implement the server side of `overhauled.wasm.gpu.v1` over length-prefixed TCP on the broker port (default 9000).
- Handshake messages use type `"handshake_request"` and `"handshake_response"` with magic `"OVERHAULED_WASM_GPU"`.
- When overhauled returns a rejection with `retryable: true`, YuKKi-OS client will retry with exponential backoff using the identical `task_id` for idempotency.

## WSM1 & BRK1 Broker Lifecycle Protocol (`src/gpu_adapter.rs`)

Additive, binary wire-level protocol support for overhauled broker WSM1 lifecycle and task operations (compatible with `rakshas-oss/overhauled` `include/wasm_sandbox.h` definitions).

### Wire Formats

#### 1. WSM1 Binary Protocol

- **Magic**: `0x57534D31` (`"WSM1"` in ASCII, big-endian)
- **Protocol Version**: `1`
- **Header (8 bytes)**:
  - `magic`: `uint32_be` (`0x57534D31`)
  - `version`: `uint16_be` (`1`)
  - `msg_type`: `uint8` (`1`: TaskRequest, `2`: TaskResponse, `3`: LifecycleRequest, `4`: LifecycleResponse)
  - `action_or_flags`: `uint8` (Lifecycle action or task status)

- **String Field Encoding**: `uint16_be` byte length + UTF-8 string data.
- **Bytes Field Encoding**: `uint32_be` byte length + raw octets.

- **Message Enums**:
  - `WasmLifecycleAction`: `Prepare = 1`, `Drain = 2`, `Release = 3`, `Query = 4`.
  - `WasmLifecycleState`: `Unknown = 0`, `Prepared = 1`, `Active = 2`, `Draining = 3`, `Stopped = 4`, `Released = 5`.
  - `WasmLifecycleStatus`: `Ok = 0`, `Rejected = 1`, `Error = 2`, `Busy = 3`, `NotFound = 4`.
  - `WasmTaskStatus`: `Ok = 0`, `Rejected = 1`, `Failed = 2`, `Timeout = 3`.

#### 2. BRK1 Message Envelope

- **Magic**: `0x42524B31` (`"BRK1"` in ASCII, big-endian)
- **Protocol Version**: `1`
- **Envelope Header & Fields**:
  - `magic`: `uint32_be` (`0x42524B31`)
  - `version`: `uint16_be` (`1`)
  - `msg_type`: `uint8` (`1`: Request, `2`: Response, `3`: Event, `4`: Error)
  - `reserved`: `uint8` (`0`)
  - `task_id`: String (`uint16_be` length + UTF-8)
  - `source`: String (`uint16_be` length + UTF-8)
  - `destination`: String (`uint16_be` length + UTF-8)
  - `kind`: String (`uint16_be` length + UTF-8)
  - `priority`: `uint8`
  - `timeout_ms`: `uint32_be`
  - `payload`: Bytes (`uint32_be` length + payload bytes, e.g. embedded WSM1 frame)

### `LifecycleClient`

`LifecycleClient` wraps and extends `GpuBrokerClient` to manage remote GPU resources during module lifecycle events:

- `LifecycleClient::new(config: GpuAdapterConfig) -> Result<Self, GpuAdapterError>`
- `LifecycleClient::from_broker_client(broker_client: Arc<GpuBrokerClient>) -> Self`
- `prepare(sandbox_id, module_id, version, target_gpu) -> Result<WasmLifecycleResponse, GpuAdapterError>`
- `drain(sandbox_id, module_id, version, timeout_ms) -> Result<WasmLifecycleResponse, GpuAdapterError>`
- `release(sandbox_id, module_id, version, lease_token) -> Result<WasmLifecycleResponse, GpuAdapterError>`
- `query(sandbox_id, module_id, version) -> Result<WasmLifecycleResponse, GpuAdapterError>`
- `submit_wsm1_task(request: &WasmTaskRequest) -> Result<WasmTaskResponse, GpuAdapterError>`

Supported wire framing modes (`LifecycleWireMode`):
- `Auto`: Encapsulates WSM1 requests inside `BRK1` frame envelopes over length-prefixed TCP, automatically parsing BRK1, raw WSM1, or JSON responses.
- `Brk1`: Always use BRK1 frame envelope.
- `RawWsm1`: Direct binary WSM1 framing without BRK1 envelope.
- `Json`: JSON-encoded `BrokerMessage` over length-prefixed TCP.

### Coordinated Hotswap Orchestration

When a `LifecycleClient` is attached to `ModuleLifecycleManager` via `.with_lifecycle_client()` or `.set_lifecycle_client()`, `ModuleLifecycleManager::hotswap()` coordinates all remote broker and local host operations:

1. **Broker Prepare**:
   Calls `LifecycleClient::prepare()` to acquire a lease and pin the module to a broker GPU. Stores `lease_token` and `assigned_gpu` on the handle.
2. **State Handoff**:
   Invokes registered `StateHandoffHook` implementations to migrate structured application state from the current active version to the candidate version. If state handoff fails, `LifecycleClient::release()` is called to release the prepared broker lease and the candidate version is marked `RolledBack`.
3. **Atomic Routing Switch**:
   Updates the active module routing table atomically.
4. **Broker Drain**:
   Calls `LifecycleClient::drain()` to begin draining broker tasks destined for the old version.
5. **Local Drain**:
   Waits until all local in-flight executions on the old version reach zero or the quiesce timeout expires.
6. **Broker Release**:
   Calls `LifecycleClient::release()` with the old version's `lease_token` to free GPU resources on the broker.
7. **Local Resource Cleanup**:
   Deallocates remaining local resources and writes an entry to the release audit log.

### Sandbox Task Submission & Negotiation

In `RustasmSandbox::submit_gpu_task()`:
- If a `LifecycleClient` is present, it constructs a `WasmTaskRequest` and transmits it using the binary WSM1 protocol in a BRK1 envelope.
- If binary submission fails due to transport error or incompatibility, or if only a standard `GpuBrokerClient` is configured, it seamlessly falls back to JSON `BrokerMessage::TaskRequest` over TCP.
- Existing methods and APIs remain 100% backward compatible.
