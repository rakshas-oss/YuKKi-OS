# YuKKi OS v6.7.0 — API and ABI Reference

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
- `YUKKI_BROKER_CONNECT_TIMEOUT_MS`
- `YUKKI_BROKER_REQUEST_TIMEOUT_MS`
- `YUKKI_BROKER_MAX_FRAME_BYTES`
- `YUKKI_BROKER_TRANSPORT_SECURITY` (`plaintext-boundary` | `authenticated-proxy`)

### Request schema (`BrokerTask`)

- `task_id: String` (required, non-empty)
- `source: String` (required, non-empty)
- `destination: String` (required, non-empty)
- `kind: String` (required, non-empty)
- `priority: u8`
- `timeout_ms: u32` (required, > 0)
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
   - `timeout_ms: u32` (> 0)
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
- `YUKKI_GPU_CONNECT_TIMEOUT_MS`: connect timeout in ms (default `3000`)
- `YUKKI_GPU_REQUEST_TIMEOUT_MS`: request timeout in ms (default `5000`)
- `YUKKI_GPU_QUIESCE_TIMEOUT_MS`: quiesce timeout in ms (default `5000`)
- `YUKKI_GPU_MAX_RETRIES`: maximum retry attempts for retryable errors (default `3`)
- `YUKKI_GPU_MAX_FRAME_BYTES`: maximum message frame size in bytes (default `65536`)

### Paired overhauled PR Compatibility Notes

- The companion `overhauled` PR must implement the server side of `overhauled.wasm.gpu.v1` over length-prefixed TCP on the broker port (default 9000).
- Handshake messages use type `"handshake_request"` and `"handshake_response"` with magic `"OVERHAULED_WASM_GPU"`.
- When overhauled returns a rejection with `retryable: true`, YuKKi-OS client will retry with exponential backoff using the identical `task_id` for idempotency.

