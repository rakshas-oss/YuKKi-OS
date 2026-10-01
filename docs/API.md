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
- `nxr1`
- `wasm_sandbox`
- `SpatiotemporalFrame`
