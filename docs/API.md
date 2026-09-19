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
- `wasm_sandbox`
- `SpatiotemporalFrame`
