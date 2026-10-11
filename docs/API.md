# YuKKi OS v6.9.3 — API and ABI Reference

## CLI API (`src/main.rs`)

### Command forms

```text
yukki_core_node bootstrap <bind-address>
yukki_core_node node <bootstrap-address> <advertised-address>
yukki_core_node gateway [listen-address] [--insecure-dev]
yukki_core_node streams list
yukki_core_node streams tune <stream-id> [--from <seq>]
```

### Environment

- `YUKKI_PSK_HEX`: 64-character hex string (32-byte PSK), required by
  `bootstrap` and `node`
- `YUKKI_GATEWAY_TOKEN`: required by `gateway` and the node gateway unless
  `--insecure-dev` is explicitly used
- `YUKKI_GATEWAY_LISTEN`: optional node gateway address (default
  `127.0.0.1:7670`)
- `YUKKI_GATEWAY_ENDPOINT`: optional address for the `streams` CLI (same default)
- `RUST_LOG`: tracing filter (default `info`)

The standalone gateway defaults to loopback. It serves its own in-memory store;
the gateway started by `node` shares that node's local registry. The CLI needs a
gateway token and writes encoded YKMC chunks to stdout when tuning in.

## Peer mesh message schema

```rust
enum SovereignCommand {
    Register(PeerInfo),
    NodeFleet(Vec<PeerInfo>),
    StreamAnnouncement(StreamAnnouncement),
    StreamDigest(Vec<StreamDigestEntry>),
}

struct PeerInfo {
    uuid: uuid::Uuid,
    addr: String,
}
```

Messages are JSON encoded and encrypted after session establishment.
Announcements are hop-limited and deduplicated by bootstrap; digests contain
descriptor IDs and SHA-256 version hashes.

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
  oversized values are rejected by `validate()`. The timeout must be supplied
  explicitly and is not derived from payload size.)
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
