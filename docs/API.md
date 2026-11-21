# YuKKi OS v6.16.0 — API and ABI Reference

## Stream dashboard and relay

The gateway serves a static stream dashboard at `/dashboard`. The page itself
is unauthenticated; it requires the gateway bearer token in the page to load
stream data from the authenticated API.

`OriginChunkClient` implements `ChunkSource` for an origin gateway's HTTP
descriptor and chunk-range endpoints. It accepts an origin `SocketAddr`, an
optional bearer token, and a configurable timeout (5 seconds by default). It
uses plain HTTP (no TLS), limits response headers to 16 KiB and bodies to
16 MiB, and reports the codec as `unknown` because stream descriptors do not
carry codec metadata.

`StreamRelay` mirrors a discovered remote stream into a local store. Applications
can pass the relay to `stream_gateway::serve_with_relay` to enable remote
WebSocket tune-in. The standard CLI does not configure an origin client or
relay; applications must construct and wire these library components.

## Browser WASM client

The standalone browser client is built from `browser-wasm/` and uses the
existing authenticated stream routes:

- `GET /v1/streams`
- `GET /v1/streams/{id}/chunks?from={sequence}&limit={1..8}`

The static app stores its bearer token only in page memory and sends it in the
Authorization header. Cross-origin deployments must configure the exact
`YUKKI_GATEWAY_CORS_ORIGINS` allow-list; the gateway permits GET preflights
with Authorization and Content-Type headers only. The browser client uses
HTTP polling, not the native WebSocket route, because browser WebSocket APIs
cannot set the Authorization request header.

The Rust WASM module verifies the YKMC v1 header, media type, flag bits,
UTF-8 metadata, payload ceiling, exact frame length, and trailing-byte rule.
It does not decode or transcode media payloads. See
[BROWSER_WASM.md](BROWSER_WASM.md) for build and deployment instructions.

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


### Spatiotemporal payload resolver (`src/spatiotemporal_resolver.rs`)

The `SpatiotemporalPayloadResolver` is the component-consumer boundary for
NXR1 broker tasks. Register one destination per component with a bounded queue:

```rust
use yukkios::{SequencePolicy, SpatiotemporalPayloadResolver};

let resolver = SpatiotemporalPayloadResolver::new();
let physics_rx = resolver.register_destination(
    "physics",
    256,
    Some(0), // advisory NUMA node; scheduler applies placement
    SequencePolicy::RejectNonIncreasing,
)?;
```

Pass each received `BrokerTask` to `resolve_and_enqueue(&task)`. The resolver
validates and decodes the existing `geospatial.frame.v1` NXR1 payload, routes
by the task's exact `destination`, and makes the decoded frame available from
the matching `PayloadReceiver`. Consumers call `recv()` or `try_recv()`.
Queue capacity is bounded; full and closed queues return explicit errors.

Sequence ordering is per source and per destination. Use `RejectNonIncreasing`
only when the producer guarantees monotonically increasing sequence IDs;
otherwise use `AllowAll`. A sequence watermark advances only after successful
enqueue. The optional NUMA node is metadata for the consuming scheduler, not
an affinity operation performed by the resolver.

This library repository currently provides the receiver API but does not
contain a broker-server receive loop that owns inbound `BrokerTask` delivery.
The application or broker adapter must call `resolve_and_enqueue` at that
boundary. The resolver does not change the BRK1/NXR1 wire format or reinterpret
the opaque NXR1 payload bytes.

The Criterion benchmark
`nxr1_resolver_decode_and_component_dispatch_256b` measures NXR1 extraction
and decode, destination routing, bounded queue dispatch, and receive for a
256-byte payload. Resolver, route, receiver, and task setup are outside the
timed loop. It is a single-threaded microbenchmark, not a network, contention,
NUMA-placement, or accelerator benchmark. Run it with:

```sh
cargo bench --locked --bench frame_benchmarks -- nxr1_resolver_decode_and_component_dispatch_256b
```

See [Benchmarking](BENCHMARKING.md) for the complete Criterion inventory,
reproducible baseline procedure, CI scope, and browser-WASM measurement plan.

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


## Symmetric numerical API (`src/symmetric_eigen.rs`)

YuKKi-OS exports a bounded CPU reference implementation for finite real-
symmetric matrices. The default entry point is
`symmetric_eigen_decomposition(matrix, dimension)`; advanced callers may use
`symmetric_eigen_decomposition_with_options(matrix, dimension, tolerance,
max_sweeps)`.

- Matrix storage is row-major and must contain exactly `dimension * dimension`
  finite values. Dimensions are limited to 1..=64.
- The result contains ascending eigenvalues and a row-major eigenvector matrix
  whose eigenvectors occupy columns, plus relative residual, orthogonality
  error, and sweep count.
- The configurable tolerance must be finite and in (0, 1); the sweep limit is
  bounded to 1..=1024.
- `EigenError` distinguishes invalid dimensions/length/options, non-finite
  values, asymmetric input, non-convergence, and numerical overflow.
- `arcsecant(value)` implements the real branch `acos(1/value)` only when
  `value` is finite and `abs(value) >= 1`. It is a domain-checked mapping,
  not an eigensolver or a substitute for the decomposition.

The solver targets small/medium covariance and correlation matrices; it is not
a general complex or non-symmetric eigensolver and does not claim GPU/NPU
execution. Run the manifest-driven numerical workload with:

```sh
cargo run --release --bin yukki_eigensolver_bench -- \
  --manifest examples/benchmark-datasets/manifest.json \
  --dataset all --profile all --output eigensolver-results.json
```

See [Benchmark-driven datasets](BENCHMARK_DRIVEN_DATASETS.md) for manifest
semantics, workload objectives, geospatial handling, solver limits, and
validation guidance.


## Native composed WebAssembly program API

The `wasm_composition` module exposes the host-side `CompositionRuntime`.
It is distinct from the one-module `RustasmSandbox`, restricted inference
guest-worker ABI, `ModuleLifecycleManager` version-replacement API,
browser-WASM app and Overhauled's WSM1 broker lifecycle.

- `CompositionRuntime::prepare_json(manifest, artifacts)` validates the
  versioned manifest, compiles/caches module bytes by SHA-256, checks the
  function-import DAG and exact signatures, and prepares every declared
  program and replica before activation.
- `CompositionRuntime::activate(prepared)` atomically replaces the
  process-local deployment routing map. Preparation errors leave the
  previous release active; already admitted calls retain the old program set
  until completion.
- `call(deployment_id, program_id, args)` ranks replicas by measured
  service-time estimate. `call_with_spatial_key(..., key)` adds a stable
  application-defined affinity key. `replica_metrics` exposes per-replica
  timing and active/completed call counts.
- Composition v1 links core-Wasm function imports only. It rejects cyclic
  graphs, unbound namespaces, imported memory/global/table/tag resources,
  WASI and implicit host imports. A program entrypoint accepts at most eight
  i32 arguments and returns one i32.
- The default is one stateful replica. Multi-replica execution requires
  `stateless: true`; each replica has an independent Wasmtime Store, memory
  and globals. Default ceilings are eight replicas per program and 32 per
  deployment, with a 256-entry process-local compiled-module cache.
- The time-weighted scheduler starts with a 1 ms estimate and updates using a
  7/8 prior + 1/8 latest-sample EWMA. A non-preferred logical shard incurs a
  25% locality penalty; measured service time can override locality. Busy
  Stores are skipped; full saturation returns
  `CompositionError::ProgramSaturated` without waiting on a busy Store.

The spatial key is an application-defined logical partition hint, not
geographic routing or physical NUMA pinning. Fuel is an instruction budget,
not a wall-clock deadline. The API has no built-in CLI or HTTP deployment
endpoint; the embedding application owns artifact delivery, authorization and
the host call path. See [WASM program composition](WASM_PROGRAM_COMPOSITION.md)
for the manifest and end-to-end Rust example.

## Parallel resolver and composed-program scheduling (v6.16.0 candidate)

`SpatiotemporalPayloadResolver` supports two sequence policies:

- `AllowAll` bypasses sequence-state tracking and the route-state lock.
- `RejectNonIncreasing` performs a short source-state map lookup, then
  serializes validation and enqueue for that source with a source-local mutex.
  Different sources targeting the same destination can progress concurrently.
  The check, enqueue and watermark update remain atomic for each source.

Strict sequence tracking is bounded to 65,536 source entries per route. When
that limit is reached, resolution returns
`ResolverError::SequenceSourceLimit`. A full destination queue does not
advance the source's last-accepted sequence.

`TimeWeightedSpatialScheduler::ranked_candidates_with_load(spatial_key,
active_calls)` ranks replicas by estimated service-time EWMA multiplied by
one plus the active-call count, with the existing locality penalty applied
to non-preferred replicas. Active-call counts are a snapshot; they are not
reservations. Each replica's non-blocking Store lock remains the final
admission check, and a fully saturated program still returns
`CompositionError::ProgramSaturated`.

These are library APIs and internal concurrency policies, not new CLI or HTTP
routes. They do not change YKMC, BRK1/BRK2, NXR1 or WSM1 wire formats.
