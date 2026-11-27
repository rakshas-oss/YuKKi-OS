# YuKKi-OS v6.22.1 — API and ABI Reference (public API unchanged from v6.22.0)

## Incremental multivariate stream observations

The native yukkios::stream_observation module exposes NdjsonObservationDecoder
for bounded incremental parsing of untrusted newline-delimited JSON records.
Schema version 1 carries source_id, sequence, timestamp_unix_ms and 1–32
numeric dimensions. A null value remains missing; non-finite values, unknown
fields, unsupported schema versions, invalid source IDs and oversized
dimension vectors are rejected.

Defaults retain at most one 16 KiB incomplete line and emit at most 256
complete records per push. The decoder does not open sockets, authenticate
sources, authorize forwarding or provide tenant isolation. Callers must apply
source/tenant admission and bounded queues/backpressure around it. See
[MULTIVARIATE_STREAM_INGEST.md](MULTIVARIATE_STREAM_INGEST.md) for the exact
record contract, limits and incremental use example.

## Bounded WASM crawler API

The optional `yukkios::crawler` module exposes the native crawler library,
and the `yukki_crawl` binary provides the operator-facing CLI. A standalone
no-std `crawler-wasm` crate implements the YCR1 HTML title/link extraction
ABI. Native networking and policy remain in the host; the guest has no
WASI/imports or direct network/filesystem access. See
[WASM_CRAWLER.md](WASM_CRAWLER.md) for the complete configuration, limits,
JSON report fields and security boundary. This API does not provide JavaScript
execution, general browser rendering, a persistent distributed frontier, or
automatic transfer of page data to Overhauled.

The `CrawledPage` record includes a bounded `summary` text excerpt (up to
480 characters) derived from visible HTML text. This is not an AI-generated
semantic summary, and it is not raw HTML. `Crawler::crawl_with_events`
accepts a bounded Tokio `mpsc::Sender<CrawlEvent>` and emits
`PageCompleted(CrawledPage)` records as fetches finish, followed by
`Finished(CrawlMetrics)`. The caller controls channel capacity; awaiting sends
applies backpressure to crawl-result delivery. Event copies limit the browser
feed to eight links of at most 1,024 bytes each. The final `CrawlReport`
retains the full normalized link list and aggregate metrics.

The native Wry browser runtime exposes this feed in a separate Crawler utility
tab. Clicking a result opens its text-only page summary in the last active
main browsing tab; the summary's original-HTML hyperlink then navigates that
main tab to the source site. The utility remains available as another tab.
Raw HTML is not broadcast to browser UI components.

### User-directed execution over crawler data

The native-only `yukkios::crawler_data_exec::CrawlerDataExecutor` API runs an
explicitly selected, capability-free core-Wasm processor over ingested bytes.
It is separate from the YCR1 HTML extractor and does not interpret crawled
page content as code. The YCE1 ABI exports `memory`, `alloc(i32) -> i32`, and
`execute(i32, i32) -> i64`; the packed return value contains output length in
the high 32 bits and output pointer in the low 32 bits.

`Crawler::crawl_with_processor(seeds, processor, output_sink)` applies that
processor to each successfully fetched page's raw HTML bytes. The native
`yukki_crawl` CLI exposes the same opt-in workflow through `--execute-wasm`
and persists outputs to `--execution-output-dir`. Each page's JSON report
record contains processor/input/output digests, output size, sink reference,
execution time and any per-page error.

Each call gets a fresh Wasmtime Store/instance, no imports are linked, and
guest memory/fuel/input/output are bounded. Defaults: 4 MiB module, 1 MiB
input/output, 16 MiB memory and 10,000,000 fuel; hard ceilings are 1,000,000,000
fuel, four concurrent processors, 1,024 runs and 64 MiB total output per crawl.
Applications own authentication, artifact authorization/provenance, user
admission, output-sink policy, persistence and audit logging. The default
gateway does not expose arbitrary guest execution. See [WASM crawler](WASM_CRAWLER.md)
for the full contract and CLI example.

## Broker service discovery and locality codec (v6.16.0 published baseline)

The optional broker discovery path uses the bounded `BrokerServiceRecord`
and `BrokerServiceRegistry`. Configure `YUKKI_BROKER_ENDPOINT` to advertise
a local Overhauled broker; without it, no broker advertisement is emitted.
Lease records are relayed through the existing authenticated peer mesh and
cached in memory by the bootstrap. This is not a full DHT, and discovery is
not authorization. Protect BRK1/BRK2 broker TCP with a trusted private network
or independent authenticated proxy.

BRK2 codec helpers encode locality intent in request field 14 and structured
placement results in response field 13. `prefer` is non-critical;
`bind` and `interleave` require the critical flag. An absent response result
means unknown/not applied. The codec does not allocate or verify physical
memory placement; see
[broker discovery](BROKER_SERVICE_DISCOVERY.md) and
[architecture](ARCHITECTURE.md) for ownership and limitations.

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

## Wasm runtime interoperability boundary

YuKKi-OS `CompositionRuntime` remains the deployment-side composition API:
it validates manifests and typed module dependencies, prepares program
replicas, and activates releases within the YuKKi process. Overhauled may
provide a separate optional native Wasmtime C API runtime-composition path
for broker-side module compilation and linker-based runtime import
resolution. These are independent runtimes, not a shared engine or an
automatic delegation path.

The explicit artifact-transfer API is documented separately below. It moves
portable core-Wasm artifact bytes and signed deployment metadata; it does not
transfer compiled-module caches, Stores, instances, replica pools or
CompositionRuntime routing state. The two runtimes must be qualified
independently. See [WASM runtime interoperability](WASM_RUNTIME_INTEROP.md).

## Authenticated WASM handoff sender API (v6.18.0 candidate)

The public `yukkios::wasm_handoff` module provides an explicit client-side API for sending portable core-Wasm artifacts to a compatible receiver. It is separate from `CompositionRuntime`, WSM1 task/lifecycle messages and the ordinary BRK1/BRK2 broker socket.

### Public types and flow

- `HandoffIdentity` pins the deployment sender's issuer, subject and key ID.
- `HandoffSigner` supplies Ed25519 signing; it can be backed by an HSM, OS key store, KMS or local key implementation. This module does not store private keys.
- `WasmArtifact` carries module ID, version and core-Wasm bytes.
- `PrepareOptions` carries receiver/receipt/publisher audiences, deployment/release IDs, runtime policy, required capabilities and resource limits.
- `HandoffSender::build_prepare` validates the artifact set, builds canonical manifest/module/aggregate SHA-256 digests, signs the prepare request and adds a separately signed publisher attestation.
- `HandoffSender::for_each_chunk` emits bounded, individually signed chunks sequentially through a callback, so the caller can apply transport backpressure without assembling a second full set of encoded chunks.
- `HandoffSender::build_activation` emits the signed activation request after the receiver accepts transfer.
- `HandoffSender::deploy` runs prepare, chunk transfer and activation through `HandoffTransport`, verifies the signed prepare decision and verifies the final receipt through `HandoffReceiptVerifier` before returning it.

### Limits

- The sender accepts 1–256 modules, at most 64 MiB per module and 256 MiB aggregate artifact bytes.
- Chunk sizes must be between 4 KiB and 4 MiB; the default is 1 MiB. The sender respects a lower chunk size returned by the receiver.
- Signed message lifetime is 1–300 seconds. Resource-intent validation also bounds memory, fuel, wall time and maximum instances.
- The receiver applies its own stricter local limits; sender-side values are requests, not authority to expand receiver policy.

### Transport and trust requirements

`HandoffTransport` is an application-supplied interface, not a built-in TCP/TLS client. Its implementation must use mutually authenticated TLS 1.3 or an equivalently protected authenticated channel, bind the authenticated peer identity to the signed deployment sender, reject plaintext downgrade, enforce frame limits before allocation and decode the shared schema into the typed decision/receipt structures. `HandoffReceiptVerifier` must pin receiver issuer, subject, key ID and audience.

The paired Overhauled receiver is a library API and is not wired into its ordinary BRK1/BRK2 listener. Replay/staging state is process-local until an integration provides durable shared storage. The optional Wasmtime bridge does not make the shared-Store runtime a multi-tenant sandbox.

Untrusted NXR1/MED1/YKMC streams remain outside this executable-artifact trust policy. They do not require a WASM publisher key and continue to be constrained by their separate stream storage, rate, connection and backpressure controls.

## Parallel resolver and composed-program scheduling (v6.15.0 published baseline)

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
