# YuKKi-OS v6.12.0 — Architecture

## System identity and scope

YuKKi-OS is a modular distributed systems platform implemented primarily in Rust. It provides an authenticated control-plane mesh and a collection of runtime, isolation, interoperability, and streaming services for coordinating distributed workloads across native and WebAssembly deployment environments.

Its architectural pillars are:

- **Distributed control plane:** authenticated peer sessions, node registration, fleet coordination, and stream discovery.
- **Concurrent runtime primitives:** bounded MPMC queues and portable NUMA topology discovery.
- **Execution isolation:** Wasmtime-based WebAssembly sandboxing with host-mediated access to selected services.
- **Interoperability:** C FFI components and versioned Rust/C++ broker wire contracts.
- **Data and streaming:** bounded media chunk storage, stream registry, gateway, relay, and geospatial codecs.
- **Hardware integration:** optional accelerator execution through an external broker such as [Overhauled](https://github.com/rakshas-oss/overhauled).

This is not a claim that YuKKi-OS currently implements a complete general-purpose kernel or a fully NUMA-aware scheduler. NUMA discovery and MPMC queues are library primitives; thread affinity, NUMA-local allocation, per-node worker placement, and cross-node work stealing remain separate scheduler-integration work. Accelerator placement and execution are owned by the configured broker.

This document describes the v6.12.0 release-candidate implementation. The release tag remains pending the required CI and release qualification gates.

## Runtime topology

YuKKi-OS runs as a control-plane mesh with two process roles:

- `bootstrap <bind-address>`: accepts peer registrations and broadcasts fleet updates
- `node <bootstrap-address> <advertised-address>`: registers to bootstrap and receives fleet updates

The CLI also provides an authenticated stream gateway and `streams list` /
`streams tune` clients. When `YUKKI_GATEWAY_TOKEN` is set, a node starts an HTTP/WebSocket gateway sharing its in-process stream registry. Its default bind address is `127.0.0.1:7670`, configurable with `YUKKI_GATEWAY_LISTEN`.

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

The generic broker client is a separate integration from the Overhauled adapter. Its raw TCP transport is not authenticated by the peer-mesh session. `YUKKI_BROKER_TRANSPORT_SECURITY=authenticated-proxy` records the expected deployment boundary; it does not enable TLS or authenticate the socket.

## Geospatial and live media codecs

`src/arcgis.rs` represents avenue/road-network line geometry as GeoJSON
LineString Features with WGS84 longitude/latitude coordinates and optional
`route_id`/`avenue_name` metadata. It does not reinterpret the legacy `NXR1`
fluid/numeric fields and does not claim compatibility with proprietary
ArcGIS feature-service formats. GeoJSON Features can cross the existing
`BrokerTask` JSON boundary under `geospatial.arcgis.avenue.v1`.

`src/nxr1.rs` provides a dependency-free NXR1 binary codec for geospatial frames,
matching the `rakshas-oss/overhauled` wire contract (magic `0x4E585231`, version `1`,
big-endian fixed geospatial/velocity/fluidity/drag/divergence fields, `u32` BE
length-prefixed opaque payload). NXR1 frames can be wrapped in the existing
`BrokerTask` JSON envelope under kind `geospatial.frame.v1`.

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

The mesh distributes discovery metadata. `src/stream_relay.rs` adds an opt-in
`StreamRelay` that mirrors a remotely discovered stream into the local store via
a pluggable `ChunkSource`. `OriginChunkClient` implements this interface for
the origin gateway's HTTP descriptor and range endpoints, using plain HTTP and
an optional bearer token. All local subscribers share one rate-limited upstream
pull per stream, and the mirror is an ordinary local stream, so downstream
nodes can relay from it to form fan-out trees. `stream_gateway::serve_with_relay`
uses a configured relay for remote WebSocket tune-in; plain `serve` still
returns `501` for remote streams. The current descriptors do not include codec
metadata, so `OriginChunkClient` reports the codec as `unknown`; applications
must account for this when relaying media.
The standalone `gateway` command
owns a separate in-memory store, while the optional node gateway shares that
node's store and registry.

WASM stream selection remains host mediated: `wasm_ingest` validates guest
memory ranges before copying one bounded encoded chunk through
`env::yukki_select_stream`. No raw pointers or direct store handles are exposed.
Applications must still protect broker TCP links with an authenticated proxy
or equivalent deployment boundary.


## Browser spatial and motion runtime

The separate `browser-wasm/` application builds a dependency-free Rust
module for `wasm32-unknown-unknown`. It is not a browser build of the native
node, the Wasmtime guest runtime, or a network service.

- `browser-wasm/src/lib.rs` validates exact YKMC v1 media-chunk framing:
  magic/version, audio/video type, flags, UTF-8 metadata, frame lengths and
  configured size bounds. Media payloads remain opaque; no codec decoding or
  transcoding occurs.
- `browser-wasm/src/mmo.rs` provides WGS84/ECEF and WGS84/ENU transforms,
  ENU-to-ECEF conversion, cubic Hermite interpolation, a fixed 512-entity
  spatial store, inclusive WGS84 bounding-box queries, and
  freshness/distance-constrained nearest-observation resolution.
- The browser module also provides an iterative arc–secant–tangent path
  simplifier with fixed storage for 512 points. It preserves endpoints and
  forces splits at sharp turns. It is intended for ordered trajectories and
  non-safety-critical display or summarization, not flight guidance or
  topology-preserving polygon generalization.
- `browser-wasm/app.js` owns browser HTTP, credentials, forms and rendering.
  The WASM module does not open sockets or access browser APIs. Sample spatial
  entities remain in browser WASM memory and are not automatically uploaded to
  the gateway or Overhauled.

The browser spatial store retains an optional `radius_m` value, but the
current nearest resolver does not use it as a match constraint. It compares
candidate ECEF distance directly against the supplied maximum distance. The
bounding-box and nearest-observation operations are bounded linear scans, not
an indexed spatial engine.

The browser client uses authenticated HTTP GET range reads for gateway
streams. It does not put bearer tokens in URLs or use the browser WebSocket
API, because that API cannot set the custom Authorization header required by
the current gateway WebSocket endpoint. See [BROWSER_WASM.md](BROWSER_WASM.md),
[MMO_BROWSER_WASM.md](MMO_BROWSER_WASM.md), and
[USER_HOWTO_MMO.md](USER_HOWTO_MMO.md).

## Native multivariate datasets and benchmark policy

The native dataset runner is implemented in `src/benchmark_dataset.rs` and
exposed by the `yukki_dataset_bench` binary. Its version-1 benchmark manifest
selects JSONL sources, sequence/timestamp fields, optional geographic fields,
numeric feature mappings, and benchmark profiles.

Each profile drives actual candidate measurements: warm-up records, a
deterministic sample, batch sizes, worker counts, objective, optional P95
latency ceiling, and optional geospatial simplification settings. The report
contains candidate measurements and a recommended batch/worker configuration.
The selected product is used to derive a bounded queue policy and can be used
by `SpatiotemporalPayloadResolver::register_benchmarked_destination` to
register an actual bounded component queue.

The native loader is bounded (including manifest, dataset, record, row-count,
feature, batch and worker ceilings) and rejects malformed or non-finite
records and invalid geographic coordinates. The native workload performs
NXR1 encode/decode round trips while retaining each complete JSONL source row
as opaque payload. The first nine declared numeric features map to the generic
NXR1 fields; geographic coordinates are handled separately by the geospatial
profile.

There are two distinct manifest contracts:

- `schemas/multivariate-datasource-manifest.schema.json` describes
  application-level heterogeneous sources, variables, units, temporal/spatial
  semantics, provenance, quality and access-policy references.
- `examples/benchmark-datasets/manifest.json` is the concrete version-1
  input consumed by `yukki_dataset_bench` and
  `yukki_eigensolver_bench`. It names JSONL files and benchmark field
  mappings.

The general data-source schema is not directly consumed by the native
benchmark runner. An application adapter or conversion step must map a
source-catalogue entry into the benchmark manifest and preserve source
provenance, units, quality flags and original attributes.

## Native symmetric eigensolver

YuKKi-OS owns a CPU cyclic-Jacobi implementation in
`src/symmetric_eigen.rs`. It accepts finite real-symmetric row-major
matrices with dimensions 1..=64 and returns ascending eigenvalues, column
eigenvectors, relative residual, orthogonality error and sweep count. It
rejects invalid dimensions, lengths, non-finite values, material asymmetry,
invalid options, non-convergence and numerical overflow.

The separate `yukki_eigensolver_bench` binary reads
`eigensolver_profiles` from the native benchmark manifest, constructs
bounded correlation-matrix workloads from the declared feature fields, and
reports solver throughput, latency and numerical diagnostics. This is a
small/medium covariance/correlation analysis primitive, not a general
complex or non-symmetric eigensolver. It does not claim GPU/NPU acceleration.
The real `arcsecant` helper is a domain-checked mapping, not an eigensolver.

See [BENCHMARK_DRIVEN_DATASETS.md](BENCHMARK_DRIVEN_DATASETS.md),
[BENCHMARKING.md](BENCHMARKING.md), and [API.md](API.md) for operational
commands, manifest details, API shape and benchmark scope.

## WebAssembly sandbox and GPU interop

`src/wasm_sandbox.rs` provides a Wasmtime-based execution sandbox:

- max linear memory: 16 MiB
- default fuel budget: 10,000,000
- optional fuel override: `YUKKI_WASM_MAX_FUEL` (must be positive)
- isolated memory: no direct host or CUDA memory pointers exposed to WASM guests

`src/gpu_adapter.rs` provides the GPU task offloading adapter and module lifecycle manager targeting `rakshas-oss/overhauled`:

- **Isolation Preservation**: Sandboxes communicate with GPU acceleration via host-mediated calls (`submit_gpu_task`). The host validates buffer sizes (capped at 64 KiB execution buffers) and gen[...]
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
- Remote stream relay requires application wiring; the CLI does not configure
  an origin client or relay automatically


## NUMA and MPMC primitives

See [NUMA_MPMC_RUNTIME.md](NUMA_MPMC_RUNTIME.md). The topology and bounded queue APIs are library primitives; workload scheduling is not yet NUMA-aware.
