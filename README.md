# YuKKi-OS v6.23.0

> **Coordinate the system. Connect the workload. Keep execution flexible.**
>
> YuKKi-OS is a Rust platform for coordinating peers, streams, and sandboxed workloads. It supplies the control-plane and host-runtime pieces; compatible execution backends can be connected when a workload needs them.

> **Latest published release:** [v6.23.0](https://github.com/rakshas-oss/YuKKi-OS/releases/tag/v6.23.0) · Published 2026-11-28. No binary assets are manually attached to this release; use its GitHub source archive or clone the tag. GitHub Release publication does not imply crates.io publication.

YuKKi-OS brings together authenticated peer networking, workload coordination, bounded stream processing, WebAssembly execution, spatial and multivariate data paths, and interoperability with the separate [Overhauled](https://github.com/rakshas-oss/overhauled) broker. It is a distributed systems platform—not just an MPMC microkernel.

## Who this is for

- **Rust and systems developers** building distributed services that need peer coordination, streaming, workload policy, or embedded WebAssembly processing.
- **Platform operators** assembling a control plane for connected nodes and bounded data-processing workloads.
- **Application and runtime integrators** that want to send work to a compatible broker while keeping workload semantics and policy in YuKKi-OS.
- **Spatial and data engineers** working with geospatial observations, chunked media, or bounded multivariate numeric streams.

## What YuKKi-OS does

- **Coordinates:** authenticated peer sessions, broker discovery, workload directives, and runtime services.
- **Processes:** bounded streams and spatial data; the optional crawler collects allowlisted static HTML and can pass results to an explicitly selected, resource-limited WebAssembly processor.
- **Browses crawler discoveries:** the native browser has a dedicated Crawler utility tab with live result hyperlinks; selecting a result opens its extracted page summary in the main browsing tab, with a separate link to the original HTML.
- **Adopts crawler metrics in browser WASM:** optionally publish bounded numeric observations through the node's existing authenticated gateway, then discover and validate them in the control-plane browser workspace.
- **Hosts:** native Wasmtime composition and supported WebAssembly guest paths, with explicit resource limits and lifecycle boundaries.
- **Interoperates:** BRK1/BRK2 broker requests connect YuKKi-OS policy to Overhauled execution and placement services.

## How YuKKi-OS and Overhauled fit together

YuKKi-OS owns the peer/control plane, workload meaning, stream and spatial semantics, and host-side WebAssembly composition. Overhauled is a separate C++ broker and execution tier: it owns broker admission, worker queues, process-local CPU/NUMA placement, and CPU/GPU/NPU backend selection. A requested accelerator or locality preference is not proof that hardware execution or physical placement occurred; inspect the broker response and telemetry.

## Choose a starting point

- **Build the runtime:** [Build and run](#build-and-run) and the [platform deployment notes](#platform-deployment).
- **Add crawler processing:** [WASM Crawler Fabric](docs/WASM_CRAWLER.md).
- **Compose WebAssembly programs:** [composition guide](docs/WASM_PROGRAM_COMPOSITION.md).
- **Connect a broker:** [broker interoperability](docs/OVERHAULED_INTEROP.md) and [protocol documentation](#documentation).
- **Understand the architecture:** [architecture diagram and component map](#architecture-map--full-colour-ansi-palette).

## Release and deployment notes

The release tag is a source/version reference; it does not mean that prebuilt binaries or every workspace package are published to a registry. Check the relevant package metadata and [package distribution guide](docs/PACKAGING.md) before choosing an installation path. YuKKi-OS is intended for development, validation, and deployment work; obtain an independent security review appropriate to your threat model before production use.

## Current baseline
- **Release:** v6.23.0 (published 2026-11-28).
- **Release assets:** no manually attached binary assets; the tag and GitHub-generated source archives are available.
- **Native Cargo package:** `yukkios` version 6.23.0 in source; crates.io publication is separate and is not claimed.
- **OCI image label:** 6.23.0; this does not imply that an image is published to GHCR.
- **Runtime:** `yukki_core_node`.
- **Rust toolchain:** 1.98.1 (`rust-toolchain.toml`).
- **WASM targets:** browser `wasm32-unknown-unknown`, WASI guest worker `wasm32-wasip1`, and native-host Wasmtime composition.
- **Independent package versions:** browser runtime, browser-WASM, crawler extractor, and WASI guest packages remain separately versioned at 0.1.0.

## What's new in v6.23.0 (published 2026-11-28)

- **Native browser crawler workflow:** the Wry browser runtime has a dedicated Crawler utility tab. Completed crawl results appear as hyperlinks; selecting one opens a YuKKi-generated text-only page summary in the last active main browsing tab, with a separate link to the original HTML.
- **Extractive previews and bounded delivery:** summaries contain a visible-text excerpt (up to 480 characters), fetch metadata, digest, and up to eight validated links. Raw HTML is not broadcast to browser UI components. A bounded 16-record event queue applies backpressure.
- **Optional control-plane metric publishing:** a single opt-in control reuses the node's existing authenticated gateway configuration. It publishes batches of schema-v1 numeric page observations for browser-WASM adoption; URLs, titles, excerpts, and HTML are excluded.
- **Browser-WASM adoption:** the browser workspace discovers these data streams separately from media streams and validates selected observations with its Rust WASM core.
- **Bounded storage and privacy:** observation retention is node-local and in-memory (128 streams, 512 observations per stream, 16,384 total). This does not imply durable storage or peer-mesh replication. Publishing failure does not cancel local crawling.

This release adds browser-facing crawler and control-plane data-stream integration. It does not turn the crawler into a JavaScript browser, AI semantic summarizer, distributed persistent frontier, or automatic accelerator pipeline. The existing crawler allowlist, DNS pinning, robots, pacing, redirect, byte, timeout, concurrency, and WASM fuel/memory controls remain authoritative.


## What's new in v6.22.1 (published 2026-11-27)

- **NDJSON validation test correction:** verify that an unterminated final record remains buffered by `push()` and is validated by `finish()`, rather than expecting incomplete input to be emitted immediately.
- **Toolchain formatting:** apply the pinned Rust 1.98.1 rustfmt layout to `guest-worker/src/lib.rs`.
- **Scope:** test and formatting maintenance only. No decoder implementation, runtime behavior, public API, wire protocol, or independently versioned 0.1.0 workspace package is changed.

## What's new in v6.22.0 (published 2026-11-26)

- **User-selected crawler processing:** add the native YCE1 CrawlerDataExecutor, the Crawler::crawl_with_processor API and the explicit yukki_crawl --execute-wasm option. Only an operator-selected, import-free core-Wasm module runs; crawled page content cannot install or choose code, and page scripts are never executed.
- **Bounded processor isolation:** use a fresh Wasmtime Store/instance per invocation; validate exports, pointers and lengths; cap module/input/output size, guest memory and fuel; limit concurrent instances, total executions and aggregate crawl output. Persist processor/input/output digests and output references.
- **Incremental multivariate stream decoding:** expose NdjsonObservationDecoder for schema-v1 numeric observations. It retains at most one incomplete line (16 KiB by default), emits at most 256 records per push, accepts 1–32 dimensions and preserves null as missing data. It rejects unknown fields, unsupported versions, oversized records and non-finite numbers.
- **Pairwise aggregation:** the paired published Overhauled v1.11.0 release adds a CPU-only, fixed-memory online covariance/correlation accumulator for up to 32 dimensions. Missing values are omitted pairwise; sample counts are part of the result. This is a separate library, not an automatic network-to-broker path or GPU/NPU crawler dispatch.

The decoder parses data but does not authenticate sources or authorize forwarding. Applications remain responsible for per-source/tenant admission, bounded queues, backpressure and audit policy. Existing YKMC, BRK1/BRK2, NXR1 and WSM1 wire identities are unchanged.

## What's new in v6.21.0 (published 2026-11-26)

- **Bounded WASM crawler fabric:** add the opt-in `yukki_crawl` CLI and Rust library with native asynchronous HTTP/HTTPS fetching and a separate no-std YCR1 WebAssembly HTML extractor. The guest has no WASI, imports, sockets, filesystem access or credentials.
- **Crawl safety controls:** require explicit DNS-domain allowlists, pin validated DNS answers, reject private/special-use destinations, disable proxy environment inheritance, do not follow redirects, evaluate robots.txt fail-closed, and enforce per-host pacing, page/crawl byte budgets, timeouts, bounded concurrency and guest fuel/memory limits.
- **Metriculation reports:** emit per-page status, timestamp, SHA-256, byte count, extracted title/links, fetch and extraction timings, plus aggregate crawl metrics. Reports are local JSON output; crawler data is not automatically forwarded to Overhauled.
- **Security and CI maintenance:** merge the Aikido dependency/security remediation and crawler validation fixes. This does not constitute an independent external security audit.
- **Paired C++ aggregation:** Overhauled v1.10.0 adds an optional CPU-only, constant-memory C++ accumulator for normalized page observations. It is a separate library, not a BRK operation or automatic GPU/NPU crawler path.

The crawler is a bounded static-HTML vertical slice, not a general-purpose browser, distributed frontier, historical metrics database, or JavaScript execution environment. See [WASM Crawler Fabric](docs/WASM_CRAWLER.md) for the operator contract and limitations.

## What's new in v6.20.0 (published 2026-11-26)

- **Persistent BRK transport:** add an endpoint-scoped pool of persistent BRK1/BRK2 TCP sessions. Each checked-out connection carries one request/response exchange; it is recycled only after a complete, valid response is decoded. Timeouts, cancellation, disconnects and malformed responses discard the socket.
- **Bounded connection admission:** configure the pool with `YUKKI_GPU_MAX_CONNECTIONS` (default 16, range 1..256). The pool applies backpressure when all connection permits are in use. Non-idempotent requests are not automatically replayed after an ambiguous transport failure.
- **Strict mTLS sidecar routing:** `YUKKI_GPU_REQUIRE_MTLS_PROXY=true` requires a numeric loopback endpoint so the application is routed through a local TLS terminator. The paired Overhauled deployment profile uses stunnel TLS 1.3 and a loopback-only broker bind.
- **Paired broker hardening:** Overhauled adds a 1,024-session ceiling, strict loopback-listener enforcement and an optional fsync-backed replay journal. The journal preserves accepted nonces across a single-process restart; it does not persist staged artifacts or active runtime state.
- **Compatibility:** existing YKMC, BRK1/BRK2, NXR1 and WSM1 identities remain unchanged. The Rust pool is still plain TCP; TLS is supplied by the sidecar, and certificate identity is not yet bound to signed artifact-sender authorization.

The native browser runtime remains a separate workspace package at 0.1.0. Browser-WASM and WASI guest-worker package versions remain independently versioned at 0.1.0.

## WASM Crawler Fabric

YuKKi-OS now includes an opt-in bounded crawler CLI and library. Native async
HTTP/HTTPS fetching is kept outside the sandbox; a no-std Wasm guest performs
HTML title and link extraction with isolated linear memory, fuel limits and no
WASI or host imports. Explicit DNS-domain allowlists, DNS pinning, private
address rejection, robots.txt checks, no automatic redirects, per-host pacing,
and page/crawl byte budgets constrain collection.

Build the guest and run a crawl using the [crawler guide](docs/WASM_CRAWLER.md):

~~~sh
rustup target add wasm32-unknown-unknown
cargo build --manifest-path crawler-wasm/Cargo.toml --target wasm32-unknown-unknown --release
cargo run --release --bin yukki_crawl -- \
  --seed https://example.org/ --allow-domain example.org \
  --wasm crawler-wasm/target/wasm32-unknown-unknown/release/yukkios_crawler_wasm.wasm
~~~

This first slice handles static HTML/XHTML only. It does not execute JavaScript,
follow redirects, crawl outside the allowlist, or automatically forward raw
documents to Overhauled. Its JSON report records page provenance, hashes,
bytes, links, and fetch/extraction timing. Persistent distributed frontiers,
historical storage, browser-rendered extraction and signed plugin admission
remain follow-up work.

## What's new in v6.19.0 (published)

- **Native browser runtime:** add a native WebKit-based browser shell for Linux and macOS, with Linux X11, native Wayland and XWayland display paths. The browser runtime includes bounded graphics benchmark coverage and can delegate compatible work to Overhauled through explicit BRK2 device preferences; CPU fallback remains available. This native runtime is a separate workspace package and retains its own `0.1.0` version.

- **Authenticated WASM handoff sender:** add a Rust sender API with pluggable signing and receiver-receipt verification, separate deployment-sender and artifact-publisher identities, canonical manifests/digests, bounded sequential chunk transfer and signed activation requests.
- **Untrusted stream availability:** stream ingestion and consumption remain independent of executable-artifact publisher authorization. Untrusted NXR1/MED1/media sources do not need a WASM publisher key.
- **Stream flood controls:** enforce hard media-store ceilings (64 MiB retained media, 256 streams, 4,096 chunks per stream, 16,384 total retained chunks and 256 KiB per chunk). Default ingestion budgets are 1,024 chunks/s globally (burst 256) and 8 MiB/s globally (burst 4 MiB), plus 256 chunks/s per stream (burst 64) and 2 MiB/s per stream (burst 1 MiB); stream opening is limited to 16/s (burst 32). The gateway and WebSocket paths also apply global/per-peer request, connection and control-rate limits with backpressure.
- **Transport boundary:** YuKKi-OS supplies the handoff protocol client and caller-provided transport abstraction; it does not silently fall back to plaintext TCP or provide TLS itself. The integration must use mTLS 1.3 or an equivalent authenticated protected channel and verify the receiver's signed decision/receipt.
- **Flood boundary:** application-level quotas bound process work and retained memory; they do not stop volumetric DDoS before traffic reaches the host. Keep network-edge firewall/proxy/provider mitigation in place.

PR #168 is merged to main at 2869a8baf9f1dd878b492b9c78fd1ca2562d2a0d. This candidate advances only the native yukkios package and its OCI metadata; the browser-WASM and WASI guest-worker packages retain their independent 0.1.0 versions.

## Package distribution

The published GitHub source release is [v6.23.0](https://github.com/rakshas-oss/YuKKi-OS/releases/tag/v6.23.0). It has no manually attached binary assets; clone the tag or use GitHub's source archive. GitHub Release publication is separate from crates.io publication. The root Cargo package is version 6.23.0 in this source tree, but do not use a crates.io dependency until that exact version is visible in the registry. See [package distribution and publishing](docs/PACKAGING.md) for source installation, package validation, and publisher setup.

## Security and hardening notes

The project includes defensive validation in native mesh helpers, FHSS synchronization, and the guest-worker shared memory channel. See [docs/SECURITY_HARDENING_NOTES.md](docs/SECURITY_HARDENING_NOTES.md) for details.

## v6.14.0 published feature baseline

The published v6.14.0 release added YuKKi-OS's policy and client side of the
cross-repository worker-class contract:

- Public `WorkerClass` and validated `WorkerDirective` APIs cover Control,
  RealtimeSpatial, Throughput, ExactCpu and Inference work.
- Directives derive stable logical spatial affinity from resolved NXR1
  routes and carry the resolver's advisory NUMA hint.
- Existing `TaskProfile` values map to worker classes with ExactCpu
  precedence, then spatial, explicit inference, and Throughput defaults.
- Relative task deadlines are converted with checked arithmetic to absolute
  Unix-nanosecond BRK2 deadlines.
- BRK2 optional request fields 11–13 carry worker class, logical affinity and
  preferred NUMA node. The explicit WSM1 task API requires BRK2 for directives
  and exposes optional queue/service/worker/NUMA telemetry.
- Lifecycle requests use Control; generic BRK2 WSM1 tasks default to
  Throughput; model inference callers explicitly select Inference.

YuKKi-OS owns workload semantics and directive policy. Overhauled owns local
worker queues, admission budgets, Linux CPU/NUMA affinity, backend selection
and execution. Existing YKMC, BRK1, BRK2, NXR1 and WSM1 identities remain
compatible. Logical affinity and preferred NUMA values are hints, not proof
of physical placement. See [Worker class policy](docs/WORKER_CLASS_POLICY.md)
and [Overhauled interoperability](docs/OVERHAULED_INTEROP.md).

The current parallelism work also removes avoidable coordination from the
native resolver and benchmark paths: unordered payload dispatch skips sequence
tracking, strict ordering is scoped per source, benchmark workers aggregate
metrics locally, and stateless Wasm replicas are ranked using active-call load
as well as service-time history. These changes do not alter BRK2 or NXR1 wire
formats.

## What's new in v6.17.0

The published v6.17.0 release builds on the v6.16.0 broker-discovery and
BRK2 locality-codec baseline:

- **Conventional WASM imports:** when a core-Wasm import namespace exactly
  matches a module ID in the same composition program, YuKKi-OS infers the
  provider binding. Explicit `bindings` entries remain available for aliases.
  Inferred bindings use the existing dependency ordering, exact signature
  validation and linker registration; unmatched imports still fail closed.
- **Authenticated WASM handoff contract v1:** adds a shared JSON Schema and
  protocol document for signed capability offers, prepare requests, decisions,
  receipts, cancellation and digest-verified artifact chunks. It specifies
  Ed25519 signatures over RFC 8785 canonical bytes, sender/audience binding,
  expiry and replay checks, bounded transfer, backend capability negotiation,
  and separate prepare/activate phases.
- **Implementation boundary at v6.17.0:** that release delivered the normative handoff schema and protocol specification. The subsequent v6.19.0 candidate adds the Rust `HandoffSender` API, separate deployment/publisher signing, bounded sequential chunk streaming, signed prepare-decision and receipt verification, and the paired Overhauled `HandoffReceiver` state machine/runtime bridge (PR #86). A concrete mTLS transport adapter, durable replay/staging service and ordinary broker-listener integration are still not included. The shared-Store Wasmtime isolation limitation still applies.

See [the composition guide](docs/WASM_PROGRAM_COMPOSITION.md),
[the handoff contract](docs/WASM_AUTHENTICATED_HANDOFF.md), and
[the schema](protocol/wasm-handoff-v1.schema.json).

## What's new in v6.16.0

The published v6.16.0 release coordinates broker discovery and BRK2 locality intent
with Overhauled:

- **Broker service discovery:** bounded lease records advertise an optional
  broker endpoint through `YUKKI_BROKER_ENDPOINT`. Validated announcements
  relay over the authenticated peer mesh with message-ID deduplication,
  bounded hop count, lease expiry and replay to joining peers.
- **BRK2 locality intent/result codec:** request field 14 carries nested
  locality intent; response field 13 carries a structured placement result.
  Validation covers extension version, scope, mode, optional NUMA node,
  payload ceiling, duplicate nested fields and unknown critical fields.
- **Compatibility:** `prefer` is non-critical; `bind` and `interleave`
  require the critical flag. An absent response result means unknown/not
  applied, never successful placement.

**Boundaries:** the discovery mechanism is bootstrap-relayed authenticated
gossip with an in-memory lease cache, not Kademlia or a full DHT. Discovery
does not authorize execution, and BRK1/BRK2 transport still needs a trusted
private network or independently authenticated proxy. The locality work is
codec-only: Overhauled does not yet apply or verify physical memory placement.
The GPU adapter does not automatically request the extension, and no
locality claim is made for WASM linear memory, datasets, accelerator staging,
GPU VRAM or NPU memory.


## v6.12.0 published feature baseline

The published v6.12.0 release unified browser spatial processing with benchmark-led native numerics. The browser-WASM path provides WGS84/ECEF and ENU transforms, Hermite interpolation, a bounded 512-entity store, antimeridian-aware queries, freshness- and distance-constrained observation resolution, and iterative arc–secant–tangent trajectory simplification. Native JSONL manifests drive real multivariate workloads across drone, finance, and environmental data; measured profiles select bounded batch/worker policies rather than generating substitute benchmark datasets. YuKKi-OS also owns a bounded CPU real-symmetric Jacobi eigensolver for 1–64 dimensional covariance/correlation matrices, with sorted eigenvalues, column eigenvectors, residual and orthogonality diagnostics, plus a domain-checked real arcsecant mapping. The `yukki_dataset_bench` and `yukki_eigensolver_bench` tools keep dataset semantics and numerical correctness in YuKKi-OS, while Overhauled remains the separate execution/placement tier. Existing YKMC, BRK1/BRK2, NXR1, and WSM1 contracts are preserved; no GPU/NPU eigensolver acceleration or measured power saving is claimed.

## v6.13.0 published feature set

The published v6.13.0 release adds native multi-module WebAssembly program composition
and time-weighted spatial replica pools. YuKKi-OS compiles declared core-Wasm
modules with Wasmtime, validates a directed acyclic module graph and exact
function signatures, instantiates isolated Store/instance replicas, and
atomically activates a prepared multi-program release. Stateless policies
may opt into bounded pools (up to eight replicas per program and 32 per
deployment); time-weighted service measurements and an optional stable
logical key influence replica selection. Busy stores are skipped, and full
saturation returns ProgramSaturated rather than waiting on a blocked store.

The composition API is a native Rust library integration. It does not add a
`yukki_core_node` subcommand or public HTTP deployment route. Stateful
programs retain the one-replica default; multi-replica execution requires an
explicit `stateless: true` declaration. The replica key is logical workload
affinity, not physical NUMA pinning. The separate Overhauled repository
continues to own broker dispatch and accelerator placement.

The scheduler starts at a 1 ms service-time estimate, applies a 7/8 prior plus 1/8 latest-sample EWMA, and adds a 25% locality penalty to non-preferred replicas. Its stable logical key is not geographic routing or physical NUMA pinning. Multi-replica execution is only valid for policies explicitly declared stateless; the safe default is one stateful replica. See [the composition guide](docs/WASM_PROGRAM_COMPOSITION.md) for limits and the Rust API.

## Architecture map — full-colour ANSI palette

![YuKKi-OS control and runtime architecture diagram](docs/diagrams/yukkios-architecture.svg)

YuKKi-OS is the coordination and host-runtime tier: it authenticates peer
sessions, coordinates bounded services, hosts Wasmtime guests, and owns stream,
spatial and multivariate dataset semantics. The Overhauled broker is a separate
execution tier reached over BRK1/BRK2. A production WSM1 task/lifecycle call
uses the adapter boundary; the optional browser benchmark instead executes
spatial WASM locally in Node and sends host-prepared numeric records as direct
BRK2 inference requests.

The diagram includes the worker-directive contract and the newly merged BRK2 v1 locality-placement codec. YuKKi-OS owns workload classification and emits optional deadline, worker-class, logical-affinity, advisory preferred-NUMA and bounded nested locality-placement intent (request field 14). The response may carry a structured placement outcome (field 13); an absent result means unknown/not applied. Both repositories currently implement codec validation only: no broker-owned allocator applies or verifies memory placement, and the GPU adapter does not automatically request it. Overhauled owns isolated per-class worker pools and broker-local Linux CPU affinity. A logical key or preferred node remains a hint, not proof of CPU or memory placement. The browser module is not the native daemon, and accelerator use remains optional and broker-reported. For a terminal-
rendered 24-bit ANSI version, run `bash docs/diagrams/print-ansi.sh`.


## CLI and stream gateway

```text
yukki_core_node bootstrap <bind-address>
yukki_core_node node <bootstrap-address> <advertised-address>
yukki_core_node gateway [listen-address] [--insecure-dev]
yukki_core_node streams list
yukki_core_node streams tune <stream-id> [--from <seq>]
```

The gateway defaults to `127.0.0.1:7670`. Open `/dashboard` for the stream dashboard and enter the gateway bearer token to load stream data. Set `YUKKI_GATEWAY_TOKEN` before starting `gateway`. The `/dashboard` HTML page is public; the stream APIs require the bearer token. `--insecure-dev` bypasses the protected gateway API auth gate and is only for local development.

Required for the peer mesh: `YUKKI_PSK_HEX` (64 hex chars / 32 bytes).

Required for an authenticated gateway: `YUKKI_GATEWAY_TOKEN` (1–4096 visible bearer-token characters).

Optional logging variable: `RUST_LOG` (default `info`).

## Build and run

```bash
cargo build --release --locked
export YUKKI_PSK_HEX="$(openssl rand -hex 32)"
./target/release/yukki_core_node bootstrap 0.0.0.0:7660
# in another shell
./target/release/yukki_core_node node 127.0.0.1:7660 127.0.0.1:9999
```

## Broker interoperability

The peer mesh and broker transports are separate:

- **Peer mesh:** X25519 + PSK + HKDF + ChaCha20-Poly1305.
- **Generic broker client** (`src/broker_client.rs`): raw TCP with a 4-byte big-endian length-prefixed JSON protocol. It is not the Overhauled protocol.
- **Overhauled adapter:** raw TCP with the same length prefix and BRK1/v1 or BRK2/v2 binary envelopes. WSM1 carries sandbox task and lifecycle payloads inside broker requests and responses. The Overhauled broker remains the execution tier, while YuKKi-OS remains the control-plane and mesh authority.

YuKKi-OS remains the control plane. Overhauled owns placement and execution, including the opt-in physical Ethos-U85 Linux DRM backend. BRK2 `device_preference=npu` is the existing NPU dispatch request.

The browser-WASM benchmark has a separate, optional BRK2 measurement mode. The Node runner executes the local spatial WASM module and can submit host-prepared numeric fixture records directly to Overhauled as BRK2 inference requests. This mode does not use the production GPU adapter or wrap the records in WSM1; it measures a broker round trip, not guest compilation/execution or browser rendering. See [Benchmarking](docs/BENCHMARKING.md) and [Overhauled interoperability](docs/OVERHAULED_INTEROP.md).

Default generic broker endpoint: `127.0.0.1:9000`.

Generic broker boundary variables:

- `YUKKI_BROKER_ENDPOINT`
- `YUKKI_BROKER_CONNECT_TIMEOUT_MS` (1..=600000 ms)
- `YUKKI_BROKER_REQUEST_TIMEOUT_MS` (1..=600000 ms)
- `YUKKI_BROKER_MAX_FRAME_BYTES`
- `YUKKI_BROKER_TRANSPORT_SECURITY` (`plaintext-boundary` or `authenticated-proxy`)

`authenticated-proxy` is documentary metadata; it does not enable TLS by itself. Per-task `timeout_ms` on broker task requests must be `1..=300000` ms; zero and oversized values are rejected.

## Geospatial and chunked media codecs

The Rust library provides an interoperable GeoJSON avenue model (`ArcGisAvenue`) using validated WGS84 longitude/latitude coordinates and optional route/avenue properties. The legacy NXR1 codec remains available for cross-version compatibility, but validation boundaries are strict and must be treated as trust-sensitive input.

Audio/video data is supported as codec-agnostic pass-through `MediaChunk`s. `LiveMediaStreams` provides bounded in-memory stream opening, ordered ingestion, sequence/range reads, acknowledgement, and retention semantics with explicit resource bounds.

See [docs/API.md](docs/API.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for API, wire layouts, trust boundaries, and resource limits. [docs/USER_HOWTO_STREAMING.md](docs/USER_HOWTO_STREAMING.md) explains the retention and playback flow.

## GPU-backed WASM sandbox adapter

The optional `src/gpu_adapter.rs` boundary supports Overhauled via BRK1/BRK2 plus WSM1 task and lifecycle payloads. The adapter is disabled by default (`YUKKI_GPU_ADAPTER_ENABLED=false`); ordinary mesh traffic remains available without GPU backend activation.

The native `wasm_composition` runtime also links multiple core-Wasm modules
into one or several live policy programs. Stateless programs can opt into
isolated replica pools; a time-weighted spatial scheduler uses recent service
time and a logical workload key to route around busy or slow replicas.
Saturated pools fail fast rather than queueing behind a locked Store. See
[WASM program composition](docs/WASM_PROGRAM_COMPOSITION.md).

Adapter variables:

- `YUKKI_GPU_ADAPTER_ENABLED` (`true` / `false`, default `false`)
- `YUKKI_GPU_BROKER_ENDPOINT` (default `127.0.0.1:9090`)
- `YUKKI_GPU_CONNECT_TIMEOUT_MS`, `YUKKI_GPU_REQUEST_TIMEOUT_MS`, `YUKKI_GPU_QUIESCE_TIMEOUT_MS` (each 1..=600000 ms)
- `YUKKI_GPU_MAX_FRAME_BYTES` (default 1048576 / 1 MiB)
- `YUKKI_GPU_MAX_RETRIES` (default `3`)

CPU is the always-available correctness baseline. GPU and NPU are optional, best-effort broker tiers. `device_preference=npu` requests NPU dispatch; it does not guarantee hardware use. Exact-precision guarantees are only valid when the backend itself is the trusted execution environment.

## Platform deployment

Mainline Windows/MSVC is unsupported. The browser application (`wasm32-unknown-unknown`) and WASI Preview 1 guest (`wasm32-wasip1`) are separate WebAssembly deployment surfaces, not native Windows builds. See [docs/PLATFORM_SUPPORT.md](docs/PLATFORM_SUPPORT.md), [docs/BROWSER_WASM.md](docs/BROWSER_WASM.md), and [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for their distinct build and deployment procedures. The browser client uses the Rust verifier to validate chunk metadata before fetch/retention operations.

## Documentation

- [Architecture and implementation map](docs/ARCHITECTURE.md) · [Step-by-step system administration how-to](docs/SYSADMIN_HOWTO.md) · [API reference](docs/API.md) · [Worker class policy](docs/WORKER_CLASS_POLICY.md)
- [Composed WASM programs and time-weighted replica routing](docs/WASM_PROGRAM_COMPOSITION.md) · [WASM guest worker](guest-worker/README.md)
- [Versioning](docs/VERSIONING.md) · [Changelog](docs/CHANGELOG.md)

- [Overhauled broker interoperability](docs/OVERHAULED_INTEROP.md) · [Ethos-U85 deployment](docs/ETHOSU_U85_DEPLOYMENT.md)
- [BRK2 conformance](docs/BRK2_CONFORMANCE_V1.md) · [BRK2 locality placement v1](docs/BRK2_LOCALITY_PLACEMENT_V1.md) · [BRK1/BRK2 executable corpus](docs/BRK_CONFORMANCE_V1.md)
- [Overhauled broker service discovery](docs/BROKER_SERVICE_DISCOVERY.md)
- [Deployment](docs/DEPLOYMENT.md) · [System administration](docs/SYSADMIN_HOWTO.md) · [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Browser WASM gateway workspace](docs/BROWSER_WASM.md) · [Native browser runtime and peer GPU/NPU delegation](docs/BROWSER_RUNTIME.md) · [MMO browser spatial core](docs/MMO_BROWSER_WASM.md) · [Spatial and multivariate data how-to](docs/USER_HOWTO_MMO.md) · [Benchmarking](docs/BENCHMARKING.md) · [Benchmark-driven datasets and eigensolver](docs/BENCHMARK_DRIVEN_DATASETS.md) · [Streaming how-to](docs/USER_HOWTO_STREAMING.md)
- [Native benchmark-driven datasets and eigensolver](docs/BENCHMARK_DRIVEN_DATASETS.md) · [Example multivariate manifest](examples/benchmark-datasets/manifest.json)
- [Security hardening notes](docs/SECURITY_HARDENING_NOTES.md)

## Docker

The repository ships a Dockerfile that builds and embeds `yukki_core_node`.

```bash
docker build -t yukkios:6.19.0 .
```

Current limitation: no built-in TLS termination for peer or broker links.

## License

GPL-3.0-only. See [LICENSE](LICENSE).


## Overhauled broker discovery

YuKKi-OS nodes can advertise reachable Overhauled worker brokers through the authenticated peer mesh. Set `YUKKI_BROKER_ENDPOINT=host:port` and optionally `YUKKI_BROKER_CAPABILITIES=cpu,gpu,npu`. Discovery uses bounded leases and hop-limited gossip; it is not yet a Kademlia DHT. See [the broker service discovery guide](docs/BROKER_SERVICE_DISCOVERY.md) and [the cross-repository wire contract](docs/OVERHAULED_INTEROP.md).
