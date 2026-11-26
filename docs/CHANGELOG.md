## v6.20.0 (release candidate; not published)

### Bounded persistent broker transport and strict sidecar routing

- Add an endpoint-scoped persistent BRK1/BRK2 TCP connection pool with one request/response exchange per lease; retain existing framing and correlation semantics.
- Bound active plus idle sessions with `YUKKI_GPU_MAX_CONNECTIONS` (default 16, maximum 256). Recycle only fully decoded successful exchanges; discard uncertain sockets and do not automatically replay non-idempotent requests.
- Add `YUKKI_GPU_REQUIRE_MTLS_PROXY=true` strict mode to reject non-numeric or non-loopback endpoints and route traffic through a local mTLS sidecar.
- Pair with Overhauled PR #93: bounded client sessions, loopback-only plaintext listener guard, TLS 1.3 stunnel profile and optional fsync-backed replay-nonce journal.

### Compatibility, security and release boundaries

- Preserve YKMC, BRK1/BRK2, NXR1 and WSM1 identities; no wire-format version change is introduced.
- The Rust socket pool remains plain TCP. TLS is terminated by the documented sidecar; the client does not inspect the sidecar's negotiated certificate identity.
- TLS peer identity is not yet passed into receiver authorization. Durable replay nonce records do not make staged artifact bytes, prepared deployments or active-release state restart-safe.
- Non-idempotent operations are not automatically replayed after an ambiguous failure. Existing untrusted-stream paths remain independently available under their existing bounds.
- PR #184 restored the missing `rand 0.9.5` Cargo.lock dependency entry; that repaired lockfile resolution but did not remediate the separately reported low-severity transitive rand advisory.
- No `6.20.0` tag, GitHub Release or crates.io publication is claimed by this candidate.

---

## v6.19.0 (published 2026-11-24)

### Native browser runtime and graphics delegation

- Add the native `yukki-browser` runtime as a separate workspace package, using WebKitGTK on Linux and WKWebView on macOS.
- Exercise Linux X11/Xvfb, native Wayland and XWayland startup paths with deterministic headless smoke orchestration; add macOS runtime contract/build coverage.
- Add a bounded CPU graphics benchmark smoke path and upload platform benchmark reports with the runtime artifacts.
- Expose explicit BRK2 device-preference APIs for browser WSM1 and inference work; return broker-reported backend telemetry so callers can distinguish requested from actual execution.
- Keep browser-runtime package versioning independent at `0.1.0`; this release advances only the native `yukkios` package.

### Compatibility and boundaries

- The browser shell is native desktop software, not the browser-WASM gateway or WASI guest worker. It does not make Windows/MSVC a supported native target.
- GPU/NPU delegation remains broker-mediated and capability-dependent. A preference is not proof of accelerator execution; CPU fallback and exact-CPU policy remain authoritative.
- Existing YKMC, BRK1/BRK2, NXR1 and WSM1 wire identities remain unchanged.
- The `6.19.0` Git tag and GitHub Release were published on 2026-11-24. This does not claim crates.io publication.

---

# Changelog

## v6.18.0 (published 2026-11-22)

### Authenticated WASM handoff sender

- Add the native Rust sender API with pluggable signing and receiver-receipt verification.
- Separate deployment-sender identity from artifact-publisher provenance; construct canonical manifests/digests and sign prepare, sequential bounded artifact chunks and activation requests.
- Keep key storage and transport security caller-supplied. The client does not silently use plaintext TCP as a substitute for authenticated transport.
- Pair with the Overhauled receiver in PR #86. This is not yet an authenticated network listener or a durable cross-process deployment transaction; protected transport and durable replay/staging integration remain deployment requirements.

### Streaming flood resistance without publisher gating

- Preserve ingestion and consumption of untrusted streams; stream trust is independent of executable-artifact publisher authorization.
- Enforce hard media-store ceilings of 64 MiB retained data, 256 streams, 16,384 retained chunks and 256 KiB per chunk.
- Add global/per-stream chunk and byte token buckets plus stream-open churn rate limiting.
- Retain gateway and WebSocket global/per-peer request and connection caps, control-rate limits, timeouts, bounded relay work, quotas and acknowledgement backpressure.
- These controls bound application resource use; upstream edge filtering is still required against volumetric network floods.

### Release metadata and boundaries

- Advance the native yukkios Cargo package, root lockfile, OCI image label, README, versioning guide and version assertion to 6.18.0.
- Keep browser-WASM and WASI guest-worker workspace package versions independent at 0.1.0.
- Preserve YKMC, BRK1/BRK2, NXR1 and WSM1 wire identities. The 6.18.0 GitHub Release was subsequently published; no external package registry upload is implied.

---

## v6.17.0 (published 2026-11-22)

### WebAssembly composition and authenticated handoff contract

- Infer conventional core-Wasm module imports when an import namespace exactly
  matches a module ID in the same composition program. Explicit bindings remain
  supported for aliases; inferred dependencies continue through dependency
  ordering, exact function-signature validation and linker registration.
- Add the authenticated WASM handoff v1 protocol document and shared JSON
  Schema covering signed capability offers, prepare requests, decisions,
  receipts, cancellation and bounded digest-verified artifact chunks.
- Specify Ed25519 signatures over RFC 8785 canonical bytes, sender/audience
  binding, expiry and replay checks, backend capability negotiation and
  separate prepare/activate phases.

### CI validation

PR #164 merged after all four required workflows passed on
`ced85a24636b35c2506f83a47ffd57cee918e996` (2026-11-22): Test & Code Quality,
Multi-Platform Build, Integration Tests, and Coverage & Metrics. Validation
included native Linux/macOS/Windows unit tests, supported Linux/macOS builds,
WASI and browser-WASM validation, security/dependency audits, formatting and
Clippy, Docker build, mesh and ABI/FFI tests, paired Overhauled BRK1/BRK2
conformance and live Rust-to-C++ interoperability, simulated NPU/CPU fallback,
coverage and Criterion benchmarks. The pull-request release-archive job was skipped because no release-tag
event occurred; the post-merge release event built and attached 10 assets.

### Compatibility and security boundaries

- No YKMC, BRK1/BRK2, NXR1 or WSM1 wire-format change is intended.
- The authenticated handoff is a protocol specification, not a completed
  network receiver or distributed deployment implementation. Receiver-side
  cryptographic enforcement, durable replay state, publisher provenance checks
  and cross-repository activation remain separate implementation work.
- The `6.17.0` tag points to `c07052f2011dc727c4a0cb7a0684a8ca435faa52`.
  The GitHub Release is published with 10 assets, including SHA256SUMS.
- GitHub Release publication does not imply publication to external package
  registries.

## v6.16.0 (published 2026-11-21)

### Broker discovery and BRK2 locality-placement codec

- Add the bounded lease-based broker service registry and optional endpoint advertisement through `YUKKI_BROKER_ENDPOINT`, relayed over the authenticated peer mesh with bounded hop count, lease expiry, message-ID deduplication and replay to newly joining peers.
- Clarify that this is bootstrap-relayed authenticated gossip with an in-memory lease cache, not Kademlia or a full DHT. Discovery records are not authorization; BRK1/BRK2 transport still requires a trusted private network or independently authenticated proxy.
- Add Rust BRK2 request field 14 locality-intent and response field 13 placement-result codec helpers, with bounded nested-TLV validation and explicit criticality rules.
- Preserve the response rule that an absent placement result means unknown/not applied, never successful placement.

### Ownership and limitations

YuKKi-OS owns workload policy and broker endpoint discovery; Overhauled owns local queueing, admission, worker placement and execution. This release does not add a broker-owned NUMA allocator or verify physical memory placement. The codec does not automatically request locality from the GPU adapter and makes no placement claim for WASM linear memory, datasets, accelerator staging, GPU VRAM or NPU memory. The discovery layer is not a DHT and does not authenticate broker transport.

### Release gate

Require native platform tests, browser-WASM and WASI validation, integration and live Overhauled interoperability, formatting/Clippy, security and dependency audits, coverage and benchmark smoke tests. Do not tag or publish v6.16.0 until all required checks pass and the release commit is approved.

# Changelog

## v6.15.0 (published 2026-11-21)

### Parallel spatiotemporal payload resolution

- `SequencePolicy::AllowAll` bypasses sequence-state locking and sends
  directly to the bounded destination queue.
- Strict `RejectNonIncreasing` sequencing uses a short route-map lookup and
  per-source mutex, allowing different sources targeting the same destination
  to validate and enqueue concurrently while preserving atomic check/enqueue/
  watermark semantics for each individual source.
- Strict sequence tracking is bounded to 65,536 source entries per route.
  The new `ResolverError::SequenceSourceLimit` reports a saturated tracking
  map; queue-full failures do not advance the source watermark.

### Load-aware composed-program scheduling

- Added `TimeWeightedSpatialScheduler::ranked_candidates_with_load` to rank
  replicas using service-time EWMA multiplied by current active-call load,
  while retaining the bounded spatial-locality preference.
- Active-call counts are a scheduling snapshot, not a reservation or queue
  depth guarantee. Non-blocking Store admission remains the final check;
  saturated programs still report `ProgramSaturated`.

### Lower-contention native benchmarks

- Dataset and eigensolver benchmark workers claim adaptive chunks instead of
  issuing a shared atomic operation for every batch/solve.
- Workers keep latency, checksum, residual and orthogonality metrics locally,
  then merge after all workers join. Numerical quality checks remain visible
  in the measured run.
- The optimization reduces shared benchmark instrumentation in the hot path;
  it is not a claim of a universal throughput or power improvement.

### Compatibility and release boundary

- No YKMC, BRK1/BRK2, NXR1 or WSM1 wire-format changes are introduced.
- The new resolver sequence-source error is an explicit bounded-resource
  outcome. Strict per-source ordering and no-watermark-advance-on-queue-full
  semantics remain intact.
- v6.15.0 was published after native/browser/WASI, integration, format,
  Clippy, audit, coverage and benchmark checks pass and the release commit
  is reviewed.

## v6.14.0 (published 2026-11-20)

### YuKKi-aware broker worker directives

- Added public `WorkerClass` and validated `WorkerDirective` types for
  Control, RealtimeSpatial, Throughput, ExactCpu and Inference workloads.
- Derive stable logical spatial affinity from resolved NXR1 source/destination
  routes and preserve the resolver's advisory NUMA hint.
- Map existing `TaskProfile` semantics into worker classes: ExactCpu takes
  precedence for exact-precision work; spatial context selects
  RealtimeSpatial; explicit inference profiles select Inference; remaining
  and data-parallel work selects Throughput.
- Convert relative `deadline_ms` values to checked absolute Unix-nanosecond
  BRK2 deadlines using a caller-supplied submission timestamp.
- Extend the Rust BRK2 codec with optional worker class, affinity and
  preferred-NUMA request fields 11–13.
- Add `submit_wsm1_task_with_worker_directive`, requiring BRK2 when a
  directive is present and returning optional worker telemetry. Lifecycle
  operations use Control; generic BRK2 WSM1 tasks default to Throughput;
  callers explicitly select Inference for model inference.
- Add policy/protocol tests and live Overhauled interoperability coverage.

### Compatibility and boundaries

- YuKKi-OS selects workload meaning and policy; Overhauled owns local worker
  queues, admission, CPU/NUMA placement, backend selection and execution.
- NXR1, WSM1 and BRK envelope identities are unchanged. BRK1/raw WSM1 paths
  remain compatible and do not transmit worker directives.
- The logical affinity key and NUMA hint are advisory. Actual NUMA placement
  is reported by Overhauled only when its Linux affinity operation succeeds.
- The v6.14.0 tag and GitHub release were published on 2026-11-20. External
  package publication remains a separate verification step.

---

## Unreleased

## v6.13.1 (release candidate; tag pending)

### Browser-WASM benchmark hardening

- Added bounded CLI validation: at most 1,000 iterations, 1,024 operations
  and the fixed 512-entity spatial capacity; broker ports and device
  preferences are range/enum checked.
- Hardened manifest, dataset and profile validation, including size ceilings,
  IDs, finite spatial outputs, resolver success and simplifier result bounds.
- Added an optional Node-to-Overhauled BRK2 benchmark leg. It sends
  host-prepared numeric records as ordinary inference requests and verifies
  response schema, request/task correlation, success status, backend identity,
  selected-GPU consistency, output bounds and deterministic CPU results.
- Reports now explicitly distinguish local-only Wasm measurements from live
  broker interoperability. They do not claim WSM1 guest execution, browser
  rendering, streaming, NUMA scheduling, or physical accelerator qualification
  unless the relevant path is separately exercised.

### Interoperability documentation and architecture maps

- Clarified the browser-WASM benchmark bridge as direct BRK2 inference traffic,
  separate from production WSM1 guest/task lifecycle operations.
- Added step-by-step instructions for running the optional CPU-only broker
  round trip and interpreting backend/fallback telemetry.
- Added ANSI-inspired full-colour SVG architecture maps and terminal
  renderers for both repositories, distinguishing library primitives from
  daemon/HTTP features and preserving the YuKKi-OS/Overhauled responsibility
  boundary.
- Preserved YKMC, BRK1/BRK2, NXR1 and WSM1 wire contracts.

### Release metadata and qualification

- Bumped the native Cargo package/root lockfile, OCI image label, library
  banner and version metadata assertion to 6.13.1.
- v6.13.1 was superseded before publication by v6.14.0; do not treat it as
  a published tag or release.
- Benchmark improvements are qualification-tool improvements; no universal
  throughput, latency, power or OPEX gain is claimed.

## v6.13.0 (published 2026-11-18)

### Native composed WebAssembly programs

- Added `CompositionRuntime` to assemble one or more live policy programs
  from a validated directed acyclic graph of core-Wasm modules and typed
  function imports.
- Added SHA-256 content-addressed, bounded in-process module caching and
  isolated per-replica Wasmtime Stores. Multi-replica execution requires an
  explicit `stateless: true` manifest declaration.
- Added atomic process-local activation of a prepared multi-program release;
  failed preparation leaves the active release unchanged, while already
  admitted calls retain their previous program set until completion.
- Added time-weighted replica ranking with stable SplitMix64 logical affinity,
  7/8 prior plus 1/8 latest-sample service-time EWMA, a 25% non-locality
  penalty and non-blocking Store admission. Full saturation returns an
  explicit `ProgramSaturated` error.
- Clarified that logical shard affinity is not geographic scheduling or
  physical NUMA pinning, and that composition remains a library API without a
  built-in CLI or HTTP deployment endpoint.

### Documentation and release metadata

- Aligned the architecture and sysadmin guides with the separate
  `ModuleLifecycleManager` and `CompositionRuntime` APIs, including exact
  scheduler scoring behavior and a WAT-to-Wasm build sequence.
- Updated the API reference, README, changelog, versioning guide, Cargo
  package/lockfile, OCI label and version metadata test to `6.13.0`.
- Preserved the YuKKi-OS/Overhauled boundary and existing YKMC, BRK1/BRK2,
  NXR1 and WSM1 protocol contracts.

---

## v6.12.0 (published 2026-11-18)

### Manifest-driven multivariate datasets and benchmark policy

- Added a bounded native JSON/JSONL manifest pipeline. Source rows and declared
  feature fields are the benchmark inputs; profiles define warm-up/sample
  windows, batch sizes, worker counts, objectives, and optional latency limits.
- Added `yukki_dataset_bench` to run NXR1 encode/decode and domain-scoped
  geospatial workload measurements across drone, finance, and environmental
  records. Reports preserve source identity, throughput/latency, working-set
  estimates, checksums, and the measured candidate selected by each profile.
- Connected measured dataset recommendations to YuKKi-OS bounded queue-policy
  APIs without changing broker/protocol wire formats or creating an artificial
  second dataset.

### Native symmetric numerics

- Added a bounded cyclic-Jacobi real-symmetric eigensolver for finite matrices
  with dimensions 1..=64. It returns ascending eigenvalues, column eigenvectors,
  residual and orthogonality diagnostics, and explicit failures for invalid,
  asymmetric, non-finite, overflowed, or non-convergent input.
- Added a domain-checked real arcsecant mapping, defined only for finite
  eigenvalues with `|lambda| >= 1`; this mapping is an optional representation,
  not a replacement for the eigensolver.
- Added `yukki_eigensolver_bench`, which consumes the same manifest feature
  fields, builds bounded correlation-matrix batches, measures throughput and
  P95 latency, and reports numerical quality alongside the selected candidate.
- Kept the numerical implementation in YuKKi-OS. Overhauled can measure
  broker/backend execution through its existing adapter and must not duplicate
  the eigensolver algorithm. No GPU/NPU acceleration or power-opex reduction
  is claimed by this CPU reference implementation.

### Browser spatial, spatiotemporal, and WASM workflows

- Documented the browser-WASM WGS84/ECEF and ENU transforms, Hermite
  interpolation, bounded 512-entity store, antimeridian-aware bounding boxes,
  freshness/distance-constrained nearest-observation resolution, and iterative
  arc–secant–tangent trajectory simplification.
- Added a user how-to for the browser spatial panel and the Manifest of Drones
  schema as a domain-neutral catalogue for drone telemetry, finance/market-site
  data, environmental mapping, real-estate observations, and similar
  multivariate sources. Full domain attributes and provenance remain on the
  host side; the spatial WASM ABI carries only the required spatial identity
  and time fields.
- Preserved the separate YuKKi-OS and Overhauled repositories, plus existing
  YKMC, BRK1/BRK2, NXR1, and WSM1 wire contracts.

### Benchmark infrastructure and release metadata

- Retained fixture-driven Criterion microbenchmarks and the browser-WASM Node
  runner that instantiates the actual compiled `wasm32-unknown-unknown`
  module. Native Criterion and browser-WASM CI reports remain diagnostic;
  shared-host timing thresholds are not used.
- Bumped the Rust package, root lockfile entry, OCI image label, README,
  versioning guide, API reference, and version assertion to `6.12.0`.
- Kept browser-WASM package versioning and the WASI guest artifact independent.

## v6.11.0 (superseded merged candidate; no tag published)

- Integrated the first browser spatial/spatiotemporal and native Criterion
  fixture candidate.
- This merged candidate was superseded before release tagging after required
  CI validation exposed benchmark type, ownership, and formatting defects.
  No `v6.11.0` release artifact or tag should be treated as published.

## v6.10.0 (last published release before the v6.11.0/v6.12.0 candidates)

### Event-driven draining, mesh validation, and NXR1 interoperability

- Replaced polling in WASM module draining with event-driven
  `tokio::sync::Notify` wakeups registered before counter inspection.
- Rejected non-finite mesh coordinates before R-tree insertion.
- Validated peer-advertised address lengths before broadcasting node-fleet
  updates.
- Hardened remote stream relay sequence arithmetic and validated complete
  upstream batches before mutating the mirror.
- Added real 256-byte NXR1 encode/decode Criterion benchmarks.
- Rejected negative WASM bridge timeouts before invoking the host handler.

---

## v6.9.5 (archived)

### Remote stream relay and dashboard

- Added `StreamRelay` to mirror discovered remote streams locally with shared,
  rate-limited upstream pulls, plus `OriginChunkClient` for authenticated HTTP
  metadata and chunk-range requests.
- Added the gateway stream dashboard at `/dashboard`; the static page is
  public, while stream data still requires the bearer token.
- Applications opt in by wiring a relay into `serve_with_relay`; the CLI does
  not configure an origin or relay automatically.
- The origin client uses plain HTTP with bounded I/O and response sizes; use a
  trusted network or TLS-terminating proxy. Origin descriptors omit codec
  metadata, so `OriginChunkClient` reports the codec as `unknown`.
