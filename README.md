# YuKKi-OS v6.13.0

> **Coordinate the system. Connect the workload. Keep execution flexible.**
>
> A distributed control plane for peers, streams, and sandboxed workloads—with accelerator execution delegated to interoperable backends.

**YuKKi-OS is a Rust-based modular distributed systems platform** providing an authenticated peer-to-peer control plane, workload coordination, concurrent runtime primitives, WebAssembly sandboxing, streaming, and accelerator interoperability.

YuKKi-OS combines distributed coordination and runtime services rather than representing a single-purpose MPMC microkernel. Its current architecture includes a peer mesh, stream infrastructure, broker boundary, accelerator fallback policy, and optional GPU/NPU integration.

> Proposed release: v6.13.0 (release candidate; tag pending required validation). YuKKi-OS is intended for validation, experimentation, and deployment; independent security review remains recommended before production use.

## Current baseline

- Release line: **v6.13.0**
- Rust toolchain: **1.98.1** (`rust-toolchain.toml`)
- Binary: **`yukki_core_node`**
- Library crate: **`yukkios`**
- Status: **release candidate — CI and release checks pending**

## Security and hardening notes

The project includes defensive validation in native mesh helpers, FHSS synchronization, and the guest-worker shared memory channel. See [docs/SECURITY_HARDENING_NOTES.md](docs/SECURITY_HARDENING_NOTES.md) for details.

## v6.12.0 published feature baseline

The published v6.12.0 release unified browser spatial processing with benchmark-led native numerics. The browser-WASM path provides WGS84/ECEF and ENU transforms, Hermite interpolation, a bounded 512-entity store, antimeridian-aware queries, freshness- and distance-constrained observation resolution, and iterative arc–secant–tangent trajectory simplification. Native JSONL manifests drive real multivariate workloads across drone, finance, and environmental data; measured profiles select bounded batch/worker policies rather than generating substitute benchmark datasets. YuKKi-OS also owns a bounded CPU real-symmetric Jacobi eigensolver for 1–64 dimensional covariance/correlation matrices, with sorted eigenvalues, column eigenvectors, residual and orthogonality diagnostics, plus a domain-checked real arcsecant mapping. The `yukki_dataset_bench` and `yukki_eigensolver_bench` tools keep dataset semantics and numerical correctness in YuKKi-OS, while Overhauled remains the separate execution/placement tier. Existing YKMC, BRK1/BRK2, NXR1, and WSM1 contracts are preserved; no GPU/NPU eigensolver acceleration or measured power saving is claimed.

## What's new in v6.13.0

The v6.13.0 candidate adds native multi-module WebAssembly program composition
and time-weighted spatial replica pools. YuKKi-OS can compile declared core-Wasm
modules with Wasmtime, validate and link a directed acyclic graph of typed
function imports, instantiate isolated program replicas, and atomically switch
a prepared multi-program release. Stateless policies may opt into bounded
replica pools; a logical affinity key prefers a stable shard while measured
service time can route around a slower replica. Busy stores are skipped, and
full saturation returns an explicit ProgramSaturated result rather than
waiting on a held store lock. This is host-side library functionality, not a
new CLI or HTTP deployment route. The separate Overhauled repository continues
to own broker dispatch and accelerator placement.

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

The diagram distinguishes implemented library primitives from stronger
deployment claims: NUMA discovery is not yet a complete NUMA-aware scheduler;
the browser module is not the native daemon; and accelerator use remains
optional and broker-reported. For a terminal-rendered 24-bit ANSI version,
run `bash docs/diagrams/print-ansi.sh`. GitHub's Markdown renderer does not
execute ANSI escape sequences, so the inline SVG is the readable colour view.


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

See [docs/PLATFORM_SUPPORT.md](docs/PLATFORM_SUPPORT.md) for native Windows MSVC, WASI Preview 1 guest, and browser-WASM deployment profiles. The browser client targets `wasm32-unknown-unknown`, using the Rust verifier to validate chunk metadata before fetch/retention operations.

## Documentation

- [Changelog](docs/CHANGELOG.md)
- [Architecture](docs/ARCHITECTURE.md) · [How-to](docs/SYSADMIN_HOWTO.md) · [Composed WASM programs](docs/WASM_PROGRAM_COMPOSITION.md) · [API](docs/API.md) · [Versioning](docs/VERSIONING.md) · [Security](docs/SECURITY.md)
- [Overhauled broker interoperability](docs/OVERHAULED_INTEROP.md) · [Ethos-U85 deployment](docs/ETHOSU_U85_DEPLOYMENT.md)
- [BRK2 conformance](docs/BRK2_CONFORMANCE_V1.md) · [BRK1/BRK2 executable corpus](docs/BRK_CONFORMANCE_V1.md)
- [Deployment](docs/DEPLOYMENT.md) · [System administration](docs/SYSADMIN_HOWTO.md) · [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Browser WASM](docs/BROWSER_WASM.md) · [MMO browser spatial core](docs/MMO_BROWSER_WASM.md) · [Spatial and multivariate data how-to](docs/USER_HOWTO_MMO.md) · [Benchmarking](docs/BENCHMARKING.md) · [Benchmark-driven datasets and eigensolver](docs/BENCHMARK_DRIVEN_DATASETS.md) · [Streaming how-to](docs/USER_HOWTO_STREAMING.md)
- [Native benchmark-driven datasets and eigensolver](docs/BENCHMARK_DRIVEN_DATASETS.md) · [Example multivariate manifest](examples/benchmark-datasets/manifest.json)
- [Changelog](docs/CHANGELOG.md) · [Versioning](docs/VERSIONING.md)
- [Security hardening notes](docs/SECURITY_HARDENING_NOTES.md)

## Docker

The repository ships a Dockerfile that builds and embeds `yukki_core_node`.

```bash
docker build -t yukkios:6.13.0 .
```

Current limitation: no built-in TLS termination for peer or broker links.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
