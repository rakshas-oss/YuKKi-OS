# YuKKi OS v6.9.6

YuKKi-OS is a Rust-based authenticated control-plane mesh with a C FFI frame engine and an optional broker client boundary.

> Current stable release: v6.9.6. YuKKi-OS is intended for validation, experimentation, and deployment; independent security review remains recommended before production use.

## Current baseline

- Release line: **v6.9.6**
- Rust toolchain: **1.98.1** (`rust-toolchain.toml`)
- Binary: **`yukki_core_node`**
- Library crate: **`yukkios_6_8_0_inet3`**
- Status: **stable release**

## CLI and stream gateway

```text
yukki_core_node bootstrap <bind-address>
yukki_core_node node <bootstrap-address> <advertised-address>
yukki_core_node gateway [listen-address] [--insecure-dev]
yukki_core_node streams list
yukki_core_node streams tune <stream-id> [--from <seq>]
```

The gateway defaults to `127.0.0.1:7670`. Open `/dashboard` for the stream
dashboard and enter the gateway bearer token to load stream data. Set
`YUKKI_GATEWAY_TOKEN` before starting `gateway`; the explicit `--insecure-dev` option is for local
development only. A node also starts its gateway when that token is set.
`YUKKI_GATEWAY_LISTEN` configures the node's listener and
`YUKKI_GATEWAY_ENDPOINT` configures the `streams` CLI target.

Required for the peer mesh:

- `YUKKI_PSK_HEX` (64 hex chars / 32 bytes)

Required for an authenticated gateway:

- `YUKKI_GATEWAY_TOKEN` (1–4096 visible bearer-token characters)

Optional logging env var:

- `RUST_LOG` (default `info`)

## Build and run

```bash
cargo build --release --locked
export YUKKI_PSK_HEX="$(openssl rand -hex 32)"
./target/release/yukki_core_node bootstrap 0.0.0.0:7660
# in another shell
./target/release/yukki_core_node node 127.0.0.1:7660 127.0.0.1:9999
```

## Broker interoperability boundary

YuKKi-OS peer mesh transport and broker transport are separate:

- Peer mesh: X25519 + PSK + HKDF + ChaCha20-Poly1305
- Broker client (`src/broker_client.rs`): raw TCP + 4-byte big-endian length-prefixed JSON

Default broker endpoint: `127.0.0.1:9000`

Broker boundary env vars:

- `YUKKI_BROKER_ENDPOINT`
- `YUKKI_BROKER_CONNECT_TIMEOUT_MS` (must be `1..=600000` ms)
- `YUKKI_BROKER_REQUEST_TIMEOUT_MS` (must be `1..=600000` ms)
- `YUKKI_BROKER_MAX_FRAME_BYTES`
- `YUKKI_BROKER_TRANSPORT_SECURITY` (`plaintext-boundary` or `authenticated-proxy`)

`authenticated-proxy` is documentary metadata for operations; it does not enable TLS by itself.

Per-task `timeout_ms` (on `BrokerTask`/`GpuTaskRequest`) must be `1..=300000`
ms (5 minutes); zero or oversized values are rejected by request validation.
Callers must supply an in-range timeout explicitly; payload size is not used to
derive task deadlines.

## Geospatial and chunked media codecs

The Rust library provides an interoperable GeoJSON avenue model
(`ArcGisAvenue`) using validated WGS84 longitude/latitude coordinates and
optional route/avenue properties. The legacy NXR1 codec remains available but
its numeric fields are not geographic coordinates.

Audio/video data is supported as codec-agnostic pass-through `MediaChunk`s.
`LiveMediaStreams` provides bounded in-memory stream opening, ordered
ingestion, sequence/range reads, acknowledgement, and finish/removal APIs.
`StreamRegistry` exposes local and discovered descriptors and bounded,
per-subscriber cursors. The authenticated gateway provides stream listing,
description, HTTP range reads, and WebSocket tune-in with sequence-prefixed
binary frames and explicit acknowledgements.
The default store retains at most 256 chunks (256 KiB maximum each); it does
not transcode media. Nodes exchange bounded stream announcements and
low-frequency digest summaries over the existing authenticated mesh transport.
`StreamRelay` can mirror discovered remote streams into a local store, sharing
one upstream pull among local subscribers and enabling relay fan-out. The
library includes `OriginChunkClient` for authenticated HTTP range reads from an
origin gateway. Applications must wire these into `serve_with_relay`; the CLI
does not configure a relay automatically. The standalone `gateway` command
owns its own in-memory store. The origin client uses plain HTTP, so use a
trusted network or a TLS-terminating proxy.
WASM guests can select bounded binary chunks through a checked host import;
they never receive raw store pointers.

See [docs/API.md](docs/API.md) for Rust examples, wire layouts, validation,
and limits, and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for trust and
resource boundaries.

## Streaming binaries and data

Use the [streaming user how-to](docs/USER_HOWTO_STREAMING.md) for chunked binary
and media streams, broker delivery, GeoJSON/NXR1 frames, and WASM deployment.

## GPU-backed WASM sandbox interoperability (rakshas-oss/overhauled)

YuKKi-OS provides an optional interoperability adapter (`src/gpu_adapter.rs`) for offloading WASM sandbox tasks to GPU placement brokers such as `rakshas-oss/overhauled`:

- Communicates over raw TCP via version-negotiated length-prefixed JSON (`overhauled.wasm.gpu.v1`).
- Preserves sandbox isolation with host-mediated execution and bounded buffer descriptors.
- Provides module lifecycle management with atomic routing switches, quiescing/draining, drain-before-release ordering, and rollback on activation failure.
- Optional / configurable: disabled by default (`YUKKI_GPU_ADAPTER_ENABLED=false`) so existing deployments run without GPU hardware or external brokers.

Environment variables:
- `YUKKI_GPU_ADAPTER_ENABLED` (`true` / `false`, default `false`)
- `YUKKI_GPU_BROKER_ENDPOINT` (default `127.0.0.1:9000`)
- `YUKKI_GPU_CONNECT_TIMEOUT_MS` (default `2000`, must be `1..=600000` ms)
- `YUKKI_GPU_REQUEST_TIMEOUT_MS` (default `5000`, must be `1..=600000` ms)
- `YUKKI_GPU_QUIESCE_TIMEOUT_MS` (default `5000`, must be `1..=600000` ms)
- `YUKKI_GPU_MAX_FRAME_BYTES` (default `1048576` / 1 MiB)
- `YUKKI_GPU_MAX_RETRIES` (default `3`)

### CPU-first execution policy

CPU is the always-available correctness baseline; accelerators are optional, best-effort tiers (`src/exec_policy.rs`). `RustasmSandbox::execute_with_policy` picks a backend from a `TaskProfile`:

1. **CPU** (default): used for small tasks, when no accelerator is available, or when `YUKKI_FORCE_CPU_FALLBACK=true`.
2. **GPU** (overhauled broker): only for data-parallel tasks above the offload threshold and when the adapter is enabled.
3. **NPU / Remote peer**: reserved tiers; not selected until an executor is registered.

Exact-precision / verification-sensitive tasks (e.g. PQC) never offload. If an accelerator fails and `cpu_retry_safe` is true, the task is retried on CPU and the reason is reported; otherwise the[...]

See [docs/API.md](docs/API.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for protocol specifications and lifecycle documentation.

## Documentation

- [docs/RELEASE_v6.9.6.md](docs/RELEASE_v6.9.6.md)
- [docs/DRONE_DASHBOARD.md](docs/DRONE_DASHBOARD.md)
- [docs/DRONE_INTEROP.md](docs/DRONE_INTEROP.md)
- [docs/USER_HOWTO_STREAMING.md](docs/USER_HOWTO_STREAMING.md)
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)
- [docs/SYSADMIN_HOWTO.md](docs/SYSADMIN_HOWTO.md)
- [scripts/deploy/README.md](scripts/deploy/README.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/API.md](docs/API.md)
- [docs/SECURITY.md](docs/SECURITY.md)
- [docs/CHANGELOG.md](docs/CHANGELOG.md)
- [docs/VERSIONING.md](docs/VERSIONING.md)
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)

## Docker

The repository ships a Dockerfile that builds and embeds `yukki_core_node`.

```bash
docker build -t yukkios:6.9.6 .
```

Current limitation: no built-in TLS termination for peer or broker links.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
