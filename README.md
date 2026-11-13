# YuKKi-OS v6.10.0

**YuKKi-OS is a Rust-based modular distributed systems platform** providing an authenticated peer-to-peer control plane, workload coordination, concurrent runtime primitives, WebAssembly sandboxing, streaming, and accelerator interoperability.

YuKKi-OS combines distributed coordination and runtime services rather than representing a single-purpose MPMC microkernel. Its current architecture includes a peer mesh, stream infrastructure, broker boundary, accelerator fallback policy, and optional GPU/NPU integration.

> Current stable release: v6.10.0. YuKKi-OS is intended for validation, experimentation, and deployment; independent security review remains recommended before production use.

## Current baseline

- Release line: **v6.10.0**
- Rust toolchain: **1.98.1** (`rust-toolchain.toml`)
- Binary: **`yukki_core_node`**
- Library crate: **`yukkios`**
- Status: **stable release**

## Security and hardening notes

The project includes defensive validation in native mesh helpers, FHSS synchronization, and the guest-worker shared memory channel. See [docs/SECURITY_HARDENING_NOTES.md](docs/SECURITY_HARDENING_NOTES.md) for details.

## What's new in v6.10.0

The v6.10.0 release adds event-driven WASM module draining, mesh coordinate and peer-address validation, hardened remote stream relay batch handling, negative-timeout rejection at the WASM bridge, and real 256-byte NXR1 encode/decode benchmarks.

## CLI and stream gateway

```text
yukki_core_node bootstrap <bind-address>
yukki_core_node node <bootstrap-address> <advertised-address>
yukki_core_node gateway [listen-address] [--insecure-dev]
yukki_core_node streams list
yukki_core_node streams tune <stream-id> [--from <seq>]
```

The gateway defaults to `127.0.0.1:7670`. Open `/dashboard` for the stream dashboard and enter the gateway bearer token to load stream data. Set `YUKKI_GATEWAY_TOKEN` before starting `gateway`; `--insecure-dev` disables the dashboard auth gate for non-production testing.

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

- [Release notes v6.9.9](docs/CHANGELOG.md)
- [Architecture](docs/ARCHITECTURE.md) · [API](docs/API.md) · [Security](docs/SECURITY.md)
- [Overhauled broker interoperability](docs/OVERHAULED_INTEROP.md) · [Ethos-U85 deployment](docs/ETHOSU_U85_DEPLOYMENT.md)
- [BRK2 conformance](docs/BRK2_CONFORMANCE_V1.md) · [BRK1/BRK2 executable corpus](docs/BRK_CONFORMANCE_V1.md)
- [Deployment](docs/DEPLOYMENT.md) · [System administration](docs/SYSADMIN_HOWTO.md) · [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Browser WASM](docs/BROWSER_WASM.md) · [Streaming how-to](docs/USER_HOWTO_STREAMING.md)
- [Changelog](docs/CHANGELOG.md) · [Versioning](docs/VERSIONING.md)
- [Security hardening notes](docs/SECURITY_HARDENING_NOTES.md)

## Docker

The repository ships a Dockerfile that builds and embeds `yukki_core_node`.

```bash
docker build -t yukkios:6.10.0 .
```

Current limitation: no built-in TLS termination for peer or broker links.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
