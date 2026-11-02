# YuKKi OS v6.9.9

YuKKi-OS is a Rust-based authenticated control-plane mesh with a C FFI frame engine and an optional broker client boundary. It coordinates peers and workload policy; accelerator execution is delegated to an explicitly configured broker such as [Overhauled](https://github.com/rakshas-oss/overhauled).

> Current stable release: v6.9.9. YuKKi-OS is intended for validation, experimentation, and deployment; independent security review remains recommended before production use.

## Current baseline

- Release line: **v6.9.9**
- Rust toolchain: **1.98.1** (`rust-toolchain.toml`)
- Binary: **`yukki_core_node`**
- Library crate: **`yukkios`**
- Status: **stable release**

## What's new in v6.9.9

The current line includes stability and deployability improvements for the authenticated mesh, stream registry, broker boundary, platform targets, and accelerator fallback policy. Recent interoperability work documents the Rust/C++ BRK1 and BRK2 wire contract, adds a shared cross-language conformance corpus and live broker tests, and enables an opt-in Overhauled Ethos-U85 Linux DRM execution path. These capabilities do not imply that physical U85 hardware has been validated; see the linked deployment guide for the validation boundary.

## CLI and stream gateway

```text
yukki_core_node bootstrap <bind-address>
yukki_core_node node <bootstrap-address> <advertised-address>
yukki_core_node gateway [listen-address] [--insecure-dev]
yukki_core_node streams list
yukki_core_node streams tune <stream-id> [--from <seq>]
```

The gateway defaults to `127.0.0.1:7670`. Open `/dashboard` for the stream dashboard and enter the gateway bearer token to load stream data. Set `YUKKI_GATEWAY_TOKEN` before starting `gateway`; `--insecure-dev` is for local development only. A node also starts its gateway when that token is set. `YUKKI_GATEWAY_LISTEN` configures the node listener and `YUKKI_GATEWAY_ENDPOINT` configures the `streams` CLI target.

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
- **Overhauled adapter:** raw TCP with the same length prefix and BRK1/v1 or BRK2/v2 binary envelopes. WSM1 carries sandbox task and lifecycle payloads inside broker requests and responses. The Overhauled server accepts BRK1 and BRK2 on one listener; the client selects the envelope and there is no JSON HELLO negotiation.

YuKKi-OS remains the control plane. Overhauled owns placement and execution, including the opt-in physical Ethos-U85 Linux DRM backend. BRK2 `device_preference=npu` is the existing NPU dispatch request; the broker response identifies the selected `backend` so clients can distinguish NPU execution from CPU fallback. A simulated NPU is CPU emulation for CI, not hardware acceleration. See [docs/OVERHAULED_INTEROP.md](docs/OVERHAULED_INTEROP.md) for wire and compatibility details and [docs/ETHOSU_U85_DEPLOYMENT.md](docs/ETHOSU_U85_DEPLOYMENT.md) for the hardware path and limits.

Default generic broker endpoint: `127.0.0.1:9000`.

Generic broker boundary variables:

- `YUKKI_BROKER_ENDPOINT`
- `YUKKI_BROKER_CONNECT_TIMEOUT_MS` (1..=600000 ms)
- `YUKKI_BROKER_REQUEST_TIMEOUT_MS` (1..=600000 ms)
- `YUKKI_BROKER_MAX_FRAME_BYTES`
- `YUKKI_BROKER_TRANSPORT_SECURITY` (`plaintext-boundary` or `authenticated-proxy`)

`authenticated-proxy` is documentary metadata; it does not enable TLS by itself. Per-task `timeout_ms` on broker task requests must be `1..=300000` ms; zero and oversized values are rejected.

## Geospatial and chunked media codecs

The Rust library provides an interoperable GeoJSON avenue model (`ArcGisAvenue`) using validated WGS84 longitude/latitude coordinates and optional route/avenue properties. The legacy NXR1 codec remains available, but its numeric fields are not geographic coordinates.

Audio/video data is supported as codec-agnostic pass-through `MediaChunk`s. `LiveMediaStreams` provides bounded in-memory stream opening, ordered ingestion, sequence/range reads, acknowledgement, and finish/removal APIs. `StreamRegistry` exposes local and discovered descriptors and bounded per-subscriber cursors. The authenticated gateway provides stream listing, description, HTTP range reads, and WebSocket tune-in with sequence-prefixed binary frames and explicit acknowledgements. The default store retains at most 256 chunks (256 KiB maximum each); it does not transcode media. Nodes exchange bounded stream announcements and low-frequency digest summaries over the authenticated mesh. `StreamRelay` and `OriginChunkClient` are library APIs that applications must wire into `serve_with_relay`; the CLI does not configure a relay automatically. Origin reads use plain HTTP, so use a trusted network or TLS-terminating proxy. WASM guests select bounded binary chunks through a checked host import and never receive raw store pointers.

See [docs/API.md](docs/API.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for API, wire layouts, trust boundaries, and resource limits. [docs/USER_HOWTO_STREAMING.md](docs/USER_HOWTO_STREAMING.md) covers streaming and media deployment.

## GPU-backed WASM sandbox adapter

The optional `src/gpu_adapter.rs` boundary supports Overhauled via BRK1/BRK2 plus WSM1 task and lifecycle payloads. The adapter is disabled by default (`YUKKI_GPU_ADAPTER_ENABLED=false`); ordinary deployments do not require a broker or accelerator. Use `LifecycleClient` with the selected BRK wire mode and `submit_wsm1_task` for this binary endpoint. `GpuBrokerClient::submit_task` and `BrokerClient` are separate legacy JSON routes and are not compatible with the Overhauled C++ listener.

Adapter variables:

- `YUKKI_GPU_ADAPTER_ENABLED` (`true` / `false`, default `false`)
- `YUKKI_GPU_BROKER_ENDPOINT` (default `127.0.0.1:9090`)
- `YUKKI_GPU_CONNECT_TIMEOUT_MS`, `YUKKI_GPU_REQUEST_TIMEOUT_MS`, `YUKKI_GPU_QUIESCE_TIMEOUT_MS` (each 1..=600000 ms)
- `YUKKI_GPU_MAX_FRAME_BYTES` (default 1048576 / 1 MiB)
- `YUKKI_GPU_MAX_RETRIES` (default `3`)

CPU is the always-available correctness baseline. GPU and NPU are optional, best-effort broker tiers. `device_preference=npu` requests NPU dispatch; it does not guarantee hardware use. Exact-precision/verification-sensitive tasks (including PQC) do not offload. CPU retry is governed by task fallback safety. Physical U85 inference requires the Overhauled DRM backend, a compatible kernel UAPI, and a Vela-generated bundle; simulator tests and successful compilation are not board validation.

## Platform deployment

See [docs/PLATFORM_SUPPORT.md](docs/PLATFORM_SUPPORT.md) for native Windows MSVC, WASI Preview 1 guest, and browser-WASM deployment profiles. The browser client targets `wasm32-unknown-unknown`, uses bounded authenticated HTTP reads, and verifies YKMC v1 frames. For separately hosted browser sites, configure the gateway's exact-origin `YUKKI_GATEWAY_CORS_ORIGINS` allow-list or use a same-origin reverse proxy; use HTTPS remotely. Browser WebSockets cannot set the Authorization header required by the gateway route.

## Documentation

- [Release notes v6.9.9](docs/RELEASE_v6.9.9.md)
- [Architecture](docs/ARCHITECTURE.md) · [API](docs/API.md) · [Security](docs/SECURITY.md)
- [Overhauled broker interoperability](docs/OVERHAULED_INTEROP.md) · [Ethos-U85 deployment](docs/ETHOSU_U85_DEPLOYMENT.md)
- [BRK2 conformance](docs/BRK2_CONFORMANCE_V1.md) · [BRK1/BRK2 executable corpus](docs/BRK_CONFORMANCE_V1.md)
- [Deployment](docs/DEPLOYMENT.md) · [System administration](docs/SYSADMIN_HOWTO.md) · [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Browser WASM](docs/BROWSER_WASM.md) · [Streaming how-to](docs/USER_HOWTO_STREAMING.md)
- [Changelog](docs/CHANGELOG.md) · [Versioning](docs/VERSIONING.md)

## Docker

The repository ships a Dockerfile that builds and embeds `yukki_core_node`.

```bash
docker build -t yukkios:6.9.9 .
```

Current limitation: no built-in TLS termination for peer or broker links.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
