# YuKKi OS v6.7.0

YuKKi-OS is a Rust-based authenticated control-plane mesh with a C FFI frame engine and an optional broker client boundary.

> Research/demo software: not production-ready without additional hardening and independent security review.

## Current baseline

- Release line: **v6.7.0**
- Rust toolchain: **1.98.1** (`rust-toolchain.toml`)
- Binary: **`yukki_core_node`**
- Library crate: **`yukkios_6_7_0_inet3`**

## What the current CLI supports

`src/main.rs` implements only two commands:

```text
yukki_core_node bootstrap <bind-address>
yukki_core_node node <bootstrap-address> <advertised-address>
```

Required environment variable:

- `YUKKI_PSK_HEX` (64 hex chars / 32 bytes)

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
- `YUKKI_BROKER_CONNECT_TIMEOUT_MS`
- `YUKKI_BROKER_REQUEST_TIMEOUT_MS`
- `YUKKI_BROKER_MAX_FRAME_BYTES`
- `YUKKI_BROKER_TRANSPORT_SECURITY` (`plaintext-boundary` or `authenticated-proxy`)

`authenticated-proxy` is documentary metadata for operations; it does not enable TLS by itself.

## Documentation

- [docs/RELEASE_v6.7.0.md](docs/RELEASE_v6.7.0.md)
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
docker build -t yukkios:6.7.0 .
docker run --rm -e YUKKI_PSK_HEX=<64-hex> yukkios:6.7.0 bootstrap 0.0.0.0:7660
```

Current limitation: no built-in TLS termination for peer or broker links.

## License

GPL-3.0. See [LICENSE](LICENSE).
