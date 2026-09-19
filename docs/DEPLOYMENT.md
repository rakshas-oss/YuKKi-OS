# YuKKi OS v6.7.0 — Deployment Guide

## Supported runtime shape

Current CLI supports:

- `bootstrap <bind-address>`
- `node <bootstrap-address> <advertised-address>`

No interactive in-process command console is implemented.

## Platform requirements

- Linux x86_64 recommended
- Rust toolchain `1.98.1` (repo pin)
- C99 compiler (`gcc` or `clang`)
- `cargo`

## Build

```bash
cargo build --release --locked
```

Output:

- `target/release/yukki_core_node`

Optional static target:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl --locked
```

## Required environment

```bash
export YUKKI_PSK_HEX="<64-hex-characters>"
```

`YUKKI_PSK_HEX` must be exactly 64 hex characters.

## Optional environment

```bash
export RUST_LOG=info
export YUKKI_BROKER_ENDPOINT=127.0.0.1:9000
export YUKKI_BROKER_CONNECT_TIMEOUT_MS=3000
export YUKKI_BROKER_REQUEST_TIMEOUT_MS=5000
export YUKKI_BROKER_MAX_FRAME_BYTES=65536
export YUKKI_BROKER_TRANSPORT_SECURITY=authenticated-proxy
```

## Ports and network

- Bootstrap listen port: operator-defined (examples use `7660/tcp`)
- Node advertised address: operator-defined routable endpoint
- Broker endpoint: default `127.0.0.1:9000`

Restrict exposure with firewall/network policy. Broker links should stay loopback/private unless protected by authenticated infrastructure.

## Run

Bootstrap:

```bash
./target/release/yukki_core_node bootstrap 0.0.0.0:7660
```

Peer:

```bash
./target/release/yukki_core_node node 10.0.0.10:7660 10.0.0.21:9999
```

## Health and logging

- Logs are JSON via `tracing_subscriber`
- Use `RUST_LOG=debug` for troubleshooting
- Health checks are process/listener/log based (no HTTP probe endpoint)

## systemd guidance

See [SYSADMIN_HOWTO.md](SYSADMIN_HOWTO.md) for hardened service examples, env file permissions, upgrade, and rollback steps.

## Docker

Build image:

```bash
docker build -t yukkios:6.7.0 .
```

Run bootstrap:

```bash
docker run --rm -e YUKKI_PSK_HEX=<64-hex> -p 7660:7660 yukkios:6.7.0 bootstrap 0.0.0.0:7660
```

Current limitation: container image does not add TLS/mTLS termination; deploy with external network controls.

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
