# YuKKi OS v6.6.6 — Deployment Guide

---

## Prerequisites

- Rust stable toolchain: `rustup toolchain install stable`
- C99 compiler: `gcc` or `clang`
- `cargo` (included with Rust toolchain)
- Linux x86-64 recommended (64-bit flat topology)

---

## Build

From the repository root:

```bash
cargo build --release
```

Binary output: `target/release/yukki_core_node`

### MUSL Static Build (optional)

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

Output: `target/x86_64-unknown-linux-musl/release/yukki_core_node`

---

## Authentication configuration

Every bootstrap and node must receive the same 32-byte secret using the `YUKKI_PSK_HEX` environment variable. Generate and distribute it through a secret manager; never place it in source control, command history, or logs.

```bash
export YUKKI_PSK_HEX="$(openssl rand -hex 32)"
```

---

## Running

### Bootstrap Node

Start the first node (bootstrap server) that peers will connect to:

```bash
./target/release/yukki_core_node bootstrap 0.0.0.0:7660
```

### Peer Node

Connect a peer node to an existing bootstrap, supplying the address it advertises to the mesh:

```bash
./target/release/yukki_core_node node 127.0.0.1:7660 127.0.0.1:9999
```

Use a routable advertised address in a multi-host deployment.

---

## Interactive Commands

Once a node is running, the interactive prompt (`>`) accepts:

| Command | Description |
|---------|-------------|
| `fleet peers` | List all connected peer nodes |
| `msg <to> <text>` | Send encrypted `FluidMessage` to a peer or `all` |
| `weave <data>` | Announce a polymorphic-woven payload |
| `exit` / `quit` | Shut down the node |

---

## ADI Auto-Tuning

On startup, the ADI auto-tuner runs two benchmarks:

1. **Encoding throughput** — 10 000-frame evaluation; target < 15 ms
2. **Queuing efficiency** — 1 000-frame queue test; target < 2 000 µs

If queuing is sufficiently fast, `optimal_queue_depth` is raised to 120 (default: 60).  
Results are printed to stdout with `[AUTO-TUNE]` prefix.

---

## Configuration

The bootstrap bind address and node addresses are command-line arguments. `YUKKI_PSK_HEX` is required and must be exactly 64 hexadecimal characters. Logs are JSON and respect `RUST_LOG` (default: `info`).

---

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common errors and debug logging.
