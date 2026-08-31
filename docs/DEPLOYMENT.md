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

## Automated Deployment Script

An automated deployment script is provided at `scripts/deploy/deploy_yukki_6_6_4_apex.zsh` (legacy filename retained).

```bash
chmod +x scripts/deploy/deploy_yukki_6_6_4_apex.zsh
./scripts/deploy/deploy_yukki_6_6_4_apex.zsh
```

This script generates the full source tree, builds the binary, and confirms the deployment.

---

## Running

### Bootstrap Node

Start the first node (bootstrap server) that peers will connect to:

```bash
./target/release/yukki_core_node bootstrap 0.0.0.0:7660
```

### Peer Node

Connect a peer node to an existing bootstrap:

```bash
./target/release/yukki_core_node node 127.0.0.1:7660 9999
```

`9999` is the local peer identifier (arbitrary u64).

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

Currently all configuration is via command-line arguments. Environment variables and config files are not yet supported.

---

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common errors and debug logging.
