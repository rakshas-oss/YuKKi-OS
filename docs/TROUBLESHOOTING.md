# YuKKi OS v6.8.0 — Troubleshooting

## Build failures

### C compiler missing

Symptom: build fails in `cc` build script for `src/ffi/chaos_weave.c`.

Fix: install `gcc` or `clang`, then rebuild.

### Lockfile mismatch

Symptom: `cargo ... --locked` fails after metadata edits.

Fix: regenerate lockfile with plain `cargo check` once, commit `Cargo.lock`, then rerun locked commands.

## Runtime failures

### `YUKKI_PSK_HEX` missing or invalid

The binary requires a 64-character hex PSK.

```bash
export YUKKI_PSK_HEX="$(openssl rand -hex 32)"
```

### Peer cannot connect (`connection refused`)

- verify bootstrap started first
- verify bootstrap bind/listen address and firewall policy
- check with `ss -tlnp | grep <port>`

### Authentication failure at startup

- ensure all peers share exactly the same PSK value
- verify no extra whitespace/newline in env files

### Broker request timeouts

- verify broker endpoint reachability
- tune `YUKKI_BROKER_CONNECT_TIMEOUT_MS` and `YUKKI_BROKER_REQUEST_TIMEOUT_MS`
  (each must be in `1..=600000` ms; out-of-range values are rejected at
  startup instead of silently clamped)
- ensure `YUKKI_BROKER_MAX_FRAME_BYTES` matches both sides
- a `GpuTaskRequest`/`BrokerTask` `timeout_ms` of `0` or greater than
  `300000` (5 minutes) is rejected by request validation; supply an explicit
  timeout within that range

### Wasm fuel exhaustion

If sandbox execution returns fuel exhaustion, raise fuel budget:

```bash
export YUKKI_WASM_MAX_FUEL=20000000
```

## Logging and diagnostics

Use structured debug logs:

```bash
RUST_LOG=debug ./target/release/yukki_core_node bootstrap 0.0.0.0:7660
```
