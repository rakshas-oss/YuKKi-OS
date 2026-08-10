# YuKKi OS — Troubleshooting

---

## Build Errors

### `cc` crate can't find C compiler

**Error:**
```
error: failed to run custom build command for `yukkios_6_6_sentinel`
  failed to find tool. Is `cc` installed?
```

**Fix:** Install a C99 compiler.
```bash
# Debian/Ubuntu
sudo apt-get install gcc

# macOS
xcode-select --install

# Arch
sudo pacman -S gcc
```

---

### Linker error: undefined symbol `chaos_engine_reseed`

**Cause:** The `build.rs` did not compile `chaos_weave.c`, or the C file path is wrong.

**Fix:**
1. Confirm `src/ffi/chaos_weave.c` exists in the versioned directory.
2. Run `cargo clean && cargo build --release` to force a full rebuild.

---

### `#[repr(C, packed)] struct` size mismatch at runtime

**Cause:** The Rust and C structs for `SpatiotemporalFrame` have diverged.

**Fix:** Check that both the Rust `#[repr(C, packed)]` definition and the C `#pragma pack(push, 1)` struct have identical field order and types. The expected total size is **88 bytes**.

```bash
# Quick check (C side):
printf '#include "src/ffi/laminar_api.h"\n#include <stdio.h>\nint main(){printf("%zu\\n",sizeof(SpatiotemporalFrame));}' | gcc -x c - -o /tmp/sz && /tmp/sz
# Expected: 88
```

---

## Runtime Errors

### `Connection refused` when starting a peer node

**Cause:** The bootstrap node is not yet running, or is listening on a different address/port.

**Fix:**
1. Start the bootstrap node first: `./yukki_sentinel bootstrap 0.0.0.0:7660`
2. Confirm port 7660 is open: `ss -tlnp | grep 7660`
3. Ensure no firewall is blocking the port.

---

### `hard quarantine` — peer immediately rejected

**Cause:** A node UUID was escalated to hard quarantine (level 2) in a previous session. The registry is not persisted across restarts.

**Fix:** Restart both nodes. Quarantine state is in-memory only and resets on process exit.

---

### Garbled or zero frames from `weave_spatiotemporal_frame`

**Cause:** `chaos_engine_reseed` was never called, so the Lorenz state is uninitialised (all zeros, which is an attractor fixed point).

**Fix:** Always call `chaos_engine_reseed` with non-zero initial conditions before generating frames. Recommended defaults: σ=10, ρ=28, β=2.667, x0=0.1, y0=0.1, z0=0.1.

---

## Performance Tuning

### Enable link-time optimisation (LTO)

Add to `Cargo.toml` under the appropriate versioned profile:

```toml
[profile.release]
lto = "thin"
codegen-units = 1
```

### MUSL static build for minimal overhead

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

### Increase Lorenz step resolution

Lower the RK4 step size in `chaos_weave.c` (`DT` constant) for higher-fidelity attractor trajectories at the cost of CPU cycles.

---

## Debug Logging

Set the `RUST_LOG` environment variable for verbose Tokio runtime output:

```bash
RUST_LOG=debug ./yukki_sentinel bootstrap 0.0.0.0:7660
```

For FFI-level tracing, add `printf` statements to `chaos_weave.c` and rebuild.
