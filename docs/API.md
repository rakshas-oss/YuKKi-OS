# YuKKi OS v6.6.4 — FFI & API Reference

This document describes the C ABI exported by `src/ffi/chaos_weave.c` and consumed by the Rust runtime via FFI, plus the Rust-level public API for v6.6.4 modules.

---

## C FFI Layer — `src/ffi/laminar_api.h`

### SpatiotemporalFrame

```c
#pragma pack(push, 1)
typedef struct {
    uint64_t seq_id;
    double   x, y, z;
    double   u, v, w;
    float    fluidity;
    float    drag;
    double   divergence;
    uint8_t  payload[16];
} SpatiotemporalFrame;
#pragma pack(pop)
```

Total size: 88 bytes. Layout is ABI-stable and byte-identical to the Rust `#[repr(C, packed)]` struct.

---

### Frame Functions

#### `lorenz_step`

```c
void lorenz_step(SpatiotemporalFrame *frame, double dt);
```

Advances the Lorenz attractor by one time step `dt`. Updates `x`, `y`, `z` (attractor state), `u`, `v`, `w` (velocity), and `divergence`.

#### `chacha_weave_payload`

```c
void chacha_weave_payload(
    SpatiotemporalFrame *frame,
    const uint8_t *key,      // 32 bytes
    const uint8_t *nonce,    // 12 bytes
    const uint8_t *input,    // up to 16 bytes
    uint8_t *output          // 16 bytes
);
```

XORs `input` against a ChaCha20 keystream whose 32-byte key is mixed with the current Lorenz attractor state. **Not authenticated** — illustrative only.

---

### Quarantine Functions

#### `sentinel_quarantine_node`

```c
void sentinel_quarantine_node(uint64_t node_id, int hard);
```

Adds `node_id` to the quarantine registry. `hard = 0` is soft quarantine (messages logged and dropped); `hard = 1` is hard quarantine (connection rejected at handshake).

#### `sentinel_release_node`

```c
void sentinel_release_node(uint64_t node_id);
```

Removes `node_id` from all quarantine levels.

#### `is_quarantined`

```c
int is_quarantined(uint64_t node_id);
```

Returns `1` if the node is quarantined (either level), `0` otherwise.

---

## Rust Public API

### `ADIAutoTuner` — `src/adi_auto_tune.rs`

```rust
pub struct ADIAutoTuner {
    pub optimal_queue_depth: usize,
    pub active_hardware_profile: String,
}

impl ADIAutoTuner {
    pub fn new() -> Self;
    pub fn test_encoding_throughput(&self) -> bool;
    pub fn test_enquing_efficiency(&mut self) -> bool;
}
```

Instantiate with `ADIAutoTuner::new()`, then call both test methods. Results are printed to stdout; return value indicates pass (`true`) or fail (`false`).

---

### `WasmSandbox` — `src/wasm_sandbox.rs`

```rust
pub struct WasmSandbox {
    engine: wasmtime::Engine,
}

impl WasmSandbox {
    pub fn new() -> Self;
    pub fn execute(&self, wasm_bytes: &[u8]) -> Result<i32, String>;
}
```

Provide raw WASM bytes to `execute`. Returns the integer result of the module's `main` export, or an error string.

---

### `SpatiotemporalFrame` — `src/main.rs`

```rust
#[repr(C, packed)]
pub struct SpatiotemporalFrame {
    pub seq_id:     u64,
    pub x: f64, pub y: f64, pub z: f64,
    pub u: f64, pub v: f64, pub w: f64,
    pub fluidity:   f32,
    pub drag:       f32,
    pub divergence: f64,
    pub payload:    [u8; 16],
}
```

Byte-identical to the C struct above.

---

## Build Dependencies

The FFI layer is compiled by `build.rs`:

```rust
fn main() {
    println!("cargo:rerun-if-changed=src/ffi/chaos_weave.c");
    cc::Build::new()
        .file("src/ffi/chaos_weave.c")
        .include("src/ffi")
        .flag("-std=c99")
        .compile("chaos_weave");
}
```
