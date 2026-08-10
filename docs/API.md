# YuKKi OS — FFI & API Reference

This document describes the C ABI exported by `chaos_weave.c` and consumed by the Rust runtime via FFI.

Header: `src/ffi/laminar_api.h` (shared across versions)

---

## SpatiotemporalFrame (ABI-stable, 88 bytes)

```c
#pragma pack(push, 1)
typedef struct {
    uint64_t seq_id;       // Monotonic frame sequence number
    double   x;            // Lorenz state x
    double   y;            // Lorenz state y
    double   z;            // Lorenz state z
    double   u;            // Lorenz velocity u
    double   v;            // Lorenz velocity v
    double   w;            // Lorenz velocity w
    float    fluidity;     // Fluidity coefficient (derived from state)
    float    drag;         // Drag coefficient
    double   divergence;   // Divergence scalar
    uint8_t  payload[16];  // Application payload slot
} SpatiotemporalFrame;
#pragma pack(pop)
```

The Rust counterpart is `#[repr(C, packed)]` and must remain byte-identical to the C struct.

---

## Lorenz Engine

### `chaos_engine_reseed`

```c
void chaos_engine_reseed(double sigma, double rho, double beta,
                         double x0, double y0, double z0);
```

Initialise or re-seed the Lorenz attractor. Standard parameters: σ=10, ρ=28, β=8/3.

### `weave_spatiotemporal_frame`

```c
void weave_spatiotemporal_frame(uint64_t seq,
                                const uint8_t *payload_src,
                                SpatiotemporalFrame *out_frame);
```

Step the Lorenz integrator and fill `out_frame` with the current state. Copies up to 16 bytes from `payload_src` into `out_frame->payload`. `out_frame` must not be NULL.

---

## ChaCha20 Polymorphic Weave

### `chacha_weave_payload`

```c
int chacha_weave_payload(const uint8_t *nonce12,
                         const uint8_t *shared_key32,
                         const uint8_t *plaintext,
                         size_t len,
                         uint8_t *out);
```

XORs `plaintext` of `len` bytes against a ChaCha20 keystream whose 256-bit key is formed by mixing `shared_key32` with the current Lorenz state. The 12-byte `nonce12` is used directly as the ChaCha20 nonce.

Returns `0` on success, `-1` on invalid arguments (NULL pointers or `len == 0`).

> **⚠ Warning:** This function does not produce an authenticated ciphertext. Use `chacha20poly1305` for authenticated encryption.

**Rust FFI binding:**
```rust
extern "C" {
    fn chacha_weave_payload(
        nonce12: *const u8,
        shared_key32: *const u8,
        plaintext: *const u8,
        len: usize,
        out: *mut u8,
    ) -> std::os::raw::c_int;
}
```

---

## Sentinel Quarantine

### `sentinel_quarantine_node`

```c
void sentinel_quarantine_node(const char *node_uuid);
```

Registers `node_uuid` in the quarantine registry. If already soft-quarantined, escalates to hard quarantine. Registry capacity: 256 entries.

### `sentinel_release_node`

```c
void sentinel_release_node(const char *node_uuid);
```

Removes `node_uuid` from the quarantine registry at all levels.

### `sentinel_is_quarantined`

```c
int sentinel_is_quarantined(const char *node_uuid);
```

Returns `1` if the node is quarantined at any level, `0` otherwise.

### `sentinel_quarantine_level`

```c
int sentinel_quarantine_level(const char *node_uuid);
```

Returns `2` (hard), `1` (soft), or `0` (clear).

---

## Usage Example (Rust)

```rust
use std::ffi::CString;

unsafe {
    let node = CString::new("node-3f7a2abc").unwrap();
    sentinel_quarantine_node(node.as_ptr());
    assert_eq!(sentinel_quarantine_level(node.as_ptr()), 1);
    sentinel_quarantine_node(node.as_ptr()); // escalate
    assert_eq!(sentinel_quarantine_level(node.as_ptr()), 2);
    sentinel_release_node(node.as_ptr());
    assert_eq!(sentinel_is_quarantined(node.as_ptr()), 0);
}
```

---

## Build Integration

The C source is compiled by `build.rs` using the `cc` crate:

```rust
// build.rs
fn main() {
    cc::Build::new()
        .file("src/ffi/chaos_weave.c")
        .flag("-std=c99")
        .compile("chaos_weave");
}
```

No separate `make` step is required — `cargo build` handles everything.
