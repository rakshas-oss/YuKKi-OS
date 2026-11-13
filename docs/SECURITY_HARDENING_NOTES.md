# Security hardening notes

This note records the defensive checks currently applied to the native mesh helpers and the shared-memory guest worker boundary.

## Native helpers

- `yukki_float_to_q16` maps non-finite inputs to zero and clamps finite values to the representable Q16.16 range before conversion. Callers should still validate application-level coordinate ranges.
- `yukki_fhss_sync` ignores contexts with no configured channels, avoiding modulo-by-zero when synchronizing uninitialized/empty channel plans. FHSS synchronization data remains trust-sensitive; authenticate it at the transport boundary.
- HMAC scratch buffers are cleared through volatile writes, including the error path, to reduce the chance that optimization removes the cleanup. This is best-effort memory hygiene, not a substitute for a reviewed crypto backend.

## Shared-memory WASM channel

The worker's shared channel layout and lock ownership are security-sensitive ABI details. Any change to its interior mutability, memory ordering, or host-side interpretation must be reviewed and tested together on native and `wasm32-wasip1` targets. The existing channel hash is for integrity/telemetry and is not cryptographic authentication.
