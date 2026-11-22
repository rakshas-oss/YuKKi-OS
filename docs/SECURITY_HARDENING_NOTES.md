# Security hardening notes

This note records the defensive checks currently applied to the native mesh helpers and the shared-memory guest worker boundary.

## Native helpers

- `yukki_float_to_q16` maps non-finite inputs to zero and clamps finite values to the representable Q16.16 range before conversion. Callers should still validate application-level coordinate ranges.
- `yukki_fhss_sync` ignores contexts with no configured channels, avoiding modulo-by-zero when synchronizing uninitialized/empty channel plans. FHSS synchronization data remains trust-sensitive; authenticate it at the transport boundary.
- HMAC scratch buffers are cleared through volatile writes, including the error path, to reduce the chance that optimization removes the cleanup. This is best-effort memory hygiene, not a substitute for a reviewed crypto backend.

## Shared-memory WASM channel

The worker's shared channel layout and lock ownership are security-sensitive ABI details. Any change to its interior mutability, memory ordering, or host-side interpretation must be reviewed and tested together on native and `wasm32-wasip1` targets. The existing channel hash is for integrity/telemetry and is not cryptographic authentication.

## Authenticated WASM artifact handoff

- `HandoffSender` uses separate deployment and publisher signer interfaces. A deployment signer does not implicitly authorize artifact provenance; the receiver checks publisher attestations against a separate trust store.
- Signed messages bind issuer, subject, key ID and audience and carry bounded expiry, UUID message IDs/nonces and SHA-256 digests. The receiver applies replay checks and strictly sequential chunk offsets.
- Sender limits are 1–256 modules, 64 MiB per module, 256 MiB aggregate bytes and 4 MiB maximum chunks (1 MiB default). Receiver policy is authoritative and may be stricter.
- The caller-supplied `HandoffTransport` must provide authenticated protected transport, bind peer identity to the signed sender and reject plaintext downgrade. YuKKi-OS does not include a concrete mTLS adapter.
- The Overhauled receiver remains a library API rather than a handler on the normal broker listener. Replay and staging state are process-local unless a deployment supplies durable shared services.
- The current shared-Store Wasmtime runtime is not a multi-tenant isolation boundary.

## Untrusted stream flood controls

- Stream ingestion does not require a WASM publisher key. Defaults enforce global and per-stream chunk/byte token buckets plus an independent stream-open bucket.
- Hard media-store ceilings are 64 MiB retained payload, 256 streams, 4,096 chunks per stream, 16,384 total chunks and 256 KiB per chunk.
- Gateway/WebSocket controls bound connections, requests, control messages, egress bytes, outstanding acknowledgements and origin pulls. These reduce in-process resource exhaustion but do not prevent volumetric DDoS before traffic reaches the host.