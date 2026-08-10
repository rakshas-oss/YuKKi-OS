# YuKKi OS v6.6.4 — Security Documentation

> **This is research/demo software. Do not deploy on untrusted networks without further hardening.**

---

## Cryptographic Primitives

| Component | Primitive | Notes |
|-----------|-----------|-------|
| Key exchange | X25519 ECDH (x25519-dalek v2) | One ephemeral key-pair per session, never persisted |
| Authenticated encryption | ChaCha20-Poly1305 AEAD | 12-byte nonce, 16-byte tag |
| Payload weave | ChaCha20 keystream (Lorenz-keyed) | **Not authenticated** — illustrative only |
| Memory wiping | zeroize v1.6 | `ZeroizeOnDrop` on all key material |
| Entropy seeding | Virtual PUF micro-timing | Device-unique jitter at boot |

---

## Known Limitations

1. **KDF is minimal** — the session key derivation (`shared_secret XOR domain_separator + rotate`) is intentionally simple. Replace with **HKDF-SHA256** before production use.
2. **Polymorphic weave is not authenticated** — `chacha_weave_payload` is illustrative. Replay and mutation attacks are possible.
3. **No mutual authentication** — nodes do not verify peer identity beyond the ephemeral ECDH handshake.
4. **No formal audit** — cryptographic mechanisms have not undergone third-party security review.
5. **Lorenz attractor is not cryptographically secure** — it provides structural variety in the data plane, not cryptographic randomness.

---

## Memory Safety

- All ephemeral key material uses `ZeroizeOnDrop` from the `zeroize` crate.
- The `secure_wipe` helper explicitly overwrites sensitive byte arrays before deallocation.
- Unsafe FFI calls are limited to explicit `unsafe` blocks with documented null-pointer guards.
- The C layer (`chaos_weave.c`) uses stack-allocated buffers; no dynamic allocation in hot paths.

---

## WebAssembly Sandbox

- The Rustasm sandbox (`src/wasm_sandbox.rs`) uses Wasmtime's isolation guarantees.
- Sandbox modules cannot access host memory outside their linear memory.
- Execution is time-bounded via Wasmtime fuel limits (configurable).

---

## Threat Model

| Threat | Mitigation | Status |
|--------|-----------|--------|
| Passive eavesdropping | ChaCha20-Poly1305 AEAD | ✅ Mitigated |
| Key reuse | Ephemeral X25519 per session | ✅ Mitigated |
| Memory disclosure | zeroize on key material | ✅ Mitigated |
| Replay attack | Sequence counter in frames | ⚠️ Partial |
| Man-in-the-middle | No cert pinning / PKI | ❌ Not mitigated |
| Denial of service | No rate limiting | ❌ Not mitigated |
| Malicious WASM module | Wasmtime sandbox | ✅ Mitigated |

---

## Reporting Security Issues

Report security vulnerabilities via the GitHub issue tracker with the `security` label, or contact the maintainer directly. Do not disclose vulnerabilities publicly before a fix is available.
