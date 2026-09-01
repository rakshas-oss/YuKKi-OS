# YuKKi OS v6.6.6 — Security Documentation

> **This is research/demo software. Do not deploy on untrusted networks without further hardening.**

---

## Cryptographic Primitives

| Component | Primitive | Notes |
|-----------|-----------|-------|
| Key exchange | X25519 ECDH (x25519-dalek v2) | One ephemeral key-pair per connection |
| Key derivation | HKDF-SHA256 | Distinct client→server and server→client keys |
| Peer authentication | 32-byte pre-shared key | Required through `YUKKI_PSK_HEX` |
| Authenticated encryption | ChaCha20-Poly1305 AEAD | Direction-marked nonces, protocol context as AAD |
| Payload weave | Lorenz frame generator | **Not a network encryption mechanism** |

---

## Known Limitations

1. **Shared PSK identity** — all peers with the same PSK have equal authority; production requires per-peer identities, rotation, and revocation.
2. **No transport encryption beyond the application protocol** — deploy only behind an appropriate network policy until TLS or a formally reviewed Noise protocol is added.
3. **Frame generation is not authenticated** — it is not exposed as a network transport.
4. **No formal audit** — cryptographic mechanisms have not undergone third-party security review.
5. **Lorenz attractor is not cryptographically secure** — it provides structural variety in the data plane, not cryptographic randomness.

---

## Memory Safety

- Derived key buffers and decrypted ciphertext buffers are explicitly overwritten with `zeroize`.
- C FFI functions reject null output pointers and non-finite state parameters.
- The C layer (`chaos_weave.c`) uses stack-allocated buffers; no dynamic allocation in hot paths.

---

## WebAssembly Sandbox

- The Rustasm sandbox (`src/wasm_sandbox.rs`) uses Wasmtime isolation with a 16 MiB memory limit and a 10 million fuel budget.
- No host functions are exposed to sandboxed modules.

---

## Threat Model

| Threat | Mitigation | Status |
|--------|-----------|--------|
| Passive eavesdropping | ChaCha20-Poly1305 AEAD | ✅ Mitigated |
| Key reuse | Ephemeral X25519 per session | ✅ Mitigated |
| Memory disclosure | zeroize on key material | ✅ Mitigated |
| Replay attack | Sequence counter in frames | ⚠️ Partial |
| Man-in-the-middle | PSK-authenticated HKDF-derived AEAD keys | ⚠️ Shared-key trust model |
| Oversized/control-plane flooding | 64 KiB frame cap, handshake/idle timeouts, 128 connection cap | ⚠️ Tune and test under load |
| Malicious WASM module | Wasmtime memory and fuel limits; no host functions | ⚠️ Requires independent review |

---

## Reporting Security Issues

Report security vulnerabilities via the GitHub issue tracker with the `security` label, or contact the maintainer directly. Do not disclose vulnerabilities publicly before a fix is available.
