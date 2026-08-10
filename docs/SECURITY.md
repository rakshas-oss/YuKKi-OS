# YuKKi OS — Security Documentation

> **This is research/demo software. Do not deploy on untrusted networks without further hardening.**

---

## Audit Status

| Component | Status |
|-----------|--------|
| Cryptographic primitives | ⚠ Proof-of-concept — **not audited** |
| FFI boundary | ⚠ Reviewed internally; no formal audit |
| Network framing | ⚠ No mutual authentication |
| Sentinel quarantine | ⚠ Illustrative only |

---

## Threat Model

### In Scope
- Passive eavesdropping on encrypted sessions (mitigated by ChaCha20-Poly1305 AEAD)
- Replay attacks within a session (mitigated by incrementing nonce)
- Node impersonation (partially mitigated by X25519 ephemeral handshake)

### Out of Scope / Known Gaps
- **Long-term identity authentication** — no persistent key infrastructure; a MITM can impersonate any node on first connect.
- **Forward secrecy beyond session lifetime** — keys are ephemeral per session but no post-quantum hardening.
- **Polymorphic weave authentication** — `chacha_weave_payload` produces a cipherstream without a MAC; replay and mutation attacks on woven payloads are possible.
- **KDF strength** — the current `shared_secret XOR domain_separator + rotate` KDF is intentionally minimal; replace with **HKDF-SHA256** (RFC 5869) before any production use.

---

## Known Limitations

1. **No HKDF**: The KDF is a XOR/rotate construction. It must be replaced with HKDF-SHA256 for any production deployment.
2. **No mutual TLS / PKI**: Nodes are not authenticated beyond the ephemeral session handshake.
3. **Sentinel bypass**: The quarantine registry (max 256 entries) can be exhausted, causing it to silently stop quarantining new offenders.
4. **Unsafe FFI**: All Rust ↔ C calls use `unsafe` blocks. Null pointer guards exist in C, but memory safety relies on caller discipline.
5. **Lorenz state leakage**: The Lorenz attractor state is embedded in every `SpatiotemporalFrame`; a sufficiently long trace may allow state reconstruction.

---

## Responsible Disclosure

Please **do not** open a public GitHub issue for security vulnerabilities.

1. Email the maintainer directly (see repository metadata) with subject `[SECURITY] YuKKi OS — <brief description>`.
2. Include a description of the vulnerability, steps to reproduce, and potential impact.
3. Allow 90 days for a patch before public disclosure.

---

## Hardening Checklist (Before Any Deployment)

- [ ] Replace XOR/rotate KDF with HKDF-SHA256
- [ ] Add mutual authentication (certificate pinning or WireGuard-style static keys)
- [ ] Add MAC to `chacha_weave_payload` output
- [ ] Increase sentinel registry beyond 256 entries or use a hash map
- [ ] Enable address-space layout randomisation (ASLR) and stack canaries in C build
- [ ] Audit all `unsafe` blocks with MIRI
- [ ] Add fuzzing targets for the framing parser and FFI boundary
- [ ] Enable `cargo audit` in CI for dependency vulnerability scanning
