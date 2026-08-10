# Changelog

All notable changes to YuKKi OS are documented here.

---

## [6.6.4] — Apex Synthesis Edition

**Generated via:** `scripts/deploy/deploy_yukki_6_6_4_apex.zsh`  
**Binary:** `yukki_core_node`

### Added
- **Epsilon-Threshold Failsafe** — deterministic trip condition for attractor divergence
- **Virtual PUF (Micro-Timing Anchor)** — device fingerprinting via micro-timing jitter
- **Explicit Zeroize (`secure_wipe`)** — guaranteed memory wiping before free, preventing secret leakage
- **Rustasm WebAssembly Sandbox** — untrusted payload execution in isolated WASM environment
- **ADI Auto-Tuning Suite** — adaptive integration for real-time Lorenz parameter adjustment
- Bilingual (French/English) labeling under the `oldies` brand (RIU — Rakshas International Unlimited)
- Strict 64-bit flat topology; all short opcodes bypassed for hardware alignment

---

## [6.6.0] — Sentinel Mesh Edition

**Directory:** `yukkios_6_6_sentinel/`  
**Binary:** `yukki_sentinel`

### Added
- Dual-layer sentinel quarantine registry (soft + hard, up to 256 entries)
- `chacha_weave_payload` — attractor-bound ChaCha20 polymorphic cipher stream
- `SpatiotemporalFrame` extended with `fluidity`, `drag`, and `divergence` fields (88 bytes total)
- `sentinel_quarantine_node`, `sentinel_release_node`, `sentinel_is_quarantined`, `sentinel_quarantine_level` FFI calls
- `WeaveAnnounce` message type for broadcast of woven payloads

### Changed
- ABI: `SpatiotemporalFrame` expanded from 72 → 88 bytes (breaking change from v6.5.0)

---

## [6.5.0] — Ephemeral Mesh Edition

**Directory:** `yukkios_6_5_ephemeral/`  
**Binary:** `yukki_ephemeral`

### Added
- X25519 ECDH ephemeral key exchange (one key-pair per session, never persisted)
- ChaCha20-Poly1305 AEAD session encryption: `[u32 len BE][12-byte nonce][ciphertext + 16-byte tag]`
- Lightweight KDF: `shared_secret XOR domain_separator + rotate` → 32-byte session key
- `FluidMessage` and `PeerList` message types

### Changed
- Replaced FNV-1a rolling-hash transport with AEAD-framed TCP sessions

---

## [6.4.3] — OOB Integrity Edition

**Directory:** `src/` (root package)  
**Binary:** `yukki_oob`

### Added
- FNV-1a rolling hash for frame integrity verification
- 60-frame out-of-band sync window
- Node quarantine (single-layer, Rust-side registry)
- Lorenz attractor C core (`chaos_weave.c`) via FFI
- Initial `SpatiotemporalFrame` ABI (72 bytes)
