# Version History

> **v6.7.0 is the current production baseline.** Previous release branches remain available in git history.

---

## Current Version

### v6.7.0 — Inet3 Production Refresh (Current)

The current release baseline for YuKKi OS. It aligns the package metadata, project documentation, and release references under a single v6.7.0 version line while preserving the established Inet3 architecture stack.

**Key features:**
- ADI Dynamic Integration auto-tuning suite
- Virtual PUF micro-timing anchor for entropy
- Rustasm WebAssembly sandbox (Wasmtime)
- Explicit volatile memory wiping (zeroize)
- Epsilon-Threshold Failsafe for Lorenz recovery
- X25519 ECDH + ChaCha20-Poly1305 AEAD control plane
- Polymorphic attractor-bound payload weave

---

## Archived Versions

### v6.6.6 — Inet3 Edition

Documentation refresh for the v6.6.x stream and branch alignment update to the Inet3 naming scheme.

### v6.6.0 — Sentinel Mesh Edition

Introduced dual-layer sentinel quarantine registry, X25519 ECDH ephemeral session security, and polymorphic ChaCha20 payload weave.

### v6.5.0 — Ephemeral Mesh Edition

Introduced X25519 ECDH key exchange and ChaCha20-Poly1305 AEAD for the control plane. Ephemeral session keys, no persistence.

### v6.4.3 — OOB Integrity Edition

FNV-1a rolling hash, 60-frame out-of-band sync, node quarantine, ChaCha20 payload binding.

---

## Accessing Legacy Versions

To access archived version code:

```bash
# View git log to find the commit for a legacy version
git log --oneline

# Checkout a specific legacy commit
git checkout <commit-hash>
```

Previous version directories and older release notes remain accessible via git history.
