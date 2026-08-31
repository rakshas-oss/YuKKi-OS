# Version History (Archived)

> **v6.6.4 is the current production version.** Previous versions are available in git history only.

---

## Current Version

### v6.6.4 — Inet3 Edition (Current)

The canonical production release. Fuses the highest-performing elements from the v6.6.x architecture line into a single unified deployment.

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

The following versions have been superseded by v6.6.4. Their source code exists in git history.

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

Previous version directories (`yukkios_6_5_ephemeral/`, `yukkios_6_6_sentinel/`) were removed in the v6.6.4 canonical restructure. Their full contents remain accessible via git history.
