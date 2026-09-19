# v6.6.6 — Inet3 Edition (Legacy / Historical)

> Superseded by [v6.7.0](RELEASE_v6.7.0.md). This file is archival.

- Tag: `v6.6.6`
- Status: historical reference

## Historical summary

v6.6.6 represented the late Inet3 line before the v6.7.0 baseline cleanup.

Key themes in that line:

- X25519 + PSK + HKDF + ChaCha20-Poly1305 control-plane design
- C FFI Lorenz frame engine and associated ABI layout checks
- Wasmtime-backed sandbox module integration
- Broker boundary split from core peer-mesh transport

## Archival note

Use current deployment and operational guidance from:

- [docs/DEPLOYMENT.md](DEPLOYMENT.md)
- [docs/SYSADMIN_HOWTO.md](SYSADMIN_HOWTO.md)
- [scripts/deploy/README.md](../scripts/deploy/README.md)
