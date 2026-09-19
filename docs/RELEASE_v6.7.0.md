# v6.7.0 — Baseline Coherence Refresh

- Tag: `v6.7.0`
- Date: 2026-09-19

## Summary

This release line establishes a coherent v6.7.0 baseline across code, metadata, deployment scripts, and operator documentation while preserving runtime compatibility for `yukki_core_node`.

## Included in this refresh

- unified active-version references to v6.7.0
- corrected Cargo metadata/lock alignment
- normalized tests and benchmark imports to `yukkios_6_7_0_inet3`
- replaced stale deploy script path with `scripts/deploy/deploy_yukki_6_7_0_inet3.zsh`
- refreshed README plus deployment/sysadmin/architecture/API/security docs to match implemented CLI and boundaries
- preserved legacy v6.6.x references as archival-only notes

## Known limitations (current implementation)

- shared PSK trust model, no per-peer identity lifecycle
- broker transport auth is external to YuKKi-OS
- no built-in TLS termination for peer/broker sockets
- no persisted runtime state or HTTP health endpoint

## Validation and benchmark context

Validation/benchmark command outcomes for this refresh are recorded with date/context in the task report and changelog entry for v6.7.0.
