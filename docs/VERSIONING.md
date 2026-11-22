# YuKKi-OS — Versioning

## Release state

- **Latest published release:** v6.17.0 (2026-11-22).
- **Next minor release candidate:** v6.18.0 (not tagged or published).
- **Native Cargo package candidate:** 6.18.0.
- **OCI image label candidate:** 6.18.0.
- **Rust toolchain pin:** 1.98.1 (unchanged).
- **Runtime binary:** yukki_core_node (unchanged).
- **Published v6.17.0 assets:** 10 GitHub Release assets, including native Linux/macOS binaries, browser-WASM, WASI and SHA256SUMS.
- **External package publication:** crates.io is not claimed; GitHub Release publication and registry publication are separate.

No 6.18.0 tag, GitHub Release or release archive is claimed by this candidate.

## Version assessment

The additive changes merged in YuKKi-OS PR #168 justify a minor increment from 6.17.0:

- Add the yukkios::wasm_handoff sender API with pluggable HandoffSigner and receiver-receipt verifier interfaces.
- Build canonical manifests and module digests, sign prepare/chunk/activation messages, preserve separate deployment-sender and artifact-publisher identities, and stream strictly sequential bounded chunks.
- Keep key management and transport protection outside the sender library. The caller supplies the authenticated transport adapter; the client does not claim to provide mTLS or to make the existing raw broker listener secure.
- Apply media retention hard ceilings: 64 MiB retained bytes, 256 streams, 16,384 chunks and 256 KiB maximum chunk size.
- Add process-wide and per-stream ingestion token buckets for chunk and byte rates, plus stream-open churn limiting. Gateway and WebSocket paths also enforce global/per-peer request rates, connection caps, control limits, timeouts, quotas and acknowledgement backpressure.
- Preserve untrusted stream ingestion and consumption without requiring executable-artifact publisher authorization.

The corresponding receiver-side state machine is in Overhauled PR #86, now merged separately. These two APIs do not by themselves create a ready-to-expose network deployment endpoint: deployment still requires a protected authenticated transport, durable replay/staging for restart-safe semantics, and integration with the broker/runtime lifecycle.

## Compatibility and security boundaries

- Existing YKMC, BRK1, BRK2, NXR1 and WSM1 wire identities are not intentionally changed by this version bump.
- The handoff sender uses a separate versioned application contract; signed executable artifacts and untrusted stream payloads have distinct trust policies.
- Streaming remains available from untrusted sources subject to bounded size, retained-memory, connection, rate and backpressure policies. Stream data does not need a WASM publisher key.
- In-process token buckets and memory ceilings constrain application resource consumption, but they cannot prevent volumetric DDoS saturating the network link. Use upstream network-edge protection.
- YuKKi-OS does not silently send handoff messages over plaintext TCP. Integrators must supply mTLS 1.3 or an equivalent authenticated channel and bind peer identity to the signed deployment sender.
- Discovery records are not execution authorization. Broker transport and the handoff transport must be authenticated independently.
- The browser-WASM crate (yukki-browser-core) and WASI guest worker (yukki_guest_worker) are separate unpublished workspaces at 0.1.0; they are not implicitly bumped with the native yukkios package.

## Release gate for 6.18.0

Before tagging or publishing:

1. Run cargo fmt --check, cargo test --locked, Clippy and the complete native Linux/macOS/Windows test matrix on the exact release candidate.
2. Run Linux, aarch64, macOS, browser-WASM and WASI build/test jobs, including the browser verifier and guest-worker contracts.
3. Run the stream ingestion/gateway/WebSocket rate-limit tests, including global cross-stream budgets, per-stream budgets and stream-open churn cases.
4. Run paired YuKKi-OS sender / Overhauled receiver conformance and negative tests for sender identity, publisher provenance, replay, expiry, digest, transfer bounds and failed activation.
5. Confirm untrusted stream access still works without an executable publisher key and that its independent resource limits reject floods.
6. Only after checks pass and the release commit is approved, create the 6.18.0 tag and GitHub Release. Verify external registry publication separately.

PR #168 (authenticated handoff sender and stream flood controls) is merged to main at 2869a8baf9f1dd878b492b9c78fd1ca2562d2a0d. The metadata candidate updates the native package, lockfile, OCI label, README, changelog and version assertion together. Its CI and release approval remain separate.

## Published release history

- v6.17.0 — published 2026-11-22; conventional WASM import binding and the authenticated WASM handoff contract/schema.
- v6.16.0 — published 2026-11-21; lease-based broker discovery and BRK2 locality intent/result codec support.
- v6.15.0 — published 2026-11-21; resolver and benchmark concurrency improvements.
- v6.14.0 — published 2026-11-20; YuKKi workload directives and BRK2 worker-class interoperability.
- v6.13.0 — published 2026-11-18; native Wasm program composition and time-weighted spatial replica pools.
- v6.12.0 — published 2026-11-18; browser spatial/motion, multivariate datasets and the bounded symmetric eigensolver.
