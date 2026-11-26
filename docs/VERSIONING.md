# YuKKi-OS — Versioning

## Release state

- **Latest published release:** v6.19.0 (2026-11-24).
- **Next minor release candidate:** v6.20.0 (not tagged or published).
- **Native Cargo package candidate:** 6.20.0.
- **OCI image label candidate:** 6.20.0.
- **Rust toolchain pin:** 1.98.1 (unchanged).
- **Runtime binary:** yukki_core_node (unchanged).
- **Published v6.19.0 assets:** GitHub Release assets include native/browser/WASI deliverables and SHA256SUMS.
- **External package publication:** crates.io is not claimed; GitHub Release publication and registry publication are separate.

No 6.20.0 tag, GitHub Release or release archive is claimed by this candidate.

## Version assessment

The published v6.19.0 release delivered the native browser runtime and explicit BRK2 device-preference integration. The additive persistent transport and strict sidecar routing work merged in YuKKi-OS PR #185, paired with Overhauled PR #93, justifies the next native package minor version, 6.20.0:

- Add endpoint-scoped persistent BRK1/BRK2 sessions with a configurable upper bound (default 16, range 1..256).
- Keep one request/response exchange in flight per socket; recycle only successfully decoded responses and discard connections after uncertain outcomes.
- Avoid automatic replay of non-idempotent operations after a transport error that may occur after broker admission.
- Add a strict environment mode that requires a numeric loopback endpoint for a local mTLS sidecar.
- Preserve independent browser-runtime, browser-WASM and WASI guest-worker package versions at 0.1.0.

The matching Overhauled change bounds listener sessions, requires loopback binding in strict mTLS-proxy mode and can persist accepted replay nonces. The current sidecar protects traffic in transit but does not yet pass the verified certificate identity into signed handoff authorization. The optional journal does not persist artifact staging or activation state.

## Compatibility and security boundaries

- Existing YKMC, BRK1, BRK2, NXR1 and WSM1 wire identities are not intentionally changed by this version bump.
- The handoff sender uses a separate versioned application contract; signed executable artifacts and untrusted stream payloads have distinct trust policies.
- Streaming remains available from untrusted sources subject to bounded size, retained-memory, connection, rate and backpressure policies. Stream data does not need a WASM publisher key.
- In-process token buckets and memory ceilings constrain application resource consumption, but they cannot prevent volumetric DDoS saturating the network link. Use upstream network-edge protection.
- YuKKi-OS does not silently send handoff messages over plaintext TCP. Integrators must supply mTLS 1.3 or an equivalent authenticated channel and bind peer identity to the signed deployment sender.
- Discovery records are not execution authorization. Broker transport and the handoff transport must be authenticated independently.
- The browser-WASM crate (yukki-browser-core) and WASI guest worker (yukki_guest_worker) are separate unpublished workspaces at 0.1.0; they are not implicitly bumped with the native yukkios package.

## Release gate for 6.20.0

Before tagging or publishing:

1. Run Cargo formatting, `cargo test --locked`, Clippy, lockfile-integrity and package-validation checks on the exact candidate; confirm the generated root lockfile changes only as Cargo resolves the new workspace package version.
2. Run the supported native Linux/macOS test/build matrix, browser-WASM and WASI build/test jobs, Docker validation, dependency/license audits, coverage and benchmark smoke tests.
3. Exercise persistent-session reuse, pool saturation/backpressure, socket discard on timeout/cancellation/malformed responses, strict loopback-mode validation and paired BRK1/BRK2 live interoperability.
4. Verify the Overhauled listener's client-session ceiling, strict loopback bind guard, mTLS sidecar configuration, and replay-journal restart/replay/corruption/capacity behavior.
5. Run the stream ingestion/gateway/WebSocket rate-limit tests and confirm untrusted stream access remains available without executable-artifact publisher authorization.
6. Review the separately reported low-severity transitive rand advisory; restoring the missing lockfile entry is not a security fix.
7. Only after required checks pass and the release commit is approved, create the 6.20.0 tag and GitHub Release. Verify crates.io publication separately.

PR #185 (bounded BRK session pooling and strict mTLS-proxy endpoint enforcement) is merged to main alongside Overhauled PR #93. PR #184 restored the missing Cargo.lock dependency entry. This candidate updates only native yukkios release metadata; browser-runtime, browser-WASM and WASI package versions remain independent.

## Published release history

- v6.19.0 — published 2026-11-24; native browser runtime, graphics smoke coverage and BRK2 device-preference delegation.
- v6.18.0 — published 2026-11-22; authenticated WASM sender and untrusted-stream flood controls.
- v6.17.0 — published 2026-11-22; conventional WASM import binding and the authenticated WASM handoff contract/schema.
- v6.16.0 — published 2026-11-21; lease-based broker discovery and BRK2 locality intent/result codec support.
- v6.15.0 — published 2026-11-21; resolver and benchmark concurrency improvements.
- v6.14.0 — published 2026-11-20; YuKKi workload directives and BRK2 worker-class interoperability.
- v6.13.0 — published 2026-11-18; native Wasm program composition and time-weighted spatial replica pools.
- v6.12.0 — published 2026-11-18; browser spatial/motion, multivariate datasets and the bounded symmetric eigensolver.
