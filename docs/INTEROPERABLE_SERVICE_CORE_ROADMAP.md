# Interoperable Service Core — YuKKi-OS implementation roadmap

**Status:** implementation roadmap; no transport-security or protocol-negotiation behavior is claimed by this document.

YuKKi-OS owns the Rust control plane: broker client lifecycle, authenticated peer discovery, endpoint policy, task/lifecycle dispatch, handoff sending, and client-side capability enforcement. Overhauled remains authoritative for broker admission, execution, and applied placement.

## Compatibility invariants

- Keep existing BRK1, BRK2, WSM1, NXR1, MED1, and YKMC identities and existing required fields working.
- New BRK2 capabilities are opt-in and only used after an authenticated peer confirms support.
- Do not infer authentication from BRK framing, peer-mesh authentication, a capability label, or a discovery record.
- Preserve access to untrusted NXR1/MED1/YKMC and stream-relay inputs. Executable-artifact publisher authorization must not become a prerequisite for data-stream ingestion.
- Never report requested GPU/NPU/locality as applied execution. Treat broker response telemetry as authoritative.
- All integration branches are based on canonical `main`; no feature branch is a CI dependency.

## Verified starting point

- The production broker endpoint uses the BRK1/BRK2 binary framing and WSM1 task/lifecycle payloads; legacy JSON broker APIs are not the current Overhauled listener contract.
- Broker connections are not automatically protected by the authenticated YuKKi peer mesh.
- The handoff sender API exists, but the receiver's authenticated transport and transport-identity binding are integration responsibilities.
- Existing documentation describes optional BRK2 worker directives and locality hints; a request hint is not proof of physical placement.
- Current discovery is bounded lease-based gossip, not a Kademlia DHT.

## Cargo resolution and reproducibility guard

The November 26, 2026 lockfile incident is now repaired on canonical `main`:

- The lockfile-only change removed the `rand 0.9.5` package record while `tungstenite 0.29.0` still referenced it.
- This made locked Linux/macOS/MUSL builds, Docker, tests, Clippy and RustSec audit fail. The audit tool panicked because the dependency tree was incomplete.
- PR [#184](https://github.com/rakshas-oss/YuKKi-OS/pull/184) restored the exact package record and was merged at `39bb428cb35e159e23c4a56fd345bcc185f1e89c`.

The follow-on guard added here runs `cargo metadata --locked` against each checked-in, independently resolved lockfile (root, guest-worker, and browser-wasm) from both quality and integration workflows. It fails before downstream tests if the selected manifest graph would rewrite its lockfile. All changes to lockfiles must be produced by Cargo, reviewed as dependency-graph changes, and committed with the matching manifest updates; do not hand-delete package records or weaken `--locked` checks.

**Security follow-up remains open:** Aikido reported low-severity `AIKIDO-2026-875754` on `rand 0.9.5`, involving deserialization validation of `UniformChar`. Restoring the missing stanza repairs dependency resolution; it does not remediate that advisory. The current transitive path comes from the older Axum WebSocket dependency chain (`tungstenite 0.29.0`). Upgrade only when a compatible Axum release moves that path to `tokio-tungstenite 0.30.x` / `rand 0.10.x`, then regenerate the lockfile with Cargo and rerun native, browser, package, audit, and paired interoperability validation. Do not suppress the advisory or hand-edit the lockfile to conceal it.

## Work packages

### YS0 — Reusable broker transport

- Introduce a long-lived endpoint-scoped client connection pool with bounded parallel connections, bounded pending requests, keepalive/idle expiry, and reconnect backoff.
- Multiplex only where the selected BRK transport implementation can correlate responses unambiguously; otherwise use a bounded pool of single-flight connections.
- Keep request deadlines end-to-end and ensure a failed connection fails or retries only idempotent requests.
- Keep BRK1 callers and existing BRK2 framing behavior compatible.
- Tests: pool saturation, reconnect, stale socket, concurrent request correlation, timeout, cancellation, and one-hour connection-count soak.

### YS1 — Shared protocol contract and feature confirmation

- Consume one normative contract for schemas, fixtures, and conformance vectors rather than maintaining independently edited copies.
- Before allocating any BRK2 message-type values, audit both implementations' assigned/reserved values and publish the assignment in the contract.
- Add optional HELLO capability confirmation only after that audit. HELLO confirms capabilities and the already-selected transport profile; it must never upgrade plaintext to TLS.
- Replace legacy best-effort JSON cancellation only after the peer confirms the BRK2 CANCEL capability. Preserve the existing local cancellation semantics for old peers.
- Tests: old-peer no-HELLO behavior, unknown optional/critical fields, request-ID correlation, cross-language fixtures, and negotiated/non-negotiated cancellation.

### YS2 — Authenticated broker connections

- Add endpoint-specific mTLS 1.3 client configuration for LAN and WAN profiles, with WAN plaintext refusal.
- Pin discovered broker identity to the key/certificate fingerprint advertised by authenticated discovery.
- Treat discovery data as routing metadata, not authorization; reject profile or identity mismatch.
- Bind handoff sender identity to the authenticated transport peer.
- Support certificate rotation without dropping in-flight work beyond the documented reconnect policy.

### YS3 — Handoff and execution lifecycle

- Implement the authenticated handoff transport and receipt verification adapter.
- Enforce bounded transfer concurrency, total bytes, per-module bytes, chunk sizes, and deadlines before buffering.
- Use durable sender/receiver replay state and release staging only after a verified terminal outcome.
- Keep the WSM1 task/lifecycle contract distinct from executable-artifact handoff.
- Do not claim multi-tenant isolation until runtime/process isolation exists.

### YS4 — Scoped discovery and observability

- Add zone and link-class metadata to authenticated broker discovery.
- Replace bootstrap-hub dependence incrementally with bounded zone-local seeds and relay policy.
- Export connection-pool, handshake, retry, request, cancellation, and discovery metrics.
- Carry optional trace correlation only after the shared contract defines it.
- Report only observed broker/backend/placement outcomes.

## Release gates

1. **A:** YS0 and YS1; BRK1/BRK2 live interoperability and shared corpus green.
2. **B:** YS2; LAN/WAN profile enforcement, identity pinning, and certificate-rotation tests green.
3. **C:** YS3; authenticated handoff prepare/transfer/activate/invoke/drain/release and restart replay tests green.
4. **D:** YS4; multi-zone discovery soak, bounded memory, health/metrics, and operational documentation green.

No version bump or release tag is implied by this roadmap. Release numbers are assigned only after the relevant implementation and CI gates pass.
