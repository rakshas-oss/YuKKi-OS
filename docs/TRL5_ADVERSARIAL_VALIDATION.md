# TRL-5 Adversarial Validation Candidate

## Purpose and claim boundary

This plan defines the YuKKi-OS side of a joint adversarial validation candidate with Overhauled. The initial target is **TRL-5 evidence preparation**: validate integrated software components in a relevant, controlled environment. CI green is necessary but not sufficient. A TRL-5 claim requires representative configuration, reproducible test evidence, measured behavior, and review of unresolved risks. TRL-6 requires a representative prototype demonstration in a relevant operating environment.

## System boundary

YuKKi-OS is the authenticated peer-mesh control plane, workload coordinator, stream/WASM host, and Overhauled client/adapter. The candidate covers:

- Authenticated mesh establishment and peer lifecycle.
- Mesh coordinate validation, origin-pull concurrency and timeout behavior.
- Stream registry, chunk ordering, retention, acknowledgement, and resource limits.
- Browser-WASM and WASI guest-worker boundaries, including shared-memory ABI behavior.
- BRK1/BRK2 codecs, WSM1 payloads, and the Overhauled GPU/NPU adapter.
- Cross-repository live operation against the Overhauled C++ broker.

The peer mesh security boundary does not automatically secure the separate Overhauled broker TCP connection. The broker transport must be isolated or protected by a separately configured authenticated transport boundary.

## Validation rules

1. Record exact YuKKi-OS and Overhauled commit SHAs for every integrated run.
2. Preserve existing tests and branch protections. Do not turn failures into skips or weaken assertions.
3. Record random seeds, minimized reproducers, environment manifests, and complete logs.
4. Distinguish CPU fallback, NPU simulation, and physical NPU execution in every result.
5. Treat protocol compatibility and resource containment as release-blocking invariants.
6. Do not claim physical hardware readiness from cross-compilation, simulator, or CI evidence alone.

## Test campaign and gates

### Gate A — reproducible build and platform baseline

- Run locked release and test builds from a clean checkout.
- Run Rustfmt, Clippy, unit tests, integration tests, dependency/security audit, and coverage workflows.
- Run supported native targets and the browser-WASM/WASI profiles that are explicitly in the current platform support matrix.
- Validate the guest shared-memory ABI on native and WASI targets; review changes to lock ownership, interior mutability, and memory ordering together.
- Record toolchain, target triple, feature flags, dependency lock state, and commit SHA.

**Pass:** all required jobs pass without suppressions; target exclusions are explicit and match the support matrix.

### Gate B — protocol and trust-boundary adversarial validation

Exercise Rust BRK1/BRK2, NXR1, and WSM1 decoding/encoding against the shared C++ conformance corpus:

- Frame length zero/minimum/maximum/maximum-plus-one, truncation, trailing bytes, and partial reads.
- Invalid magic/version, reserved bits/bytes, invalid response statuses, malformed TLVs, duplicate singular fields, unknown optional/critical fields, and invalid enums.
- Correlation and task-ID mismatch across outer broker envelope and inner WSM1 messages.
- NXR1 81-byte header, canonical field order, endian conversion, payload length mismatch, and golden-vector parity.
- WSM1 lifecycle prepare/drain/release/query sequencing, malformed descriptors, invalid message types, and oversized payloads.

Run at least 10,000 deterministic mutations per pull request and a nightly campaign targeting at least 1,000,000 mutations over the shared corpus and Rust-specific inputs. Persist every minimized failure as a regression fixture.

**Pass:** no panic, crash, unbounded allocation, accepted malformed frame outside the contract, cross-language disagreement, or identity/correlation mismatch. Undefined reserved-byte/status semantics must be specified before release.

### Gate C — mesh, origin, stream, and WASM resilience

- Fuzz and property-test mesh node inputs, including NaN, positive/negative infinity, extreme finite coordinates, duplicate IDs, and update races.
- Saturate the origin-pull semaphore; verify the configured cap is never exceeded and saturation produces bounded, observable behavior rather than unbounded task creation.
- Inject connect/read/write stalls, partial responses, disconnects, timeout races, and peer restart during origin pulls.
- Exercise stream open/close churn, out-of-order and duplicate chunks, sequence gaps, retention limits, acknowledgement races, and concurrent readers/writers.
- Exercise WASM guest malformed descriptors, shared-memory boundary indices, invalid lifecycle transitions, worker termination, and sandbox escape attempts within the supported test harness.
- Run randomized peer joins/leaves and concurrent stream operations while asserting state invariants.

**Pass:** no panic, deadlock, memory/FD/task leak, unauthorized state transition, cross-tenant data exposure, or unbounded queue growth. All resource caps are observed under saturation.

### Gate D — end-to-end control-plane/execution-plane validation

Against the matching Overhauled candidate branch/commit:

- Run live BRK1 and BRK2 broker requests through the YuKKi adapter.
- Exercise WSM1 task and lifecycle prepare/drain/release/query flows.
- Verify request ID, task ID, response status, payload, and backend across the boundary.
- Exercise CPU-only baseline, simulated NPU, fallback-permitted and fallback-forbidden cases.
- Inject broker restart, refused connections, malformed responses, response delay, and connection loss during work.
- Verify retry behavior is bounded and does not duplicate non-idempotent operations.
- Verify the client does not claim remote cancellation or hardware execution where the protocol does not guarantee it.

**Pass:** end-to-end semantics match the protocol contract, no duplicate completion or cross-task response mix-up occurs, and fallback behavior matches explicit task policy.

### Gate E — soak, recovery, and operational evidence

- Run a 24-hour representative mesh + stream + broker-adapter soak in an isolated test environment.
- Capture peer count, reconnect rate, origin-pull concurrency, active tasks, queue depth, stream retention, memory, file descriptors, task count, p50/p95/p99 latency, timeout/error/retry rates, and backend distribution.
- Inject peer loss, broker loss, process restart, guest-worker termination, and resource saturation.
- Verify restart/rejoin behavior and document any state that is intentionally not durable.
- Archive logs, metrics, seeds, minimized corpus, test commands, and exact paired commit SHAs.

**Pass:** no unexplained crash, leak trend, deadlock, silent data corruption, or uncontrolled retry storm. Compare performance to a same-hardware baseline; investigate p95/p99 or throughput regressions greater than 10%. This is an investigation threshold, not a universal service-level objective.

## Required evidence package

The candidate report must include:

- Candidate identifier and paired repository commit SHAs.
- Hardware/software inventory, OS/kernel, toolchain, target triples, feature flags, and dependency lock state.
- Test matrix, commands, seeds, durations, raw logs, coverage summaries, and minimized regression corpus.
- Gate status and linked defects, with severity, owner, mitigation, and retest evidence.
- Baseline/candidate performance comparison and variance.
- Explicit exclusions: unsupported deployment targets, broker-native TLS/authentication, remote cancellation/preemption guarantees, and physical accelerator paths not tested on hardware.
- Engineering, security, and test-owner review.

## Candidate result template

| Gate | Result | Evidence link | Open blockers |
|---|---|---|---|
| A — Build/platform | Not run | | |
| B — Protocol/fuzz | Not run | | |
| C — Mesh/stream/WASM | Not run | | |
| D — End-to-end interop | Not run | | |
| E — Soak/recovery | Not run | | |
| Relevant-environment demonstration | Not run | | |

Do not claim TRL-5 validated until required gates and the relevant-environment demonstration have evidence and review. Treat TRL-6 as a separate demonstration milestone.

## Cross-repository plan

The matching Overhauled campaign is documented in [TRL-5 Adversarial Validation Candidate](https://github.com/rakshas-oss/overhauled/blob/main/docs/TRL5_ADVERSARIAL_VALIDATION.md). Run both campaigns against paired, immutable commit SHAs; isolated repository results are not sufficient end-to-end evidence.
