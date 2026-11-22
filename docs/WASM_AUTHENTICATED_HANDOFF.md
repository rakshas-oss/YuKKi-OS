# Authenticated WASM handoff contract v1

Normative envelope: `protocol/wasm-handoff-v1.schema.json`.

## Ownership and discovery
YuKKi-OS remains authoritative for workload semantics, deployment/release identity, module DAG, entrypoint policy, deadlines and required capabilities. Overhauled owns broker admission, receiver authorization, backend availability, local runtime selection and execution telemetry. YuKKi discovers candidate nodes through the authenticated mesh/service registry, but registry discovery is only a locator, never artifact authorization.

The receiver advertises a short-lived capability offer: contract versions, backend IDs, engine/version, target architectures, WASM features, ABI and WASI profiles. YuKKi sends a signed prepare request with `runtime_policy=auto` by default. A preferred backend is advisory; required features and capabilities are mandatory. No fallback may weaken requested security or semantic requirements.

## Authentication and replay
- Use mutually authenticated TLS 1.3. If carried over authenticated BRK2, bind its authenticated peer identity to the signed envelope sender and audience.
- Sign RFC 8785 JSON Canonicalization Scheme bytes of the envelope with the `signature` member omitted, using Ed25519. Verify key ID, trust, authorization, audience, expiry, nonce uniqueness and request ID before transfer.
- Retain nonce/request replay state for at least the maximum message lifetime plus configured clock skew. Capability offers are short-lived hints; re-check at prepare time.

## Artifact transfer
Transfer portable core-Wasm bytes, canonical composition manifest and metadata only. Never transfer compiled modules, native caches, Stores, instances, memory or runtime handles. Every module includes version, byte length and SHA-256 digest; separately verify manifest and aggregate artifact-set digests. After an accepted prepare decision, stream bounded BRK2 frames with transfer ID, digest, offset, total length, per-chunk digest and final marker. Reject gaps, overlaps, conflicting duplicate offsets, oversized chunks and length mismatches. Stage privately; verify full digests before parsing/compiling. Verify publisher provenance separately from sender identity. Delete staged bytes on expiry, cancellation or failure.

## Runtime selection
The receiver independently validates format, imports/exports, ABI, WASM feature set, DAG, resource limits and capability policy. It selects only a locally available backend meeting every required property and reports exact backend ID, engine/version and ABI profile. Unknown imports and ungranted host capabilities fail closed. Sender limits are upper bounds; receiver applies the stricter local/requested value. `auto` allows a compatible backend choice; pinned policies restrict engine family. No compatible backend means rejection, not silent downgrade.

## Lifecycle
`DISCOVERED -> AUTHORIZED -> PREPARE_ACCEPTED -> TRANSFERRING -> VERIFIED -> COMPILED -> PREPARED -> ACTIVATED -> RUNNING -> SUCCEEDED|FAILED|CANCELLED`. Preparation and activation are separate; activation is local, not a distributed atomic transaction. Failed preparation leaves the active release unchanged. Receipts report actual backend and resource usage; missing telemetry is unknown.

## Security boundary
This contract does not turn the current shared-Store Overhauled Wasmtime embedding into a tenant sandbox. Until fuel/epoch interruption, per-task isolation/teardown and fine-grained WASI grants are implemented and tested, restrict that backend to trusted workloads or a separately isolated process boundary.

## Conformance
Both implementations must test signature tampering, wrong audience, expired/replayed nonce, unauthorized sender/publisher, digest mismatch, truncated/reordered/overlapping chunks, size limits, unsupported features/imports, capability escalation, backend mismatch, no-compatible-backend rejection, cancellation and failed-prepare rollback. Assert backend identity from signed receipts.
