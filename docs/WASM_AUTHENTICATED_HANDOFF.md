# Authenticated WASM handoff contract v1

Normative envelope: `protocol/wasm-handoff-v1.schema.json`. The shared
schema is kept byte-for-byte aligned with Overhauled.

## Ownership and discovery

YuKKi-OS owns workload semantics, deployment/release identity, module
metadata, publisher selection, resource intent and deployment orchestration.
Overhauled owns admission, local module validation, backend availability,
runtime promotion and execution telemetry. Broker/service discovery returns
candidate locations only; it is never artifact authorization.

## Sender implementation

The Rust library `yukkios::wasm_handoff` provides:

- `HandoffSender::build_prepare`: validates core-Wasm headers and artifact
  bounds, builds canonical manifest/module/aggregate SHA-256 digests, signs
  the deployment request and adds a separate publisher attestation.
- `HandoffSender::for_each_chunk`: emits one signed chunk at a time through
  a callback, allowing transport backpressure without constructing a second
  in-memory vector of base64-encoded artifact data.
- `HandoffSender::build_activation`: signs the explicit activation request.
- `HandoffSender::deploy`: drives prepare, bounded chunk transfer and
  activation through a caller-supplied `HandoffTransport`, verifies the
  receiver's signed prepare decision and validates the signed activation
  receipt before reporting success.

Private keys are not stored by this module. `HandoffSigner` is the boundary
for a local Ed25519 implementation, OS key store or HSM. Publisher and
deployment signers are separate. `HandoffReceiptVerifier` must pin the
receiver's issuer, subject, key ID and audience and verify its Ed25519
signature.

`HandoffTransport` is intentionally an interface, not a plaintext TCP
client. Its implementation must use mutually authenticated TLS 1.3 or an
equivalent authenticated protected channel, bind the peer certificate
identity to the signed envelope sender, reject plaintext downgrade, bound
frames before allocation, and map signed prepare decisions/receipts to the
shared schema. No concrete TLS transport adapter is included yet.

## Authentication and replay

Sign RFC 8785 JSON Canonicalization Scheme bytes of the envelope with the
`signature` member omitted, using Ed25519. Verify key ID, exact issuer and
subject, audience, expiry, nonce uniqueness, request ID and transport peer
identity. The receiver uses a separate publisher trust store; a deployment
sender cannot authorize its own artifact publisher identity.

The receiver's current replay guard is bounded but process-local. Multi-node
or restart-safe deployments must provide shared durable replay storage.
The sender creates fresh UUID message IDs/nonces for each prepare, chunk and
activation message. Capability offers are hints only; re-check capabilities
during receiver prepare.

## Artifact transfer and runtime selection

Transfer portable core-Wasm bytes and canonical metadata only. Do not transfer
compiled modules, native caches, Stores, instances, memory or runtime handles.
Every module has a version, length and SHA-256 digest. After an accepted,
signed prepare decision, send sequential bounded chunks with transfer ID,
digest, offset, total length, per-chunk digest and final marker. The sender
respects the receiver's returned chunk ceiling and streams one chunk at a time.

The receiver verifies publisher provenance, module/manifest/aggregate digests,
capabilities and stricter local/requested limits. It currently accepts only
the configured Wasmtime backend policy and requires explicit module-validation
and atomic-activation callbacks. No-compatible-backend or missing callback
means rejection, not silent fallback.

## Flood controls and untrusted streams

The WASM sender validates 1..=256 modules, per-module and aggregate size,
core-Wasm version, unique identifiers, bounded chunks and finite resource
limits before emitting data. It does not load all chunks into memory at once.

Separately, stream ingestion remains available to untrusted sources; a WASM
publisher key is not required to send or view media/geospatial data. The stream
store has hard ceilings of 64 MiB retained payload, 256 streams, 16,384
retained chunks and 256 KiB per chunk. The gateway caps total TCP connections
at 128; per remote IP it allows a 40-request burst and refills at 20 requests
per second, while global requests are capped at a 300-request burst and
100 requests per second. WebSockets are capped at 64 globally and four per IP.
A WebSocket may have only one chunk awaiting acknowledgement, has a 60-second
idle timeout, and remote origin pulls are bounded to eight concurrent
operations. Existing relay batch/rate limits and store backpressure continue
to apply. Excess traffic is throttled or rejected; these limits prevent
unbounded in-process growth, not volumetric denial-of-service upstream of the
host's network interface.

## Lifecycle and isolation boundary

`DISCOVERED -> AUTHORIZED -> PREPARE_ACCEPTED -> TRANSFERRING -> VERIFIED ->
VALIDATED -> ACTIVATED`. Preparation and activation are separate; activation
is local, not a distributed atomic transaction. Failed preparation or module
validation must leave the active release unchanged. Receipts identify the
actual backend/engine/ABI; missing telemetry is unknown.

The current Overhauled shared-Store Wasmtime embedding is not an untrusted
multi-tenant sandbox. Until fuel/epoch interruption, per-task isolation and
teardown, and fine-grained WASI grants are qualified, restrict execution to
trusted artifacts or an independently isolated process boundary.

## Conformance status

Both repositories have sender/receiver unit coverage for canonical messages,
Ed25519 trust, publisher provenance, replay, chunk integrity, bounded staging,
signed decisions/receipts, rate limiting and failed-activation rollback.
The production TLS transport adapter, durable replay service, capability-offer
endpoint and actual broker listener integration remain separate work.
