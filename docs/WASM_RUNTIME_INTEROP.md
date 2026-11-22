# YuKKi-OS and Overhauled WebAssembly runtime interoperability

## Scope

This document defines the current ownership boundary between YuKKi-OS's
native Rust WebAssembly composition runtime and Overhauled's optional native
Wasmtime C API runtime-composition facility.

The two runtimes are complementary but independent. This integration does
not introduce a second YuKKi compiler/linker, nor does it imply that a
YuKKi deployment is automatically executed by Overhauled.

## Responsibility split

| Concern | YuKKi-OS | Overhauled |
|---|---|---|
| Deployment manifest and release identity | Authoritative owner | Not authoritative |
| Dependency DAG and policy validation | Authoritative owner | Validates modules/imports supplied to its own runtime |
| Typed function binding policy | Validates exact signatures and allowed imports | Wasmtime linker resolves imports and checks types at instantiation |
| Module compilation | Existing Rust Wasmtime/Cranelift runtime | Optional native Wasmtime C API runtime, when enabled |
| Program replicas and logical spatial selection | Owns program replica pools and scheduler | Owns broker execution/worker placement, not YuKKi replica state |
| Broker admission, dispatch and accelerator selection | Supplies workload intent | Authoritative owner |
| Release activation | Atomic within YuKKi process | Independent broker/runtime lifecycle |
| Artifact authorization and delivery | Deployment/application boundary | Must be supplied by caller/integration |

YuKKi's runtime composes a manifest-defined DAG of core-Wasm modules with
typed function imports/exports, rejects unsupported import classes and
cycles, and prepares isolated Store/instance graphs before process-local
activation. Its limits, cache and replica state are local to YuKKi.

Overhauled's optional runtime compiles core-Wasm module bytes and registers
modules under linker namespaces. The linker resolves imports when dependent
modules are instantiated. Its Store, linker, limits, module registration and
lifecycle are local to Overhauled. A shared broker process/runtime is not a
shared trust domain with YuKKi's Wasmtime stores.

## Explicit authenticated artifact handoff (separate from BRK1/BRK2 and WSM1)

The shared `wasm-handoff/1` contract now has client and receiver implementations. This does not change the BRK1/BRK2 frame format or WSM1 task/lifecycle messages.

**YuKKi-OS sender:** `yukkios::wasm_handoff::HandoffSender` validates portable core-Wasm artifact sets, builds canonical module/manifest/aggregate SHA-256 digests, signs the deployment prepare request, adds a separately signed publisher attestation, emits sequential bounded signed chunks and signs activation. Its `deploy` method drives this sequence through a caller-supplied `HandoffTransport`, verifies the receiver's signed prepare decision and validates the activation receipt with a separately provisioned `HandoffReceiptVerifier`.

**Overhauled receiver:** `HandoffReceiver` verifies the deployment sender and artifact publisher against separate trust stores, checks issuer/subject/audience/key ID, lifetime and nonce/replay state, bounds concurrent preparations and staged bytes, verifies sequential chunk and complete module digests, and signs prepare decisions and activation receipts. It fails closed when required validation or activation callbacks are absent.

**Optional runtime bridge:** when both `ENABLE_WASM_HANDOFF=ON` and `ENABLE_WASM_RUNTIME=ON` are enabled, `WasmHandoffRuntimeBridge` installs a Wasmtime compile-only validator and an atomic activation callback. It builds a fresh runtime/store for the staged release and publishes it only after the full module set compiles and registers. Failed validation/activation preserves the previous active runtime.

### Deliberate integration boundaries

- `HandoffTransport` is an interface; YuKKi-OS does not ship a concrete mTLS adapter. The integrating application must supply mTLS 1.3 or an equivalent authenticated protected channel, bind the peer identity to the signed deployment sender, reject plaintext downgrade, enforce frame limits before allocation and decode the shared schema into the receiver's typed messages.
- The receiver is not wired into Overhauled's ordinary BRK1/BRK2 listener and is not an HTTP endpoint. Do not send artifact handoff through the unauthenticated raw broker socket.
- Replay guard, prepared artifact staging and active-release state are process-local/in-memory. Durable shared replay/staging and restart-safe multi-process activation require deployment-supplied services.
- Handoff transfers portable core-Wasm bytes and signed metadata, not compiled module caches, native code, Wasmtime Stores/instances, linear memory, replica pools or either runtime's routing state.
- Activation is local to the receiving runtime, not a distributed atomic transaction across YuKKi-OS and Overhauled.
- The current shared-Store Wasmtime embedding is not a multi-tenant sandbox. Restrict it to trusted operator-authorized artifacts or an independent process-isolation boundary.
- Untrusted NXR1/MED1/YKMC stream ingestion and consumption are outside this executable-artifact trust policy and do not require a WASM publisher key. Stream paths use separate size, retained-memory, request, connection, rate and backpressure limits.

The two composition runtimes remain independent. A successful artifact activation through the handoff receiver is not equivalent to deploying or activating a YuKKi `CompositionRuntime` program graph and does not migrate its module-cache, replica or routing state.

## Cross-runtime conformance requirements

A shared fixture suite should be consumed independently by both repositories.
It should cover:

- one valid standalone core-Wasm module and deterministic entrypoint result;
- a provider/consumer pair with a typed function import and export;
- multiple providers and deterministic dependency ordering;
- missing namespace, missing export and signature mismatch rejection;
- cyclic dependency rejection where the runtime's manifest model supports
  dependency graphs;
- rejection of imported memories, tables, globals, tags, WASI and undeclared
  host capabilities according to each runtime's declared policy;
- module-size, memory, table, instance and fuel/resource-limit behavior;
- duplicate module namespace/identity rejection;
- independent instance state and no accidental cross-Store mutable state;
- prepare failure leaves the previously active release unchanged;
- execution failure and saturation/fuel exhaustion are surfaced distinctly.

Each runtime may have different configuration ceilings. The shared corpus
defines expected semantic outcomes, while per-runtime tests assert each
runtime's own configured numeric limits. Do not require equal fuel counts or
identical performance across the C and Rust embeddings.

## Security and operational boundaries

The Overhauled optional runtime is not a complete tenant isolation boundary
merely because it uses Wasmtime. Fuel metering, epoch interruption, WASI
capability grants, artifact signing, cache eviction and per-task instance
teardown must be verified in the implementation before being claimed.
YuKKi's existing fuel and Store limits apply only to YuKKi's own runtime.

Do not treat a broker endpoint discovered through YuKKi's service registry
as artifact authorization. The registry advertises candidate endpoints;
the artifact delivery channel needs its own authenticated transport and
authorization policy. Do not claim NUMA-local Wasm linear memory or accelerator
staging from CPU-thread affinity telemetry.

## CI integration

The repositories now have sender/receiver unit tests for canonical message construction, Ed25519 trust, publisher provenance, replay/expiry, digest integrity, bounded sequential transfer, signed decisions/receipts, rate limiting and failed-activation rollback. Paired validation should identify both tested commit SHAs and Wasmtime versions. It must not be described as a full release gate unless all required native CI jobs in both repositories are included.

Overhauled's runtime-composition implementation is present on its main branch behind `ENABLE_WASM_RUNTIME`. The authenticated handoff receiver is independently gated by `ENABLE_WASM_HANDOFF`; the Wasmtime runtime bridge requires both flags. A source checkout alone is not evidence of a successful Wasmtime-enabled build: qualify the pinned Wasmtime CI lane and receiver/bridge test on the exact commit before relying on that path.
