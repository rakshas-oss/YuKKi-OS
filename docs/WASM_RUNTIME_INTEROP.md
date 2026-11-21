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

## No implicit handoff

The current BRK1/BRK2 and WSM1 contracts do not define a Wasm artifact
transfer, composition-manifest transfer, module namespace registry, or
cross-repository activation transaction. A broker task payload must not be
assumed to contain a deployable Wasm module or trusted manifest.

Until a versioned handoff protocol is implemented:

1. The deployment application chooses YuKKi composition or Overhauled
   runtime composition for a given execution path.
2. The application authenticates and authorizes artifact delivery.
3. The receiving runtime independently validates, compiles, links and
   prepares the modules under its own resource limits.
4. Activation is local to that runtime. Coordinating activation across
   YuKKi and Overhauled remains the application's responsibility.
5. Failure, timeout or resource exhaustion in one runtime must not be
   reported as successful preparation or activation in the other.

Do not send native compiled-code cache entries between runtimes. Treat
portable core-Wasm bytes plus an explicit manifest as the interchange
candidate; do not assume identical Wasmtime versions, host functions,
resource limits or ABI behavior.

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

The paired CI work should first validate each repository's native runtime
independently, then run the shared semantic fixture corpus against both
implementations. A paired green result must identify both tested commit SHAs
and the Wasmtime versions used. It must not be described as a full repository
release gate unless all required native CI jobs from both repositories are
also included in the aggregate check.

Until Overhauled's runtime-composition PR is merged and its optional Wasmtime
lane passes, describe that capability as proposed/optional and do not imply
that the default Overhauled build supports it.
