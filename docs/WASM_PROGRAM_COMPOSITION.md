# YuKKi-OS composed WebAssembly programs

This guide covers the native-host composition API in `src/wasm_composition.rs`.
It is separate from the browser spatial WASM application, the restricted
WASI guest worker, and Overhauled's WSM1 broker lifecycle.

## What it enables

A deployment can contain one or several executable programs. Each program is
assembled from a directed acyclic graph of separately compiled core-Wasm
modules. Modules call one another through declared, typed function imports
and exports. A program exposes one stable entrypoint and behaves as a
composed policy function.

The same artifact can be reused by several programs and several replicas.
Wasmtime compiles its bytes once per runtime cache key (SHA-256); each program
replica receives its own Store and independently instantiated module graph.
Compiled code is shared, but mutable globals, linear memory, tables and
execution state are not.

One release can include several program IDs. A single routing-map replacement
activates all programs in that release together. Calls already admitted to
the previous release retain its program set until completion; new calls use
the new release. This keeps updates atomic at the YuKKi-OS process boundary.

## Composition contract v1

- Modules are core WebAssembly modules compiled by Wasmtime/Cranelift.
- Module dependencies are resolved from typed imports. If an import namespace
  exactly matches a module ID in the same program, YuKKi-OS binds it automatically;
  no `bindings` entry is needed. The optional `bindings` map remains available
  for aliases where the import namespace differs from the provider module ID.
- Cross-module imports must be functions with exact matching signatures.
  Providers are instantiated before consumers using a stable topological
  order.
- Cyclic dependencies, unbound imports, missing exports and signature
  mismatches fail during preparation, before activation.
- Imported memories, globals, tables, tags, WASI imports and implicit host
  namespaces are rejected. Private memories inside modules remain isolated.
- A program entrypoint accepts zero to eight i32 parameters and returns one
  i32. Internal cross-module functions can use other core-Wasm signatures.
- The default is one replica per program. A program may request up to eight
  replicas, and a deployment may contain up to 32 replicas in total.
  Multi-replica execution requires `stateless: true`. This is an explicit
  application promise that a policy does not rely on mutable guest globals,
  linear memory, tables or per-instance state persisting between calls.
- Each replica has an independent Store and instance graph. Calls to one
  replica are serialized, while other replicas and other program IDs can
  execute concurrently.
- Fuel is reset for every call. The default is 10,000,000 fuel. Each memory
  is capped at 4 MiB, each table at 65,536 elements, and each Store at 16
  instances, memories and tables by default.
- The compiled-module cache is process-local, content-addressed and bounded
  to 256 entries by default. It is not a persistent disk cache or a portable
  native-code artifact format.

This API is for deterministic policy and orchestration modules. It is not a
language-model weights loader, general WASI distribution, arbitrary dynamic
linker, or replacement for the separate guest-worker/XPU execution bridge.

## Time-weighted spatial replica selection

The runtime uses `TimeWeightedSpatialScheduler` from
`src/temporal_spatial_scheduler.rs` to rank a program's replicas:

1. An optional 64-bit spatial key (for example, a tenant, entity, tile,
   sensor or partition key) selects a preferred logical replica. Repeated
   work with the same key tends to reuse that replica and its warm state.
2. Each replica records an exponentially weighted moving average of
   completed service time: 7/8 prior estimate plus 1/8 of the latest call.
3. The estimated service cost is multiplied by one plus the replica's
   currently active-call count. This load factor helps avoid concentrating
   new work on a replica that is already busy. The preferred shard still
   receives a 25% locality penalty on competing replicas, so locality is
   retained when the estimated costs are comparable.
4. Admission uses a non-blocking Store lock. Busy replicas are skipped. If
   every replica is busy, the call immediately returns
   `CompositionError::ProgramSaturated` rather than waiting behind a
   long-running guest. Active-call load is a snapshot, not a reservation or
   queue-depth guarantee; the Store lock remains the final admission check.

This avoids head-of-line blocking on one replica while spare replicas exist.
It does **not** promise zero stalls: if all replicas are busy, the call
returns overload; fuel bounds guest instruction work but is not a wall-clock
deadline. Callers should use bounded retries/backpressure or increase the
replica count after measuring memory and CPU cost.

The spatial key is a logical affinity/shard hint. It does not imply physical
NUMA pinning, geometry-aware placement or shared state between replicas. The
separate `SpatiotemporalPayloadResolver` continues to route NXR1 payloads
and enforce per-source sequence policy; the new scheduler uses execution-time
measurements to choose a local program replica.

Use `call` for time-weighted selection without a spatial affinity key, or
`call_with_spatial_key` when the caller has a stable logical partition key.
`replica_metrics` reports the per-replica service-time EWMA, completed call
count and active call count.

## Manifest

The manifest is JSON. The shipped example runs two policies; they both reuse
the `math-kernel:1.0.0` artifact. The scoring policy has four stateless
replicas and the alert policy has two.

```json
{
  "schema_version": 1,
  "deployment_id": "risk-engine",
  "release_id": "2026.11.18.1",
  "programs": [
    {
      "program_id": "risk-score-policy",
      "modules": [
        { "module_id": "math-kernel", "version": "1.0.0" },
        { "module_id": "risk-score", "version": "1.0.0" }
      ],
      "bindings": { "math": "math-kernel" },
      "replicas": 4,
      "stateless": true,
      "entrypoint": {
        "module_id": "risk-score",
        "export": "run",
        "params": 1
      }
    },
    {
      "program_id": "risk-alert-policy",
      "modules": [
        { "module_id": "math-kernel", "version": "1.0.0" },
        { "module_id": "risk-alert", "version": "1.0.0" }
      ],
      "bindings": { "math": "math-kernel" },
      "replicas": 2,
      "stateless": true,
      "entrypoint": {
        "module_id": "risk-alert",
        "export": "run",
        "params": 1
      }
    }
  ]
}
```

The `bindings` map is per program. Both programs reuse the same compiled
math-kernel module, but each replica instantiates it into a separate Store.

Omitting `replicas` and `stateless` preserves the safe default of one
stateful replica. Do not set `stateless: true` for a policy that relies on
mutable per-instance guest state.

The manifest is limited to 64 KiB. Each module is limited to 4 MiB, total
artifact bytes per deployment to 32 MiB, program count to 16, and modules
per program to 16. The replica ceilings are 8 per program and 32 per
deployment.

## Example modules

The WAT sources in `examples/wasm-composition/` illustrate the two linked
policies. Convert them to core-Wasm binaries with WABT:

```sh
wat2wasm examples/wasm-composition/math-kernel.wat -o math-kernel.wasm
wat2wasm examples/wasm-composition/risk-score.wat -o risk-score.wasm
wat2wasm examples/wasm-composition/risk-alert.wat -o risk-alert.wasm
```

## Prepare, activate and execute

The composition API is currently a Rust library API. There is no built-in
deployment CLI or public HTTP deployment endpoint.

```rust
use std::fs;
use yukkios::wasm_composition::{CompositionRuntime, ModuleArtifact};

let manifest = fs::read("examples/wasm-composition/manifest.json")?;
let artifacts = vec![
    ModuleArtifact {
        module_id: "math-kernel".into(),
        version: "1.0.0".into(),
        wasm: fs::read("math-kernel.wasm")?,
    },
    ModuleArtifact {
        module_id: "risk-score".into(),
        version: "1.0.0".into(),
        wasm: fs::read("risk-score.wasm")?,
    },
    ModuleArtifact {
        module_id: "risk-alert".into(),
        version: "1.0.0".into(),
        wasm: fs::read("risk-alert.wasm")?,
    },
];

let runtime = CompositionRuntime::with_defaults();

// Compile, validate, link and instantiate every program before activation.
let prepared = runtime.prepare_json(&manifest, &artifacts)?;
let receipt = runtime.activate(prepared)?;
assert_eq!(receipt.active_release, "2026.11.18.1");

// No spatial key: choose the best current replica by measured service time.
let score = runtime.call("risk-engine", "risk-score-policy", &[55])?;

// Keep related work near the same logical shard where that is still timely.
let alert = runtime.call_with_spatial_key(
    "risk-engine",
    "risk-alert-policy",
    &[55],
    0x98F4_CA01_E5B2_3344,
)?;

// Inspect service-time and active-call measurements for autoscaling policy.
let metrics = runtime.replica_metrics("risk-engine", "risk-score-policy")?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Validate input ranges and policy outputs at the application boundary. Fuel
is an instruction budget, not a wall-clock deadline. The per-replica Store
lock serializes calls to that replica; a pool permits concurrent calls up
to its replica count. If all replicas are occupied, the API returns
`ProgramSaturated` immediately rather than blocking on a mutex.

Run the focused tests with:

```bash
cargo test wasm_composition
cargo test temporal_spatial_scheduler
```

## Updating several live programs

To replace one or several programs together:

1. Create a new manifest with the same `deployment_id` and a new
   `release_id`.
2. Supply all module versions referenced by the new release.
3. Call `prepare`. Compilation, dependency resolution, signature checks,
   instantiation, and replica-pool creation finish before activation.
4. Exercise the candidate in an isolated runtime as part of qualification.
5. Call `activate` once with the prepared program set.

The active map stores one `Arc<ProgramSet>` per deployment. A new release
containing several programs becomes visible with one map replacement.
Callers cannot observe only part of the deployment from the new release.
An already admitted call retains the previous program set until it returns;
then the old stores and instances can be released.

Activation is a YuKKi-OS process-local routing operation, not a distributed
transaction with Overhauled or an external model server. If an application
also changes broker registrations or model artifacts, its deployment layer
must coordinate those resources. Overhauled owns backend selection,
accelerator placement, task dispatch and broker-side Prepare/Drain/Release
metadata. Its optional native Wasmtime runtime-composition path is a separate
execution capability: when enabled, it can compile core-Wasm modules and
resolve module imports in its own linker. This does not automatically import
a YuKKi deployment, manifest, compiled cache, replica pool or release state.
The two runtimes remain independently prepared and activated until an explicit
artifact/manifest handoff protocol is implemented.

## Future extensions

Composition v1 deliberately excludes cyclic linking, imported shared
memories, arbitrary host capabilities, multi-value/non-i32 entrypoint ABIs,
background compilation queues, persistent compiled-artifact storage,
component-model/WASI linking and automatic physical NUMA placement. Introduce
those as separately versioned capabilities with explicit resource and trust
policies rather than silently widening the current contract.
