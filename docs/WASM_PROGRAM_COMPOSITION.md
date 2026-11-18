# YuKKi-OS composed WebAssembly programs

This document describes the native-host module composition API in
\`src/wasm_composition.rs\`. It is separate from the browser spatial WASM app,
the restricted WASI guest worker, and the Overhauled WSM1 broker lifecycle.

## What it enables

A deployment can contain one or several executable programs. Each program is
assembled from a directed acyclic graph of separately compiled core-Wasm
modules. Modules call each other through declared, typed function imports and
exports. A program exposes one stable entrypoint; YuKKi-OS can call that
entrypoint as a composed policy function.

The same source artifact can be used by multiple programs. Wasmtime compiles
the bytes once per runtime cache key (SHA-256), while each program receives
its own Store and independently instantiated module graph. This shares
compiled code without sharing guest linear memory, mutable globals, or tables
between programs.

A release containing several programs is activated by one routing-map update.
Calls admitted before the switch finish on the previous release; new calls
route to the new release. Old program Stores and instances remain alive while
old calls are in flight, then are released as the final call drops its
reference. This provides an atomic route switch and drain-before-release
lifetime rule within the YuKKi-OS process.

## Composition contract v1

The v1 composition contract is intentionally restricted:

- Modules are core WebAssembly modules compiled by Wasmtime/Cranelift.
- Module dependencies are explicit in the manifest. An import namespace maps
  to one module ID in the same program.
- Cross-module imports must be functions with an exact matching function
  signature. Providers are instantiated before consumers using a stable
  topological order.
- Cyclic dependencies, unbound imports, missing exports, and signature
  mismatches fail during preparation, before activation.
- Imported memories, globals, tables, tags, WASI imports, and implicit host
  namespaces are not accepted in v1. This prevents accidental shared mutable
  state and implicit host capabilities. A module with its own private memory
  may still be composed with other modules through functions.
- A program entrypoint must return one i32 and accept zero to eight i32
  parameters. Internal module-to-module functions may use other core-Wasm
  function signatures, subject to Wasmtime's linker type checks.
- Each program has a separate Store. Calls to the same program are serialized
  by that Store's mutex; distinct programs can execute concurrently.
- Fuel is reset for each entrypoint call. The default is 10,000,000 fuel.
  Each memory is capped at 4 MiB by default, and each table is capped at
  65,536 elements. A Store may create at most 16 instances, memories, and
  tables by default.
- The compiled-module lookup cache is in-memory, process-local, content
  addressed, and bounded to 256 entries by default. It is not a persistent
  disk cache or a portable native-code artifact format.

This is for small/medium policy and orchestration modules. It is not a
language-model weights loader, WASI distribution, general-purpose dynamic
linker, or replacement for the existing guest-worker/XPU execution bridge.

## Manifest

The deployment manifest is JSON:

\`\`\`json
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
      "bindings": {
        "math": "math-kernel"
      },
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
      "bindings": {
        "math": "math-kernel"
      },
      "entrypoint": {
        "module_id": "risk-alert",
        "export": "run",
        "params": 1
      }
    }
  ]
}
\`\`\`

The \`bindings\` map is per program. Here both programs use the same
\`math-kernel:1.0.0\` artifact. It is compiled once in the runtime's SHA-256
cache but instantiated separately into the two program Stores.

Each artifact is supplied out-of-band as \`ModuleArtifact { module_id,
version, wasm }\`. The manifest is limited to 64 KiB by default. Each module
is limited to 4 MiB and the total supplied artifact bytes per deployment are
limited to 32 MiB. Program count defaults to 16; each program may contain up
to 16 modules.

## Example modules

The source examples in \`examples/wasm-composition/\` illustrate the two
function-linked policies from the manifest. Convert the WAT files to core-Wasm
binaries with WABT's \`wat2wasm\`:

\`\`\`sh
wat2wasm examples/wasm-composition/math-kernel.wat \\
  -o math-kernel.wasm
wat2wasm examples/wasm-composition/risk-score.wat \\
  -o risk-score.wasm
wat2wasm examples/wasm-composition/risk-alert.wat \\
  -o risk-alert.wasm
\`\`\`

## Prepare, test, activate

The API is currently a Rust library API; there is no deployment CLI or HTTP
endpoint for composed programs.

\`\`\`rust
use std::{fs, time::Duration};
use yukkios::wasm_composition::{
    CompositionRuntime, ModuleArtifact,
};

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

// Stage compiles, validates, links and instantiates every program.
// A failure leaves the currently active release unchanged.
let prepared = runtime.prepare_json(&manifest, &artifacts)?;

// Test candidate entrypoints before activation is also possible by building
// an isolated CompositionRuntime for qualification.
let receipt = runtime.activate(prepared)?;
assert_eq!(receipt.active_release, "2026.11.18.1");

// Both programs now route through the same active release.
let score = runtime.call("risk-engine", "risk-score-policy", &[55])?;
let alert = runtime.call("risk-engine", "risk-alert-policy", &[55])?;
# Ok::<(), Box<dyn std::error::Error>>(())
\`\`\`

A production caller should also validate input ranges and policy outputs at
its application boundary. Fuel is a compute budget, not a wall-clock
deadline. A program's mutex serializes invocations of that program; use
separate program IDs or a future bounded replica pool when parallel calls to
the same policy are required.

## Updating several live programs

To replace one or several programs together:

1. Create a new manifest with the same \`deployment_id\` and a new
   \`release_id\`.
2. Supply all module versions referenced by the new release.
3. Call \`prepare\`. Compilation, import resolution, signature validation,
   entrypoint validation, and instantiation all complete before the release
   can be activated.
4. Exercise the candidate in an isolated runtime as part of application
   qualification.
5. Call \`activate\` once with the prepared program set.

The active map stores one \`Arc<ProgramSet>\` per deployment. Therefore a
release containing several programs becomes visible with one map replacement;
callers cannot observe half of the programs from the new release and half from
the old release. An already admitted call retains the old program set until it
returns. The old program set is then eligible for release.

Activation is a routing operation, not a distributed transaction with a
broker or an external model server. If an application also changes Overhauled
broker registrations or external model artifacts, it must coordinate those
resources at its own deployment layer. Overhauled continues to own backend
selection, accelerator placement, broker task dispatch, and broker-side
Prepare/Drain/Release metadata; it does not compile or link these Wasm modules.

## Future extensions

The current v1 deliberately does not support cyclic linking, imported shared
memories, arbitrary host capabilities, multi-value/non-i32 program entrypoint
ABIs, background compile queues, persistent compiled-artifact storage, or
component-model/WASI linking. Those should be introduced as separately
versioned capabilities with explicit resource and trust policies rather than
implicitly widening v1.
