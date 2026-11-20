# YuKKi-OS Worker-Class Policy

YuKKi-OS owns workload classification and scheduling intent. Overhauled owns
local execution admission, worker-pool selection, CPU/NUMA placement,
accelerator dispatch, and execution telemetry. This is a cross-repository
contract carried through optional BRK2 TLVs; it does not change BRK1, BRK2, or
WSM1 envelope identities and does not move Wasmtime or NXR1 semantics into
Overhauled.

## Worker classes

The public types are in `yukkios::worker_policy`:

| Class | Intended workload |
|---|---|
| `Control` | Lifecycle, protocol, and coordination requests |
| `RealtimeSpatial` | Time-sensitive, source-affined spatial streams |
| `Throughput` | Dataset and batch processing |
| `ExactCpu` | Verification-sensitive, cryptographic, and exact CPU work |
| `Inference` | Inference requests eligible for locally permitted NPU/GPU dispatch |

YuKKi-OS selects the class from workload semantics. Overhauled does not
reclassify the request; it validates the optional directive and enforces local
capacity and hardware policy. A class is not a guarantee of a specific
accelerator.

## WorkerDirective

`WorkerDirective` carries:

- `worker_class`: one of the five stable kebab-case class names.
- `spatial_affinity_key`: optional stable logical affinity key. Required for
  `RealtimeSpatial`.
- `preferred_numa_node`: optional advisory local NUMA node ID.
- `deadline_unix_ns`: optional absolute Unix deadline in nanoseconds.

`WorkerDirective::for_resolved_spatial_payload` computes a deterministic
FNV-1a key from the resolved source and destination identifiers and preserves
the resolver's optional NUMA hint. The key is a logical stream/shard identity,
not a geographic coordinate or CPU ID. It does not replace the existing
time-weighted Wasm replica scheduler or NXR1 freshness/sequence checks.

Example for a spatial stream:

```rust
use yukkios::{WorkerDirective, WorkerClass};

let directive = WorkerDirective::for_resolved_spatial_payload(
    &resolved_payload,
    Some(deadline_unix_ns),
);
assert_eq!(directive.worker_class, WorkerClass::RealtimeSpatial);
```

Other workload intents can use `WorkerDirective::control()`,
`throughput()`, `exact_cpu()`, or `inference()`.

When a caller already has YuKKi-OS's `exec_policy::TaskProfile`, it can
derive a directive without duplicating the class-selection rules:

```rust
use yukkios::{ResolvedPayload, WorkerDirective};

let directive = WorkerDirective::for_task_profile(
    &task_profile,
    now_unix_ns,
    resolved_spatial_payload.as_ref(),
)?;

client
    .submit_wsm1_task_with_worker_directive(&task, &directive)
    .await?;
```

Exact-precision requirements select `ExactCpu` even when a spatial payload is
present; the logical affinity and NUMA hints are retained for placement. A
spatial payload otherwise selects `RealtimeSpatial`. Inference profiles
without spatial context select `Inference`; other profiles, including
data-parallel work, select `Throughput`. Backend choice is separate and
remains subject to Overhauled's local accelerator policy.

The `deadline_ms` in `TaskProfile` is interpreted as a relative duration
from `now_unix_ns`; it is converted using checked arithmetic to the absolute
Unix-nanosecond deadline carried by BRK2. Supply a timestamp captured
immediately before submission. Zero, overflow, and values outside the signed
clock range are rejected.

## Submit a WSM1 task over BRK2

Explicit directives require the BRK2 wire mode. WSM1 remains the inner task
payload and is not modified.

```rust
use yukkios::gpu_adapter::{LifecycleClient, LifecycleWireMode, WasmTaskRequest};
use yukkios::{GpuAdapterConfig, WorkerDirective};

let client = LifecycleClient::new(config)?
    .with_wire_mode(LifecycleWireMode::Brk2);

let directive = WorkerDirective::realtime_spatial(
    spatial_affinity_key,
    Some(preferred_numa_node),
    Some(deadline_unix_ns),
);
let execution = client
    .submit_wsm1_task_with_worker_directive(&task, &directive)
    .await?;

let response = execution.response;
if let Some(telemetry) = execution.worker_telemetry {
    println!(
        "class={:?} queue_wait_us={} service_time_us={} worker={} numa={:?}",
        telemetry.worker_class,
        telemetry.queue_wait_us,
        telemetry.service_time_us,
        telemetry.worker_id,
        telemetry.numa_node,
    );
}
```

The code above is illustrative: `config`, `task`, and the request's
application-specific deadline/key must be supplied by the embedding
application.

The existing `submit_wsm1_task` remains available. In BRK2 mode it defaults
to the Throughput class because a generic WSM1 task is not necessarily model
inference. Callers that know a task is inference must send an explicit
`WorkerDirective::inference()`. In BRK1/raw WSM1 modes the API preserves legacy
framing and does not transmit a worker directive. Lifecycle operations sent over BRK2 use
the Control class.

## What the broker does with the directive

The BRK2 request uses optional fields 11 (class), 12 (logical affinity U64), and
13 (preferred NUMA node U32). The response can include field 8 (class), field
9 (queue wait microseconds), field 10 (service time microseconds), field 11
(worker ID), and field 12 (applied NUMA node). These fields are optional for
backwards compatibility.

Overhauled uses a separate dynamically growing queue and reserved worker
pool per class. Control, Throughput, ExactCpu, and Inference preserve FIFO
admission. RealtimeSpatial uses earliest-deadline-first ordering when a
deadline is present, with FIFO tie-breaking; work without a deadline follows
deadline-bearing work. There is no cross-class global order. This isolation
keeps throughput backlogs from consuming reserved control or real-time workers.

Linux Overhauled workers discover CPU sets from sysfs, intersect them with the
process CPU affinity mask, and attempt thread pinning. A NUMA node is reported
only if the affinity call succeeds. Unsupported platforms or restricted
containers continue without claiming NUMA placement.

The queues have no fixed per-class entry count, but are not allowed to consume
unlimited process memory. Overhauled enforces a process-wide outstanding
request cap (default derived from configured clients and in-flight limits,
capped at 65,536) and a default 64 MiB in-flight request-memory budget.
Reservations persist until completion, including after the client disconnects.
Budget exhaustion or allocation failure is an explicit rejection.

## Benchmark and validation expectations

Benchmark real dataset records through the live BRK2 broker, not a mocked
queue. Report per-class request count, queue wait, service time, end-to-end
p50/p95/p99, throughput, backend, applied NUMA node, rejected admissions, and
resident memory. Exercise class saturation, mixed classes, client
disconnect/reconnect churn, absolute deadlines that expire while queued,
invalid worker hints, and CPU fallback.

A successful worker-pool microbenchmark alone does not validate the full
YuKKi-OS-to-Overhauled data path. Keep the BRK conformance corpus and live
interoperability tests enabled.
