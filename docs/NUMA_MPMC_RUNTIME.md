# NUMA topology and MPMC queue runtime

YuKKi-OS exposes two portable library primitives:

- `yukkios::numa::NumaTopology` discovers CPU/memory NUMA domains.
- `yukkios::mpmc::BoundedMpmc<T>` provides a bounded blocking MPMC queue.

## NUMA discovery

Linux reads node CPU lists and memory totals from /sys/devices/system/node.
Windows uses GetNumaHighestNodeNumber, GetNumaNodeProcessorMaskEx, and
GetNumaAvailableMemoryNodeEx. Other targets, including browser WASM, receive
an explicit portable one-domain fallback. The fallback does not claim the
physical host has only one NUMA node.

The result is a topology snapshot. This implementation does not pin threads,
bind allocations, or guarantee later placement. Callers should refresh the
snapshot when needed and handle discovery errors.

## MPMC queue

Create BoundedMpmc with a non-zero capacity and clone its handle across
producer and consumer threads. send and recv block under backpressure;
try_send and try_recv are non-blocking. close wakes blocked senders and
receivers, rejects future sends, and lets already queued items drain.

The implementation uses a mutex and condition variables, not a lock-free
ring. It prioritizes bounded memory, explicit shutdown, and auditable
correctness over lock-free progress. It is a correctness baseline, not yet
a tuned scheduler or NUMA-local work-stealing runtime.

## Broker worker-class integration

The YuKKi topology snapshot and bounded MPMC queue remain independent library
primitives; the new broker directive does not silently wire either primitive
into the generic task-admission path. Instead, `worker_policy` can forward a
logical affinity key and optional preferred NUMA node to Overhauled through
optional BRK2 fields. Overhauled independently discovers the CPU topology
visible to its process and attempts worker-thread affinity on Linux. It returns
the NUMA node only when pinning succeeds.

The broker worker fabric now has isolated FIFO pools per worker class and
returns queue/service telemetry. It is not a lock-free work-stealing runtime,
does not bind allocations, and does not give browser WASM guests host NUMA
handles or direct host memory access. See [WORKER_CLASS_POLICY.md](WORKER_CLASS_POLICY.md)
for the YuKKi side of the boundary.
