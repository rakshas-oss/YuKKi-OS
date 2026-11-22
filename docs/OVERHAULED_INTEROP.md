# YuKKi-OS ↔ Overhauled broker interoperability

This document describes the current cross-repository contract between the YuKKi-OS Rust client and the Overhauled C++ broker. Overhauled is authoritative for broker execution behavior and its protocol documentation; YuKKi-OS documents the matching client path. The repositories are independently built and have no source dependency on each other.

## Responsibility boundary

- **YuKKi-OS:** authenticated peer-mesh control plane, task policy, and optional broker client.
- **Overhauled:** placement and execution plane, broker service, CPU/GPU dispatch, and optional NPU executor.
- **Interop:** bounded binary broker frames over TCP. Peer-mesh encryption is not automatically inherited by this separate broker connection.

The generic `src/broker_client.rs` JSON protocol is not the Overhauled wire protocol. For the Overhauled endpoint, use the GPU adapter's BRK1/BRK2 client and WSM1 task/lifecycle payloads.

## Wire stack

```text
TCP connection
└── uint32_be frame length (body bytes only)
    └── BRK1/v1 or BRK2/v2 request/response body
        └── WSM1 task/lifecycle payload (request.payload / response.result)
```

The 4-byte prefix is not included in the body length. Both implementations use big-endian envelope integers. BRK1 remains supported; BRK2 is selected by frame magic. There is no JSON HELLO negotiation, remote cancellation contract, or TLS implied by this framing.

## BRK1 and BRK2

BRK1 request/response layouts, validation limits, and status values are specified in [Overhauled `BROKER_PROTOCOL.md`](https://github.com/rakshas-oss/overhauled/blob/main/docs/BROKER_PROTOCOL.md). Request timeout is explicitly required and must be `1..=300000` ms; zero and values above five minutes are rejected. The decoder does not infer a deadline from payload size.

BRK2 uses the same length prefix, a 32-byte fixed header, then 8-byte-header TLV fields. Header and TLV lengths are checked, reserved bits and malformed values are rejected, singular duplicates are invalid, unknown optional fields are forward-compatible, and unknown critical fields are rejected at schema validation. Request schema 1 and response schema 2 are shared by the Rust codec and C++ broker. The request correlation ID is echoed in the response.

The current broker request schema includes the optional `device_preference` string field (field 10): `cpu`, `gpu`, or `npu`. Unknown preference values are rejected. The response includes `backend` (field 7), allowing clients to distinguish `cpu`, `gpu`, and `npu` execution rather than assuming that a request preference guarantees a device. Clients should validate this field together with `selected_gpu`; `selected_gpu=-1` alone cannot distinguish CPU from NPU. These fields do not change BRK1 framing. See the Overhauled protocol document and shared conformance corpus for the normative current schema and vectors.

## WSM1 payload kinds

The outer request `kind` selects the broker handler:

| Kind | WSM1 payload |
|---|---|
| `wasm.task.v1` | TaskRequest (message type 1) |
| `wasm.lifecycle.prepare.v1` | LifecycleRequest, Prepare (1) |
| `wasm.lifecycle.drain.v1` | LifecycleRequest, Drain (2) |
| `wasm.lifecycle.release.v1` | LifecycleRequest, Release (3) |
| `wasm.lifecycle.query.v1` | LifecycleRequest, Query (4) |

Responses carry a WSM1 TaskResponse (message type 2) or LifecycleResponse (message type 4) in the broker result. YuKKi-OS verifies that the outer task ID matches the inner task ID or request ID. WSM1 layouts, enums, buffer descriptors, and lifecycle sequencing are specified in [Overhauled `WASM_INTEROP.md`](https://github.com/rakshas-oss/overhauled/blob/main/docs/WASM_INTEROP.md).

## Authenticated WASM artifact handoff (separate from WSM1)

The v1 authenticated handoff protocol is a separate executable-artifact path; it is not a BRK2 frame extension and does not change WSM1 task/lifecycle messages.

- YuKKi-OS provides `yukkios::wasm_handoff::HandoffSender` to validate core-Wasm artifacts, construct canonical manifest/digests, sign deployment and separate publisher provenance, emit sequential signed chunks, and issue an activation request.
- Overhauled provides the `HandoffReceiver` API to check deployment-sender and publisher trust independently, replay/expiry, module/chunk/aggregate digests, capability/resource policy, bounded admission and signed prepare/activation receipts.
- When Overhauled is built with both `ENABLE_WASM_HANDOFF=ON` and `ENABLE_WASM_RUNTIME=ON`, `WasmHandoffRuntimeBridge` can validate/compile the full module set in a fresh runtime/store and atomically promote it after success.
- The YuKKi caller must implement `HandoffTransport` over mTLS 1.3 or an equivalent authenticated protected channel and implement a receiver `HandoffReceiptVerifier`. The transport identity must be bound to the signed deployment sender; do not route this transfer through the ordinary raw broker socket.

The receiver is not wired to the ordinary BRK1/BRK2 listener or a built-in HTTP endpoint. The handoff adapter, durable replay/staging service and restart-safe multi-process semantics are not supplied by these library APIs. The current shared-Store Wasmtime runtime is not a multi-tenant sandbox, so restrict artifacts to operator-authorized trusted code or an independently isolated process.

This trust domain applies only to executable artifacts. Untrusted NXR1/MED1/YKMC and stream-relay data remains accessible without a WASM publisher key and is protected by separate framing, storage, connection, rate and backpressure limits.

## NPU dispatch and Ethos-U85 execution

YuKKi-OS remains the control plane and requests NPU placement using the existing BRK2 `device_preference=npu` contract; no new wire negotiation is required. The Overhauled broker owns physical Ethos-U85 execution via its opt-in mainline Linux DRM backend. Build it on Linux with:

```sh
cmake -S . -B build \
  -DENABLE_ETHOSU_DRM=ON \
  -DENABLE_CUDA=OFF \
  -DENABLE_TENSORRT=OFF \
  -DBUILD_BROKER=ON
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
```

Start with a Vela-generated bundle:

```sh
./build/broker_server 9090 --npu-ethosu-bundle model.yu85
```

If needed, select a DRM render node explicitly using `--ethosu-device /dev/dri/renderD128`. The `YU85BND1` format, tensor quantization, region layout, and runtime requirements are documented in [Overhauled `ETHOSU_U85_BUNDLE.md`](https://github.com/rakshas-oss/overhauled/blob/main/docs/ETHOSU_U85_BUNDLE.md). YuKKi's existing BRK2 preference is the dispatch signal; the broker reports NPU only when execution completes on that executor. If a request is marked fallback-safe and hardware execution fails, configured CPU fallback may apply.

`--npu-simulated` is a distinct CPU-emulated path for conformance/CI; it is not NPU hardware acceleration. The source `src/drivers/ethosu85_async.rs` in YuKKi-OS is an orphaned placeholder, not a Linux DRM driver, and is not an execution path. Physical validation requires an appropriate kernel exposing the mainline Ethos-U DRM UAPI, a compatible Vela command stream and bundle, and a successful inference on the target board. Compilation or simulator tests alone do not establish board support.

## Compatibility and security limits

- Overhauled accepts BRK1 and BRK2 on the same TCP listener; client and server must agree on each frame's envelope and schema.
- The C++ listener does not implement the YuKKi JSON `HandshakeRequest` or `CancelTaskRequest`.
- Local cancellation or socket closure does not guarantee preemption of broker work already executing.
- Broker transport is a bounded protocol, not an authentication layer. Use a trusted network or an independently secured proxy; labels such as `authenticated-proxy` do not enable TLS.
- Keep client frame/payload limits at or below server `ProtocolLimits`. Task timeout must be `1..=300000` ms.
- CPU fallback is only allowed where the request/task policy is marked safe; requesting a backend is not proof that backend was used. Inspect the response backend.

## Browser-WASM benchmark bridge (BRK2 inference, not WSM1)

The browser-WASM runner provides a second, benchmark-only route to the same
broker. It builds and executes YuKKi-OS's local spatial module in Node's
WebAssembly runtime, then optionally sends host-prepared numeric records from
the multivariate fixture directly to the Overhauled BRK2 listener as ordinary
inference tasks. This client does not use the YuKKi production GPU adapter,
does not submit WSM1 task/lifecycle envelopes, and does not send executable
Wasm modules to Overhauled.

From the YuKKi-OS repository root, after building the browser module and
starting a trusted CPU-only Overhauled broker on port 9090:

~~~sh
node browser-wasm/bench/run.mjs --quick --broker-host 127.0.0.1 --broker-port 9090 --broker-device cpu --output browser-wasm-brk2.json
~~~

Without `--broker-host`, the runner performs local WASM measurements only.
With broker mode enabled, the report includes actual backend counts, selected
GPU IDs, fallback count, and request latency. The response's BRK2 backend
field is authoritative; a requested GPU/NPU preference is not proof of
hardware use. BRK2 has no built-in authentication or TLS, so keep this
benchmark endpoint on loopback, a trusted private network, or a separately
secured proxy.

This path validates a useful data-plane seam, not the complete application
stack: it does not test the browser UI, gateway, Wasmtime guest lifecycle,
streaming, worker-class queue contention, or physical accelerator
qualification. YuKKi-OS owns workload classification, logical spatial affinity,
and the advisory NUMA hint sourced from its resolver. Overhauled independently
discovers the CPUs allowed to its process, applies best-effort Linux worker
thread affinity, owns GPU topology and backend selection, and returns queue,
service, and applied-NUMA telemetry. This keeps the two NUMA responsibilities
distinct rather than duplicating the resolver or pretending a logical key is
a physical CPU placement.


## Conformance and live interoperability

Both repositories carry the shared BRK1/BRK2 conformance corpus and language-specific runners. The live YuKKi-OS integration workflow builds the CPU-only C++ broker and exercises Rust lifecycle operations over its TCP listener in BRK1 and BRK2 modes. The Overhauled CPU-only CTest suite includes protocol, conformance, service, backend-dispatch, broker-server E2E, and other registered tests. These CI and simulator checks validate protocol/software behavior, not physical Ethos-U85 hardware.

- [YuKKi BRK2 conformance](BRK2_CONFORMANCE_V1.md)
- [YuKKi executable BRK corpus](BRK_CONFORMANCE_V1.md)
- [Overhauled BRK2 conformance](https://github.com/rakshas-oss/overhauled/blob/main/docs/BRK2_CONFORMANCE_V1.md)
- [Overhauled executable BRK corpus](https://github.com/rakshas-oss/overhauled/blob/main/docs/BRK_CONFORMANCE_V1.md)


## YuKKi-directed worker classes

The optional BRK2 worker directive now lets YuKKi-OS select one of Control,
RealtimeSpatial, Throughput, ExactCpu, or Inference. Fields 11–13 carry class,
logical affinity key, and preferred NUMA node. Overhauled applies the local
class queue and placement policy, then returns queue wait, service time,
worker ID, and applied NUMA node as optional response fields. Per-class queues
grow dynamically and preserve FIFO order within their class; a process-wide
request-count and in-flight memory budget remains in force to protect the
broker from memory exhaustion. See [WORKER_CLASS_POLICY.md](WORKER_CLASS_POLICY.md)
and the [Overhauled worker-fabric guide](https://github.com/rakshas-oss/overhauled/blob/main/docs/YUKKI_WORKER_FABRIC.md).


## Broker service discovery

The optional `YUKKI_BROKER_ENDPOINT=host:port` setting makes a YuKKi-OS node advertise a reachable Overhauled broker through the authenticated peer mesh. `YUKKI_BROKER_CAPABILITIES` optionally supplies descriptive comma-separated capability labels (default `cpu`). Records advertise BRK1/BRK2, a bounded frame limit, node/service IDs, and a lease. YuKKi refreshes the lease every 30 seconds, expires stale records, bounds the registry to 4,096 entries, and forwards announcements for at most eight hops. See [BROKER_SERVICE_DISCOVERY.md](BROKER_SERVICE_DISCOVERY.md).

This is gossip-based discovery over the current bootstrap-relayed mesh, not a Kademlia DHT. Discovery does not authorize execution. The broker protocol remains unauthenticated; advertise only an endpoint protected by a trusted private network or independently authenticated mTLS proxy. The service record contains coarse capabilities only and must not expose raw CPU/NUMA topology.
