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

The current broker request schema includes the optional `device_preference` string field (field 10): `cpu`, `gpu`, or `npu`. Unknown preference values are rejected. The response includes `backend` (field 7), allowing clients to distinguish `cpu`, `gpu`, and `npu` execution rather than assuming that a request preference guarantees a device. These fields do not change BRK1 framing. See the Overhauled protocol document and shared conformance corpus for the normative current schema and vectors.

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

## Conformance and live interoperability

Both repositories carry the shared BRK1/BRK2 conformance corpus and language-specific runners. The live YuKKi-OS integration workflow builds the CPU-only C++ broker and exercises Rust lifecycle operations over its TCP listener in BRK1 and BRK2 modes. The Overhauled CPU-only CTest suite includes protocol, conformance, service, backend-dispatch, broker-server E2E, and other registered tests. These CI and simulator checks validate protocol/software behavior, not physical Ethos-U85 hardware.

- [YuKKi BRK2 conformance](BRK2_CONFORMANCE_V1.md)
- [YuKKi executable BRK corpus](BRK_CONFORMANCE_V1.md)
- [Overhauled BRK2 conformance](https://github.com/rakshas-oss/overhauled/blob/main/docs/BRK2_CONFORMANCE_V1.md)
- [Overhauled executable BRK corpus](https://github.com/rakshas-oss/overhauled/blob/main/docs/BRK_CONFORMANCE_V1.md)
