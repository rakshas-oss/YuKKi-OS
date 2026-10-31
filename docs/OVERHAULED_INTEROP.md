# YuKKi-OS ↔ overhauled broker interoperability

This document records the wire contract implemented by the current
`rakshas-oss/overhauled` C++ broker and the corresponding YuKKi-OS client
path. The overhauled repository is authoritative for the broker envelope.

## Supported wire stack

```text
TCP connection
└── uint32_be frame length (body bytes only)
    └── BRK1/v1 request or response body
        └── WSM1/v1 task or lifecycle payload (inside request.payload /
            response.result)
```

The outer TCP length prefix is not included in the BRK1 body length.

### BRK1 request body

All multibyte values are big-endian. The request body is:

1. `magic`: 4 bytes, ASCII `BRK1`
2. `version`: uint16, value 1
3. `message_type`: uint8, value 1 (request)
4. `reserved`: uint8, value 0
5. `task_id`: uint16 length + UTF-8 bytes
6. `source`: uint16 length + UTF-8 bytes
7. `destination`: uint16 length + UTF-8 bytes
8. `kind`: uint16 length + UTF-8 bytes
9. `priority`: uint8
10. `timeout_ms`: uint32
11. `payload`: uint32 length + bytes

Request validation follows the C++ broker: non-empty routing identifiers,
timeout in 1..=300000 ms, strings within the configured string limit, payload
within the configured payload limit, and no trailing bytes.

### BRK1 response body

The response layout is different from the request layout:

1. `magic`: 4 bytes, ASCII `BRK1`
2. `version`: uint16, value 1
3. `message_type`: uint8, value 2 (response)
4. `reserved`: uint8, value 0
5. `task_id`: uint16 length + UTF-8 bytes
6. `status`: uint8 (0=ok, 1=rejected, 2=error, 3=timeout)
7. `selected_gpu`: int32
8. `latency_ms`: uint64
9. `result`: uint32 length + bytes
10. `error`: uint16 length + UTF-8 bytes

Do not decode a response with the request decoder. The response's `result`
contains the encoded WSM1 response for WSM1 task/lifecycle kinds.

## WSM1 payload kinds

The outer BRK1 `kind` selects the broker handler:

| Kind | WSM1 payload |
|---|---|
| `wasm.task.v1` | WSM1 TaskRequest (message type 1) |
| `wasm.lifecycle.prepare.v1` | WSM1 LifecycleRequest, action Prepare (3) |
| `wasm.lifecycle.drain.v1` | WSM1 LifecycleRequest, action Drain (3) |
| `wasm.lifecycle.release.v1` | WSM1 LifecycleRequest, action Release (3) |
| `wasm.lifecycle.query.v1` | WSM1 LifecycleRequest, action Query (3) |

The broker returns a BRK1 response whose `result` is the corresponding WSM1
TaskResponse (message type 2) or LifecycleResponse (message type 4). YuKKi-OS
validates that the outer BRK1 `task_id` equals the inner WSM1 `task_id` or
`request_id`.

The WSM1 task status byte is: 0=Ok, 1=Rejected, 2=Error, 3=Timeout,
4=ModuleDraining, 5=ModuleNotFound, 6=VersionMismatch. YuKKi-OS now accepts
all seven values; the Rust variant `Failed` represents wire value 2 (named
`Error` by the C++ implementation).

The WSM1 field layouts, status enums, and buffer descriptor formats are
specified in [overhauled/docs/WASM_INTEROP.md](https://github.com/rakshas-oss/overhauled/blob/main/docs/WASM_INTEROP.md).
The outer BRK1 format is specified in
[overhauled/docs/BROKER_PROTOCOL.md](https://github.com/rakshas-oss/overhauled/blob/main/docs/BROKER_PROTOCOL.md)
and implemented by `overhauled/src/broker_protocol.cpp`.

## Compatibility boundary

- The current overhauled broker accepts BRK1/v1, not BRK2.
- The current overhauled broker does not implement a JSON protocol handshake.
  BRK1/v1 is selected by the client configuration; do not send a JSON
  `HandshakeRequest` to this server.
- The current overhauled broker does not implement the YuKKi JSON
  `CancelTaskRequest`. Local cancellation and socket teardown do not guarantee
  preemption of work already executing in the broker.
- YuKKi-OS `BrokerClient` (in `src/broker_client.rs`) remains a separate
  JSON broker client. It is not compatible with the C++ overhauled server.
- YuKKi-OS `GpuBrokerClient::submit_task` is the legacy JSON message route.
  Use `LifecycleClient` in BRK1 mode and `submit_wsm1_task` for the current
  overhauled WSM1 task endpoint.

## Limits and defaults

- Broker endpoint: `127.0.0.1:9090` (matches the overhauled broker's documented
  default launch port; deployments may override it).
- BRK1 frame limit: 1 MiB in the YuKKi-OS GPU adapter default.
- Broker default payload limit: 512 KiB.
- Broker default string limit: 1024 bytes.
- WSM1 buffer descriptor limit: 64 per task.
- Encoded WSM1 payload limit: 512 KiB.
- Broker task timeout: 1..=300000 ms.

The actual server-side limits are configured by `ProtocolLimits`; client
limits should be set no higher than the server's configured values.

## Interoperability tests

YuKKi-OS includes a byte-level BRK1 response decoder test using the exact field
order and big-endian representation from the C++ implementation. End-to-end
acceptance still requires running the Rust client against an overhauled
`broker_server --cpu-only` instance and validating WSM1 task and lifecycle
round trips. A codec unit test alone is not evidence of live network
interoperability.
