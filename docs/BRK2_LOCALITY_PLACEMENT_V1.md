# BRK2 Locality Placement Extension v1

Status: proposal for cross-repository implementation. This document specifies an optional BRK2 request/response extension; it does not claim that a host allocator currently honours placement requests.

## Ownership

YuKKi-OS owns workload placement policy and decides whether locality is preferred or mandatory. Overhauled owns broker-local execution and the allocation of broker-owned request-payload memory. The allocator-owning process is the only component that may report placement as honoured.

A placement request is intent, never authority. It cannot widen a process cpuset, bypass memory quotas, expose raw topology, or override local admission policy.

## Compatibility and versioning

The BRK2 envelope remains major version 2, schema IDs remain request=1 and response=2, and existing fields 1–13 are unchanged. This extension adds optional request field 14 and optional response field 13. The nested extension has its own version field, initially 1.

- A prefer request MUST be encoded with the field's critical flag clear. An older peer may ignore it; the sender must treat an absent placement result as unknown/not applied, never as success.
- A bind or interleave request MUST set the critical flag. A peer that does not understand field 14 must reject the request through the existing unknown-critical-field rule. It must not silently run a mandatory request without its constraint.
- A peer that understands field 14 but cannot satisfy a mandatory request must return a normal broker rejection with a placement result explaining why.
- Unknown optional nested fields may be ignored. Unknown critical nested fields reject the placement extension. Duplicate singular nested fields reject the extension.

No JSON HELLO or implicit transport authentication is introduced. Capability discovery, where available, is advisory; actual acceptance is determined by parsing and processing the request.

## Request field 14: placement intent

Outer TLV: field ID 14, wire type Nested (11), flags as described above.

The nested value is itself a sequence of standard 8-byte BRK2 TLV headers and values:

| Nested field | Wire type | Required | Meaning |
|---|---|---:|---|
| 1 | U16 | yes | Extension version; exactly 1 |
| 2 | U8 | yes | Scope; 1 = broker_request_payload |
| 3 | U8 | yes | Mode; 1 = prefer, 2 = bind, 3 = interleave |
| 4 | U32 | conditional | Preferred/bound NUMA node; required for prefer and bind, absent for interleave |
| 5 | U64 | yes | Maximum bytes subject to this placement request; nonzero and no greater than the decoded payload size |

V1 deliberately covers only the broker-owned request payload copy. It does not claim placement of YuKKi-OS WASM linear memory, caller-owned datasets, accelerator staging buffers, GPU VRAM, or NPU memory. Those have different allocator owners and require separately scoped extensions.

Prefer allows a safe local fallback. Bind requires the specified node or rejection. Interleave requests distribution across the allocator's eligible local NUMA nodes; it does not expose a node list or CPU mask on the wire.

The node identifier is an opaque node ID in the sender's negotiated locality domain. It is not a CPU ID, cpuset, or globally meaningful machine identifier. If the receiver cannot establish a compatible locality domain, it must reject bind; for prefer, it may fall back and report that result.

## Response field 13: placement result

Outer TLV: field ID 13, wire type Nested (11), non-critical. It is present only when field 14 was supplied and the receiver processed it.

Nested fields:

| Nested field | Wire type | Required | Meaning |
|---|---|---:|---|
| 1 | U16 | yes | Extension version; exactly 1 |
| 2 | U8 | yes | Scope; 1 = broker_request_payload |
| 3 | U8 | yes | Result; 1 = honored, 2 = rejected, 3 = fallback |
| 4 | U32 | conditional | Applied NUMA node; present only when a single node was actually applied |
| 5 | U16 | conditional | Reason code; required for rejected/fallback |

Reason codes: 1 unsupported_scope, 2 unsupported_mode, 3 locality_domain_mismatch, 4 node_unavailable, 5 process_policy_denied, 6 memory_quota, 7 allocator_unavailable, 8 size_limit, 9 placement_failed.

A response MUST NOT say honored merely because a worker thread was pinned to a NUMA node. It must be based on allocator-level success for the exact requested allocation. For interleave, omit field 4 because there is no single applied node. For fallback, include a reason code. For rejection, the broker task status is Rejected.

If the request contains no field 14, field 13 is absent. If a legacy peer ignores an optional prefer field, field 13 is absent and the client records the result as unknown, not honoured.

## Bounds and validation

- The outer nested value and every inner TLV are bounded by the existing BRK2 frame/payload limits.
- Accept exactly one outer field 14 and at most one each of nested fields 1–5.
- Reject zero or over-payload max_bytes, invalid enum values, invalid conditional node presence, unsupported extension versions, and malformed nested TLVs.
- Apply a strict local cap before allocator calls. Never allocate based only on the peer-provided max_bytes.
- Validate node IDs against the receiver's own allowed memory policy and process constraints.
- Do not serialize raw CPU masks, machine topology, physical addresses, or allocator handles.

## Required conformance cases

Both Rust and C++ runners must share vectors for: optional prefer accepted by an old peer as unknown optional; critical bind rejected by an old peer; v1 prefer/bind/interleave decoded identically; unknown optional nested field accepted; unknown critical nested field rejected; duplicate nested singular field rejected; invalid scope/mode/node combinations rejected; zero/oversized max_bytes rejected; honored/fallback/rejected response decoding; absent result treated as unknown; and mandatory placement failure correlated to the original request ID.

## Implementation boundary

This specification is not allocator implementation or NUMA qualification. The first runtime implementation must wire the codec and explicit result reporting before enabling a platform allocator. Allocation backends must be separately tested for the broker payload copy and must report allocator-level success/failure. Other memory classes remain unsupported until their owning process implements and verifies them.
