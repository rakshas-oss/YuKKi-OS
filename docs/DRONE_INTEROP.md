# Drone Interoperability Guide

This guide explains recommended integration patterns for drones and unmanned nodes interacting with YuKKi-OS. It covers two common models: gateway-proxied drones and direct peer-mesh drones.

Overview

YuKKi-OS provides a secure authenticated mesh and an authenticated gateway. Drones may be resource-constrained and should prefer gateway-proxied operation in many deployments; direct peer-mesh participation is supported when a drone can maintain the required crypto and network connectivity.

Common integration patterns

1) Gateway-proxied drones (recommended for resource-constrained drones)

- Architecture: Drone ↔ Gateway (authenticated HTTP/WebSocket) ↔ YuKKi-OS node mesh
- How it works:
  - The drone communicates with the gateway using HTTP/WebSocket.
  - The gateway presents a bearer-token authenticated surface (`YUKKI_GATEWAY_TOKEN`) and can translate drone requests into internal stream or broker operations.
  - Telemetry and binary chunks from drones are stored in the gateway's in-memory store and optionally relayed into the mesh using `StreamRelay` if the embedding application wires it in.
- Advantages:
  - Minimal crypto on the drone (use TLS + short-lived bearer token to the gateway).
  - Centralised access control and audit at the gateway boundary.
- Recommended config:
  - Protect the gateway with a reverse proxy (TLS, rate-limiting, IP allowlist).
  - Use `YUKKI_GATEWAY_TOKEN` for gateway authentication; rotate tokens regularly.
  - Use the streaming range and WebSocket tune endpoints to present live telemetry to the dashboard.

2) Direct peer-mesh drones (when drones can run native stack)

- Architecture: Drone ↔ YuKKi-OS peer mesh
- How it works:
  - Drone runs a minimal YuKKi-OS agent or uses the provided CLI (`yukki_core_node node`) to join a bootstrap node.
  - The peer mesh transport uses X25519 + PSK + HKDF + ChaCha20-Poly1305 for authenticated encryption.
  - The drone must be provisioned with `YUKKI_PSK_HEX` (64 hex chars / 32 bytes) and an appropriate advertised address.
- Advantages:
  - Lower-latency peer-to-peer exchanges, direct stream replication, and in-mesh discovery.
- Recommended config:
  - Provision `YUKKI_PSK_HEX` via a secure commissioning process, never embed it in public artifacts.
  - Set `YUKKI_GATEWAY_TOKEN` only if the node should also serve a gateway UI or be managed via the gateway.
  - Use bootstrapping carefully — drones should limit which bootstrap nodes they accept.

Message and control conventions

- Telemetry streams: Use the existing stream model (LiveMediaStreams / MediaChunk) for telemetry and chunked sensor payloads. Streams are discoverable via the stream registry and can be tuned via the gateway WebSocket endpoints.
- Commands & tasks: Use BrokerTasks for command-and-control where you need request/response semantics. Set `timeout_ms` explicitly (`1..=300000`) and include `task_id`, `source`, `destination`, and `kind` fields.
- Data formats: Use JSON for control/metadata and length-prefixed binary frames for large payloads (broker client wire contract uses a 4-byte big-endian length prefix for JSON frames).

Sample minimal gateway-proxied flow (telemetry upload)

1. Drone POSTs telemetry chunk to gateway (`/v1/streams/<stream-id>/chunks` — implementor-provided HTTP handler).
2. Gateway stores chunk in its in-memory store and returns a sequence id.
3. Dashboard or subscribers `tune` to the stream to receive live updates via WebSocket.

Sample direct peer join (CLI)

# On an existing bootstrap node
./target/release/yukki_core_node bootstrap 0.0.0.0:7660

# On the drone (or drone agent)
export YUKKI_PSK_HEX="<64-hex-secret>"
./target/release/yukki_core_node node <bootstrap-address> <advertised-address>

Security and operational recommendations

- Never expose `YUKKI_PSK_HEX` or `YUKKI_GATEWAY_TOKEN` publicly. Use secure provisioning and short-lived credentials where possible.
- Prefer gateway-proxied mode for drones that cannot securely store long-lived PSKs or run the full crypto stack.
- For drone control operations that execute commands, implement auditing, authorization scopes, and rate-limiting at the gateway/broker boundary.
- Use TLS (reverse proxy) for all gateway-facing traffic and consider mTLS for sensitive operations.

Troubleshooting

- If a drone cannot join the peer mesh: verify `YUKKI_PSK_HEX` is correct and that the bootstrap node is reachable and listening.
- If telemetry does not appear in the dashboard: ensure the gateway bearer token is set, the stream is being written by the drone, and the dashboard's `YUKKI_DRONE_DASHBOARD_MAX_CHUNKS` is not exceeded.

Extending interoperability

- You can implement protocol adapters in `src/` (for example, a tiny drone agent) that translate common drone telemetry formats into the stream/broker models used by YuKKi-OS.
- For GPU-backed drones or offload scenarios, consider BrokerTask-based offload to GPU brokers via `src/gpu_adapter.rs`.

See also

- docs/DRONE_DASHBOARD.md
- docs/API.md
- docs/ARCHITECTURE.md
