# Drone Interoperability Guide

This guide explains recommended integration patterns for drones and unmanned nodes interacting with YuKKi-OS. It covers two common models: gateway-proxied drones and direct peer-mesh drones.

## Overview

YuKKi-OS provides a secure authenticated mesh and an authenticated gateway. Drones may be resource-constrained and should prefer gateway-proxied operation in many deployments; direct peer-mesh participation is supported when a drone can maintain the required crypto and network connectivity.

## The Manifest of Drones is also a multivariate data-source manifest

Despite its name, the Manifest of Drones need not be limited to UAV fleets or drone telemetry. It can be used as a domain-independent inventory and description of heterogeneous data sources that are to be discovered, correlated, time-aligned, spatially aligned where applicable, and processed together.

A manifest entry can describe a source and its variables, including:

- Stable source and dataset identifiers, owner/operator, provenance, and access policy.
- Variable names, types, units, dimensions, and schema/version.
- Temporal coverage, sampling/update frequency, timestamps, and timezone.
- Spatial reference system, coordinates, geographic extent, and resolution when relevant.
- Transport or adapter information, payload encoding, quality flags, and retention requirements.

A source can expose many variables, and a workflow can combine many sources. Sources do not need to share a sampling frequency, unit system, spatial resolution, or transport. An ingestion/normalization adapter should validate these differences and preserve original values, units, timestamps, provenance, and missing-data markers rather than silently coercing them.

### Example application domains

- **Finance:** combine market prices, trading volume, volatility, interest rates, FX rates, macroeconomic indicators, and portfolio exposures. Time alignment and market-calendar handling are important; preserve currency, exchange, instrument identifiers, and source timestamps.
- **Real estate:** combine property attributes and valuations, transaction/rental histories, occupancy, demographics, zoning, and nearby infrastructure. Preserve property identifiers, valuation dates, geographic references, and provenance.
- **Environmental data mapping:** combine drone and satellite observations, weather stations, air quality, soil measurements, water quality, vegetation indices, and land-use changes. Preserve coordinate reference systems, measurement units, sensor calibration, collection times, and spatial resolution.

For example, an environmental workflow could correlate a drone image tile with satellite observations, rainfall readings, and soil measurements for the same region and time window. A finance workflow could align prices, volumes, rates, and volatility over a market session. These are examples of how applications can use the manifest; they are not claims that YuKKi-OS ships built-in finance, real-estate, or environmental data connectors.

### Mapping manifest entries into YuKKi-OS

Use the manifest as the source catalogue and metadata contract; use YuKKi-OS's existing transport/runtime interfaces to move the actual data:

- Use JSON control/metadata messages to describe source identity, variables, units, timestamps, provenance, and references to payloads.
- Use `LiveMediaStreams` / `MediaChunk` for ordered or chunked observations and larger binary payloads.
- Use `BrokerTasks` for bounded request/response work such as validation, transformation, aggregation, feature extraction, or inference.
- Use mesh/gateway APIs for discovery and distribution where the application has wired the relevant source adapters and authorization.

The manifest itself does not create a connector, ingest external systems, harmonize units, or guarantee temporal/spatial alignment. Implement and test a domain-specific adapter for each external datasource, validate its schema and trust boundary, and record the adapter/version used to produce normalized observations.

## Common integration patterns

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

## Message and control conventions

- Telemetry streams: Use the existing stream model (LiveMediaStreams / MediaChunk) for telemetry and chunked sensor payloads. Streams are discoverable via the stream registry and can be tuned via the gateway WebSocket endpoints.
- Commands & tasks: Use BrokerTasks for command-and-control where you need request/response semantics. Set `timeout_ms` explicitly (`1..=300000`) and include `task_id`, `source`, `destination`, and `kind` fields.
- Data formats: Use JSON for control/metadata and length-prefixed binary frames for large payloads (broker client wire contract uses a 4-byte big-endian length prefix for JSON frames).

## Sample minimal gateway-proxied flow (telemetry upload)

1. Drone POSTs telemetry chunk to gateway (`/v1/streams/<stream-id>/chunks` — implementor-provided HTTP handler).
2. Gateway stores chunk in its in-memory store and returns a sequence id.
3. Dashboard or subscribers `tune` to the stream to receive live updates via WebSocket.

## Sample direct peer join (CLI)

```sh
# On an existing bootstrap node
./target/release/yukki_core_node bootstrap 0.0.0.0:7660

# On the drone (or drone agent)
export YUKKI_PSK_HEX="<64-hex-secret>"
./target/release/yukki_core_node node <bootstrap-address> <advertised-address>
```

## Security and operational recommendations

- Never expose `YUKKI_PSK_HEX` or `YUKKI_GATEWAY_TOKEN` publicly. Use secure provisioning and short-lived credentials where possible.
- Prefer gateway-proxied mode for drones that cannot securely store long-lived PSKs or run the full crypto stack.
- For drone control operations that execute commands, implement auditing, authorization scopes, and rate-limiting at the gateway/broker boundary.
- Use TLS (reverse proxy) for all gateway-facing traffic and consider mTLS for sensitive operations.
- Treat external datasource manifests as untrusted input: validate identifiers, schemas, units, timestamps, coordinate systems, payload sizes, and access policies before ingestion.

## Troubleshooting

- If a drone cannot join the peer mesh: verify `YUKKI_PSK_HEX` is correct and that the bootstrap node is reachable and listening.
- If telemetry does not appear in the dashboard: ensure the gateway bearer token is set, the stream is being written by the drone, and the dashboard's `YUKKI_DRONE_DASHBOARD_MAX_CHUNKS` is not exceeded.
- If multivariate observations do not align: check source timestamps/timezones, units, coordinate reference systems, sampling intervals, missing-value handling, and adapter versions. Do not assume that matching stream IDs imply matching measurement semantics.

## Extending interoperability

- You can implement protocol adapters in `src/` (for example, a tiny drone agent) that translate common drone telemetry formats into the stream/broker models used by YuKKi-OS.
- The same adapter pattern applies to financial feeds, property datasets, environmental sensors, satellite products, and other multivariate sources.
- For GPU-backed drones or offload scenarios, consider BrokerTask-based offload to GPU brokers via `src/gpu_adapter.rs`.

See also

- docs/DRONE_DASHBOARD.md
- docs/MESH_DASHBOARD.md
- docs/USER_HOWTO_STREAMING.md
- docs/API.md
- docs/ARCHITECTURE.md
