# Drone Dashboard — Optional component

This repository provides an optional, lightweight dashboard intended for drone operators and fleets. The Drone Dashboard is a frontend on top of the existing gateway/dashboard functionality and is designed for low-latency telemetry, stream inspection, and operational control of unmanned nodes ("drones"). It is optional and disabled by default.

Key characteristics

- Sits behind the existing authenticated gateway: the dashboard uses the gateway bearer token model for authentication.
- Read-only by default: telemetry and stream views are read-only unless you explicitly wire control endpoints into your application (see Security below).
- Works with the existing stream model: drones publish telemetry/frames to LiveMediaStreams or as BrokerTasks; the dashboard can present live streams, chunked media, and per-drone metadata.
- Accepts binary chunk ranges via the gateway's HTTP range APIs and WebSocket "tune" endpoints for live updates.

Environment variables

- `YUKKI_DRONE_DASHBOARD_ENABLED` (`true` / `false`, default `false`) — enable the drone dashboard UI on the gateway.
- `YUKKI_DRONE_DASHBOARD_LISTEN` (e.g. `0.0.0.0:7671`) — override the dashboard listen address (defaults to the gateway listen when unset).
- `YUKKI_GATEWAY_TOKEN` — required bearer token for dashboard access; dashboard UI prompts for this token.
- `YUKKI_DRONE_DASHBOARD_MAX_CHUNKS` (default `256`) — max chunks to retain per drone stream in the dashboard view.

Endpoints and UI

- `/dashboard/drones` — drone list and status (gateway-hosted UI).
- `/dashboard/drones/<drone-id>` — per-drone detail, last-seen, active streams, and recent chunks.
- WebSocket tune endpoint(s) (same pattern as stream dashboard) for low-latency telemetry updates.

Operational notes

- The dashboard presents information the gateway already exposes; it does not bypass gateway authentication or authorization.
- For deployments with many drones, run the dashboard behind a reverse proxy and enable TLS termination there. The gateway and dashboard do not provide built-in TLS.
- Dashboard storage is in-memory and bounded by `YUKKI_DRONE_DASHBOARD_MAX_CHUNKS`. For persistent storage or long-term telemetry retention wire the gateway into an external store.

Security considerations

- Treat `YUKKI_GATEWAY_TOKEN` as a secret. Do not embed long-lived tokens in client-side code or public images.
- If you enable write/control actions (e.g., remote commands), implement a separate authenticated control channel and audit all commands. The default dashboard is read-only and intended for monitoring.
- Prefer deploying the dashboard behind an authenticated proxy (e.g., OAuth2 proxy) and use short-lived gateway tokens where possible.

Extensibility

- The dashboard can be extended to show telemetry graphs, health indicators, and per-drone logs. Those features should be implemented as application-side wiring into the gateway APIs and not enabled by default.
