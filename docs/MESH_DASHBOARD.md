# Mesh dashboard and optional drone map

This feature is intentionally optional. It is behind the `mesh_dashboard` Cargo feature.

## UI interoperability and system integration

The built-in dashboard is not a separate subsystem: it consumes the same HTTP and WebSocket APIs that the rest of YuKKi-OS exposes. That makes it interoperable with external clients and browser-based tooling without requiring a proprietary protocol.

The UI surfaces are:

- `/dashboard` — the primary static UI page for stream and mesh telemetry
- `/v1/mesh` — JSON mesh snapshot or bbox-filtered subset
- `/v1/mesh/ws` — live mesh telemetry stream (when `mesh_dashboard` is enabled)
- `/v1/streams/{id}/ws` — live stream subscription for media consumers
- `/dashboard/drones` and `/dashboard/drones/{id}` — optional drone-oriented view when `YUKKI_DRONE_DASHBOARD_ENABLED=1`

A browser or external client can therefore integrate by using the same authenticated endpoints the system already exposes. The static page stores the bearer token only in page memory and does not write it to disk.

## Manifest-driven multivariate mapping

See the [formal Multivariate Data-Source Manifest specification](MULTIVARIATE_DATASOURCE_MANIFEST.md) and its [JSON Schema](../schemas/multivariate-datasource-manifest.schema.json) for the versioned contract.

The Manifest of Drones can be used as a general multivariate datasource catalogue, not only as a list of aircraft. An application can describe heterogeneous sources—such as drone/satellite observations, weather stations, air-quality sensors, financial time series, or real-estate datasets—and associate each source with its variables, units, timestamps, spatial reference, provenance, update cadence, and payload location.

This enables an application to build map and time-series views that combine multiple measurements. Examples include:

- Environmental mapping: overlay drone imagery, satellite vegetation observations, rainfall, soil readings, and water-quality samples by location and collection time.
- Real-estate analysis: combine property locations and valuations with rental history, demographics, zoning, and nearby transport or services.
- Finance: align prices, trading volume, volatility, FX rates, and macroeconomic indicators over a selected instrument and time window. Financial datasets may be non-geospatial; they can still use the same manifest and stream model without appearing on a geographic map.

The manifest describes sources and their semantics; it does not itself fetch, normalize, or reconcile them. Application-side adapters must ingest each datasource, validate units and schemas, preserve provenance and timestamps, and handle differing sampling intervals and coordinate reference systems. YuKKi-OS supplies the mesh, stream, gateway, and broker primitives that an application can use after those adapters are wired in. The optional drone dashboard remains drone-oriented; a finance or general-purpose analytics UI requires an application-specific frontend.

## Features

- `GET /v1/mesh` returns a mesh snapshot or bbox-filtered subset
- `GET /v1/mesh?bbox=minLon,minLat,maxLon,maxLat&limit=500` is viewport-aware
- `GET /v1/mesh/ws` streams incremental mesh telemetry updates
- the existing `/dashboard` page gains a map panel and a "Map" toggle when the feature is enabled
- default builds remain unchanged unless the feature is enabled

## Build with the feature

```bash
cargo build --features mesh_dashboard --release
```

## Runtime

```bash
export YUKKI_GATEWAY_TOKEN="$(openssl rand -hex 32)"
./target/release/yukki_core_node gateway 127.0.0.1:7670 --insecure-dev
```

Then open `http://127.0.0.1:7670/dashboard` and use the dashboard map panel.

To exercise the same API from a non-browser client:

```bash
curl -H "Authorization: Bearer $YUKKI_GATEWAY_TOKEN" \
  http://127.0.0.1:7670/v1/mesh

curl -H "Authorization: Bearer $YUKKI_GATEWAY_TOKEN" \
  http://127.0.0.1:7670/v1/streams
```

For the optional drone dashboard:

```bash
export YUKKI_DRONE_DASHBOARD_ENABLED=1
export YUKKI_DRONE_DASHBOARD_MAX_CHUNKS=256
```

Then open `http://127.0.0.1:7670/dashboard/drones`.

## Notes

- The mesh dashboard is optional and not required for the core mesh or stream paths.
- Existing gateway auth still applies.
- The UI is designed to interoperate cleanly with external applications using the same JSON contracts already served by the system.
- In production, bind the gateway behind trusted networking or TLS termination.
