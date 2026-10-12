# Mesh dashboard and optional drone map

This feature is intentionally optional. It is behind the `mesh_dashboard` Cargo feature.

## Features

- `GET /v1/mesh` returns a mesh snapshot or bbox-filtered subset
- `GET /v1/mesh?bbox=minLon,minLat,maxLon,maxLat&limit=500` is viewport-aware
- `GET /v1/mesh/ws` can be added later for delta updates
- the existing `/dashboard` page gains a map panel and a "Map" toggle when the feature is enabled
- default builds remain unchanged unless the feature is enabled

## Build with the feature

```bash
cargo build --features mesh_dashboard --release
```

## Runtime

```bash
yukki_core_node gateway 127.0.0.1:7670 --insecure-dev
```

Then open `http://127.0.0.1:7670/dashboard` and use the dashboard map panel.

## Notes

- The mesh dashboard is optional and not required for the core mesh or stream paths.
- Existing gateway auth still applies.
- In production, bind the gateway behind trusted networking or TLS termination.
