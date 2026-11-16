# Multivariate Data-Source Manifest

## Purpose

The Manifest of Drones generalizes to a **domain-independent multivariate data-source manifest**. “Drone” is one source kind, not a restriction on the data model. A manifest describes heterogeneous sources, the variables each source provides, units and dimensions, temporal and spatial semantics, provenance, quality, and transport/adapter metadata.

The normative version-1 JSON Schema is [`schemas/multivariate-datasource-manifest.schema.json`](../schemas/multivariate-datasource-manifest.schema.json).

## Application domains

- **Drones and robotics:** position, attitude, battery, imagery, range/depth, payload and mission events.
- **Finance:** instrument prices, trading volume, volatility, rates, FX, macroeconomic series and portfolio exposures. Preserve instrument/exchange identifiers, currency, market calendar and event/observation timestamps.
- **Real estate:** property attributes, valuations, transaction and rental histories, occupancy, zoning, demographics and nearby infrastructure. Preserve property identifiers, valuation dates and spatial references.
- **Environmental mapping:** drone and satellite imagery, weather, air quality, soil and water measurements, vegetation indices and land-use observations. Preserve calibration, units, coordinate reference systems, spatial resolution and collection time.

Sources can be non-geospatial. Financial time series, for example, use temporal dimensions without requiring a map coordinate system.

## Manifest structure

A version-1 manifest contains a version, stable manifest identifier, timestamps, optional domain label, and one or more sources. Each source has a stable identifier, source kind, one or more variables, required provenance, and optional temporal, spatial, transport, quality, access-policy and extension metadata.

Each variable declares its type, unit, dimensions, coordinate role and optional schema reference. Optional relationships describe source correlations, derivations, calibration, spatial overlap or temporal alignment.

The manifest describes semantics; it does not itself harmonize units, resample time series, transform coordinate systems, or fill missing values.

## Example: environmental mapping

```json
{
  "manifest_version": "1.0",
  "manifest_id": "regional-watershed-survey",
  "created_at": "2026-11-16T10:00:00Z",
  "domain": "environmental",
  "sources": [
    {
      "source_id": "uav-survey-17",
      "kind": "drone",
      "name": "Watershed UAV survey",
      "variables": [
        { "variable_id": "image_tile", "value_type": "binary", "unit": "encoded_image", "dimensions": ["time", "latitude", "longitude"] },
        { "variable_id": "altitude", "value_type": "number", "unit": "m", "dimensions": ["time"] }
      ],
      "temporal": { "timestamp_semantics": "observation_time" },
      "spatial": { "reference_system": "EPSG:4326", "geometry_type": "raster" },
      "transport": { "protocol": "live_media_stream", "stream_id": "watershed-uav-17", "media_type": "image/tiff" },
      "provenance": { "origin": "survey-team-alpha", "collected_at": "2026-11-16T09:30:00Z" },
      "quality": { "status": "unvalidated", "missing_value_policy": "preserve-and-flag" }
    },
    {
      "source_id": "weather-station-4",
      "kind": "weather_station",
      "variables": [
        { "variable_id": "rainfall", "value_type": "number", "unit": "mm", "dimensions": ["time"] },
        { "variable_id": "air_temperature", "value_type": "number", "unit": "Cel", "dimensions": ["time"] }
      ],
      "temporal": { "sampling_interval": "PT10M", "timestamp_semantics": "observation_time" },
      "spatial": { "reference_system": "EPSG:4326", "geometry_type": "point" },
      "provenance": { "origin": "station-network-operator" }
    }
  ],
  "relationships": [
    {
      "from_source": "uav-survey-17",
      "to_source": "weather-station-4",
      "relation": "temporally_aligns",
      "description": "Correlate image collection windows with local rainfall observations."
    }
  ]
}
```

## Finance example

A finance manifest can describe separate market-feed sources for prices and volumes, plus a macroeconomic source for rates. Variables should declare currency and units; use dimensions such as `time` and `instrument`. Set a market calendar where relevant. Do not treat different exchanges' timestamps or trading sessions as interchangeable.

## Resolution and ingestion rules

1. **Discover:** read the manifest and resolve source IDs and non-secret endpoint/configuration references.
2. **Authorize:** enforce application access policy before fetching or subscribing. Never put bearer tokens, passwords, private keys or other credentials in a manifest.
3. **Validate:** check schema version, identifiers, payload size, variable types, units, timestamps, coordinate reference systems and provenance.
4. **Adapt:** use a source-specific adapter to convert source payloads into the application's normalized observation representation. Record adapter and version.
5. **Align:** apply explicit temporal resampling, calendar rules, unit conversions and coordinate transformations. Preserve original values and metadata, and mark missing/invalid observations rather than silently dropping or coercing them.
6. **Publish/process:** use YuKKi-OS stream and broker interfaces for chunked data and bounded processing tasks as appropriate.
7. **Audit:** retain source lineage, timestamps, quality flags and transformation versions.

## YuKKi-OS integration boundary

The manifest is a catalogue and metadata contract. YuKKi-OS provides mesh, gateway, stream and broker primitives that applications can use after their domain-specific adapters are wired in. A manifest does not automatically add connectors for finance APIs, property registries, satellite products or environmental sensor networks.

Use `LiveMediaStreams` / `MediaChunk` for ordered or chunked observations and larger payloads, and `BrokerTasks` for bounded request/response processing. Use gateway and mesh APIs for discovery/distribution only where the application has implemented and authorized that path.

The optional `/dashboard/drones` UI remains drone-oriented. Other domains require an application-specific frontend or analytics view; the common manifest does not imply that a finance dashboard or real-estate connector ships with YuKKi-OS.

## Compatibility and security

Consumers should reject unsupported major manifest versions, validate required fields, and ignore unknown namespaced extension fields unless configured otherwise. Do not infer units, coordinate systems, timestamp semantics or missing-value behavior from variable names.

Treat manifests and source metadata as untrusted input. Keep credentials in a secret manager or protected runtime configuration, enforce size/timeout/rate/retention limits at ingestion, preserve provenance and licensing, and verify semantic compatibility before joining datasets.
