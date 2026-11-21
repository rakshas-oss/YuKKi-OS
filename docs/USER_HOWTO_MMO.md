# User how-to: browser spatial, spatiotemporal, and multivariate data

This guide covers the browser-side spatial and motion feature set first shipped in
the published YuKKi-OS v6.12.0, v6.13.0 and v6.14.0 releases, and retained
in the v6.15.0 feature candidate. It is additive: the native node, the separate
`rakshas-oss/overhauled` repository, and the existing wire protocols remain in
place. The browser path uses the existing `browser-wasm/` application and
`wasm32-unknown-unknown` target.

## 1. Build and run the browser application

From the YuKKi-OS repository root:

```sh
rustup target add wasm32-unknown-unknown
cargo fmt --manifest-path browser-wasm/Cargo.toml -- --check
cargo test --manifest-path browser-wasm/Cargo.toml --locked
cargo build --manifest-path browser-wasm/Cargo.toml --release --locked --target wasm32-unknown-unknown

mkdir -p browser-wasm/dist
cp browser-wasm/index.html browser-wasm/app.js browser-wasm/styles.css browser-wasm/dist/
cp browser-wasm/target/wasm32-unknown-unknown/release/yukki_browser_core.wasm browser-wasm/dist/
```

Serve `browser-wasm/dist/` from a static HTTPS origin. Do not open the page
using `file://`: browsers block the WASM module fetch in that mode. Configure
the static host to serve `.wasm` with `Content-Type: application/wasm`.

The browser verifier and spatial module are not a browser build of the native
node. The browser target is `wasm32-unknown-unknown`; the separate WASI guest
worker uses `wasm32-wasip1`.

## 2. Use the MMO spatial panel

Open the deployed application and find **MMO spatial resolver**.

1. Enter a stable numeric entity ID. The current ABI accepts a 32-bit unsigned
   ID (the UI keeps the maximum below the reserved all-ones sentinel).
2. Enter latitude and longitude in WGS84 degrees and altitude in metres.
3. Select **Add / update observation**. Reusing an ID replaces that entity;
   adding a new ID consumes one of the fixed 512 slots.
4. Add multiple observations in insertion/trajectory order when you plan to
   simplify a path.
5. Use **Resolve nearest eligible entity** with a query position, maximum age,
   and maximum distance.
6. Use **Simplify current entity path** to reduce the current ordered sequence
   while preserving endpoints and significant turns.

The panel's sample entities live in the WASM instance's linear memory. They are
not uploaded to the gateway, persisted across page reloads, or sent to
Overhauled. **Clear local entities** resets this local sample store.

The UI timestamps inserted records using the browser clock and stores them as
unsigned nanoseconds. The resolver query also uses the browser clock. For
external feeds, normalize the source timestamp explicitly rather than assuming
every system uses the browser clock or the same epoch/unit.

## 3. What the spatial and motion operations do

- **WGS84 to ECEF:** converts geodetic latitude/longitude/altitude to
  Earth-Centred, Earth-Fixed coordinates in metres.
- **WGS84 to ENU:** expresses a point as east/north/up metres relative to a
  WGS84 origin.
- **ENU to ECEF:** transforms local east/north/up values into Earth-fixed
  coordinates around an origin.
- **Hermite interpolation:** estimates a point between endpoint positions and
  velocities. The interpolation parameter is normalized to 0..1 and the
  interval is supplied in seconds.
- **Bounding-box query:** applies inclusive WGS84 bounds. A west longitude
  greater than east represents a box crossing the antimeridian.
- **Nearest-observation resolution:** selects the spatially nearest eligible
  entity in ECEF space. It rejects future observations, observations older
  than the supplied maximum age, and candidates at or beyond the maximum distance (the upper bound is strict).
- **Arc–secant–tangent simplification:** applies an iterative, bounded
  Douglas–Peucker-style path reduction. Positional error combines perpendicular
  deviation from the endpoint chord with arc-length excess. A separate
  tangent-turn guard forces a split at sharp direction changes.

The entity store and path simplifier each have a 512-entry capacity. The current
bounding-box and nearest-observation operations scan the active entries; they
are bounded linear scans, not an R-tree or other indexed spatial engine.
Invalid coordinates, non-finite numbers, negative distance/tolerance values,
and capacity overflow are rejected. The optional radius_m value is retained
with each entity but is not currently used by the nearest resolver; apply any
radius-aware matching policy in the host application.

The simplifier returns indices into the original ordered point list. It
preserves the first and last point and retains sharp turns even when a large
positional tolerance would otherwise remove them. Straight or gently curved
segments can often be represented with fewer points; a route with important
turns should retain those turns. The simplified result is for display,
summarization, or downstream non-safety-critical geometry—not authoritative
flight navigation or a topology-preserving polygon operation.

## 4. Use the Manifest of Drones as a multivariate data-source manifest

The Manifest of Drones is not limited to drones. The existing
[Multivariate Data-Source Manifest schema](../schemas/multivariate-datasource-manifest.schema.json)
describes heterogeneous sources, their variables, units, temporal/spatial
semantics, transport, provenance, quality metadata, and application access
policy. Its `domain` label can describe drone, finance, real-estate,
environmental, industrial, or mixed datasets.

A source can expose many variables and a workflow can combine multiple
sources. Sources do not need to share a sample frequency, unit system,
coordinate reference system, transport, or spatial resolution. Validate and
normalize these differences in an application-side adapter; preserve original
values, units, timestamps, null markers, quality flags, and provenance.

There are two related but distinct manifest contracts. The file
schemas/multivariate-datasource-manifest.schema.json describes the
application-level source catalogue: variables, units, transport, temporal and
spatial semantics, provenance, quality, and access-policy references. The
native benchmark runner does not ingest that schema directly. It consumes the
version-1 benchmark manifest at
examples/benchmark-datasets/manifest.json, which names JSONL source files,
sequence/timestamp fields, optional geographic fields, numeric feature
mappings, and benchmark profiles. An application adapter or conversion step
must map source-catalogue entries into that runner manifest while preserving
the original record and its provenance.

### Normalize only the fields needed by the spatial core

The browser spatial store represents identity, location, and observation time.
It does not store arbitrary multivariate attributes. A typical application-side
projection is:

| Normalized field | Purpose |
|---|---|
| `entity_id` | Stable numeric ID for an asset, station, venue, property, or observation source |
| `latitude_deg`, `longitude_deg`, `altitude_m` | Validated WGS84 location |
| `timestamp_ns` | Source observation time converted to unsigned nanoseconds |
| `radius_m` | Optional application-defined observation radius |
| `attributes` | Original domain values retained by the host application |

Keep `attributes` in the original host-side record or authoritative data
store. Upsert the spatial projection into WASM, use the returned stable entity
ID/index to join back to the source record, and retain the source ID,
timestamp, thresholds, and provenance with any downstream result.

### Drone telemetry

Map each vehicle's stable manifest identifier to a numeric entity ID. Project
validated GNSS latitude/longitude/altitude and observation time into the WASM
store. Keep battery percentage, ground speed, velocity, payload state, mission
phase, health flags, operator, and vehicle metadata in the host-side manifest.

Use bounding-box selection to find vehicles in an operational region. Use the
nearest resolver with a maximum age and distance to reject stale or irrelevant
observations. Simplify an ordered path for a lower-cost map display. Do not use
the simplified display path as an authoritative flight plan, geofence, or
safety-critical navigation input.

### Finance and market-site mapping

The same pattern applies to geospatial finance data such as exchange locations,
broker branches, commodity facilities, data-centre locations, or geographically
tagged market observations. Project the venue/site location and observation
timestamp into the spatial fields. Keep instrument symbol, bid/ask, price,
volume, spread, volatility, currency, venue, market session, and source
metadata in the host record.

The resolver can select a spatially nearby observation subject to freshness and
distance limits. It does not calculate prices, forecast returns, recommend
trades, calculate portfolio risk, or establish that two instruments or venues
are economically comparable. Apply instrument, currency, venue, calendar, and
session filters in the application before interpreting a spatial match.

### Environmental data mapping

For weather stations, air-quality monitors, water gauges, soil sensors,
satellite tiles, or drone/satellite observation sets, project the sample
location and capture time into the spatial fields. Keep temperature,
precipitation, particulate concentration, water level, soil moisture,
vegetation indices, sensor calibration, uncertainty, and quality flags in the
source record.

Use bounding-box queries to select a region and freshness/distance policy to
identify candidate observations. A nearest sensor is not automatically
representative of an entire region. Use domain-appropriate interpolation,
aggregation, grid resampling, and quality control when an application needs a
spatial field estimate.

### Real-estate and other datasets

Property registries, valuation observations, transaction/rental history, and
nearby infrastructure can use the same source catalogue. Keep property ID,
valuation date, currency, tenure, zoning, and provenance in host-side records.
The spatial resolver can help locate and time-filter observations; it does not
value property or infer demographic or legal attributes.

## 5. Recommended ingestion sequence

1. Validate the manifest and source schema against the data-source contract.
2. Validate the source coordinate reference system, units, timestamp format,
   stable identity, and provenance.
3. Convert location to WGS84 and time to unsigned nanoseconds using explicit
   unit/epoch conversion with overflow checks.
4. Keep the complete source record and its domain attributes in the host-side
   data model or authoritative store.
5. Upsert only the spatial projection into the bounded WASM store.
6. Apply domain filters such as instrument/session, sensor quality, mission
   status, or property type at the application layer.
7. Resolve by location, observation time, maximum age, and maximum distance.
8. Join the selected entity ID back to the original record and retain the
   source ID, thresholds, adapter version, and provenance with the result.

Do not confuse media chunk timestamps (milliseconds in the gateway model) with
the spatial ABI's nanoseconds. Convert explicitly; never multiply timestamps
without verifying their source representation and overflow bounds.

## 6. Connect network data safely

The browser page and WASM module have separate responsibilities:

- JavaScript handles authenticated HTTP requests to the YuKKi-OS gateway and
  the user interface.
- Rust WASM validates YKMC v1 chunk framing and performs local spatial and
  motion calculations.
- The WASM module does not open sockets, access POSIX shared memory, or talk
  directly to accelerator hardware.

Keep the gateway bearer token in page memory and send it in the Authorization
header. Use HTTPS for remote deployments. Configure
`YUKKI_GATEWAY_CORS_ORIGINS` with exact allowed origins for cross-origin
hosting. CORS is not authentication. Never put bearer tokens in URLs.

The browser verifier checks structure and bounds; it does not decode H.264,
Opus, or other media codecs. The sample spatial panel is local and is not
automatically populated from gateway streams.

## 7. Preserve repository and protocol boundaries

- YuKKi-OS remains the control-plane, mesh, gateway, manifest, and browser
  application authority.
- Overhauled remains a separate repository and owns broker execution and
  accelerator placement.
- YKMC v1 remains the browser media-chunk framing contract.
- BRK1/BRK2 remain the broker envelope versions.
- NXR1 remains the geospatial broker frame contract.
- WSM1 remains the sandbox task/lifecycle payload contract.
- The browser WASM target `wasm32-unknown-unknown` and WASI guest target
  `wasm32-wasip1` remain separate build products.

See [MMO Browser WASM integration](MMO_BROWSER_WASM.md) for the ABI and
algorithm constraints, [Drone interoperability](DRONE_INTEROP.md) for the
manifest and adapter patterns, and [Benchmarking](BENCHMARKING.md) for the
dataset-driven native and browser-WASM measurement harnesses.


## 8. Run benchmark-backed workload checks

The native and browser runners answer different questions. The native
manifest-driven runner measures declared JSONL source records and bounded
policy candidates; the eigensolver runner measures numerical quality as well
as speed; the browser runner measures the compiled spatial WASM module.

From the YuKKi-OS repository root:

~~~sh
cargo run --release --bin yukki_dataset_bench -- --manifest examples/benchmark-datasets/manifest.json --dataset all --profile all --output dataset-benchmark.json

cargo run --release --bin yukki_eigensolver_bench -- --manifest examples/benchmark-datasets/manifest.json --dataset all --profile all --output eigensolver-benchmark.json

rustup target add wasm32-unknown-unknown
cargo build --manifest-path browser-wasm/Cargo.toml --release --locked --target wasm32-unknown-unknown
node browser-wasm/bench/run.mjs --quick --output browser-wasm-benchmark.json
~~~

For the optional live broker leg, build and start the CPU-only Overhauled
broker as described in the [system administration how-to](SYSADMIN_HOWTO.md),
then rerun the browser command with:

~~~sh
node browser-wasm/bench/run.mjs --quick --broker-host 127.0.0.1 --broker-port 9090 --broker-device cpu --output browser-wasm-brk2.json
~~~

Review the report's execution scope before comparing results. Local WASM
measurements are not broker measurements; broker telemetry is taken from the
BRK2 response, not inferred from the requested device. CPU is the correctness
baseline. Use GPU/NPU preferences only on deliberately configured brokers and
confirm the returned backend and selected GPU ID. The browser benchmark
submits host-side numeric records; it does not execute WSM1 guests in
Overhauled.

The checked-in finance, drone, and environmental fixtures are synthetic.
Replacing them with real sources requires explicit units, timestamp/epoch
normalization, coordinate validation, access policy, provenance, quality
metadata, and any required licensing. Benchmark throughput does not validate
a financial model, environmental estimate, drone mission, or production
workload by itself. Use [Benchmarking](BENCHMARKING.md) for sampling,
reproducibility, CI, and interpretation details.
