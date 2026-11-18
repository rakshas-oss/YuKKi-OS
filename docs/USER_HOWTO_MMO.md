# User how-to: browser spatial and spatiotemporal features

This guide covers the v6.11.0 browser-WASM spatial feature set. It is an additive capability in the existing `browser-wasm/` application. It does not replace the native YuKKi-OS node, change the Overhauled repository boundary, or introduce a new network protocol.

## 1. Build and launch the browser application

From the YuKKi-OS repository root:

```sh
rustup target add wasm32-unknown-unknown
cargo test --manifest-path browser-wasm/Cargo.toml --locked
cargo build --manifest-path browser-wasm/Cargo.toml --release --locked --target wasm32-unknown-unknown

mkdir -p browser-wasm/dist
cp browser-wasm/index.html browser-wasm/app.js browser-wasm/styles.css browser-wasm/dist/
cp browser-wasm/target/wasm32-unknown-unknown/release/yukki_browser_core.wasm browser-wasm/dist/
```

Serve `browser-wasm/dist/` from a static HTTPS origin. Do not open the page using `file://`; browsers block the WASM module fetch in that mode. The static server should send `Content-Type: application/wasm` for the `.wasm` file.

For gateway connection, CORS, TLS, and artifact instructions, see [Browser WASM deployment](BROWSER_WASM.md).

## 2. Use the browser spatial panel

Open the deployed browser application and use **MMO spatial resolver**:

1. Enter a stable numeric entity ID.
2. Enter latitude and longitude in WGS84 degrees and altitude in metres.
3. Select **Add / update observation**. Reusing an ID updates that entity; new IDs consume one of the fixed 512 slots.
4. Add at least two observations in trajectory order if you intend to simplify a path.
5. Use **Resolve a spatiotemporal match** to enter a query position, maximum observation age, and maximum distance.
6. Use **Arc–secant–tangent path reduction** to reduce an ordered trajectory while retaining endpoints and sharp turns.

The panel's sample observations stay in the browser WASM instance. They are not uploaded to the gateway, persisted between page reloads, or sent to Overhauled. **Clear local entities** resets the local sample set.

## 3. Understand the spatial operations

- **WGS84 to ECEF:** converts geodetic latitude/longitude/altitude to Earth-Centred, Earth-Fixed metres.
- **ENU transforms:** converts positions relative to a local origin into east/north/up metres, and converts ENU vectors back to ECEF.
- **Hermite interpolation:** estimates a position between two samples using endpoint positions and velocities. The interpolation parameter is normalized to 0..1 and the interval is supplied in seconds.
- **Bounding-box query:** uses inclusive WGS84 bounds. A west longitude greater than east denotes a box crossing the antimeridian.
- **Nearest-observation resolution:** selects the nearest eligible entity in ECEF space, rejecting observations from the future, observations older than the supplied maximum age, and observations beyond the supplied distance.
- **Arc–secant–tangent simplification:** applies an iterative, bounded Douglas–Peucker-style reduction. Positional error combines perpendicular chord deviation and arc excess; a separate tangent-turn limit protects sharp turns. Output entries are indices into the original ordered point list.

The spatial entity store and path simplifier each have a 512-entry bound. Invalid coordinates, non-finite values, negative distances/tolerances, and capacity overflow are rejected. These limits are intentional safeguards.

## 4. Apply the resolver to multivariate data sources

The spatial core is domain-neutral. A drone manifest is one possible source, not a required schema. The same processing pattern can be used with finance, environmental monitoring, logistics, telemetry, or other timestamped multivariate observations.

Use an application-side adapter to normalize each source record into:

| Normalized field | Purpose |
|---|---|
| `entity_id` | Stable numeric identity for an asset, sensor, station, route sample, or observation source |
| `latitude_deg`, `longitude_deg`, `altitude_m` | WGS84 location used by the spatial core |
| `timestamp_ns` | Source observation time as unsigned nanoseconds |
| `attributes` | Domain values kept by the application, such as price, volume, temperature, humidity, air quality, battery, or status |

Only identity, position, and observation time are represented in the current spatial entity store. Keep domain attributes in the host application's own records and join them to the selected entity ID; do not assume the WASM spatial ABI stores arbitrary key/value attributes.

### Drone manifest example

For a drone fleet, map each vehicle's stable manifest ID to a numeric entity ID, and map its latest validated GNSS position and observation timestamp to WGS84 plus nanoseconds. Retain battery level, payload state, velocity, mission phase, and health flags in the manifest/application record.

Use a bounding-box query to select vehicles in an operating region, then use the nearest resolver with a freshness ceiling and maximum distance to choose a relevant observation for a local task. Use the path simplifier on an ordered flight trajectory for a lower-cost map display. Do not use simplified display geometry as the authoritative flight path or as a safety-critical navigation input.

### Finance example

For geospatial finance data—such as exchange locations, branch networks, commodity facilities, or geographically tagged market observations—map the site or instrument location and its observation time into the spatial fields. Keep price, volume, spread, volatility, instrument symbol, and market/session metadata in the host data model.

The resolver can select a spatially nearby observation subject to a maximum age, which helps prevent stale market data from being treated as current. It does not calculate prices, forecast returns, perform portfolio risk analysis, or establish that two financial observations are economically comparable. Apply instrument, currency, venue, and session filters in the application before interpreting a match.

### Environmental mapping example

For weather stations, air-quality sensors, water gauges, or remote-sensing samples, map each station/sample location and capture time into the spatial fields. Keep temperature, precipitation, particulate concentration, water level, quality flags, and sensor provenance in the source record.

Use a bounding-box query to select a region and freshness/distance limits to identify relevant observations. Preserve units, calibration metadata, quality flags, and source provenance in the host data layer. A nearest observation is not automatically representative of an entire region; use domain-specific interpolation or aggregation where the application requires a field estimate.

### Recommended ingestion sequence

1. Validate source identity, coordinate reference system, units, and timestamp.
2. Convert coordinates to WGS84 and timestamps to unsigned nanoseconds.
3. Keep the original record and its domain-specific attributes in the host application or authoritative data store.
4. Upsert the spatial identity and location into the bounded WASM store.
5. Apply source-specific filters (instrument, sensor quality, mission status, or other domain criteria) before or after spatial selection as appropriate.
6. Resolve by location, observation time, maximum age, and maximum distance.
7. Join the selected stable ID back to the original record to read its multivariate attributes.
8. Record the selected source ID, timestamp, thresholds, and quality/provenance alongside downstream results for reproducibility.

Do not mix coordinate systems, units, or time bases. Convert source timestamps explicitly; the browser spatial ABI accepts nanoseconds, while gateway media chunk timestamps are milliseconds. Do not multiply timestamps without first checking their source representation and overflow bounds.

## 5. Connect network data safely

The browser page and WASM core have separate responsibilities:

- JavaScript performs authenticated HTTP requests to the YuKKi-OS gateway.
- The Rust WASM module validates YKMC v1 chunk framing and runs local spatial calculations.
- The browser module does not open sockets, access POSIX shared memory, or communicate directly with accelerator hardware.

Keep the gateway bearer token in page memory and send it in the Authorization header. Use HTTPS for remote deployments. Configure `YUKKI_GATEWAY_CORS_ORIGINS` with exact allowed origins for cross-origin hosting; CORS is not authentication. Never put bearer tokens in URLs.

The browser verifier checks structure and bounds; it does not decode H.264, Opus, or other media codecs. The browser spatial panel's sample records are local examples and are not automatically populated from gateway streams.

## 6. Preserve the protocol and deployment boundaries

- YKMC v1 remains the browser media-chunk framing contract.
- BRK1/BRK2 remain the broker envelope versions.
- NXR1 remains the geospatial broker frame contract.
- WSM1 remains the sandbox task/lifecycle payload contract.
- Overhauled remains the broker execution and accelerator-placement tier; YuKKi-OS remains the control-plane and gateway authority.
- The browser target is `wasm32-unknown-unknown`; the WASI guest worker is a separate `wasm32-wasip1` artifact. Neither is a browser build of the native node.

See [MMO Browser WASM integration](MMO_BROWSER_WASM.md) for the exported ABI, algorithm limits, and native-only exclusions; see [API](API.md) for broker and NXR1 details.
