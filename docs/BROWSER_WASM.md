# YuKKi-OS Browser WebAssembly Client

The browser-wasm directory contains a responsive static browser workspace and a dependency-free Rust verifier compiled to wasm32-unknown-unknown. It is a browser client for the existing stream gateway; it is not a browser build of the native YuKKi-OS node or a general-purpose HTML/CSS browser engine.

## Responsive workspace

The interface is mobile-first and fluid rather than tied to a fixed device-resolution list. Its layout adapts to available CSS viewport width and component space:

| Layout range | Behaviour |
| --- | --- |
| 320–671 CSS px | Single-column workspace, stacked forms, wrapping navigation and full-width touch actions |
| 672–1023 CSS px | Compact two-column form layouts; workspace remains a readable single column |
| 1024–1599 CSS px | Two-column workspace grid |
| 1600–2239 CSS px | Three-column wide workspace; chunk reader receives a taller dedicated column |
| 2240 CSS px and above | Expanded spacing and content width for ultrawide / 4K-class displays |

These are layout transition points, not supported-resolution limits. Intermediate widths, portrait/landscape changes, browser zoom, and OS text scaling use fluid sizing and reflow. The browser's device-pixel ratio is intentionally not used as a layout breakpoint: CSS viewport dimensions determine layout, while the browser handles raster density.

The interface includes a skip link, semantic landmarks, keyboard focus indicators, reduced-motion handling, forced-colors support, and larger controls for coarse pointers. The layout is designed to reflow at 320 CSS px and keep text readable under zoom; verify the result in the target browser/device matrix before release.

Run the responsive markup/style contract check with:

~~~sh
node browser-wasm/tests/responsive-layout.test.mjs
~~~

## Features

- Connects to a gateway using its base URL and bearer token.
- Lists GET /v1/streams descriptors.
- Reads bounded ranges through GET /v1/streams/{id}/chunks (the gateway caps each request at eight chunks).
- Checks every returned chunk by reconstructing its YKMC v1 frame and passing it through the Rust WASM verifier.
- Can poll the next retained sequence every two seconds.
- Lists authenticated `/v1/data-streams` separately from YKMC media streams and reads bounded schema-v1 observation ranges from `/v1/data-streams/{id}/observations`.
- Validates each adopted numeric observation through the Rust WASM core, preserving null/missing dimensions and exact u64 sequence/timestamp values.
- Keeps credentials in page memory only; it does not use local storage, cookies, query parameters, or credential-bearing WebSocket URLs.

The browser app intentionally uses authenticated HTTP range reads. The current gateway WebSocket path requires the Authorization header; the browser WebSocket API does not let applications set arbitrary request headers. Do not move bearer tokens into WebSocket query strings as a workaround.

The gateway is codec-agnostic. The client validates YKMC framing and metadata but does not decode or transcode H.264, Opus, or other media payloads.

## Multivariate data-stream adoption

The control plane exposes a separate authenticated data-observation API:
`GET /v1/data-streams` lists retained observation streams,
`GET /v1/data-streams/{id}/observations?from=0&limit=64` reads a bounded
sequence range, and authenticated native publishers use
`POST /v1/data-streams/{id}/observations` with schema-v1 NDJSON.
These endpoints do not reuse YKMC media chunks.

The native browser's Crawler utility can optionally publish numeric page
metrics through the already-configured node gateway. The browser-WASM
workspace lists the resulting crawler streams and validates each record in
Rust WASM before adoption. The gateway retains data streams in bounded
in-memory storage on that node; this is not durable persistence or peer-mesh
replication. See [bounded multivariate stream ingestion](MULTIVARIATE_STREAM_INGEST.md).


## MMO spatial WASM core

The same browser WASM module exposes the portable spatial and motion core described in [MMO Browser WASM integration](MMO_BROWSER_WASM.md). The page includes a local entity panel for WGS84/ECEF conversion and bounded spatiotemporal nearest-observation resolution. These sample entities remain in the WASM instance's linear memory; they are not posted to the gateway.

The spatial core is deliberately separate from the native daemon sketch. POSIX shared memory, futexes, pthread workers, and hardware SIMD are not browser APIs. Networked data continues to use the authenticated gateway, existing YKMC stream framing, and BRK1/BRK2 plus NXR1/WSM1 at the Overhauled broker boundary. The WASM resolver is a local computational primitive, not a new transport or authentication mechanism. The user-facing ingestion workflows for drone telemetry, finance/market-site data, environmental monitoring, and other multivariate sources are covered in [User how-to](USER_HOWTO_MMO.md). Browser-WASM performance measurements run against the compiled module with the data-driven harness described in [Benchmarking](BENCHMARKING.md).

## Build and run locally

From the repository root:

~~~sh
rustup target add wasm32-unknown-unknown
cargo test --manifest-path browser-wasm/Cargo.toml --locked
cargo build --manifest-path browser-wasm/Cargo.toml --release --locked --target wasm32-unknown-unknown

mkdir -p browser-wasm/dist
cp browser-wasm/index.html browser-wasm/app.js browser-wasm/styles.css browser-wasm/dist/
cp browser-wasm/target/wasm32-unknown-unknown/release/yukki_browser_core.wasm browser-wasm/dist/
~~~

Serve browser-wasm/dist/ over HTTPS using any static web server. Do not open the HTML page directly with file://; browsers block the module/WASM fetch in that mode. The static server should serve .wasm with Content-Type: application/wasm for best compatibility.

The multi-platform workflow uploads the ready-to-host site as the yukkios-browser-wasm artifact.

## Gateway setup and CORS

For a same-origin reverse proxy, serve the static site and proxy /v1/ to the gateway on the same origin. Leave CORS unset in that arrangement.

For a separately hosted site, configure the gateway with an exact comma-separated origin allow-list:

~~~sh
YUKKI_GATEWAY_CORS_ORIGINS=https://dashboard.example.com
~~~

Multiple origins may be separated by commas. Entries are exact origins (scheme, host, and optional port), not URL paths. Wildcards are rejected. Preflight requests are allowed only for GET and the Authorization / Content-Type request headers. Cookie credentials are not enabled; the browser sends the bearer token in the Authorization header and omits cookies.

Use HTTPS for remote sites and gateways. HTTP is accepted by the client only for localhost, 127.0.0.1, or [::1] development addresses. Keep the gateway bearer token private; CORS is not authentication and does not replace the gateway token.

## Deployment artifact layout

The CI artifact contains index.html, app.js, styles.css, and yukki_browser_core.wasm. Publish these files together under the same static origin. Configure the static host's Content Security Policy to permit same-origin scripts, wasm-unsafe-eval, and connections to the gateway origin. If using a reverse proxy, preserve the gateway's Authorization header.

## Validation boundary

The browser verifier accepts only exact YKMC v1 frames: correct magic/version, audio/video type, known flags, bounded UTF-8 stream and codec labels, a payload no larger than 256 KiB, and no trailing or truncated bytes. The verifier is a structural protocol guard, not a media decoder or a security boundary against a user controlling their own browser.


## Native browser runtime

The gateway workspace remains a browser-hosted WASM application; it does not render arbitrary websites. The separate native Wry-based page renderer, browser chrome, and current runtime security limits are documented in [YuKKi Browser Runtime](BROWSER_RUNTIME.md).
