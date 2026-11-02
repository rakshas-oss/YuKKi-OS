# YuKKi-OS Browser WebAssembly Client

The browser-wasm directory contains a static browser application and a dependency-free Rust verifier compiled to wasm32-unknown-unknown. It is a browser client for the existing stream gateway; it is not a browser build of the native YuKKi-OS node.

## Features

- Connects to a gateway using its base URL and bearer token.
- Lists GET /v1/streams descriptors.
- Reads bounded ranges through GET /v1/streams/{id}/chunks (the gateway caps each request at eight chunks).
- Checks every returned chunk by reconstructing its YKMC v1 frame and passing it through the Rust WASM verifier.
- Can poll the next retained sequence every two seconds.
- Keeps credentials in page memory only; it does not use local storage, cookies, query parameters, or credential-bearing WebSocket URLs.

The browser app intentionally uses authenticated HTTP range reads. The current gateway WebSocket path requires the Authorization header; the browser WebSocket API does not let applications set arbitrary request headers. Do not move bearer tokens into WebSocket query strings as a workaround.

The gateway is codec-agnostic. The client validates YKMC framing and metadata but does not decode or transcode H.264, Opus, or other media payloads.

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
