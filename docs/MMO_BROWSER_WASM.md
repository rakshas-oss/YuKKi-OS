# Browser WASM MMO integration

The MMO suite is integrated additively through YuKKi-OS's existing
`browser-wasm` application. The original `overhauled` and `YuKKi-OS`
repositories remain separate; this is not a monorepo conversion, native daemon
replacement, or change to the broker protocol.

## Runtime split

- **Browser execution:** `browser-wasm/src/mmo.rs` provides bounded, portable
  spatial and motion primitives compiled into the existing
  `wasm32-unknown-unknown` browser module.
- **Browser host:** `browser-wasm/app.js` handles forms, rendering, and
  authenticated gateway/stream HTTP. The WASM module does not open sockets or
  access browser APIs.
- **Control plane:** YuKKi-OS retains mesh, manifest, gateway, stream, and
  authorization responsibilities.
- **Broker/execution plane:** Overhauled retains accelerator placement and
  BRK1/BRK2 broker execution. Its existing NXR1 geospatial codec and WSM1 task
  boundary remain the wire contracts for broker-side work.

The browser module is single-threaded and uses bounded memory. It does not
claim to implement the original POSIX shared-memory daemon in a browser.

## Portable features

The initial browser module exposes:

- WGS84 geodetic to ECEF conversion.
- WGS84 to local ENU and ENU to ECEF transforms, including the vertical
  component (the uploaded scaffold's ENU implementation omitted it).
- Cubic Hermite position interpolation.
- A fixed-capacity, 512-entity spatial store with stable-ID upsert.
- Inclusive WGS84 bounding-box queries, including antimeridian-crossing boxes.
- Spatiotemporal nearest-observation resolution, filtering future observations,
  stale observations, and candidates outside a maximum ECEF distance.

Coordinates are validated for finite values and WGS84 latitude/longitude
ranges. Entity storage is bounded; an insert beyond capacity returns a stable
error code instead of allocating without limit. Timestamps are unsigned
nanoseconds supplied by the host.

## Arc–secant–tangent geometric reduction

The browser module also provides a bounded path simplifier. It uses an
iterative Douglas–Peucker-style split stack, with an error metric combining:

- **Secant deviation:** perpendicular distance from each candidate point to
  the endpoint chord.
- **Arc excess:** half of the excess of the two-segment path length over the
  endpoint chord length.
- **Tangent guard:** an independent maximum-turn constraint that forces a
  split at sharp direction changes even when the positional tolerance is
  large.

The input is WGS84 and distances/tangents are evaluated in ECEF metres. The
algorithm has fixed storage for 512 points, preserves the first and last
points, avoids recursion, and returns original point indices. The tangent
limit is configurable from 1 to 180 degrees; the positional tolerance is a
non-negative metre value. Use regional path segments or pre-tiled geometry
for efficient map rendering—this is a bounded simplifier, not a general
topology-preserving polygon generalizer. It operates on ordered trajectories,
not arbitrary polygon rings.

The browser UI can simplify the current ordered entity sequence and reports
the retained point count and percentage reduction. This is local processing
inside WASM; it does not mutate the broker's source data or overwrite
observations in the YuKKi-OS control plane.

## Browser WASM exports

The browser module keeps the existing YKMC exports and additionally exports:

- `adi_mmo_reset`
- `adi_mmo_entity_count`
- `adi_mmo_upsert_entity`
- `adi_mmo_query_wgs84_bbox`
- `adi_mmo_query_count`
- `adi_mmo_query_entity_index`
- `adi_mmo_entity_id`, `adi_mmo_entity_lat`, `adi_mmo_entity_lon`,
  `adi_mmo_entity_alt`, `adi_mmo_entity_timestamp_ns`
- `adi_mmo_resolve_nearest`
- `adi_mmo_wgs84_to_ecef`, `adi_mmo_wgs84_to_enu`,
  `adi_mmo_enu_to_ecef`, `adi_mmo_hermite_position`
- `adi_mmo_simplify_reset`, `adi_mmo_simplify_push_wgs84`,
  `adi_mmo_simplify_run`, `adi_mmo_simplify_output_count`,
  `adi_mmo_simplify_output_index`, and output coordinate accessors

The coordinate and interpolation functions return a pointer to three
little-endian f64 values in WASM linear memory, or a null pointer when the
arguments are invalid. JavaScript must copy the three values before calling
another function that writes the same result buffer.

## Deliberate native-only boundaries

The uploaded C scaffold is useful as a domain sketch, but several parts cannot
be copied directly into browser WASM:

- POSIX `shm_open`, `mmap`, futex syscalls, pthread workers, and daemon
  lifecycle are native-host facilities, not browser APIs.
- Its packed `adi_packet_t` is a host-layout C struct, not an endian-neutral
  wire protocol. Use the existing length-prefixed BRK1/BRK2 envelopes and
  versioned NXR1/WSM1 payload formats at the broker boundary.
- Hardware-specific SIMD and device execution remain backend concerns.
- The uploaded codec is a placeholder, and its octree implementation is a
  bounded flat array rather than an actual octree. Neither is presented as a
  production implementation in this browser increment.

When a future deployment needs shared-memory transport, the browser host must
use the existing authenticated gateway/stream path or a separately qualified
host bridge. Do not expose raw process pointers or credentials to the page.

## User workflows

For step-by-step browser usage, including drone-manifest ingestion patterns and examples for finance and environmental multivariate data, see [User how-to: browser spatial and spatiotemporal features](USER_HOWTO_MMO.md). That guide also covers timestamp normalization, attribute joins, freshness/distance policy, and safe deployment boundaries.

## Build and test

From the YuKKi-OS repository root:

```sh
rustup target add wasm32-unknown-unknown
cargo fmt --manifest-path browser-wasm/Cargo.toml -- --check
cargo test --manifest-path browser-wasm/Cargo.toml --locked
cargo clippy --manifest-path browser-wasm/Cargo.toml --locked --target wasm32-unknown-unknown -- -D warnings
cargo build --manifest-path browser-wasm/Cargo.toml --release --locked --target wasm32-unknown-unknown
```

The browser build workflow also smoke-tests the exported ABI. Unit tests cover
WGS84/ECEF, full ENU transforms, Hermite endpoints, fixed-capacity behavior,
antimeridian queries, and temporal freshness filtering.

This increment establishes the browser-side computational path. It does not
claim that the native MMO daemon, multi-process MPMC queue, hardware compositor,
or real-time deployment has been ported to WASM.
