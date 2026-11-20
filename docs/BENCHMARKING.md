# Benchmarking YuKKi-OS

This guide describes the native Criterion suites and the browser-WASM
measurement runner introduced for v6.12.0 and retained in the published v6.13.0 baseline and v6.14.0 feature candidate. Benchmark inputs are
fixture-driven: source datasets live in versioned JSON files, and benchmark
code consumes those fixtures instead of maintaining independent hard-coded
sample values.

## 1. Benchmark datasets are the source of truth

### Native Criterion fixture

`benches/datasets/native-v1.json` drives all three native Criterion targets:

- `spatiotemporal_frame_construction` reads the frame values and fixed payload.
- NXR1 encode/decode and resolver dispatch read their frame, payload size,
  sequence, and route configuration from the same fixture.
- X25519 and ChaCha20-Poly1305 measurements read test keys, nonce bytes,
  message bytes, and payload sizes from the fixture.

The Rust benchmark sources load it using `include_str!`; changing the fixture
changes benchmark input without editing the measurement loops. The crypto
material is deterministic and test-only. Never reuse its keys or nonce values
in production.

### Manifest-driven native workloads and eigensolver

`examples/benchmark-datasets/manifest.json` points to bounded source JSONL
datasets. The manifest's `feature_fields` order is authoritative; records are
not regenerated with random numbers by the benchmark runner. Each profile
selects the source rows, warm-up/sample sizes, batch sizes, worker counts,
objective, domain applicability, and optional P95 latency ceiling.

Run the native dataset and policy-selection benchmark:

```sh
cargo run --release --bin yukki_dataset_bench -- \
  --manifest examples/benchmark-datasets/manifest.json \
  --dataset all --profile all --output benchmark-results.json
```

The CLI measures NXR1 round trips and, for applicable domains, geospatial
trajectory workloads. It reports the candidates and chosen bounded execution
policy. The profile decides whether latency, throughput, working set, or
geospatial throughput is optimized; do not replace source rows with a
synthetic benchmark-only dataset.

Run the dataset-driven symmetric eigensolver benchmark:

```sh
cargo run --release --bin yukki_eigensolver_bench -- \
  --manifest examples/benchmark-datasets/manifest.json \
  --dataset all --profile all --output eigensolver-results.json
```

The runner turns the declared numeric features into bounded correlation
matrices and invokes YuKKi-OS's CPU cyclic-Jacobi eigensolver. Reports include
throughput, mean/P95 solve latency, residual, orthogonality error, and a
deterministic checksum. Numerical quality remains visible alongside speed.
The eigensolver is limited to finite real-symmetric matrices of dimension
1..=64; it does not imply general non-symmetric support or accelerator use.

### Browser-WASM multivariate fixture

`browser-wasm/bench/datasets/multivariate-v1.json` defines deterministic
synthetic profiles for:

- drone telemetry (battery, speed, payload, mission phase);
- finance-site observations (indicative synthetic price, volume, spread,
  venue, currency); and
- environmental sensors (temperature, particulate concentration, water
  level, quality and calibration metadata).

The manifest also sets the supported sample sizes (16, 128, and 512), time
intervals, spatial origins, attribute generators, and path-simplification
parameters. `browser-wasm/bench/run.mjs` materializes records from that
manifest and passes only stable ID, WGS84 location, altitude, timestamp, and
radius through the WASM spatial ABI. Domain attributes stay in host-side
records and are identified in the report.

These profiles are synthetic test fixtures, not observations from actual
drone fleets, markets, exchanges, or environmental stations. Replace or extend
them with controlled, licensed datasets when representative real-world
workloads are available. Preserve source provenance, units, and data
classification.

## 2. Native Criterion inventory

The root `Cargo.toml` declares three Criterion harnesses:

| Target | Benchmark ID | Timed operation |
|---|---|---|
| `frame_benchmarks` | `spatiotemporal_frame_construction` | Construct a `SpatiotemporalFrame` from the native fixture |
| `frame_benchmarks` | `nxr1_resolver_decode_and_component_dispatch_256b` | Decode a prepared NXR1 broker task, route it, enqueue it, and receive the frame |
| `adi_benchmarks` | `adi_nxr1_encode_256b` | Encode an NXR1 frame with a 256-byte payload |
| `adi_benchmarks` | `adi_nxr1_decode_256b` | Decode the encoded NXR1 frame with a 256-byte payload |
| `crypto_benchmarks` | `x25519_keypair_generation` | Derive an X25519 public key from a fixture secret |
| `crypto_benchmarks` | `x25519_diffie_hellman` | Derive a shared X25519 secret using a precomputed peer public key |
| `crypto_benchmarks` | `chacha20_encrypt/{16,64,256,1024}` | ChaCha20-Poly1305 encryption at the fixture payload sizes |
| `crypto_benchmarks` | `chacha20_decrypt/{16,64,256,1024}` | ChaCha20-Poly1305 decryption at the fixture payload sizes |
| `crypto_benchmarks` | `session_establishment_heuristic` | Synthetic combined key-generation, ECDH, cipher-construction, and message-encryption path |

The `adi_benchmarks` name is historical. Its current cases measure NXR1
serialization and decoding; they do not run a complete ADI auto-tuning cycle.

### Resolver benchmark scope

The resolver, registered route, receiver, and broker task are created before
the timed loop. Each iteration measures NXR1 extraction/decoding from the
prepared broker task, destination routing, bounded queue send, and receive.
It is a single-threaded API microbenchmark. It does not measure concurrent
producer contention, queue saturation, TCP transport, broker-server
scheduling, NUMA pinning, or GPU/NPU execution. A route's optional NUMA node is
advisory metadata; the resolver does not apply affinity or NUMA placement.

### Crypto benchmark scope

The crypto tests use deterministic fixture secrets, a fixed test key, and a
fixed nonce so repeated runs use the same input. They do not measure
operating-system entropy generation, production key management, a complete
authenticated peer handshake, or a full session protocol. The
`session_establishment_heuristic` is explicitly a synthetic heuristic, not a
production handshake benchmark. Nonce reuse is limited to this isolated
benchmark fixture and must not be copied into production encryption code.

## 3. Run native benchmarks

From the repository root:

```sh
# Run all native Criterion suites.
cargo bench --locked

# Run a specific suite.
cargo bench --locked --bench frame_benchmarks
cargo bench --locked --bench adi_benchmarks
cargo bench --locked --bench crypto_benchmarks

# Filter to one benchmark ID.
cargo bench --locked --bench frame_benchmarks -- nxr1_resolver_decode_and_component_dispatch_256b
cargo bench --locked --bench adi_benchmarks -- adi_nxr1_encode_256b
cargo bench --locked --bench crypto_benchmarks -- x25519_diffie_hellman
```

Capture and compare baselines on the same host:

```sh
cargo bench --locked --bench frame_benchmarks -- --save-baseline v6.12.0-reference
cargo bench --locked --bench frame_benchmarks -- --baseline v6.12.0-reference
```

Criterion writes measurements and HTML reports under `target/criterion/`.
Keep separate baselines for different machines, OS versions, architectures,
toolchains, features, and power profiles. Do not interpret results from
unrelated shared CI runners as a controlled before/after comparison.

## 4. Run browser-WASM measurements

The browser runner benchmarks the actual compiled `wasm32-unknown-unknown`
module under Node's WebAssembly runtime. It does not benchmark a native
reimplementation of the spatial algorithms. An optional live BRK2 mode also
submits numeric attributes from the same host-side records used to populate
the WASM spatial workload to an Overhauled broker. That mode measures the
sequential TCP request/response path, validates correlation/status/backend and
result bounds, and checks CPU output against the deterministic reference
kernel. It is the benchmark's broker-interop qualification path; without
`--broker-host`, the run remains local-only.

```sh
rustup target add wasm32-unknown-unknown
cargo fmt --manifest-path browser-wasm/Cargo.toml -- --check
cargo test --manifest-path browser-wasm/Cargo.toml --locked
cargo build --manifest-path browser-wasm/Cargo.toml --release --locked --target wasm32-unknown-unknown

node browser-wasm/bench/run.mjs \
  --dataset browser-wasm/bench/datasets/multivariate-v1.json \
  --output browser-wasm-benchmark.json

# Shorter local smoke run.
node browser-wasm/bench/run.mjs \
  --dataset browser-wasm/bench/datasets/multivariate-v1.json \
  --quick
```

To include the Overhauled broker in the same workload run, build and start its
CPU-only broker on a trusted local endpoint, then run:

```sh
node browser-wasm/bench/run.mjs --quick \
  --broker-host 127.0.0.1 --broker-port 9090 --broker-device cpu \
  --output browser-wasm-brk2.json
```

The optional broker mode uses the existing BRK2 schema and does not change
BRK1/BRK2/WSM1 wire layouts. It records actual backend counts, selected GPU
IDs, fallback count, and request latency. BRK2 has no authentication or TLS;
do not point this mode at an untrusted network listener. GPU/NPU preferences
are requests, and the response backend remains authoritative.

The runner measures:

| WASM operation | Sample sizes | Reported outputs |
|---|---|---|
| Reset and stable-ID upsert | 16, 128, 512 entities | Batch time, throughput, entity count |
| WGS84 bounding-box query | 16, 128, 512 entities | Query time, scanned-set size, match count |
| Spatiotemporal nearest resolution | 16, 128, 512 entities | Query time, number of successful resolutions |
| WGS84/ECEF and WGS84/ENU transforms | 16, 128, 512 entities | Median/p95 latency, throughput, checksums |
| ENU-to-ECEF transform | 16, 128, 512 entities | Median/p95 latency, throughput, checksum |
| Hermite interpolation | 16, 128, 512 entity-derived endpoints | Median/p95 latency, throughput, checksum |
| Arc–secant–tangent simplification | 16, 128, 512 path points | Simplification latency, retained points, reduction percentage |

For repeated operations, the report includes iteration count, operations per
sample, median batch time, p95 batch time, median nanoseconds per operation,
and operations per second. Path simplification is timed as one path operation
per sample; path setup is done before the measured interval.

The current spatial store is fixed-capacity (512 entities). Its upsert,
bounding-box query, and nearest-observation operations scan up to the active
entity count; they are bounded linear scans, not indexed spatial queries. The
path simplifier is iterative and bounded at 512 points; its report makes
geometric reduction visible through retained-point count and reduction
percentage while the tangent guard preserves sharp changes.

The report records whether broker interoperability was enabled. When disabled,
it explicitly marks `broker_interoperability: false` and does not claim TCP,
BRK2/WSM1, broker placement, or accelerator execution. The runner validates manifest
bounds, dataset profile structure, finite spatial outputs, resolver success,
and simplifier output bounds before accepting a benchmark report. CLI
iteration and operation counts are capped to keep adversarial inputs bounded.

The report also records the WASM binary size, Node runtime and architecture,
dataset identifiers, domain labels, and source attribute names. The runner
includes the JavaScript-to-WASM call boundary and reads returned values from
WASM linear memory. Browser rendering, gateway throughput, and the native
YuKKi-OS node are not measured. The optional BRK2 mode measures only the
explicit broker TCP round trip; it does not imply WSM1 guest compilation or
execution in Overhauled.

## 5. CI measurement behavior

### Native Criterion job

The `Performance Benchmarks` job in
`.github/workflows/coverage-and-metrics.yml` executes all native suites using
a shortened CI configuration:

```sh
cargo bench --locked --bench frame_benchmarks -- --warm-up-time 1 --measurement-time 2 --sample-size 10
cargo bench --locked --bench adi_benchmarks -- --warm-up-time 1 --measurement-time 2 --sample-size 10
cargo bench --locked --bench crypto_benchmarks -- --warm-up-time 1 --measurement-time 2 --sample-size 10
```

It runs each Criterion target explicitly so Criterion-only CLI flags are never forwarded to the library or ordinary binary test harnesses. It uploads `target/criterion/` as the `yukkios-native-criterion` artifact.
This is a real timed run, not merely a `--no-run` compile check. The shortened
sampling configuration and shared GitHub runner make it a regression
visibility aid, not a stable cross-runner performance gate.

### Browser-WASM job

The browser job in
`.github/workflows/multi-platform-build.yml` builds and smoke-tests the
browser module, then runs the dataset-driven Node runner with a shorter
six-iteration/32-operation configuration. It uploads
`browser-wasm-benchmark.json` as `yukkios-browser-wasm-benchmark`.

This proves that the WASM module can execute the benchmark workload in the CI
runtime and produces a report. It is not a browser-engine benchmark and does
not set hard performance thresholds. Use controlled, same-host repeated runs
for performance claims.

### Cross-repository live integration job

The `overhauled-live-cpp` job in
`.github/workflows/integration-tests.yml` checks out both repositories'
canonical `main` branches and records both commit SHAs in the job log. It
builds the browser-WASM module and a CPU-only Overhauled broker, compares the
mirrored BRK conformance corpus, runs the live Rust-to-C++ BRK1/BRK2 WSM1
lifecycle tests, and then invokes the browser benchmark with the quick profile:

~~~sh
node browser-wasm/bench/run.mjs --quick --broker-host 127.0.0.1 --broker-port 19090 --broker-device cpu --output /tmp/yukkios-wasm-brk2.json
~~~

The resulting report is uploaded as the `yukkios-wasm-brk2-interop` artifact.
This Node invocation is a distinct BRK2 inference request path: the spatial
operations run locally in Node's WebAssembly runtime, while host-prepared
numeric fixture records are sent to the broker. It is not a WSM1 guest task,
does not compile or instantiate a Wasm module in Overhauled, and does not
qualify GPU/NPU hardware. The same job separately exercises the NPU simulator
and CPU-fallback paths; simulator success is software conformance, not physical
accelerator validation.

The workflow is a compatibility check against the two checked-out revisions,
not a stable performance gate. Keep both logged SHAs with the artifact because
the two repositories are versioned independently. The report verifies
protocol response properties; it does not establish production domain-data
validity, browser-engine performance, power savings, or OPEX reduction.


## 6. Reproducibility and interpretation

Record these details with any published measurement:

- Git commit SHA and clean/dirty state.
- Rust/Cargo versions for native runs; Node version for browser-WASM runs.
- OS/kernel, architecture, CPU model, and available memory.
- Build target, features, release profile, and relevant compiler flags.
- Dataset file path, schema version, dataset/profile ID, sample count, and
  whether data is synthetic or externally sourced.
- Exact command, benchmark ID, iteration count, and Criterion/JSON report.
- Power profile, thermal state, competing workloads, and baseline host.

Keep coordinate units, timestamp epochs/units, original domain attributes,
source provenance, and quality flags. The spatial ABI receives only identity,
WGS84 position, altitude, time, and radius; benchmark and application adapters
must not silently discard or reinterpret the multivariate host record.

Do not infer an environmental field estimate, financial forecast, portfolio
risk, or safe drone trajectory from these microbenchmarks. They measure code
paths and geometric reduction, not domain-model validity or operational safety.

## 7. Composition replica measurements

The composition runtime exposes per-replica service-time EWMA, completed-call
count and active-call count. For a representative workload, record the
manifest and artifact SHA-256 digests, number of programs/replicas,
`stateless` declaration, runtime/toolchain, host CPU and memory, logical-key
distribution, concurrency and warm-up policy.

Compare one replica with the intended pool at identical guest inputs and
concurrency. Report throughput, p50/p95/p99 latency, per-replica service-time
EWMA, active calls, ProgramSaturated responses, CPU use and memory footprint.
Include an even key distribution, a hot-key/skewed distribution, and the
all-replicas-busy case. Replica count is a concurrency ceiling, not a promise
of linear scaling; each replica has a separate Store and instance graph.

The routing constants (7/8 EWMA, 25% penalty for non-preferred logical shards)
are heuristics to evaluate, not performance guarantees. Fuel is an
instruction budget rather than a wall-clock timeout. Do not claim reduced
latency, higher throughput or energy savings without controlled measurement
against the same guest workload and host.

## 8. Browser-WASM validation and optional BRK2 benchmark leg

The browser runner executes the actual `wasm32-unknown-unknown` spatial module
under Node's WebAssembly runtime. Before reporting a result it validates
manifest/profile structure, finite spatial outputs, resolver success and
simplifier index/capacity bounds. The CLI caps iterations at 1,000, operations
at 1,024, and uses the fixed 512-entity spatial store.

Local-only mode measures WASM code paths. It does **not** imply TCP, BRK2,
WSM1, broker placement or accelerator execution. The JSON report records
`broker_interoperability: false` when the broker leg is disabled.

For an optional live broker round trip, build and start a CPU-only Overhauled
broker on a trusted local endpoint, then run from the YuKKi-OS root:

```sh
node browser-wasm/bench/run.mjs --quick \
  --broker-host 127.0.0.1 --broker-port 9090 --broker-device cpu \
  --output browser-wasm-brk2.json
```

The broker mode sends host-prepared numeric records as ordinary BRK2 inference
requests. It does not submit Wasm bytecode, use the production WSM1 lifecycle
adapter, or execute the spatial module inside Overhauled. The runner validates
BRK2 response schema, request/task correlation, successful status, backend
identity, selected-GPU consistency, result bounds and deterministic CPU output.
Reports include actual backend counts, selected GPU IDs and fallback counts.

The broker protocol has no built-in authentication or TLS. Keep this
qualification listener on loopback or an independently secured trusted
network. This benchmark leg does not test browser rendering, gateway
streaming, NUMA scheduling, or physical GPU/NPU qualification. Inspect the
scope fields in the JSON report before comparing runs.

## 9. Related documentation

- [Browser spatial and multivariate data how-to](USER_HOWTO_MMO.md) — usage and
  ingestion patterns for drones, finance, environmental and other datasets.
- [MMO Browser WASM integration](MMO_BROWSER_WASM.md) — spatial operations,
  ABI exports, and fixed limits.
- [Browser WASM deployment](BROWSER_WASM.md) — build and hosting instructions.
- [API and ABI reference](API.md) — NXR1 resolver and broker boundaries.
- [Benchmark-driven native datasets and eigensolver](BENCHMARK_DRIVEN_DATASETS.md) — manifest-driven records, queue policy, and accuracy-checked symmetric eigensolver.
