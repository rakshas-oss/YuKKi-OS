# Benchmarking YuKKi-OS

This guide describes the benchmark targets present on `main`, how to run
repeatable native measurements, and what is (and is not) measured by CI.
It also gives a measurement plan for the browser-WASM spatial core. The
browser-WASM plan is not an implemented performance harness and must not be
reported as measured results.

## 1. Current benchmark inventory

The root `Cargo.toml` declares three Criterion harnesses:

| Target | Benchmark ID | Timed operation |
|---|---|---|
| `frame_benchmarks` | `spatiotemporal_frame_construction` | Construct a `SpatiotemporalFrame` from fixed sample values |
| `frame_benchmarks` | `nxr1_resolver_decode_and_component_dispatch_256b` | Decode a prepared NXR1 broker task, resolve its destination, enqueue the frame, and receive it from the bounded component queue |
| `adi_benchmarks` | `adi_nxr1_encode_256b` | Encode an NXR1 frame with a 256-byte payload |
| `adi_benchmarks` | `adi_nxr1_decode_256b` | Decode the encoded NXR1 frame with a 256-byte payload |
| `crypto_benchmarks` | `x25519_keypair_generation` | Derive an X25519 public key from a fixed 32-byte secret |
| `crypto_benchmarks` | `x25519_diffie_hellman` | Derive a shared X25519 secret using a precomputed peer public key |
| `crypto_benchmarks` | `chacha20_encrypt/{16,64,256,1024}` | ChaCha20-Poly1305 encryption at the listed payload sizes in bytes |
| `crypto_benchmarks` | `chacha20_decrypt/{16,64,256,1024}` | ChaCha20-Poly1305 decryption at the listed payload sizes in bytes |
| `crypto_benchmarks` | `session_establishment_heuristic` | Synthetic combined path: two key derivations, cipher construction, and encryption of a short fixed message |

The `adi_benchmarks` name is historical. Its current cases measure NXR1
serialization and decoding; they do not run a complete ADI auto-tuning cycle.

### What the resolver measurement includes

The resolver, registered destination, receiver, and broker task are created
before the timed loop. Each iteration measures NXR1 extraction/decoding through
the broker-task adapter, destination routing, bounded queue send, and receive.
The NXR1 payload is 256 bytes.

This is a single-threaded microbenchmark of the resolver API. It does not
measure concurrent producer contention, queue saturation, network I/O,
broker-server scheduling, NUMA pinning, or GPU/NPU execution. A registered
NUMA node is advisory metadata; the resolver does not set CPU affinity or
perform NUMA memory placement.

### Cryptographic benchmark caveats

These cases use deterministic fixed test keys and a fixed nonce so the
measurement is repeatable. They do not measure operating-system entropy
generation, a production key-management service, a complete authenticated
peer handshake, or a full session protocol. The session-establishment case is
a heuristic microbenchmark, not a benchmark of the production handshake.
Nonce reuse is confined to this isolated benchmark fixture; never copy the
fixture's key/nonce pattern into production encryption code.

## 2. Run the native benchmarks

Run from the repository root using the Rust toolchain pinned by the project:

```sh
# Compile every native benchmark target without collecting timings.
cargo bench --locked --no-run

# Run all native Criterion benchmarks.
cargo bench --locked

# Run one benchmark suite.
cargo bench --locked --bench frame_benchmarks
cargo bench --locked --bench adi_benchmarks
cargo bench --locked --bench crypto_benchmarks
```

Filter to an individual benchmark by passing Criterion arguments after `--`:

```sh
cargo bench --locked --bench frame_benchmarks -- nxr1_resolver_decode_and_component_dispatch_256b
cargo bench --locked --bench adi_benchmarks -- adi_nxr1_encode_256b
cargo bench --locked --bench crypto_benchmarks -- x25519_diffie_hellman
```

Criterion writes measurement data and HTML reports below
`target/criterion/`. The `--no-run` command only builds benchmark
executables; it does not produce timings.

## 3. Capture and compare baselines

Use the same host and configuration for baseline and candidate runs:

```sh
# Capture the reference measurements.
cargo bench --locked --bench frame_benchmarks -- --save-baseline main-reference

# Compare a later build with that reference.
cargo bench --locked --bench frame_benchmarks -- --baseline main-reference
```

Keep independent baseline names for different machines, operating systems,
architectures, Rust toolchains, feature sets, or power configurations. Do not
treat results from unrelated shared CI runners as a controlled before/after
comparison. Repeat surprising measurements and inspect Criterion's estimates
and distributions instead of relying on one displayed point estimate.

## 4. Reproducibility checklist

Attach the following context to any benchmark result or performance claim:

- Git commit SHA and whether the working tree was clean.
- `rustc -Vv` and `cargo -V` output.
- OS/kernel, architecture, CPU model, logical/physical core count, and memory.
- Cargo features, target triple, release profile, and relevant `RUSTFLAGS`.
- Power/performance mode, thermal state, CPU load, and competing workloads.
- Exact command, benchmark ID, payload size, and Criterion report.
- Baseline name and confirmation that the baseline was collected on the same
  host under equivalent conditions.

Use a release-mode run, close unrelated CPU-heavy workloads, and repeat the
measurement. Keep fixture generation and setup outside the timed loop when
measuring primitive costs. Add a separate end-to-end measurement when parsing,
host/WASM boundary calls, I/O, source filtering, or application-level joins
are part of the workload users actually experience.

## 5. Browser-WASM spatial and motion performance

The separate `browser-wasm/` package contains the browser spatial core
documented in [MMO Browser WASM integration](MMO_BROWSER_WASM.md): WGS84/ECEF
and ENU transforms, Hermite interpolation, a fixed-capacity 512-entity store,
bounding-box queries, nearest-observation resolution, and bounded path
simplification.

The browser package has its own Cargo manifest and does not declare a Criterion
target. The root Criterion suites are native benchmarks; they do not measure
browser-WASM operations. The browser build and unit tests validate compilation,
ABI behavior, and correctness, not throughput or latency.

The current bounding-box query and nearest-observation resolver scan the
active entity entries, with a maximum of 512 entities. They are bounded linear
scans, not R-tree or other indexed spatial queries. The entity upsert also
searches the current entries for an existing stable ID. Benchmark this current
implementation as it exists; do not describe it as an indexed spatial engine.

### Recommended browser measurement matrix

When a browser timing harness is implemented, use fixed fixtures at the
following sizes (subject to the 512-entity/point capacities):

| Operation | Suggested cases | Measurements |
|---|---|---|
| WGS84/ECEF and ENU transforms | Repeated valid coordinates; include altitude and high-latitude cases | Calls/second, median and tail latency, numeric error against reference fixtures |
| Hermite interpolation | Fixed endpoints, velocities, and interval | Interpolations/second, median/tail latency, endpoint and reference error |
| Stable-ID upsert | 1, 16, 128, and 512 entities; new ID and replacement ID | Operation latency and throughput |
| Bounding-box query | 16, 128, and 512 entities; ordinary and antimeridian-crossing bounds; sparse and dense matches | Query latency, number of records scanned, matches returned |
| Nearest-observation resolution | 16, 128, and 512 entities; fresh, stale, future, in-range, and out-of-range records | Query latency, selected/rejected counts |
| Arc–secant–tangent simplifier | 16, 128, and 512 points; straight, curved, and sharp-turn trajectories | Simplification latency, retained count, reduction ratio, endpoint/turn correctness |

Separate module download/instantiation and first-call costs from warmed steady
state. Measure both the WASM operation and the complete JavaScript-to-WASM
call path. Record browser name/version, OS, CPU, WASM release build settings,
module byte size, fixture identity, number of entities/points, warm-up policy,
iteration count, and repeated-run spread.

For drone, finance, environmental, and other multivariate workloads, the
spatial ABI stores identity, position, and observation time—not arbitrary
domain attributes. Keep attributes in the host data model. Where the
application applies timestamp/coordinate normalization, source filtering, or
joins an entity ID back to its source record, measure those stages separately
and as a complete workflow. Preserve source units, provenance, quality flags,
and fixture versions.

This is a proposed test matrix only. No browser-WASM latency, throughput,
speedup, or performance regression result is currently published by the
Criterion suite. Add and run a dedicated browser benchmark harness before
making such claims.

## 6. How to interpret the CI benchmark job

The `Performance Benchmarks` job in
`.github/workflows/coverage-and-metrics.yml` runs:

```sh
cargo bench --no-run
```

This is a compilation gate for the native Criterion targets. It catches
benchmark build failures but does not execute timed measurements, compare
baselines, enforce performance thresholds, or upload Criterion timing reports.
The separate browser-WASM workflow builds and tests the browser package; it
does not turn the native Criterion job into a browser performance test.

For actual performance measurements, run section 2 on a controlled host and
retain the Criterion report with the reproducibility record from section 4.

## 7. Related documentation

- [MMO Browser WASM integration](MMO_BROWSER_WASM.md) — spatial operations,
  exported ABI, capacity limits, and browser/native boundaries.
- [Browser WASM deployment](BROWSER_WASM.md) — browser build and deployment.
- [API and ABI reference](API.md) — NXR1 resolver and broker boundaries.
- [Changelog](CHANGELOG.md) — release history.
