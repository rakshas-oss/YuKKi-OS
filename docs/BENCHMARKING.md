# Benchmarking YuKKi-OS

This guide documents the benchmark targets that exist in the v6.11.0 release
branch and a reproducible way to measure them. It distinguishes native
Criterion measurements from browser-WASM performance work: the latter is
not yet represented by a Criterion target or a browser timing job.

## 1. Benchmark inventory

The root package declares three Criterion harnesses in `Cargo.toml`:

| Target | Benchmark IDs | What is timed |
|---|---|---|
| `frame_benchmarks` | `spatiotemporal_frame_construction` | Construction of a fixed-value `SpatiotemporalFrame` |
| `frame_benchmarks` | `nxr1_resolver_decode_and_component_dispatch_256b` | Decode an already-built NXR1 broker task, validate/route it, enqueue it, and receive the resolved frame |
| `adi_benchmarks` | `adi_nxr1_encode_256b`, `adi_nxr1_decode_256b` | NXR1 serialization and parsing with a 256-byte payload |
| `crypto_benchmarks` | `x25519_keypair_generation`, `x25519_diffie_hellman` | X25519 key-pair generation and Diffie-Hellman operation |
| `crypto_benchmarks` | `chacha20_encrypt/{16,64,256,1024}`, `chacha20_decrypt/{16,64,256,1024}` | ChaCha20-Poly1305 encryption/decryption for the listed byte sizes |
| `crypto_benchmarks` | `session_establishment_heuristic` | A combined key-generation, ECDH, cipher-construction, and short encryption path |

The `adi_benchmarks` target name is retained for compatibility with the
existing harness; its current cases measure NXR1 encode/decode, not a complete
ADI auto-tuning cycle.

The resolver benchmark is deliberately narrow. Its resolver, registered
destination, receiver, and broker task are prepared outside the timed loop.
Each iteration measures decode plus route/queue dispatch and receive for one
256-byte NXR1 payload. It is a single-threaded microbenchmark: it does not
measure multi-producer contention, queue saturation, network transport,
NUMA placement, broker-server scheduling, or accelerator execution. The
optional NUMA node on a resolver route is advisory metadata and is not CPU or
memory affinity performed by this library.

## 2. Build and run

Run commands from the repository root with the pinned Rust toolchain:

```sh
# Compile every native Criterion target without running timings.
cargo bench --locked --no-run

# Run every native Criterion benchmark.
cargo bench --locked

# Run each suite independently.
cargo bench --locked --bench frame_benchmarks
cargo bench --locked --bench adi_benchmarks
cargo bench --locked --bench crypto_benchmarks
```

To focus on one benchmark, pass its Criterion filter after `--`:

```sh
cargo bench --locked --bench frame_benchmarks -- nxr1_resolver_decode_and_component_dispatch_256b
cargo bench --locked --bench adi_benchmarks -- adi_nxr1_encode_256b
```

Criterion writes local estimates and HTML reports under `target/criterion/`.
Keep the generated directory with the test record when a report must be
reviewed or archived; do not copy a single timing value without its machine
and toolchain context.

## 3. Baselines and comparisons

Use a named baseline on the same machine and under the same conditions:

```sh
# Capture a baseline.
cargo bench --locked --bench frame_benchmarks -- --save-baseline v6.11.0-linux-x86_64

# Compare a later build against that baseline.
cargo bench --locked --bench frame_benchmarks -- --baseline v6.11.0-linux-x86_64
```

Create separate baseline names for materially different hosts, operating
systems, Rust toolchains, compiler flags, or power configurations. Do not
compare timings from unrelated GitHub-hosted runners as though they were a
controlled before/after experiment. A regression claim should be supported by
repeated runs and the Criterion estimate/distribution, not by one noisy sample.

## 4. Reproducible measurement record

For each published result, record:

- Git commit SHA and whether the working tree was clean.
- Rust and Cargo versions (`rustc -Vv` and `cargo -V`).
- OS, kernel, architecture, CPU model, core count, and memory.
- Build target, enabled Cargo features, profile, and relevant `RUSTFLAGS`.
- Power/performance mode, CPU load, thermal state, and whether other workloads
  were running.
- Exact command, benchmark ID, payload size, sample count, and Criterion report.
- For comparisons, the baseline name and the host on which it was collected.

Use a release-mode Criterion run, close unnecessary applications, avoid
running competing build or benchmark jobs, and repeat the measurement after a
fresh build when results are surprising. Keep setup outside the timed loop for
primitive-cost measurements. Add a separate end-to-end benchmark when setup,
serialization, host/WASM crossings, I/O, or application joins are part of the
real workload.

## 5. Browser-WASM spatial feature measurements

The v6.11.0 browser application adds WGS84/ECEF and ENU transforms, Hermite
interpolation, a bounded 512-entity store, antimeridian-aware bounding-box
queries, freshness/distance-constrained nearest-observation resolution, and
iterative arc–secant–tangent path simplification. These operations run in the
separate `browser-wasm/` package, whose current manifest does not declare a
Criterion benchmark target.

Consequently:

- The root `cargo bench` suites do **not** measure these browser-WASM
  operations.
- The `coverage-and-metrics` workflow's `cargo bench --no-run` step compiles
  the native benchmark harnesses; it does not execute timings or validate
  browser-WASM performance.
- The browser-WASM build and correctness/smoke tests are not performance
  benchmarks. No throughput, latency, or speedup claim for the new spatial
  operations should be inferred from their passing.

### Recommended browser benchmark matrix

When a browser timing harness is added, report the complete JavaScript-to-WASM
call path as well as the isolated kernel where the ABI permits it. Use fixed,
versioned input fixtures and include at least these cases:

| Operation | Suggested input cases | Measurements |
|---|---|---|
| WGS84/ECEF and ENU transforms | Repeated valid points; include altitude variation | Calls/second, median and tail latency |
| Hermite interpolation | Fixed endpoint positions/velocities and interval | Interpolations/second, numerical error against the fixture |
| Bounding-box query | 16, 128, and 512 entities; ordinary and antimeridian-crossing boxes | Query latency, matches returned |
| Nearest-observation resolver | 16, 128, and 512 entities; fresh, stale, future, in-range, and out-of-range candidates | Query latency, selected/rejected counts |
| Arc–secant–tangent simplifier | 16, 128, and 512 ordered points; straight, smooth-curved, and sharp-turn paths | Simplification latency, retained count, reduction ratio, endpoint/turn correctness |

Separate cold page/module startup from warmed steady-state runs. Record browser
name/version, OS, CPU, WASM build profile, module byte size, entity/point count,
fixture identity, warm-up policy, iteration count, and repeated-run spread.
Measure the host-to-WASM boundary because the browser UI invokes the exported
ABI; do not report kernel-only time as application latency.

The spatial store carries identity, location, and observation time. For drone,
finance, environmental, or other multivariate sources, keep domain attributes
in the host data model. If the user-facing workflow depends on normalization,
source filtering, or joining a selected entity ID back to a source record,
measure those steps separately and also as an end-to-end scenario. Record
coordinate/time conversion and fixture provenance. Do not treat the spatial
resolver as a financial forecaster, environmental interpolation model, or
safety-critical flight-navigation system.

These cases are a measurement plan, not existing benchmark results or a claim
that a browser performance harness is already wired into CI. Add a dedicated
browser harness and publish its raw results before making performance claims
about the new WASM feature set.

## 6. CI interpretation

The current `.github/workflows/coverage-and-metrics.yml` performance job runs:

```sh
cargo bench --no-run
```

This is a benchmark-compilation gate. It catches benchmark source/build
problems but does not execute Criterion measurements, compare baselines, set
performance thresholds, or upload timing reports. Run the commands in section
2 on a controlled host for actual measurements.

## 7. Related documentation

- [MMO Browser WASM integration](MMO_BROWSER_WASM.md) — operations, ABI, and
  bounds.
- [Browser spatial and multivariate data how-to](USER_HOWTO_MMO.md) — drone,
  finance, and environmental data workflows.
- [API reference](API.md) — NXR1 resolver and codec boundary.
