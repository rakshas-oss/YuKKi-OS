# Benchmark-driven native dataset execution

YuKKi-OS now has a native benchmark runner in \`src/benchmark_dataset.rs\`
and the \`yukki_dataset_bench\` command. Its direction is deliberate:

**The dataset and benchmark profile are the inputs; the benchmark result selects
the execution policy.** The runner does not synthesize a replacement dataset
with random values.

## Dataset manifest

A manifest is JSON with a version, one or more dataset definitions, and one
or more benchmark profiles. Each dataset points to a UTF-8 JSONL source. Every
non-empty JSONL row must be an object containing:

- An unsigned sequence field.
- An unsigned nanosecond timestamp field.
- Every declared numeric feature field.
- Both latitude and longitude when geographic fields are mapped. Altitude is
  optional and defaults to zero.

The \`feature_fields\` array defines the stable numeric feature order. The first
nine numeric features feed the generic NXR1 numeric fields. Geographic
coordinates are deliberately not written into NXR1's generic \`x/y/z\` vector:
they are processed separately by the geographic benchmark, and the complete
source row stays in NXR1's opaque payload.

The loader bounds the manifest, dataset size, row size, record count, number
of datasets, feature count, batch sizes, and worker counts. It rejects
non-finite numbers, invalid WGS84 coordinates, duplicate mappings, malformed
JSONL, and incomplete geographic mappings.

## Profiles drive the work

Each profile controls the measurement rather than simply labeling a report:

- \`warmup_records\` chooses records run before measurements.
- \`sample_records\` selects a deterministic, evenly spaced sample from the
  remaining source records.
- \`batch_sizes\` and \`worker_counts\` define the actual native candidate
  configurations that are executed.
- \`objective\` chooses the candidate policy: lowest P95 batch latency,
  highest records per second, lowest estimated working set, or the geospatial
  throughput objective.
- \`max_p95_batch_ms\` filters candidates against a latency ceiling. If none
  meet the ceiling, the result is explicit: \`met_latency_target=false\`.

A profile may set \`applicable_domains\`, so a geospatial profile can run on
drone and environmental datasets without being incorrectly applied to
financial data.

The native work being timed is a real per-record NXR1 encode/decode round trip.
The runner reports elapsed time, record throughput, mean/P50/P95/P99 batch
latency, encoded bytes, deterministic checksum, and an estimated peak working
set based on row size, batch size, and worker count. The working-set figure is
a bounded estimate, not an operating-system RSS measurement.

For geospatial profiles, the selected dataset path is converted from WGS84 to
ECEF and simplified once across the complete sampled trajectory. It uses
arc-length excess, perpendicular distance to the secant, and a separate
tangent-turn guard. Geometric reduction and its elapsed time are reported
separately. Batch boundaries do not create artificial path endpoints.

## Run the supplied multivariate example

From the repository root:

\`\`\`sh
cargo run --release --bin yukki_dataset_bench -- \\
  --manifest examples/benchmark-datasets/manifest.json \\
  --dataset all \\
  --profile all \\
  --output benchmark-results.json
\`\`\`

The supplied fixture manifest covers three domains:

- \`drone-flight-east\`: WGS84 position, altitude, velocity, heading, battery,
  link quality, and motor telemetry.
- \`market-ticks\`: price, volume, return, volatility, spread, order imbalance,
  trade count, and depth.
- \`urban-air-quality\`: WGS84 station location, temperature, humidity,
  pressure, wind, CO2, PM2.5, NO2, and ozone.

Profiles include latency, throughput, bounded-memory, and geospatial
simplification. The geospatial profile declares applicability to the
\`drone\` and \`environment\` domains, so it is skipped for the finance dataset.

Run a single dataset or profile by changing \`--dataset\` or \`--profile\`.
Available IDs are in the manifest.

## Where the result goes

For each dataset/profile pair, the report includes every measured candidate
and the selected candidate. The CLI applies the selected batch size and worker
count to the native `ADIAutoTuner` policy, deriving a bounded queue depth
(`batch_size × workers`, clamped to 1..=1024) and a profile identifier. This
means the benchmark result, rather than a static queue constant, drives the
reported native policy.

The result can also allocate an actual YuKKi-OS MPMC component destination via
`SpatiotemporalPayloadResolver::register_benchmarked_destination`. That API
uses the chosen batch/worker product as queue capacity while retaining the
existing bounded MPMC queue and caller-selected sequence policy. Runtime
components therefore do not need to select queue depth independently of the
benchmarked dataset workload.

This initial native runner is a local dataset/codec/geospatial benchmark and
policy selector. It does not claim to measure GPU/NPU execution, wall power,
or live broker placement. Those require the separate Overhauled execution
tier and its existing BRK1/BRK2 + WSM1 boundary. No broker protocol, NXR1 wire
layout, or repository boundary is changed by this runner.

## Extending it

Add a dataset definition and JSONL source for a new domain, then map its
sequence, timestamp, numeric features, and optional geographic columns. Add
profiles only when they represent a distinct objective or workload envelope.
Use the same source data for competing candidates so comparisons are
reproducible; do not mix generated values into one candidate and real records
into another.


## Dataset-driven eigensolver

The same manifest may define an optional `eigensolver_profiles` array. These
profiles are consumed by `yukki_eigensolver_bench`, independently of the
transport/geospatial profiles. They select the data rows, feature matrix
dimension, matrix batch sizes, worker counts, repeat count, numerical tolerance,
and Jacobi sweep limit.

Run the supplied workload:

```sh
cargo run --release --bin yukki_eigensolver_bench -- \\
  --manifest examples/benchmark-datasets/manifest.json \\
  --dataset all \\
  --profile all \\
  --output eigensolver-results.json
```

For each selected dataset, the runner forms bounded batch correlation matrices
from the declared `feature_fields`. Each matrix is passed to the native
real-symmetric Jacobi eigensolver. The output reports decompositions per second,
mean and P95 solve latency, eigenvalue residual, eigenvector orthogonality
error, and a deterministic result checksum. The selected candidate is chosen
by the profile objective and optional P95 latency ceiling. Data values are
scaled before covariance accumulation to avoid overflow from large finite
source values; this benchmark therefore measures the correlation spectrum,
not a unit-dependent raw covariance spectrum.

The eigensolver accepts finite real-symmetric matrices with dimensions
1..=64. It returns ascending real eigenvalues and column eigenvectors. It
rejects non-square, non-finite, materially asymmetric, or non-convergent input.
This is appropriate for small/medium covariance and correlation matrices
(PCA-style analysis); it is not a general complex or non-symmetric eigensolver.
Benchmark residuals and orthogonality are reported so throughput cannot hide
an inaccurate decomposition.

The solver is owned and maintained by YuKKi-OS; Overhauled does not duplicate
the numerical algorithm. Overhauled consumes the same manifest-described
records through a BRK2 broker workload adapter and measures broker ingress,
dispatch, request latency and throughput. It does not solve the eigenproblem.
This keeps numerical semantics and accuracy validation in one repository
while preserving an end-to-end execution benchmark in the broker repository.
The two projects remain independently buildable and have no compile-time
dependency on one another.
