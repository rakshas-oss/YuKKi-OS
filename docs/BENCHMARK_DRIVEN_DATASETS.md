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
