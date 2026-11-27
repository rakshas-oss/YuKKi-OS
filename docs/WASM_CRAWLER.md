# YuKKi-OS WASM Crawler Fabric

## Scope

The crawler is an opt-in native CLI and library. YuKKi-OS owns URL discovery,
native HTTPS/HTTP fetching, host policy, robots.txt enforcement, byte budgets,
and report provenance. A no-std WebAssembly guest extracts a title and anchor
links from each fetched HTML document. The guest has no imported functions,
WASI, sockets, filesystem access, or credentials.

This is an initial vertical slice, not a general-purpose browser. It does not
execute JavaScript, render pages, solve CAPTCHAs, submit forms, or bypass
access controls. It fetches only HTML and XHTML responses and does not follow
HTTP redirects. JavaScript-rendered websites need an explicitly designed
browser integration rather than an implicit sandbox privilege.

## Build the extraction guest

The guest is a separate standalone crate and is not linked into the native
host dependency graph:

~~~sh
rustup target add wasm32-unknown-unknown
cargo build --manifest-path crawler-wasm/Cargo.toml \
  --target wasm32-unknown-unknown --release
~~~

The artifact is:

~~~text
crawler-wasm/target/wasm32-unknown-unknown/release/yukkios_crawler_wasm.wasm
~~~

The guest ABI is YCR1:

- Host calls alloc(input_length) and copies one bounded document into guest
  linear memory.
- Host calls process(pointer, length).
- Guest returns a packed 64-bit value containing output length and output
  pointer.
- Output contains the input byte count, extracted title, and bounded raw
  href attributes.
- Host validates every pointer, length, string and link count before use.

The runtime compiles the module once per extractor, instantiates an isolated
Store for each document, applies Wasmtime fuel and memory limits, and rejects
all module imports. The initial guest uses a bounded byte scanner for ordinary
HTML title and anchor tags; it is not a full HTML5 parser, does not decode
entities, and does not execute scripts. Only operator-provisioned guest
artifacts should be loaded.
A future signed-plugin policy can build on the existing artifact-signature
infrastructure; this initial crawler does not claim publisher verification.

## Run a crawl

First choose domains that you are authorized to crawl. Every seed and
discovered link must belong to one of the explicitly allowed DNS domains or
their subdomains.

~~~sh
cargo run --release --bin yukki_crawl -- \
  --seed https://example.org/ \
  --allow-domain example.org \
  --wasm crawler-wasm/target/wasm32-unknown-unknown/release/yukkios_crawler_wasm.wasm \
  --max-pages 100 \
  --depth 2 \
  --concurrency 8 \
  --delay-ms 500 \
  --output crawl-report.json
~~~

Repeat --seed and --allow-domain as required. The report is JSON with
per-page status, retrieval timestamp, byte count, SHA-256, extracted title,
normalized in-allowlist links, fetch/extraction timings and an aggregate
summary. Failed pages are retained as records with an error rather than
silently disappearing.

## Execute user-selected processors over ingested data

Applications can opt in to a second, separate execution stage with
`yukkios::crawler_data_exec::CrawlerDataExecutor`. This is for user-directed
processing of crawler output (for example normalization, filtering, feature
extraction or transformation). It does **not** execute JavaScript, scripts,
WASM, or other instructions found inside crawled pages. Ingested page bytes
remain opaque input data.

The native `yukki_crawl` CLI now exposes this stage through the explicit
`--execute-wasm` option. When supplied, the selected processor is applied to
each successfully fetched page's raw HTML bytes. This is an opt-in operation:
omitting the option preserves the original fetch-and-extract-only behavior.
The CLI writes each processor result as a separate binary file and records the
processor/input/output SHA-256 digests, byte count, output reference, duration
and any per-page error in that page's JSON report record.

The Rust API exposes the same flow through
`Crawler::crawl_with_processor(seeds, processor, output_sink)`. Applications
must authenticate and authorize the user, choose the processor artifact, and
supply an output sink. The default stream gateway does not expose arbitrary
guest execution; an HTTP frontend must add authentication, authorization,
admission and audit controls before invoking this library API.

The YCE1 processor ABI requires three core-Wasm exports:

- `memory`: guest linear memory;
- `alloc(i32) -> i32`: reserve a guest input buffer;
- `execute(i32, i32) -> i64`: process the input and return a packed output
  descriptor (output length in the high 32 bits, output pointer in the low
  32 bits).

The host rejects all module imports, creates a fresh Store and instance for
each invocation, and validates all guest pointers and output lengths before
copying results. Defaults and hard ceilings are 4 MiB per module, 1 MiB input,
1 MiB output, 16 MiB guest memory and 10,000,000 fuel per call (hard maximum 1,000,000,000). A crawl is limited to 1,024 processor runs, four concurrent processor instances and 64 MiB of aggregate output. Fuel is an
instruction budget, not a wall-clock deadline. The processor has no WASI,
filesystem, sockets, credentials, or host callbacks.

A runnable byte-count example is included at
`examples/crawler-processors/byte-count.wat`. It returns the input size as an
8-byte little-endian integer. Compile and run it with:

~~~sh
wat2wasm examples/crawler-processors/byte-count.wat -o byte-count.wasm
cargo run --release --bin yukki_crawl -- \
  --seed https://example.org/ --allow-domain example.org \
  --wasm crawler-wasm/target/wasm32-unknown-unknown/release/yukkios_crawler_wasm.wasm \
  --execute-wasm byte-count.wasm \
  --execution-output-dir crawl-execution-output \
  --execution-fuel 10000000 \
  --output crawl-report.json
~~~

The output directory contains per-run `<run-id>-<page-url-sha256>-<output-sha256>.bin` files.
The JSON record's `execution.output_reference` identifies the corresponding
file; `processor_sha256` identifies the exact processor artifact. The byte
count example is illustrative, not a semantic HTML parser or production
feature extractor.

The application remains responsible for user authentication, processor
provenance/signature policy, job admission, rate limits, result retention,
cancellation and audit logging. Do not load a processor merely because a
crawled page references it. The executor is capability-free but is not a
substitute for process/container isolation against runtime or engine
vulnerabilities. Keep crawler network access and processor execution as
separate privileges.

## Default and hard limits

| Resource | Default | Hard/configuration limit |
|---|---:|---:|
| Concurrent fetch/extract jobs | 8 | 128 |
| Attempted pages | 100 | 10,000 |
| Link depth | 2 | 16 |
| HTML bytes per page | 1 MiB | 1 MiB (guest ABI) |
| Total bytes per crawl | 64 MiB | 512 MiB |
| Extracted links per page | 128 | 128 |
| Links stored by guest | 128 | 128 |
| Link length | — | 2,048 bytes |
| Title length | — | 256 bytes |
| WASM memory | — | 4 MiB |
| WASM fuel per document | 5,000,000 | operator-configured |
| Request timeout | 15 seconds | 120 seconds |
| Per-host request spacing | 500 ms | minimum 100 ms |
| robots.txt response | — | 64 KiB |

The crawl-wide byte budget is charged as response chunks arrive, including a
partial response that subsequently fails. This is intentionally conservative:
a failed request cannot be used to reclaim budget during the same crawl.

## Network and source safety

- Explicit DNS-domain allowlist; discovered links outside it are discarded.
- Only HTTP and HTTPS URLs; credentials and IP-literal URLs are rejected.
- DNS is resolved before requests. Any private, loopback, link-local,
  multicast, documentation, shared-address or other non-public answer rejects
  the host. Validated DNS answers are pinned into the per-host HTTP client to
  reduce DNS-rebinding risk.
- Proxy environment variables are disabled so the DNS pin applies to the
  actual destination.
- Redirects are not followed. This prevents redirect-based allowlist or
  private-network escapes; redirected pages must be separately reviewed and
  supplied as seeds.
- robots.txt is fetched and evaluated before page retrieval. Denied,
  unavailable, oversized or unsafe-to-evaluate robots responses fail closed.
  The parser supports user-agent groups, allow/disallow path prefixes,
  asterisk wildcards and dollar end anchors; operators should validate
  policies for sites with more advanced robots extensions.
- Per-host request spacing, bounded concurrency, request timeouts, page and
  crawl-wide byte ceilings prevent one source from consuming unbounded work.
- Only HTML/XHTML is accepted. No cookies, authentication, form submission,
  script execution, browser fingerprinting or access-control bypass is
  provided.

The crawler's DNS and URL controls reduce SSRF risk but are not a replacement
for network egress controls. Run it in a restricted network namespace or
container with outbound firewall policy, and keep metadata services and private
service networks unreachable from the crawler process.

Untrusted page text remains data. A page cannot install a WASM plugin or gain
artifact-publisher privileges by being crawled. Public stream ingestion and
untrusted-source availability remain independent from executable-artifact
authorization.

## Metriculation output

Each successful page record includes source URL, timestamp, content digest,
bytes, link count, fetch time and extraction time. The report aggregates pages
attempted/succeeded/failed, total bytes and links, and mean document/fetch/
extraction measurements.

This report is an initial in-memory crawl result written to one JSON file. It
is not a durable distributed crawl frontier, historical time-series database,
or claim of production-grade scheduler throughput. Persistent storage,
resumable checkpoints, cross-node frontier leasing, full HTML5 parsing,
content-type discovery, canonicalization rules, and signed crawler plugins are
follow-up work.

## Overhauled relationship

Overhauled v1.10.0 provides the optional C++17
`Overhauled::crawler_metrics` library (public header `crawler_metrics.h`).
It accepts normalized `PageObservation` values containing document bytes,
link count, fetch/extraction durations and HTTP status. Each worker or NUMA
shard can maintain its own fixed-memory `MetricAccumulator` and merge at a
barrier; the accumulator rejects counter overflow without partial mutation.
It reports counts, totals, min/max/mean/population-standard-deviation and
approximate P50/P95/P99 upper bounds from fixed 64-bucket base-2 histograms.

This is a separate CPU-side aggregation API. YuKKi-OS does not automatically
send page records or raw HTML to the broker; the caller must explicitly map
numeric observations into the library. It adds no BRK1/BRK2 operation and
does not dispatch reductions to GPU/NPU. The percentile values are bucket
upper bounds, not exact quantiles. See Overhauled
[CRAWLER_METRICS.md](https://github.com/rakshas-oss/overhauled/blob/main/docs/CRAWLER_METRICS.md).

## Tests and qualification

Run native tests and formatting:

~~~sh
cargo test --all-targets --locked
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
~~~

Build the guest:

~~~sh
cargo build --manifest-path crawler-wasm/Cargo.toml \
  --target wasm32-unknown-unknown --release
~~~

Tests cover the YCR1 ABI, import rejection, input ceilings, robots matching,
public-IP filtering, configuration limits and summary calculations. Live
network crawling and production throughput must be qualified against a
controlled test server and explicitly authorized production domains.
