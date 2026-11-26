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

Overhauled remains an optional numeric metric-computation tier. Its worker
fabric can schedule CPU/GPU/NPU-eligible inference and throughput requests,
but this first crawler release does not automatically send raw HTML or
individual page observations to the broker. Raw web documents should not be
forwarded to an accelerator by default. The paired Overhauled change adds a
bounded streaming accumulator for page observations (bytes, links, fetch time,
extraction time and HTTP status) that can be embedded by downstream metric
services. It is not a GPU implementation; CPU reduction is deterministic and
constant-memory.

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
