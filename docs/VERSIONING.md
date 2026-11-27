# YuKKi-OS — Versioning

## Release state

- **Latest published GitHub release:** v6.22.0 (published 2026-11-27T01:28:43Z; 2026-11-26 in Toronto). The release has no attached binary assets.
- **Next patch release candidate:** v6.22.1 (not tagged or published).
- **Native Cargo package candidate:** 6.22.1.
- **OCI image label candidate:** 6.22.1.
- **Rust toolchain pin:** 1.98.1.
- **Runtime binary:** `yukki_core_node`.
- **External package publication:** crates.io is not claimed; GitHub Release publication and registry publication are separate.

The v6.22.1 metadata is a maintenance patch candidate. It records post-release NDJSON test and Rust formatting corrections only; no decoder implementation, public API, runtime or protocol behavior is changed. Do not tag or publish until the exact candidate passes the release gate below.

## Version assessment

The published v6.22.0 release added user-selected YCE1 crawler processing and bounded multivariate NDJSON observation decoding. The v6.22.1 patch candidate contains only post-release validation maintenance from merged PRs #194 and #195:

- Correct the incremental NDJSON test to assert that an unterminated final record is validated by `finish()`; `push()` retains the incomplete record until a delimiter or end-of-stream.
- Apply the repository-pinned Rust 1.98.1 rustfmt layout to `guest-worker/src/lib.rs`, restoring the repo-wide formatting gate.
- Preserve the existing decoder implementation and public contract. No new code path, API, schema, wire identity, or backend behavior is introduced.

## Version assessment

The published v6.21.0 release delivered the bounded WASM crawler fabric, static HTML extraction, crawl provenance/metriculation reports, and the Aikido dependency/security remediation. The additive changes merged after that tag justify the next minor version:

- Add the native YCE1 CrawlerDataExecutor API and Crawler::crawl_with_processor, plus the explicit yukki_crawl --execute-wasm operator path for user-selected core-Wasm processors.
- Keep the YCR1 HTML extractor separate from YCE1 processors. Each processor invocation receives a fresh Wasmtime Store/instance, rejects imports, validates guest memory ranges, and is bounded by module/input/output limits, fuel, concurrency, execution-count and aggregate-output ceilings.
- Add NdjsonObservationDecoder, an incremental parser for schema-v1 untrusted numeric observations. Defaults retain at most one 16 KiB incomplete record and return at most 256 records per push; records support 1–32 dimensions and preserve missing values as None.
- Reject unsupported schema versions, unknown fields, oversized records, invalid source IDs/dimensions and non-finite numeric values. The decoder does not authenticate publishers or authorize forwarding; applications still apply source/tenant policy and backpressure.
- Pair with Overhauled v1.11.0's candidate multivariate_stats library for fixed-memory, pairwise online covariance/correlation over normalized numeric observations. This integration remains caller-driven.

## Compatibility and security boundaries

- Existing YKMC, BRK1, BRK2, NXR1 and WSM1 wire identities remain unchanged; the v6.22.1 maintenance patch introduces no protocol or framing change.
- YCR1 performs bounded static HTML extraction only. It has no WASI, imports, sockets, filesystem or credentials.
- YCE1 is separately opt-in and user-selected. Crawled content is opaque data and cannot select or install a processor; page scripts are not executed. The default stream gateway does not expose arbitrary guest execution.
- The crawler is not a JavaScript browser, CAPTCHA/form automation tool, distributed or persistent crawl frontier, historical metrics database, or automatic accelerator pipeline.
- The CLI persists processor outputs locally; application-specific sinks must enforce their own authorization, provenance and retention policy.
- The NDJSON decoder is a parser, not a network listener or an authorization boundary. Keep per-source/tenant quotas, bounded queues and backpressure around untrusted streams.
- Untrusted NXR1/MED1/YKMC streams remain ingestible without WASM publisher authorization. Stream trust and executable-artifact trust remain separate.
- Application-level byte, rate and memory ceilings do not replace upstream egress policy or DDoS protection.
- The persistent broker client pool remains plain TCP; TLS is supplied by a separately configured local sidecar. Its verified certificate identity is not yet bound to signed artifact-sender authorization.
- The native browser runtime, browser-WASM crate and WASI guest worker retain independent workspace versions; the 6.22.1 bump applies to the native yukkios package only.

## Release gate for 6.22.1

Before tagging or publishing:

1. Run bash scripts/check-cargo-lockfiles.sh, cargo +1.98.1 metadata --format-version 1 --locked, cargo +1.98.1 fmt --all -- --check, cargo +1.98.1 test --all-targets --locked, and strict Clippy on the exact candidate.
2. Validate standalone crawler-WASM, browser-WASM and WASI guest manifests and their lockfiles; build supported native Linux/macOS targets plus browser/WASI artifacts.
3. Pass Cargo package validation, Cargo lockfile integrity, RustSec/license audits, coverage, Docker validation and native Linux/macOS unit-test jobs.
4. Exercise crawler allowlist enforcement, DNS pinning, private/special-address rejection, proxy disablement, redirect refusal, robots fail-closed behavior, per-host pacing, page/crawl budgets, YCR1/YCE1 memory/fuel bounds and processor output caps.
5. Test NDJSON chunk boundaries, incomplete records, 16 KiB record limits, 256-record push limits, unknown fields/versions, dimension/source limits, null handling and non-finite values. Confirm callers apply source/tenant admission and bounded backpressure.
6. Pass paired Overhauled CMake/CTest multivariate and crawler-metric tests, BRK1/BRK2 live interoperability, browser-WASM broker smoke, NPU simulator and CPU fallback, plus supported Wayland/X11/XWayland smoke tests.
7. Confirm untrusted stream ingestion remains independent of executable publisher authorization and that no wire-format identity changed.
8. Only after all required checks pass and the release commit is approved, create the v6.22.1 tag and GitHub Release. Verify crates.io publication separately.

## Published release history

- v6.22.0 — published 2026-11-26; user-selected YCE1 crawler processing and bounded multivariate NDJSON observations. The GitHub Release has no attached binary assets.
- v6.21.0 — published 2026-11-26; bounded WASM crawler fabric, static extraction, provenance/metriculation reports and security remediation.
- v6.20.0 — published 2026-11-26; persistent broker sessions and strict mTLS-proxy endpoint routing.
- v6.19.0 — published 2026-11-24; native browser runtime, graphics smoke coverage and BRK2 device-preference delegation.
- v6.18.0 — published 2026-11-22; authenticated WASM sender and untrusted-stream flood controls.
- v6.17.0 — published 2026-11-22; conventional WASM import binding and the authenticated WASM handoff contract/schema.
- v6.16.0 — published 2026-11-21; lease-based broker discovery and BRK2 locality intent/result codec support.
- v6.15.0 — published 2026-11-21; resolver and benchmark concurrency improvements.
- v6.14.0 — published 2026-11-20; YuKKi workload directives and BRK2 worker-class interoperability.
