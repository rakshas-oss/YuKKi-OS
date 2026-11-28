# YuKKi-OS — Versioning

## Release state

- **Latest published GitHub release:** [v6.23.0](https://github.com/rakshas-oss/YuKKi-OS/releases/tag/v6.23.0) (published 2026-11-28); no binary assets are manually attached.
- **Native Cargo package source version:** 6.23.0.
- **OCI image label:** 6.23.0; registry publication is separate.
- **Rust toolchain pin:** 1.98.1.
- **Runtime binary:** `yukki_core_node`.
- **Independent workspace packages:** native browser runtime, browser-WASM, crawler extractor, and WASI guest remain independently versioned at 0.1.0.
- **External package publication:** crates.io is not claimed; GitHub Release publication and registry publication are separate.

The v6.23.0 release is an additive feature release. It advances the native `yukkios` package and OCI image metadata for the native-browser crawler workflow and optional control-plane metric adoption. It does not change the separately versioned 0.1.0 browser/WASI workspace packages. The GitHub tag is published; crates.io and OCI registry publication are not implied.

## Version assessment

The published v6.23.0 native package source includes the following additive user-facing capabilities:

- A dedicated Crawler utility tab in the native Wry browser runtime receives bounded page-completion events from the native crawler.
- Result hyperlinks open an extractive, text-only page summary in the last active main browsing tab. The summary provides a separate hyperlink to the original HTML; raw HTML is not broadcast to the browser UI.
- An optional publishing control reuses the node's configured authenticated gateway. It sends batches of schema-v1 numeric page observations for adoption by the browser-WASM workspace; page URLs, titles, excerpts, and raw HTML are excluded.
- The browser-WASM workspace discovers the node-local observation streams separately from YKMC media and validates adopted records in its Rust WASM core.

These are additive native/browser and gateway-surface capabilities and justify a minor version increment from 6.22.x to 6.23.0. No existing YKMC, BRK1, BRK2, NXR1, or WSM1 wire identity is intentionally changed.

## Compatibility, privacy, and security boundaries

- The crawler fetches allowlisted static HTML/XHTML. It does not execute page JavaScript, solve CAPTCHAs, submit forms, bypass access controls, or follow redirects.
- The page preview is an extractive visible-text excerpt, not an AI-generated semantic summary.
- Raw HTML remains on the native host and is not broadcast into the crawler utility or generated summary view.
- Crawler results remain local unless an operator explicitly enables the numeric metric-publishing option. The published observation vector excludes URLs, titles, excerpts, and page bodies.
- Gateway publishing requires the existing bearer-authenticated gateway configuration. Remote publishing requires HTTPS; missing or unavailable gateway configuration leaves local crawling available and reports a non-fatal publish warning.
- The observation store is bounded to 128 streams, 512 observations per stream, and 16,384 observations total. It is in-memory and node-local; persistence and peer-mesh replication are not implied.
- The browser result event queue is bounded to 16 pending records; per-event link and preview limits remain enforced. The UI page-count control does not replace crawler network policy.
- YCR1 extraction and optional YCE1 processor execution remain separate capabilities. Crawled content is opaque data and cannot install or select executable code.
- Untrusted stream decoding does not authenticate sources or authorize execution. Applications remain responsible for per-source/tenant admission, bounded queues, backpressure, and audit policy.
- Application-level rate and memory ceilings do not replace host egress controls or upstream DDoS protection.
- The native browser runtime, browser-WASM crate, crawler extractor, and WASI guest worker retain independent 0.1.0 versions.
- GitHub source/artifact publication does not imply crates.io publication.

## Validation record and future release process

The v6.23.0 Git tag and GitHub Release were published on 2026-11-28. The release has no manually attached binary assets. Do not infer that crates.io or GHCR publication occurred. For a future release, repeat the following checks on the exact proposed tag candidate:

1. Run `bash scripts/check-cargo-lockfiles.sh`, `cargo +1.98.1 metadata --format-version 1 --locked`, `cargo +1.98.1 fmt --all -- --check`, `cargo +1.98.1 test --all-targets --locked`, and strict Clippy on the exact candidate.
2. Validate standalone crawler-WASM, browser-WASM, browser-runtime, and WASI guest manifests and lockfiles; build all supported native, browser, and WASI targets.
3. Pass Cargo package validation, lockfile integrity, RustSec/license audits, coverage, Docker validation, and supported native Linux/macOS tests.
4. Exercise crawler domain allowlists, DNS pinning, private/special-address rejection, proxy disablement, redirect refusal, robots fail-closed behavior, pacing, page/crawl budgets, timeouts, concurrency, and YCR1/YCE1 fuel/memory/output caps.
5. Test browser Crawler utility event ordering, bounded-queue backpressure, hyperlink navigation to the main tab, extractive summary length, original-HTML navigation, and the guarantee that raw HTML is not sent to browser UI components.
6. Test opt-in gateway publishing with inherited token/address configuration, HTTPS-only remote mode, non-fatal behavior when publishing is unavailable, 16-record batching, nine numeric fields, and exclusion of URLs/text/HTML.
7. Test data-stream admission and retention limits, source/tenant quotas at callers, browser-WASM discovery and schema validation, and the node-local/non-durable storage boundary.
8. Pass paired Overhauled CMake/CTest crawler-metric and multivariate tests, BRK1/BRK2 live interoperability, browser-WASM broker smoke, NPU simulator and CPU fallback, plus supported Wayland/X11/XWayland smoke tests.
9. Confirm untrusted stream ingestion remains independent of executable-publisher authorization and that existing wire identities are unchanged.
10. After the required checks pass and the release commit is approved, publish the next intended tag and GitHub Release. Verify crates.io and OCI registry publication separately.

## Published release history

- v6.23.0 — published 2026-11-28; native-browser crawler utility, extractive summary navigation, optional authenticated numeric metric publishing, and browser-WASM observation adoption. No manually attached binary assets.
- v6.22.1 — published 2026-11-27; NDJSON final-record test and Rust formatting maintenance. Native/browser/WASI archives and SHA256SUMS are attached to the GitHub Release.
- v6.22.0 — published 2026-11-26; user-selected YCE1 crawler processing and bounded multivariate NDJSON observations. No release assets were attached.
- v6.21.0 — published 2026-11-26; bounded WASM crawler fabric, static extraction, provenance/metriculation reports, and security remediation.
- v6.20.0 — published 2026-11-26; persistent broker sessions and strict mTLS-proxy endpoint routing.
- v6.19.0 — published 2026-11-24; native browser runtime, graphics smoke coverage, and BRK2 device-preference delegation.
- v6.18.0 — published 2026-11-22; authenticated WASM sender and untrusted-stream flood controls.
- v6.17.0 — published 2026-11-22; conventional WASM import binding and the authenticated WASM handoff contract/schema.
- v6.16.0 — published 2026-11-21; lease-based broker discovery and BRK2 locality intent/result codec support.
- v6.15.0 — published 2026-11-21; resolver and benchmark concurrency improvements.
- v6.14.0 — published 2026-11-20; YuKKi workload directives and BRK2 worker-class interoperability.
