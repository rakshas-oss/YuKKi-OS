# YuKKi-OS — Versioning

## Release state

- **Latest published GitHub release:** v6.20.0 (2026-11-26), with native/browser/WASI assets and SHA256SUMS.
- **Next minor release candidate:** v6.21.0 (not tagged or published).
- **Native Cargo package candidate:** 6.21.0.
- **OCI image label candidate:** 6.21.0.
- **Rust toolchain pin:** 1.98.1.
- **Runtime binary:** `yukki_core_node`.
- **External package publication:** crates.io is not claimed; GitHub Release publication and registry publication are separate.

The v6.21.0 version metadata is a candidate only. Do not create a tag or publish archives until the release gate below passes on the exact release commit.

## Version assessment

The published v6.20.0 release delivered endpoint-scoped persistent BRK1/BRK2 client sessions and strict mTLS-sidecar endpoint enforcement, paired with Overhauled's bounded broker-session and replay-journal work.

The new crawler capability merged after v6.20.0 is an additive user-facing feature and justifies a minor version increment to v6.21.0:

- Add the opt-in native `yukki_crawl` CLI/library for bounded asynchronous HTTP/HTTPS fetching.
- Add a separate no-std YCR1 WebAssembly guest for static HTML title/link extraction, instantiated with isolated Wasmtime state and bounded fuel/memory.
- Enforce explicit DNS-domain allowlists, validated-answer pinning, private/special-address rejection, no inherited proxy use, no redirects, robots.txt checks, per-host pacing, bounded concurrency, request timeouts and page/crawl byte budgets.
- Produce page-level provenance, content digests, status, link and byte counts, fetch/extraction timings and an aggregate JSON report.
- Include Aikido dependency/security remediation and the associated crawler CI fixes from PR #188.

Overhauled v1.10.0 adds a separate constant-memory C++ accumulator for normalized crawler page observations. This is CPU-side aggregation; it is not a BRK1/BRK2 operation, does not receive raw HTML, and does not claim GPU/NPU crawler dispatch.

## Compatibility and security boundaries

- Existing YKMC, BRK1, BRK2, NXR1 and WSM1 wire identities are preserved; this release candidate does not intentionally change protocol framing.
- The crawler's native host owns networking and policy. The WASM guest has no WASI, imports, sockets, filesystem or credentials; it performs bounded static HTML extraction only.
- The crawler is not a JavaScript browser, a CAPTCHA/form automation tool, a distributed or persistent crawl frontier, or a historical metrics database.
- Do not forward raw HTML into the broker/accelerator path. The paired Overhauled accumulator accepts normalized numeric observations only and remains separately embedded by the caller.
- Untrusted NXR1/MED1/YKMC streams remain ingestible without WASM publisher authorization. Stream trust and executable-artifact trust remain separate.
- Application-level byte, rate and memory ceilings do not replace upstream egress policy or DDoS protection.
- The persistent broker client pool remains plain TCP; TLS is provided by a separately configured local sidecar. The verified sidecar certificate identity is not yet bound to the signed artifact-sender identity.
- The native browser runtime, browser-WASM crate and WASI guest worker retain independent workspace versions; the 6.21.0 bump applies to the native `yukkios` package only.

## Release gate for 6.21.0

Before tagging or publishing:

1. The lock-refresh workflow's hard-coded `wasmtime 50.0.3` downgrade is corrected here to `51.0.0`, matching the manifest's `^51.0` requirement and the existing Cargo.lock resolution. The PR's branch checks cannot validate a main-only push workflow, so verify the workflow succeeds after this change reaches main; keep the full RustSec audit and locked dependency checks mandatory.
2. Run `cargo metadata --locked` for the root, crawler guest and browser-WASM manifests; then run `cargo fmt --all -- --check`, `cargo test --all-targets --locked`, and strict Clippy on the exact candidate.
3. Pass supported native Linux/macOS tests/builds, browser-WASM and WASI builds, crawler-specific YCR1/host tests, Cargo lockfile integrity, dependency/license/security audits, Docker validation and coverage.
4. Exercise crawler allowlist enforcement, DNS pinning, private/special-address rejection, proxy disablement, redirect refusal, robots fail-closed behavior, per-host pacing, page/crawl byte ceilings, concurrency limits and guest memory/fuel bounds.
5. Confirm JSON report provenance and aggregate counts for success and failed pages; verify the paired Overhauled accumulator's own CMake/CTest lane and preserve its CPU-only/no-BRK boundary.
6. Re-run paired BRK1/BRK2 live interoperability, stream/gateway limits and mTLS sidecar validation. Confirm untrusted stream ingestion remains independent from executable publisher authorization.
7. Only after all required checks pass and the release commit is approved, create the v6.21.0 tag and GitHub Release. Verify crates.io publication separately.

## Published release history

- v6.20.0 — published 2026-11-26; bounded persistent broker sessions and strict mTLS-proxy endpoint routing.
- v6.19.0 — published 2026-11-24; native browser runtime, graphics smoke coverage and BRK2 device-preference delegation.
- v6.18.0 — published 2026-11-22; authenticated WASM sender and untrusted-stream flood controls.
- v6.17.0 — published 2026-11-22; conventional WASM import binding and the authenticated WASM handoff contract/schema.
- v6.16.0 — published 2026-11-21; lease-based broker discovery and BRK2 locality intent/result codec support.
- v6.15.0 — published 2026-11-21; resolver and benchmark concurrency improvements.
- v6.14.0 — published 2026-11-20; YuKKi workload directives and BRK2 worker-class interoperability.
