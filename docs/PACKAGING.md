# YuKKi-OS package distribution

> **Release line:** v6.21.0 is the latest published GitHub Release; v6.22.0 is a candidate. GitHub Release publication and crates.io publication are separate. The release workflow does not publish the browser-WASM or WASI guest packages to crates.io.

## Primary Rust package: crates.io

The root Cargo package is `yukkios` and includes the `yukkios` library plus
`yukki_core_node`, `yukki_dataset_bench`, and `yukki_eigensolver_bench`
binaries. The guest-worker and browser-WASM Cargo packages remain
`publish = false`; they are distributed as target-specific release archives,
not as generic host crates.

### Consumer commands

Install the runtime CLI:

```sh
cargo install yukkios --version 6.21.0 --locked --bin yukki_core_node
```

Add the library as a dependency:

```toml
[dependencies]
yukkios = "6.21.0"
```

Cargo's platform and native build prerequisites still apply. The optional
`native-crypto` feature links system mbed TLS libraries; it is not enabled by
default.

### First publication

A crates.io namespace is globally unique and an uploaded release version
cannot be replaced. The `Cargo Package Validation` workflow packages and
build-verifies the exact crate and enforces the published 10 MB archive limit.

The first crates.io publication needs a crates.io account with a verified
email and a publish-capable API token. Add that token as the repository Actions
secret `CRATES_IO_API_TOKEN`, then run **Actions → Publish yukkios to
crates.io**, selecting the `v6.22.0` release tag after it is created and validated. The workflow checks that the tag is an
ancestor of main, that the package version matches, and that no Rust runtime
or native source paths changed after the tag. It then runs `cargo package`
before publishing. The workflow now requires an exact v-prefixed tag match, unchanged packaged source after the tag, a successful locked package build, and a crates.io ownership/version check. The v6.22.0 candidate must not be published until its release gate is green. Do not add the token to a workflow file or commit it.

After the initial crate exists, configure a GitHub Actions trusted publisher in
the crates.io crate settings:
- Provider: GitHub Actions
- Owner: `rakshas-oss`
- Repository: `YuKKi-OS`
- Workflow file: `publish-crates.yml`

For later releases, dispatch the same workflow with `auth_method=trusted`.
It uses `rust-lang/crates-io-auth-action@v1` to obtain a short-lived OIDC
token, which is revoked at job completion. The long-lived API token is then no
longer needed. Trusted Publishing requires the initial manual publication and
a one-time publisher configuration; each crate has its own configuration.
Never publish a version that is already present.

## Native and WebAssembly release artifacts

The GitHub Release remains the source of platform-specific binaries and
WebAssembly artifacts. It publishes Linux x86_64, ARM64, ARMv7 and musl,
macOS x86_64 and ARM64, WASI guest-worker, browser-WASM application and
benchmark archives, plus SHA256SUMS. These artifacts are not Cargo crates.

## OCI images

The checked-in Dockerfile is a build recipe, not evidence that an image has
been published. GHCR publishing should be a separate release workflow with
`packages: write`, provenance, and multi-architecture validation before the
image is advertised as available.
