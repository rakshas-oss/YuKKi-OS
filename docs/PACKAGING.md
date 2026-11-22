# YuKKi-OS package distribution

## Primary Rust package: crates.io

The root Cargo package is `yukkios` and includes the `yukkios` library plus
`yukki_core_node`, `yukki_dataset_bench`, and `yukki_eigensolver_bench`
binaries. The guest-worker and browser-WASM Cargo packages remain
`publish = false`; they are distributed as target-specific release archives,
not as generic host crates.

### Consumer commands

Install the runtime CLI:

```sh
cargo install yukkios --version 6.17.0 --locked --bin yukki_core_node
```

Add the library as a dependency:

```toml
[dependencies]
yukkios = "6.17.0"
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
crates.io**, selecting immutable release tag `6.17.0`. The workflow checks
that the tag and Cargo package version match and runs `cargo package` before
publishing. Do not add the token to a workflow file or commit it.

After the initial crate exists, configure crates.io Trusted Publishing for:
- GitHub owner: `rakshas-oss`
- Repository: `YuKKi-OS`
- Workflow: `publish-crates.yml`

Then replace the one-time API-token step with crates.io OIDC Trusted
Publishing for subsequent releases. Each crate requires its own trusted
publisher configuration. Never publish a version that is already present.

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
