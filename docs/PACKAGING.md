# YuKKi-OS package distribution

> **Release line:** v6.22.0 is the latest published GitHub Release; v6.22.1 is a patch candidate. The v6.22.0 release has no attached binary assets. GitHub Release publication and crates.io publication are separate. The release workflow does not publish the browser-WASM or WASI guest packages to crates.io.

## Primary Rust package: crates.io

The root Cargo package is `yukkios` and includes the `yukkios` library plus
`yukki_core_node`, `yukki_dataset_bench`, and `yukki_eigensolver_bench`
binaries. The guest-worker and browser-WASM Cargo packages remain
`publish = false`; they are distributed as target-specific release archives,
not as generic host crates.

### Consumer commands

The v6.22.0 GitHub Release has no attached binary assets; the root crate has
not yet been published to crates.io. To install the CLI from the latest
published source tag:

```sh
cargo install --git https://github.com/rakshas-oss/YuKKi-OS --tag v6.22.0 \
  --locked --bin yukki_core_node
```

Until the first crates.io publication, depend on the published source tag:

```toml
[dependencies]
yukkios = { git = "https://github.com/rakshas-oss/YuKKi-OS", tag = "v6.21.0" }
```

After crates.io accepts the first upload, consumers can use a registry
dependency such as `yukkios = "6.22.0"`. Do not use that form before the
version is visible in crates.io. Cargo's platform and native build
prerequisites still apply. The optional `native-crypto` feature links system
mbed TLS libraries; it is not enabled by default.

### First publication

A crates.io namespace is globally unique and an uploaded release version
cannot be replaced. The `Cargo Package Validation` workflow packages and
build-verifies the exact crate and enforces the published 10 MB archive limit.

The first crates.io publication needs a crates.io account with a verified
email and a publish-capable API token. Add that token as the repository Actions
secret `CRATES_IO_API_TOKEN`, then run **Actions → Publish yukkios to
crates.io**, selecting the already-published `v6.22.0` release tag. Do not select
v6.22.1 until its patch-candidate release gate has passed. For this first publication, explicitly choose
`auth_method=token`; the workflow will fail closed if the secret is absent.
The workflow checks that the tag is an ancestor of main, that the package
version matches, that packaged source files have not changed after the tag,
and that the crates.io package identity belongs to this repository and the
version is unused. It then runs a locked `cargo package` before publishing.
After the first publication, configure the crates.io Trusted Publisher and
subsequent runs may select `auth_method=trusted` to use short-lived OIDC
credentials. Do not publish the v6.22.1 patch candidate until its release gate is green. Do not add the token to a workflow file or commit it.

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

GitHub Release assets are release-specific and must be verified rather than
assumed. The current v6.22.0 release has no attached native, browser-WASM or
WASI binary assets and no attached SHA256SUMS. Build supported targets from
the published source tag or use a release whose attached assets and checksums
have been independently verified. These artifacts are not Cargo crates.

## OCI images

The checked-in Dockerfile is a build recipe, not evidence that an image has
been published. GHCR publishing should be a separate release workflow with
`packages: write`, provenance, and multi-architecture validation before the
image is advertised as available.
