# Third-Party Notices

Rust dependencies are obtained from crates.io as recorded in `Cargo.lock`.
Their licenses and any applicable attribution or notice requirements continue
to apply when distributing binaries. No third-party source is vendored in this
repository.

The Docker image is based on Debian and redistributes Debian packages along
with the application binary. Those packages remain subject to their respective
licenses; consult Debian's package documentation and license notices for the
contents of a specific image.

To regenerate the dependency license inventory, install
[cargo-license](https://crates.io/crates/cargo-license) with
`cargo install cargo-license --locked`, then run `cargo license --tsv` from the
repository root. Review the output for dependency changes and preserve any
required third-party notices when distributing the application.

## Provenance follow-up

Verify the provenance and licensing of `src/drivers/ethosu85_async.rs` and
`src/net/nxr1_channel.rs` before relying on or distributing those orphaned
source files.
