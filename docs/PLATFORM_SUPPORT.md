# Platform Support and Deployment Profiles

This document defines the supported deployment boundaries for YuKKi-OS.

## Native Windows (MSVC)

The native node is built for `x86_64-pc-windows-msvc` using the Microsoft
Visual C++ toolchain. The CI release build produces
`yukki_core_node.exe`; the Windows test job exercises the native target.

Build locally from a Visual Studio Developer PowerShell with the MSVC C++
build tools installed:

```powershell
rustup target add x86_64-pc-windows-msvc
cargo build --release --locked --target x86_64-pc-windows-msvc
cargo test --all-targets --locked
```

The optional `native-crypto` feature requires separately installed and
configured mbedTLS libraries and is not part of the default Windows build.

## WebAssembly guest deployment (WASI Preview 1)

The WebAssembly deployment artifact is the isolated, `no_std` guest worker in
`guest-worker/`, not the native YuKKi-OS node/library. It targets
`wasm32-wasip1` and is hosted by the native YuKKi-OS Wasmtime runtime.

Build and test:

```sh
rustup target add wasm32-wasip1
cargo build --manifest-path guest-worker/Cargo.toml --release --locked --target wasm32-wasip1
cargo test --manifest-path guest-worker/Cargo.toml --locked
```

Artifact:
`guest-worker/target/wasm32-wasip1/release/yukki_guest_worker.wasm`

The host validates module size, imports, exports, fuel, memory, and execution
limits before instantiation. Deployment HTTP authentication belongs to the
front end that invokes the host-side ingest handler.

## Explicit non-goals

- The native node is not itself a browser `wasm32-unknown-unknown` application.
- The WASI guest worker does not contain the peer mesh, TCP broker client,
  gateway, or Wasmtime host runtime.
- The guest worker does not provide a standalone network server.
- Native MSVC builds with optional mbedTLS are supported only when the
  operator supplies compatible Windows mbedTLS libraries and linker settings.

## Qualification gates

A platform is release-qualified only when its corresponding CI jobs pass:
native Windows build and tests for MSVC; WASI guest build and guest tests for
WebAssembly. A successful cross-compile alone is not runtime qualification.
