# YuKKi-OS guest worker

User-safe `no_std` Wasm worker exporting `execute_inference_pipeline`. It
validates its inputs, takes the channel lock with `compare_exchange` (released
by an RAII guard on every path), hashes the tensor (128-bit FNV-style mix, for
integrity/telemetry only, not cryptographic), and yields to the host via
`wasmtime_yield_xpu` with a clamped timeout (default 5000 ms, max 30000 ms).
Error codes are documented in `src/lib.rs` (-1 invalid pointer, -2 lock
contention, -3 misaligned, -4 tensor too large, -5 empty, -6 XPU timeout, -7
other host status; host statuses <= -64 pass through).

## Build

    ./scripts/build_guest_worker.sh          # or add --check to run tests
    # manual: rustup target add wasm32-wasip1
    #         cd guest-worker && cargo build --release --target wasm32-wasip1

Output: `guest-worker/target/wasm32-wasip1/release/yukki_guest_worker.wasm`.

## Host integration and deployment boundary

The host-side API is `yukkios::wasm_ingest::handle_deploy`. It is a pure request handler, not an HTTP server or built-in `POST /v1/sandbox/deploy` route. A front end that exposes that route must authenticate the caller before invoking the function; YuKKi-OS does not supply that front end in this repository.

The handler validates the module and then smoke-runs it with a 16-byte zero tensor. A successful response does not persist or register the module. For real work, an application must call `run_guest` or `run_guest_with_streams` with the actual tensor and a host-provided `XpuHandler`. The latter can also expose bounded chunks from the host media store.

The worker currently validates input/channel state, hashes the tensor for integrity/telemetry (not cryptographic authentication), and yields to the host. It does not include a tokenizer, `llama.cpp`, model weights, or a complete inference engine.

### Version lifecycle and compilation

The native `ModuleLifecycleManager` can synchronously validate a candidate with Wasmtime, register its bytecode under a module/version identity, and coordinate a replacement through optional state handoff, active-version routing, quiesce, drain and release. The temporary compiled `wasmtime::Module` used during `prepare_version` is not retained as a compiled cache. The application must connect the active version handle to the real guest execution function.

This lifecycle is version replacement, not code merging: YuKKi-OS does not currently link multiple Wasm modules or policy functions into one merged compiled artifact, nor does it migrate guest linear memory or live GPU state. Overhauled manages broker-side module-version/placement metadata and task drainage; it is not a Wasm bytecode compiler or runtime.

An application-owned HTTP front end may choose to delegate a request body to `handle_deploy`, for example:

```sh
curl -X POST "https://YOUR_AUTHENTICATED_FRONTEND/v1/sandbox/deploy" \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Content-Type: application/wasm" \
     -H "X-YuKKi-Channel-Id: 0x98F4CA01E5B23344" \
     --data-binary @yukki_guest_worker.wasm
```

The URL above is served by your integration, not by `yukki_core_node`. See [the system administration how-to](../docs/SYSADMIN_HOWTO.md) for limits and lifecycle details.
