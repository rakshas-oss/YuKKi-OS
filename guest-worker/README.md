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

## Deploy

The host-side ingest logic is `yukkios_6_8_0_inet3::wasm_ingest::handle_deploy`
(max module size, `\0asm` check, only the `env.wasmtime_yield_xpu` import,
required exports, fuel/epoch/memory limits, hex `X-YuKKi-Channel-Id`). The repo
ships no HTTP server or auth layer, so the front end serving
`POST /v1/sandbox/deploy` must authenticate callers before invoking it.

    curl -X POST "http://${YUKKI_NODE}/v1/sandbox/deploy" \
         -H "Authorization: ******" \
         -H "Content-Type: application/wasm" \
         -H "X-YuKKi-Channel-Id: 0x98F4CA01E5B23344" \
         --data-binary @yukki_guest_worker.wasm
