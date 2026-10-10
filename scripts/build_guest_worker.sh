#!/usr/bin/env bash
# Build the YuKKi-OS guest worker to wasm32-wasip1. Pass --check to also run
# the guest unit tests and the host integration test against the built wasm.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET=wasm32-wasip1
WASM="$ROOT/guest-worker/target/$TARGET/release/yukki_guest_worker.wasm"

rustup target add "$TARGET"
(cd "$ROOT/guest-worker" && cargo build --release --target "$TARGET")
echo "built: $WASM"

if [[ "${1:-}" == "--check" ]]; then
  (cd "$ROOT/guest-worker" && cargo test)
  (cd "$ROOT" && YUKKI_GUEST_WASM="$WASM" cargo test --test test_wasm_ingest)
fi
