#!/usr/bin/env zsh
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
BINARY_PATH="$REPO_ROOT/target/release/yukki_core_node"
INSTALL_DIR="/usr/local/libexec/yukki"
INSTALL_PATH="$INSTALL_DIR/yukki_core_node"

show_usage() {
  cat <<USAGE
Usage:
  deploy_yukki_6_7_0_inet3.zsh --build-only
  deploy_yukki_6_7_0_inet3.zsh --install

Options:
  --build-only   Build release binary only
  --install      Build and install binary to $INSTALL_PATH (requires sudo)
USAGE
}

if [[ $# -ne 1 ]]; then
  show_usage
  exit 1
fi

MODE="$1"
if [[ "$MODE" != "--build-only" && "$MODE" != "--install" ]]; then
  show_usage
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "[error] cargo is required" >&2
  exit 1
fi

if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1 && ! command -v clang >/dev/null 2>&1; then
  echo "[error] a C compiler (cc/gcc/clang) is required" >&2
  exit 1
fi

echo "[info] building YuKKi OS v6.7.0 from $REPO_ROOT"
cd "$REPO_ROOT"
cargo build --release --locked

echo "[ok] build completed: $BINARY_PATH"

if [[ "$MODE" == "--install" ]]; then
  echo "[info] installing to $INSTALL_PATH"
  sudo install -d -o root -g root -m 0755 "$INSTALL_DIR"
  sudo install -o root -g root -m 0755 "$BINARY_PATH" "$INSTALL_PATH"
  echo "[ok] install completed"
fi
