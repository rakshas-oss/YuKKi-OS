#!/usr/bin/env bash
set -euo pipefail

browser_bin="${1:-browser-runtime/target/release/yukki-browser}"
if [[ ! -x "$browser_bin" ]]; then
  echo "Browser binary not found or not executable: $browser_bin" >&2
  exit 1
fi

runtime_dir="${RUNNER_TEMP:-/tmp}/yukki-wayland-runtime"
weston_log="${RUNNER_TEMP:-/tmp}/yukki-weston.log"
rm -rf "$runtime_dir"
mkdir -p "$runtime_dir"
chmod 700 "$runtime_dir"
export XDG_RUNTIME_DIR="$runtime_dir"
export LIBGL_ALWAYS_SOFTWARE=1

weston \
  --backend=headless \
  --renderer=pixman \
  --socket=wayland-1 \
  --idle-time=0 \
  --xwayland \
  --log="$weston_log" &
weston_pid=$!

cleanup() {
  kill "$weston_pid" 2>/dev/null || true
  wait "$weston_pid" 2>/dev/null || true
}
trap cleanup EXIT

for _ in $(seq 1 100); do
  [[ -S "$XDG_RUNTIME_DIR/wayland-1" ]] && break
  if ! kill -0 "$weston_pid" 2>/dev/null; then
    cat "$weston_log" >&2 || true
    echo "Weston exited before creating its Wayland socket" >&2
    exit 1
  fi
  sleep 0.2
done

if [[ ! -S "$XDG_RUNTIME_DIR/wayland-1" ]]; then
  cat "$weston_log" >&2 || true
  echo "Weston did not create the Wayland socket" >&2
  exit 1
fi

export WAYLAND_DISPLAY=wayland-1
echo "Launching the GTK/WebKit browser through native Wayland"
YUKKI_BROWSER_DISPLAY_BACKEND=wayland \
YUKKI_BROWSER_SMOKE_EXIT_AFTER_MS=3000 \
  "$browser_bin" https://example.com

x_display=""
for _ in $(seq 1 100); do
  x_display="$(sed -nE 's/.*xserver listening on display (:[0-9]+).*/\1/p' "$weston_log" | tail -n 1)"
  [[ -n "$x_display" ]] && break
  if ! kill -0 "$weston_pid" 2>/dev/null; then
    cat "$weston_log" >&2 || true
    echo "Weston exited before XWayland became available" >&2
    exit 1
  fi
  sleep 0.2
done

if [[ -z "$x_display" ]]; then
  cat "$weston_log" >&2 || true
  echo "Weston did not start its XWayland server" >&2
  exit 1
fi

echo "Launching the GTK/WebKit browser through XWayland on DISPLAY=$x_display"
DISPLAY="$x_display" \
YUKKI_BROWSER_DISPLAY_BACKEND=xwayland \
YUKKI_BROWSER_SMOKE_EXIT_AFTER_MS=3000 \
  "$browser_bin" https://example.com
