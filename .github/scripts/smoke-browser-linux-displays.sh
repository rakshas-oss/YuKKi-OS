#!/usr/bin/env bash
set -euo pipefail

browser_bin="${1:-browser-runtime/target/release/yukki-browser}"
if [[ ! -x "$browser_bin" ]]; then
  echo "Browser binary not found or not executable: $browser_bin" >&2
  exit 1
fi

runtime_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/yukki-display-smoke.XXXXXX")"
chmod 700 "$runtime_dir"
xvfb_display_file="$runtime_dir/xvfb.display"
xvfb_log="$runtime_dir/xvfb.log"
mkdir -p /tmp/.X11-unix
chmod 1777 /tmp/.X11-unix
export LIBGL_ALWAYS_SOFTWARE=1
export XDG_RUNTIME_DIR="$runtime_dir"

xvfb_pid=""
cleanup() {
  if [[ -n "$xvfb_pid" ]]; then
    kill "$xvfb_pid" 2>/dev/null || true
    wait "$xvfb_pid" 2>/dev/null || true
  fi
  rm -rf "$runtime_dir"
}
trap cleanup EXIT

run_browser() {
  local label="$1"
  shift
  echo "Launching YuKKi Browser through $label"
  timeout 30s env "$@" YUKKI_BROWSER_SMOKE_EXIT_AFTER_MS=3000 "$browser_bin" https://example.com
}

# First exercise a conventional X11 server independently of Wayland. -displayfd
# asks Xvfb to allocate a free display number instead of racing a fixed :99.
Xvfb -displayfd 3 -screen 0 1280x820x24 -nolisten tcp -ac \
  3>"$xvfb_display_file" >"$xvfb_log" 2>&1 &
xvfb_pid=$!

for _ in $(seq 1 100); do
  if [[ -s "$xvfb_display_file" ]]; then
    break
  fi
  if ! kill -0 "$xvfb_pid" 2>/dev/null; then
    cat "$xvfb_log" >&2 || true
    echo "Xvfb exited before allocating a display" >&2
    exit 1
  fi
  sleep 0.1
done

if [[ ! -s "$xvfb_display_file" ]]; then
  cat "$xvfb_log" >&2 || true
  echo "Xvfb did not allocate an X11 display" >&2
  exit 1
fi

xvfb_number="$(tr -d '[:space:]' < "$xvfb_display_file")"
if [[ ! "$xvfb_number" =~ ^[0-9]+$ ]]; then
  cat "$xvfb_log" >&2 || true
  echo "Xvfb returned an invalid display number: $xvfb_number" >&2
  exit 1
fi
xvfb_socket="/tmp/.X11-unix/X$xvfb_number"
for _ in $(seq 1 100); do
  [[ -S "$xvfb_socket" ]] && break
  if ! kill -0 "$xvfb_pid" 2>/dev/null; then
    cat "$xvfb_log" >&2 || true
    echo "Xvfb exited before creating its X11 socket" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ ! -S "$xvfb_socket" ]]; then
  cat "$xvfb_log" >&2 || true
  echo "Xvfb did not create its X11 socket" >&2
  exit 1
fi

run_browser "X11/Xvfb" \
  -u WAYLAND_DISPLAY -u WAYLAND_SOCKET -u XAUTHORITY \
  XDG_RUNTIME_DIR="$runtime_dir" DISPLAY=":$xvfb_number" \
  XDG_SESSION_TYPE=x11 GDK_BACKEND=x11 \
  YUKKI_BROWSER_DISPLAY_BACKEND=x11

# Run the Wayland client as a Weston child. Weston supplies the exact
# WAYLAND_DISPLAY and XDG_RUNTIME_DIR pair to its child process; this avoids
# stale runner-session variables and makes the smoke test self-contained.
wayland_log="$runtime_dir/weston-wayland.log"
echo "Launching YuKKi Browser through native Wayland"
timeout 30s env \
  -u DISPLAY -u WAYLAND_DISPLAY -u WAYLAND_SOCKET -u XAUTHORITY \
  XDG_RUNTIME_DIR="$runtime_dir" XDG_SESSION_TYPE=wayland GDK_BACKEND=wayland \
  YUKKI_BROWSER_DISPLAY_BACKEND=wayland YUKKI_BROWSER_SMOKE_EXIT_AFTER_MS=3000 \
  weston --no-config --backend=headless --renderer=pixman \
    --socket=wayland-native --idle-time=0 --log="$wayland_log" \
    -- "$browser_bin" https://example.com || {
      cat "$wayland_log" >&2 || true
      echo "Native Wayland browser smoke test failed" >&2
      exit 1
    }

# Weston exports DISPLAY (and its XWayland session context) to the child
# process. This is intentionally distinct from the standalone Xvfb/X11 test.
xwayland_log="$runtime_dir/weston-xwayland.log"
echo "Launching YuKKi Browser through XWayland"
timeout 30s env \
  -u DISPLAY -u WAYLAND_DISPLAY -u WAYLAND_SOCKET -u XAUTHORITY \
  XDG_RUNTIME_DIR="$runtime_dir" XDG_SESSION_TYPE=wayland GDK_BACKEND=x11 \
  YUKKI_BROWSER_DISPLAY_BACKEND=xwayland YUKKI_BROWSER_SMOKE_EXIT_AFTER_MS=3000 \
  weston --no-config --backend=headless --renderer=pixman \
    --socket=wayland-xwayland --idle-time=0 --xwayland --log="$xwayland_log" \
    -- "$browser_bin" https://example.com || {
      cat "$xwayland_log" >&2 || true
      echo "XWayland browser smoke test failed" >&2
      exit 1
    }
