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
if [[ ! -d /tmp/.X11-unix ]]; then
  mkdir -m 1777 /tmp/.X11-unix
fi
export LIBGL_ALWAYS_SOFTWARE=1
export XDG_RUNTIME_DIR="$runtime_dir"

xvfb_pid=""
weston_pid=""
cleanup() {
  if [[ -n "$weston_pid" ]]; then
    kill "$weston_pid" 2>/dev/null || true
    wait "$weston_pid" 2>/dev/null || true
  fi
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

wait_for_wayland_socket() {
  local socket_name="$1"
  local log_file="$2"
  for _ in $(seq 1 100); do
    if [[ -S "$XDG_RUNTIME_DIR/$socket_name" ]]; then
      return 0
    fi
    if ! kill -0 "$weston_pid" 2>/dev/null; then
      cat "$log_file" >&2 || true
      echo "Weston exited before creating Wayland socket '$socket_name'" >&2
      return 1
    fi
    sleep 0.1
  done
  cat "$log_file" >&2 || true
  echo "Weston did not create Wayland socket '$socket_name'" >&2
  return 1
}

stop_weston() {
  if [[ -n "$weston_pid" ]]; then
    kill "$weston_pid" 2>/dev/null || true
    wait "$weston_pid" 2>/dev/null || true
    weston_pid=""
  fi
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
  if [[ -S "$xvfb_socket" ]]; then
    break
  fi
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

run_browser "standalone X11/Xvfb" \
  -u WAYLAND_DISPLAY -u WAYLAND_SOCKET -u XAUTHORITY \
  XDG_RUNTIME_DIR="$runtime_dir" DISPLAY=":$xvfb_number" \
  XDG_SESSION_TYPE=x11 GDK_BACKEND=x11 \
  YUKKI_BROWSER_DISPLAY_BACKEND=x11

# Start Weston as a compositor process, then connect the browser as a separate
# client. Weston does not act as a generic command wrapper for arbitrary
# commands after "--"; the socket is the explicit readiness boundary.
wayland_log="$runtime_dir/weston-wayland.log"
echo "Starting headless Weston for native Wayland"
weston --no-config --backend=headless --renderer=pixman \
  --socket=wayland-native --idle-time=0 --log="$wayland_log" \
  >"$runtime_dir/weston-wayland.stdout" 2>&1 &
weston_pid=$!
wait_for_wayland_socket wayland-native "$wayland_log"
run_browser "native Wayland" \
  -u DISPLAY -u WAYLAND_SOCKET -u XAUTHORITY \
  XDG_RUNTIME_DIR="$runtime_dir" WAYLAND_DISPLAY=wayland-native \
  XDG_SESSION_TYPE=wayland GDK_BACKEND=wayland \
  YUKKI_BROWSER_DISPLAY_BACKEND=wayland
stop_weston

# A second Weston instance owns a Wayland session and launches XWayland. Wait
# for its reported X display and Unix socket before connecting the X11 client.
xwayland_log="$runtime_dir/weston-xwayland.log"
echo "Starting headless Weston with XWayland enabled"
weston --no-config --backend=headless --renderer=pixman \
  --socket=wayland-xwayland --idle-time=0 --xwayland --log="$xwayland_log" \
  >"$runtime_dir/weston-xwayland.stdout" 2>&1 &
weston_pid=$!
wait_for_wayland_socket wayland-xwayland "$xwayland_log"

xwayland_display=""
for _ in $(seq 1 100); do
  xwayland_display="$(sed -nE 's/.*xserver listening on display (:[0-9]+).*/\1/p' "$xwayland_log" | tail -n 1)"
  if [[ -n "$xwayland_display" && -S "/tmp/.X11-unix/X${xwayland_display#:}" ]]; then
    break
  fi
  if ! kill -0 "$weston_pid" 2>/dev/null; then
    cat "$xwayland_log" >&2 || true
    echo "Weston exited before XWayland became available" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ -z "$xwayland_display" || ! -S "/tmp/.X11-unix/X${xwayland_display#:}" ]]; then
  cat "$xwayland_log" >&2 || true
  cat "$runtime_dir/weston-xwayland.stdout" >&2 || true
  echo "Weston did not make an XWayland display socket available" >&2
  exit 1
fi

run_browser "XWayland inside Weston" \
  -u WAYLAND_SOCKET -u XAUTHORITY \
  XDG_RUNTIME_DIR="$runtime_dir" WAYLAND_DISPLAY=wayland-xwayland \
  DISPLAY="$xwayland_display" XDG_SESSION_TYPE=wayland GDK_BACKEND=x11 \
  YUKKI_BROWSER_DISPLAY_BACKEND=xwayland
stop_weston
