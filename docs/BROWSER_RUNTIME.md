# YuKKi Browser Runtime

## Purpose

The existing `browser-wasm` application is a responsive gateway workspace for authenticated YuKKi streams and local spatiotemporal tools. It is not an HTML browser engine. This document describes the separate native runtime that adds a real page-rendering surface without replacing the WASM workspace.

The first implementation uses [Wry](https://docs.rs/wry/latest/wry/) as the engine adapter and [Tao](https://docs.rs/tao/latest/tao/) for the native window/event loop. Wry delegates rendering to the platform WebView:
- macOS: WKWebView / WebKit
- Linux: WebKitGTK

The actual engine and feature support therefore follow the installed OS runtime. This is not a Chromium/CEF distribution and does not promise identical engine versions across hosts.

## Runtime contract and proof of concept

The `yukki-browser-runtime` crate defines a narrow `EngineAdapter` contract for navigation, back/forward, reload, and history capability. The Wry adapter implements that contract. Browser chrome runs in a separate, bundled toolbar WebView; website pages are rendered in their own WebView child surfaces. The two surfaces communicate only through a host-validated IPC command schema.

Start the proof of concept from the repository root:

```sh
# Linux (Debian/Ubuntu)
sudo apt install libwebkit2gtk-4.1-dev

cargo test --manifest-path browser-runtime/Cargo.toml
cargo run --manifest-path browser-runtime/Cargo.toml -- https://example.com
```

The initial implementation targets macOS and Linux/X11. Wry uses WebKitGTK on Linux; Wayland requires the GTK-container integration path and is not enabled by this first adapter. Windows MSVC is not an advertised YuKKi-OS target. The existing `browser-wasm` target remains independently built and deployable as a static web application.

The address bar accepts HTTP(S) URLs, hostnames (upgraded to HTTPS), and search terms. The shell includes navigation, reload, tabs, bounded history, and bookmarks. The runtime caps the number of resident tabs at eight. Per-tab top-level page-load timings are exposed in the tab tooltip and status line as an initial performance baseline; they do not measure GPU work or whole-page resource costs. The toolbar probes whether WebGL 2 and a WebGPU adapter are available in the platform WebView and reports the APIs detected. This is capability detection only: it does not prove hardware acceleration, driver stability, or YuKKi GPU/NPU scheduling.

YuKKi's own history and bookmarks are stored separately under the user's XDG state directory (or `~/.local/state` fallback). The state file is capped at 1 MiB, history/bookmarks at 200 entries each, URLs at 2,048 bytes, and the Unix state directory/file are restricted to mode 0700/0600. The stored history includes page URL paths and query strings. WebView page storage is configured for incognito/private sessions, but YuKKi's own history/bookmarks remain persistent.

## Security and resource boundaries

The initial policy:
- permits only HTTP and HTTPS top-level navigation;
- limits address and navigation URLs to 2,048 bytes;
- rejects embedded URL credentials, active/local schemes, obvious local/internal hostnames, and private/loopback/link-local/reserved IP literals;
- denies pop-up windows by default and routes valid `window.open` requests into a bounded tab;
- delegates page permission prompts to the native WebView default prompt;
- disables browser downloads in this proof of concept rather than silently allowing unbounded disk writes;
- bounds toolbar IPC messages to 4 KiB, resident tabs to eight, and the host history/bookmark lists to 200 entries each.

### Optional outbound proxy

Set `YUKKI_BROWSER_PROXY` to an HTTP CONNECT or SOCKS5 endpoint to route page WebViews through that proxy:

```sh
YUKKI_BROWSER_PROXY=socks5://127.0.0.1:1080 cargo run --manifest-path browser-runtime/Cargo.toml -- https://example.com
YUKKI_BROWSER_PROXY=http://127.0.0.1:3128 cargo run --manifest-path browser-runtime/Cargo.toml -- https://example.com
```

Proxy URLs must include an explicit port and cannot include credentials, paths, queries, or fragments. The runtime does not start or manage the proxy, authenticate to it, or prove that it filters private destinations. The Wry macOS proxy integration requires macOS 14 or later.

**Important limitation:** the URL policy is a top-level navigation guard, not a network egress firewall. Wry does not provide one uniform cross-platform hook here for filtering every subresource request and DNS result. A hostile page may cause its engine to request subresources or attempt connections outside the top-level navigation callback. Private-network and mesh isolation therefore still requires a host-enforced egress proxy/firewall before this runtime is treated as a hardened browsing environment. The runtime does not expose YuKKi mesh APIs, bearer tokens, stream credentials, NPU/GPU controls, or filesystem paths to page JavaScript.

The initial version also does not impose hard per-page CPU, memory, or download-byte quotas. The optional WebView proxy is a routing control, not an enforceable egress policy; use an OS firewall or a trusted policy-enforcing proxy with DNS resolution and private-network denial for that boundary. WebRTC and other platform networking paths also need to be included in the host-level egress policy. Eight tabs is a count limit, not a substitute for OS-enforced process/resource limits. WebGL/WebGPU and hardware acceleration are provided only to the extent supported and enabled by the underlying WebKit/WebView runtime; YuKKi does not yet schedule browser rendering on its NPU or expose deterministic GPU allocation controls.

The default private WebView mode avoids intentionally persisting website cookies/storage, while YuKKi's own bookmarks/history remain persistent. Permission handling is delegated to the host engine's default prompt behavior, which varies by OS and permission type. Per-origin permission management is a follow-up requirement.

## Phases and current implementation status

| Capability | Status |
|---|---|
| Engine adapter and page-rendering proof of concept | Implemented in this PR |
| Separate browser chrome and site-rendering surfaces | Implemented |
| URL scheme/credential/local-target checks | Implemented for top-level navigation only; address/IPC length bounded |
| Optional HTTP CONNECT / SOCKS5 page proxy | Implemented through Wry; no proxy is started or enforced by default |
| Tabs, navigation history, bookmarks | Implemented with an eight-tab cap |
| Native permission prompt delegation | Basic engine default; per-origin settings pending |
| Downloads | Disabled pending bounded download storage and quota enforcement |
| Whole-request egress mediation / mesh isolation | Not complete; requires OS proxy/firewall integration |
| Hard CPU/memory quotas and robust site/process isolation | Not complete |
| Wayland GTK container adapter | Not enabled in this first implementation |
| Page-load timing baseline | Implemented per tab; measures Wry page-load event duration only |
| Browser graphics acceleration benchmarking | Not complete; platform engine defaults apply |

## Relationship to the browser-WASM workspace

Keep `browser-wasm` as the portable stream/spatiotemporal client and preserve its existing WASM verifier, authenticated gateway behavior, bounded stream reads, and responsive layout. The native runtime is an optional desktop page-rendering host; it does not replace or change the browser-WASM deployment artifact.

## References

- [Wry crate documentation](https://docs.rs/wry/latest/wry/)
- [Tao crate documentation](https://docs.rs/tao/latest/tao/)
- [Wry platform and Linux dependency notes](https://docs.rs/crate/wry/latest)


## Delegation across YuKKi servers

The browser runtime can delegate bounded auxiliary compute to other YuKKi
servers using the broker records learned by the local node over its
PSK-authenticated peer mesh. Make the capability and broker endpoint
environment variables available to both the YuKKi node and browser process
when both run on the same server; the browser does not infer a local GPU from
the mere presence of a broker connection. This is a separate execution plane: WebKit still
renders web pages locally and owns the WebGL/WebGPU context. The broker path
does not remote-render or move a page's compositor.

### Advertise participating servers

On each YuKKi node, point the node process and co-located browser process at
the same private directory file:

```sh
install -d -m 0700 "$HOME/.local/state/yukki-os"
export YUKKI_BROKER_DIRECTORY_FILE="$HOME/.local/state/yukki-os/broker-services.json"
```

Advertise only capabilities actually configured on that server:

```sh
# CPU-only server:
export YUKKI_BROKER_ENDPOINT=10.0.0.21:9090
export YUKKI_BROKER_CAPABILITIES=cpu

# GPU server:
export YUKKI_BROKER_ENDPOINT=10.0.0.22:9090
export YUKKI_BROKER_CAPABILITIES=cpu,gpu

# NPU server:
export YUKKI_BROKER_ENDPOINT=10.0.0.23:9090
export YUKKI_BROKER_CAPABILITIES=cpu,npu
export YUKKI_NPU_AVAILABLE=true
```

These capability labels are operator-supplied declarations, not hardware
attestations. The node writes expiring records it learned from its own broker
and authenticated peer announcements. The snapshot is limited to 4 MiB,
atomically replaced, and private on Unix (directory 0700, file 0600). The
browser revalidates leases and BRK2 support and refreshes the file while
running. The node advertises a 1 MiB broker-frame ceiling; the normal BRK2
payload ceiling remains 512 KiB.

### Enable browser-side delegation

```sh
export YUKKI_BROKER_DIRECTORY_FILE="$HOME/.local/state/yukki-os/broker-services.json"
export YUKKI_BROWSER_REMOTE_ACCELERATION=true
# Keep the local broker's declared capabilities in the browser process too:
export YUKKI_BROKER_CAPABILITIES=cpu,gpu
# Optional local broker connection:
export YUKKI_GPU_ADAPTER_ENABLED=true
export YUKKI_GPU_BROKER_ENDPOINT=127.0.0.1:9090
# Optional; off by default because LAN latency can exceed local CPU cost:
export YUKKI_BROWSER_REMOTE_CPU=true
# For a local GPU broker, configure the regular adapter variables:
export YUKKI_GPU_ADAPTER_ENABLED=true
export YUKKI_GPU_BROKER_ENDPOINT=127.0.0.1:9090
```

The browser toolbar includes a **Test compute** diagnostic button. It creates
one deterministic 128×128 synthetic RGBA tile inside the native host, submits
it to the scheduler, compares the result with the local CPU reference, and
reports the actual broker backend and execution node. It never captures or
sends a webpage, canvas, screenshot, or user-selected image. The same scheduler
is also used by the CLI benchmark.

The browser schedules a deterministic RGB channel-gain tile task using the
Overhauled generic BRK2 inference/compute path. Each 128×128 RGBA tile is
bounded to 64 KiB. YuKKi encodes its RGB channels as network-order f64 values;
Overhauled's generic compute kernel multiplies each value by two, and YuKKi
reconstructs the RGBA output while preserving alpha. The CPU reference performs
the same saturating RGB operation.

The dispatch order is local GPU broker, discovered GPU peers, explicitly
enabled CPU-only peers, then the local CPU reference. GPU is counted only when
BRK2 response field 7 reports `gpu` and the returned values decode correctly.
CPU peer results are counted separately and only used when
`YUKKI_BROWSER_REMOTE_CPU=true`. This explicit `device_preference=gpu`
path depends on Overhauled PR #89, which makes an explicit GPU request bypass
the broker's automatic 1 MiB size heuristic while preserving forced-CPU and
exact-CPU protections. Without that Overhauled change, these sub-512-KiB
tiles can be answered by CPU and will not be reported as GPU work.

A peer advertising `npu` can receive an inference request if its broker has an
enabled concrete NPU executor. NPU work uses network-order f64 input values
for the configured inference/bundle; arbitrary file bytes are not a valid
tensor. YuKKi accepts an NPU result only when BRK2 field 7 reports `npu`.
NPU is a model-inference path, not a WebKit rasterization path.

### Graphics delegation benchmark

```sh
cargo build --manifest-path browser-runtime/Cargo.toml --release \
  --bin yukki-browser-graphics-bench

YUKKI_BROKER_DIRECTORY_FILE="$HOME/.local/state/yukki-os/broker-services.json" \
YUKKI_BROWSER_REMOTE_ACCELERATION=true \
cargo run --manifest-path browser-runtime/Cargo.toml --release \
  --bin yukki-browser-graphics-bench -- \
  --iterations 3 --concurrency 4 --output browser-graphics.json
```

Full runs cover 320×240, 1280×720, 1920×1080 and 3840×2160 frames. The frame
is split into 128×128 RGBA tiles, each no larger than 64 KiB. In-flight broker
requests are capped at eight (default four). The report includes CPU-reference
median, scheduled median/p95, local/remote CPU/GPU counts, and remote node IDs;
every returned tile is checked against the CPU reference. Use
`--quick --cpu-only` for the hardware-free CI smoke test.

An optional `--npu-input <file>` accepts 1..=64 KiB of 8-byte-aligned
network-order f64 values. The file must represent a tensor accepted by the
configured NPU executor and model bundle; the runner does not invent tensor
semantics.

### Security and measurement boundary

The broker service announcement is learned over the authenticated peer mesh,
but the later browser-to-broker BRK2 TCP connection is not authenticated or
encrypted by that mesh. Keep broker endpoints on a trusted private network;
do not use this path for private webpage pixels, credentials, or other
sensitive browser data until the broker transport has independent
authentication and confidentiality. The current benchmark uses deterministic
synthetic pixel data.

These measurements cover an auxiliary RGB channel-gain compute operation and
broker delegation overhead. They are not page-render FPS, WebGL/WebGPU
throughput, display latency, or WebKit driver benchmarks. Browser page
rasterization remains local to the native WebView and is not automatically
delegated by this PR.
