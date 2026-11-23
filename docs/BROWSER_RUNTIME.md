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

The browser runtime can use the node's local broker-directory snapshot to
delegate bounded browser-adjacent compute to other YuKKi servers. This is
separate from page rendering: the user's WebKit instance still renders pages
locally and owns its WebGL/WebGPU context. The broker path is for compute
modules and model inference, not a remote display server.

Configure the YuKKi node and browser process to use the same private
`YUKKI_BROKER_DIRECTORY_FILE`. The node populates it from broker records
received over its authenticated peer mesh. Then enable delegation in the
browser:

```sh
export YUKKI_BROKER_DIRECTORY_FILE="$HOME/.local/state/yukki-os/broker-services.json"
export YUKKI_BROWSER_REMOTE_ACCELERATION=true
export YUKKI_BROWSER_GRAPHICS_MODULE_ID=browser.graphics.rgba-invert
export YUKKI_BROWSER_GRAPHICS_MODULE_VERSION=1
```

The graphics module ID/version must refer to a WSM1 compute module already
prepared and active on the target broker nodes. That module must accept the
bounded RGBA8 tile payload and return an output of the same byte length. The
runtime tries a local GPU broker first, then discovered peers advertising
`gpu`. It accepts a GPU result only when the broker's BRK2 response field 7
reports `gpu`, the WSM1 task status is successful, and the output length is
correct. An advertised GPU that reports CPU or omits backend attestation is
not counted as GPU work.

CPU-only servers remain useful. They advertise `cpu` and can receive the
same already-deployed RGBA tile module only when the operator explicitly sets
`YUKKI_BROWSER_REMOTE_CPU=true`. This is disabled by default because network
latency can cost more than local CPU execution. If a peer is unavailable,
unattested, or returns invalid output, the browser falls back to the identical
local CPU reference transform.

A peer advertising `npu` can receive model inference requests. Physical
Ethos-U85 execution is still provided by Overhauled's opt-in DRM executor and
requires a Vela-generated `YU85BND1` bundle. The browser runtime accepts NPU
execution only when BRK2 field 7 says `npu`; a GPU/CPU fallback is not
silently reported as NPU. The NPU input must be a tensor compatible with the
operator's active model bundle. NPU is not used to rasterize arbitrary web
pages.

### Graphics delegation benchmark

Build and run the bounded tile benchmark:

```sh
cargo build --manifest-path browser-runtime/Cargo.toml --release --bin yukki-browser-graphics-bench

YUKKI_BROKER_DIRECTORY_FILE="$HOME/.local/state/yukki-os/broker-services.json" \
YUKKI_BROWSER_REMOTE_ACCELERATION=true \
YUKKI_BROWSER_GRAPHICS_MODULE_ID=browser.graphics.rgba-invert \
YUKKI_BROWSER_GRAPHICS_MODULE_VERSION=1 \
cargo run --manifest-path browser-runtime/Cargo.toml --release \
  --bin yukki-browser-graphics-bench -- \
  --iterations 3 --concurrency 4 --output browser-graphics.json
```

The full run covers 320×240, 1280×720, 1920×1080, and 3840×2160 frames.
Frames are divided into 128×128 RGBA8 tiles, each no larger than 64 KiB.
Concurrency is bounded (default four, maximum eight). Every output tile is
compared with the CPU reference. Reports include CPU-reference median time,
scheduled median/p95 time, actual backend counts, and remote node IDs.

Use `--quick --cpu-only` for a hardware-free smoke run. Use
`YUKKI_BROWSER_REMOTE_CPU=true` to include CPU-only peers in the remote
fallback chain. To benchmark NPU inference, supply a real model-compatible
input tensor with `--npu-input <file>`; the runner rejects arbitrary oversized
or empty inputs and only accepts a BRK2-attested NPU response.

**Benchmark boundary:** these measurements cover the auxiliary RGBA tile
transform and broker delegation overhead. They are not page-render FPS,
WebGL/WebGPU throughput, full-screen compositor measurements, or a benchmark
of WebKit's own graphics driver. Those require instrumentation inside the
platform WebView renderer. The current NPU benchmark is model inference, not
graphics rasterization.

The BRK2 broker transport remains unauthenticated. Directory discovery over
the PSK-authenticated mesh does not protect the later browser-to-broker TCP
connection. Keep endpoints on a trusted private network; do not expose them
to untrusted peers.
