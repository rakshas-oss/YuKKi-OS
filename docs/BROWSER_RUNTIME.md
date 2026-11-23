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

The address bar accepts HTTP(S) URLs, hostnames (upgraded to HTTPS), and search terms. The shell includes navigation, reload, tabs, bounded history, and bookmarks. The runtime caps the number of resident tabs at eight. Per-tab top-level page-load timings are exposed in the tab tooltip and status line as an initial performance baseline; they do not measure GPU work or whole-page resource costs.

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
