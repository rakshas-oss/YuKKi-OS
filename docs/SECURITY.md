# YuKKi-OS v6.22.1 — Security Notes (patch release candidate)

> Patch release candidate v6.22.1. Research/demo software; do not expose directly to untrusted networks.

## Cryptographic baseline

- Key exchange: X25519 (ephemeral per session)
- Key schedule: HKDF-SHA256 with shared PSK as salt input
- Authenticated transport encryption: ChaCha20-Poly1305
- AAD: `YuKKi-OS/control/v1`

## Current trust model

- Shared cluster PSK (`YUKKI_PSK_HEX`) is required.
- Any node with PSK can authenticate as a mesh participant.
- There is no per-peer certificate/identity system in current code.

## Broker boundary

Broker I/O in `src/broker_client.rs` uses raw TCP + length-prefixed JSON.

- `authenticated-proxy` mode is operational metadata only.
- YuKKi-OS does not implement TLS/mTLS wrapping for broker traffic.
- Deploy broker traffic behind authenticated infrastructure (mTLS sidecar/proxy/service mesh).

## Stream gateway

- `gateway` and node-embedded gateways require `YUKKI_GATEWAY_TOKEN`; the only
  unauthenticated mode is the explicit `--insecure-dev` option.
- The standalone gateway binds to `127.0.0.1:7670` by default. A node gateway
  may use `YUKKI_GATEWAY_LISTEN`; bind to a non-loopback address only behind
  appropriate network controls.
- Bearer-token digests are compared without early exit. Keep the token secret
  and transmit it only over a trusted local link.
- The gateway has no built-in TLS. Terminate TLS in a trusted reverse proxy
  before exposing it beyond loopback.
- Accepted TCP connections, HTTP request handling, request bodies, frames,
  ranges, and idle time are bounded. WebSocket clients must acknowledge each
  frame before the next is sent.
- Stream discovery metadata is relayed only over the authenticated encrypted
  peer transport. Remote media relay is an application-configured feature;
  `OriginChunkClient` uses plain HTTP and must only connect over a trusted link
  or through a TLS-terminating proxy.

## Memory safety controls

- Rust-owned session key material and plaintext buffers use `zeroize` where implemented.
- The native mbedTLS header-MAC path wipes temporary full/expected MAC buffers with a volatile-write C helper. That helper is compiled only when `USE_MBEDTLS` is enabled; callers retain ownership of input key buffers.
- FFI calls validate expected pointer/state conditions in C for critical paths.
- Wasm sandbox enforces explicit memory/fuel limits.

## Denial-of-service controls present

- Max frame size bound
- Handshake timeout
- Read timeout
- Bootstrap connection semaphore cap (128)
- Gateway accepted-connection semaphore cap (128)
- Stream registry, subscriber, announcement, range, and WebSocket frame limits

## Gaps and limitations

- No formal external cryptographic audit
- No replay window protocol beyond nonce monotonicity per session
- No identity revocation/rotation protocol
- No built-in secure secret distribution mechanism
- No transport-layer TLS termination in process

## Operational guidance

- Keep `YUKKI_PSK_HEX` in secure env files, never in repository history.
- Restrict listener exposure with host/network policy.
- Log and monitor repeated auth/timeout failures.
- Rotate PSK through coordinated restarts when needed.


## Untrusted multivariate observation input

The incremental NDJSON decoder rejects invalid schema versions, unknown
fields, invalid source IDs, excessive dimensions, oversized lines and
non-finite values. Its 16 KiB incomplete-line and 256-record-per-push defaults
bound parser retention and return size. These checks do not authenticate the
source, prove sequence freshness, enforce tenant quotas, or authorize onward
delivery. Applications must supply those policies and keep bounded queues
with backpressure around untrusted stream input.

## Authenticated WASM artifact handoff

The v1 handoff protocol is an executable-artifact trust domain separate from peer-mesh authentication and ordinary broker traffic.

- `HandoffSender` signs deployment messages with a deployment identity and carries a separate publisher attestation. The Overhauled receiver checks those identities against separate operator-provisioned Ed25519 trust stores; a deployment signer cannot authorize arbitrary publisher content.
- Signed messages bind issuer, subject, key ID and audience and include bounded expiry, UUID message IDs/nonces and SHA-256 digests. The receiver applies replay checks, strict sequential chunk offsets, per-chunk/module/aggregate digest validation and bounded session/staging/rate admission.
- The YuKKi API does not store private keys and does not implement a concrete mTLS transport. The caller must provide `HandoffTransport` over mTLS 1.3 or an equivalent protected authenticated channel, bind transport identity to the signed sender, reject plaintext downgrade and enforce frame limits before decoding.
- The paired Overhauled `HandoffReceiver` is a library API, not a handler on the ordinary BRK1/BRK2 listener. Replay and staging are process-local unless a deployment supplies durable shared services; no restart-safe or multi-process guarantee is implied.
- The optional Wasmtime runtime bridge is not a multi-tenant sandbox: the current shared-Store embedding must be restricted to operator-authorized trusted artifacts or an independently isolated process.

## Current stream flood controls

- Untrusted NXR1/MED1/YKMC stream ingestion and consumption do not require a WASM publisher key.
- Default media ingestion budgets are 1,024 chunks/s globally (burst 256) and 8 MiB/s globally (burst 4 MiB), plus 256 chunks/s per stream (burst 64) and 2 MiB/s per stream (burst 1 MiB). Stream opens are limited to 16/s (burst 32).
- Hard media-store ceilings are 64 MiB retained payload, 256 streams, 4,096 chunks per stream, 16,384 total chunks and 256 KiB per chunk. The default configured store is smaller.
- Gateway and WebSocket paths also cap connections, requests, control messages, egress bytes, outstanding acknowledgements and remote-origin pulls. These controls bound in-process resource use; they do not prevent volumetric DDoS saturating the host's network link. Use network-edge mitigation.

The handoff transport and stream gateway are separate surfaces. Do not infer that peer-mesh encryption secures broker TCP or the external handoff transport.

## Vulnerability reporting

Open a private security report with repository maintainers before public disclosure.


## Broker discovery records

Overhauled broker service records are relayed only inside the existing PSK-protected peer mesh. The shared PSK admits every holder as a cluster participant; records are not individually signed identities and discovery does not grant execution authorization. BRK1/BRK2 broker transport remains unauthenticated, so advertise only a trusted private endpoint or an endpoint protected by an independent mTLS proxy. Records intentionally omit raw CPU/NUMA topology and tenant metadata. See [BROKER_SERVICE_DISCOVERY.md](BROKER_SERVICE_DISCOVERY.md).


## Crawler network and sandbox boundary

The optional crawler is designed for authorized public-web collection, not
arbitrary network reachability. It requires explicit DNS-domain allowlists,
pins validated DNS answers, rejects private/special-use destinations, disables
system proxy inheritance, refuses redirects, and fails closed when robots.txt
cannot be safely evaluated. Per-host pacing, request timeouts, bounded
concurrency and page/crawl byte ceilings constrain resource use.

The YCR1 guest receives a bounded document in isolated Wasmtime state and has
no WASI, imports, sockets, filesystem or credentials. It extracts static HTML
title/link data only; it does not execute JavaScript, submit forms, solve
CAPTCHAs or bypass access controls. Load only operator-provisioned extractor
artifacts.

The separate YCE1 `CrawlerDataExecutor` lets an application explicitly run
an approved, user-selected core-Wasm processor over ingested bytes. It rejects
all imports and gives every invocation a fresh Store with bounded input,
output, memory and fuel. Crawled content is always opaque data: it cannot
install or select a processor, and it is never executed as code. Applications
must authenticate/authorize users, verify processor provenance, apply job
admission and rate limits, and audit execution. The library does not provide
an HTTP execution route or durable job service. The native `yukki_crawl` CLI
does expose the explicit `--execute-wasm` option for operator-selected
processors; it never loads a processor referenced by page content. The CLI's
filesystem sink uses host-generated digest filenames and create-new semantics.
Neither Wasmtime fuel nor in-process memory limits replace OS process/container
isolation and outbound network restrictions.

