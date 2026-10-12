# YuKKi OS v6.9.5 — Security Notes

> Research/demo software. Do not expose directly to untrusted networks.

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

- Session key material and plaintext buffers are zeroized in Rust where implemented.
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

## Vulnerability reporting

Open a private security report with repository maintainers before public disclosure.
