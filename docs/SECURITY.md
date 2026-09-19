# YuKKi OS v6.7.0 — Security Notes

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

## Memory safety controls

- Session key material and plaintext buffers are zeroized in Rust where implemented.
- FFI calls validate expected pointer/state conditions in C for critical paths.
- Wasm sandbox enforces explicit memory/fuel limits.

## Denial-of-service controls present

- Max frame size bound
- Handshake timeout
- Read timeout
- Bootstrap connection semaphore cap (128)

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
