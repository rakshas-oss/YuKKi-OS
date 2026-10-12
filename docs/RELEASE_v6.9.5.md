# v6.9.5 — Remote Stream Relay and Gateway Dashboard

- Tag: `v6.9.5`
- Release: https://github.com/rakshas-oss/YuKKi-OS/releases/tag/v6.9.5

## Summary

YuKKi-OS v6.9.5 adds application-configurable remote stream relay, an HTTP
client for origin gateways, and a stream dashboard. The peer mesh continues to
distribute bounded stream discovery metadata; media chunks are fetched from an
origin gateway only when an application wires the relay into its gateway.

## Highlights

- `StreamRelay` mirrors discovered streams into a local store and shares
  rate-limited upstream pulls among local subscribers.
- `OriginChunkClient` reads stream descriptors and chunk ranges from an origin
  gateway using HTTP and an optional bearer token.
- The gateway provides a stream dashboard at `/dashboard`; API requests from
  the dashboard remain bearer-token authenticated.
- Stream discovery, authenticated gateway APIs, subscriber backpressure, and
  the bounded WASM stream selector are documented in the streaming how-to and
  API reference.

## Compatibility and limitations

- Existing CLI commands and the `yukki_core_node` executable name remain
  available. The CLI does not configure a relay or origin client automatically;
  embedding applications must wire these library components into
  `stream_gateway::serve_with_relay`.
- The origin client uses plain HTTP without TLS. Use a trusted network or
  TLS-terminating proxy.
- Stream descriptors do not include codec metadata, so `OriginChunkClient`
  reports the codec as `unknown`.
- The Cargo package version remains `6.9.3`; the library crate name remains
  `yukkios_6_8_0_inet3`.

See [CHANGELOG.md](CHANGELOG.md), [VERSIONING.md](VERSIONING.md), and
[USER_HOWTO_STREAMING.md](USER_HOWTO_STREAMING.md) for additional details.
