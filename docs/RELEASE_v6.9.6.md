# v6.9.6 — Maintenance release and documentation refresh

- Tag: `v6.9.6`
- Release: https://github.com/rakshas-oss/YuKKi-OS/releases/tag/v6.9.6

## Summary

YuKKi-OS v6.9.6 is a small maintenance and documentation refresh on the v6.9.x release line. It advances the active documentation baseline and updates release metadata references.

## Highlights

- Documentation and metadata refreshed to reflect `v6.9.6` as the active release line.
- Docker image metadata and README references updated to match the active baseline.

## Compatibility and limitations

- Existing CLI commands and the `yukki_core_node` executable name remain
  available. The CLI does not configure a relay or origin client automatically;
  embedding applications must wire these library components into
  `stream_gateway::serve_with_relay`.
- The origin client uses plain HTTP without TLS. Use a trusted network or
  TLS-terminating proxy.

See [CHANGELOG.md](CHANGELOG.md), [VERSIONING.md](VERSIONING.md), and
[USER_HOWTO_STREAMING.md](USER_HOWTO_STREAMING.md) for additional details.
