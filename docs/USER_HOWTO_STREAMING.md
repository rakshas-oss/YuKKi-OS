`YUKKI_BROKER_REQUEST_TIMEOUT_MS` (default 5000),
`YUKKI_BROKER_MAX_FRAME_BYTES` (default 65536), and
`YUKKI_BROKER_TRANSPORT_SECURITY` (`plaintext-boundary` by default, or
`authenticated-proxy`). Timeout values must be in `1..=600000` ms; a task's
`timeout_ms` must be in `1..=300000` ms.

`MediaChunk::to_broker_task` wraps an encoded YKMC chunk in the broker task
JSON. `BrokerClientConfig::from_env` reads the broker environment variables,
and `BrokerClient::submit` sends the task:

```rust,ignore
use yukkios::{BrokerClient, BrokerClientConfig, MediaChunk};

let task = chunk.to_broker_task("task-1", "camera-1", "broker", 1, 5_000)?;
let client = BrokerClient::with_config(BrokerClientConfig::from_env()?)?;
let result = client.submit(&task).await?;
```


## Untrusted-source availability and flood limits

The stream gateway does not require an executable-artifact publisher identity.
External media/geospatial sources remain usable subject to bounded framing,
storage, concurrency and rate controls.

Current in-process defaults/hard limits include:

- Retained media payload is capped at 64 MiB; stream configuration cannot
  exceed 256 streams, 16,384 retained chunks or 256 KiB per chunk.
- The gateway accepts at most 128 TCP connections. It rate-limits each
  remote IP to a 40-request burst and 20 requests/second, with an aggregate
  300-request burst and 100 requests/second.
- WebSockets are limited to 64 active sessions globally and four per remote
  IP. Only one chunk may be awaiting acknowledgement per session; sessions
  close after 60 seconds without activity.
- Remote origin socket operations are capped at eight concurrent pulls;
  each relay pull is rate-limited and asks for at most eight chunks.

Excess traffic is throttled with HTTP 429 or rejected by bounded store/relay
backpressure. These protections constrain in-process resource use. They do
not replace network-edge DDoS mitigation, firewall policy or deployment-level
quotas at a reverse proxy. Reverse proxies should preserve the actual client
address securely; spoofable `X-Forwarded-For` values are not used as identity.
