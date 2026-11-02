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
