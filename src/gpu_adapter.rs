use std::{
    collections::HashMap,
    env,
    ops::Deref,
    sync::{
        atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
    time::{sleep, timeout},
};

pub const CURRENT_PROTOCOL_VERSION: &str = "overhauled.wasm.gpu.v1";
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["overhauled.wasm.gpu.v1"];
pub const DEFAULT_GPU_BROKER_ENDPOINT: &str = "127.0.0.1:9090";
pub const DEFAULT_GPU_MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const DEFAULT_GPU_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
pub const DEFAULT_GPU_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_GPU_MAX_RETRIES: usize = 3;
pub const DEFAULT_GPU_RETRY_BACKOFF: Duration = Duration::from_millis(50);
pub const DEFAULT_GPU_QUIESCE_TIMEOUT: Duration = Duration::from_secs(5);

/// Lower bound for an individual GPU task's `timeout_ms`. Values of zero are
/// never meaningful (they would never allow the task to complete), so this is
/// effectively the floor above zero.
pub const MIN_TASK_TIMEOUT_MS: u32 = 1;
/// Upper bound for an individual GPU task's `timeout_ms` (5 minutes). This
/// guards against misconfigured or malicious callers requesting absurdly long
/// timeouts (e.g. `u32::MAX` ms, ~49 days) that would tie up broker resources
/// and connection slots indefinitely.
pub const MAX_TASK_TIMEOUT_MS: u32 = 300_000;

fn broker_deadline_ms(timeout: Duration) -> u32 {
    let ms = timeout.as_millis();
    if ms == 0 {
        return MIN_TASK_TIMEOUT_MS;
    }
    ms.min(u128::from(MAX_TASK_TIMEOUT_MS)) as u32
}

#[cfg(test)]
mod broker_deadline_tests {
    use super::{broker_deadline_ms, MAX_TASK_TIMEOUT_MS, MIN_TASK_TIMEOUT_MS};
    use std::time::Duration;

    #[test]
    fn broker_deadline_is_clamped_without_affecting_submillisecond_floor() {
        assert_eq!(broker_deadline_ms(Duration::ZERO), MIN_TASK_TIMEOUT_MS);
        assert_eq!(
            broker_deadline_ms(Duration::from_micros(999)),
            MIN_TASK_TIMEOUT_MS
        );
        assert_eq!(broker_deadline_ms(Duration::from_millis(125)), 125);
        assert_eq!(
            broker_deadline_ms(Duration::from_secs(600)),
            MAX_TASK_TIMEOUT_MS
        );
    }
}

/// Upper bound accepted for `connect_timeout`/`request_timeout`/`quiesce_timeout`
/// style configuration durations (10 minutes). Env-configured values beyond
/// this are rejected rather than silently trusted, to avoid accidental
/// multi-hour hangs from misconfiguration.
pub const MAX_CONFIG_TIMEOUT: Duration = Duration::from_secs(600);

/// Magic byte constant for WSM1 binary messages ("WSM1" in big-endian: 0x57534D31).
pub const WSM1_MAGIC: u32 = 0x57534D31;
/// Protocol version for WSM1 messages.
pub const WSM1_PROTOCOL_VERSION: u16 = 1;
pub const OVERHAULED_MAX_STRING_BYTES: usize = 1024;
pub const OVERHAULED_MAX_PAYLOAD_BYTES: usize = 512 * 1024;
pub const OVERHAULED_MAX_BUFFERS: usize = 64;

/// Magic byte constant for BRK1 binary frame envelope ("BRK1" in big-endian: 0x42524B31).
pub const BRK1_MAGIC: u32 = 0x42524B31;
/// Protocol version for BRK1 frame envelope.
pub const BRK1_PROTOCOL_VERSION: u16 = 1;
/// BRK1 frame message type: Request.
pub const BRK1_MSG_REQUEST: u8 = 1;
/// BRK1 frame message type: Response.
pub const BRK1_MSG_RESPONSE: u8 = 2;

// ...

/// Decode a `Brk1Frame` from bytes.
pub fn decode_brk1_frame(data: &[u8]) -> Result<Brk1Frame, GpuAdapterError> {
    if data.len() < 8 {
        return Err(GpuAdapterError::Wsm1Codec(
            "BRK1 frame too short".to_string(),
        ));
    }
    let mut r = ByteReader::new(data);
    let magic = r.read_u32()?;
    if magic != BRK1_MAGIC {
        return Err(GpuAdapterError::Wsm1Codec(format!(
            "invalid BRK1 magic: 0x{magic:08X}"
        )));
    }
    let version = r.read_u16()?;
    if version != BRK1_PROTOCOL_VERSION {
        return Err(GpuAdapterError::Wsm1Codec(format!(
            "unsupported BRK1 version: {version}"
        )));
    }
    let msg_type = r.read_u8()?;
    let reserved = r.read_u8()?;
    if reserved != 0 {
        return Err(GpuAdapterError::Wsm1Codec(format!(
            "invalid BRK1 reserved byte: expected 0, got 0x{reserved:02X}"
        )));
    }
    let task_id = r.read_str()?;
    let source = r.read_str()?;
    let destination = r.read_str()?;
    let kind = r.read_str()?;
    let priority = r.read_u8()?;
    let timeout_ms = r.read_u32()?;
    if timeout_ms == 0 {
        return Err(GpuAdapterError::Wsm1Codec(
            "BRK1 timeout_ms must be nonzero".to_string(),
        ));
    }
    let payload = r.read_bytes()?;
    r.ensure_exhausted()?;
    Ok(Brk1Frame {
        msg_type,
        task_id,
        source,
        destination,
        kind,
        priority,
        timeout_ms,
        payload,
    })
}

// ...
