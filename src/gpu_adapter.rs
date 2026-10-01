//! GPU-backed WebAssembly sandbox interoperability adapter for `rakshas-oss/overhauled`.
//!
//! This module provides the YuKKi-OS-side client adapter and module lifecycle
//! management for scheduling GPU compute tasks through the `overhauled` broker.
//!
//! ## Architectural Overview
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────┐
//! │                       YuKKi-OS Node                           │
//! │                                                               │
//! │   ┌───────────────────────┐                                   │
//! │   │  RustasmSandbox       │                                   │
//! │   │  (WASM Sandbox)       │                                   │
//! │   └──────────┬────────────┘                                   │
//! │              │ host-mediated GPU task call                    │
//! │              ▼                                                │
//! │   ┌───────────────────────┐   hotswap / quiesce / drain       │
//! │   │ ModuleLifecycleManager├──────────────────────────────┐    │
//! │   └──────────┬────────────┘                              │    │
//! │              │ active module version                     ▼    │
//! │              ▼                                   ┌──────────┐ │
//! │   ┌───────────────────────┐                      │ Old Ver  │ │
//! │   │ GpuBrokerClient       │                      │ Draining │ │
//! │   └──────────┬────────────┘                      └──────────┘ │
//! └──────────────┼────────────────────────────────────────────────┘
//!                │ 4-byte big-endian length-prefixed JSON over TCP
//!                ▼
//! ┌───────────────────────────────────────────────────────────────┐
//! │                 overhauled Broker (C++/CUDA)                  │
//! │                                                               │
//! │   ├── Protocol version negotiation ("overhauled.wasm.gpu.v1") │
//! │   ├── NVLink-aware GPU placement                              │
//! │   ├── Fractional stream allocation & dynamic batching         │
//! │   └── GPU kernel execution & buffer management                │
//! └───────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Hotswapping and State Migration Guarantees
//!
//! **Important**: This adapter does **NOT** migrate WASM linear memory pages or
//! arbitrary live GPU VRAM / CUDA stream state across module versions.
//! Arbitrary device pointers and WASM memory allocations cannot be safely
//! transferred across binaries. Instead, safe module hotswapping is achieved via:
//! 1. **Preparation**: Register and validate the new module version in the background.
//! 2. **State Handoff Hooks**: If configured, high-level application state is
//!    exported by the active version and imported by the new version prior to activation.
//! 3. **Atomic Routing Switch**: Active traffic is atomically redirected to the new module.
//! 4. **Quiesce & Drain**: The superseded version stops accepting new tasks and waits
//!    for all in-flight GPU tasks to finish.
//! 5. **Drain-Before-Release Ordering**: Resources associated with the old module version
//!    (GPU buffers, sandbox instances) are released **only after** all in-flight tasks have
//!    completed.
//! 6. **Rollback on Failure**: If preparation, validation, or state handoff fails,
//!    activation is aborted and the existing active module continues serving uninterrupted.
//!
//! ## Wire Protocol Contract (Versioned Broker Contract)
//!
//! Transport is TCP with 4-byte big-endian length framing. All messages are JSON encoded.
//! Supported protocol version: `overhauled.wasm.gpu.v1`.

use std::{
    collections::HashMap,
    env,
    ops::Deref,
    sync::{
        atomic::{AtomicI32, AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{sleep, timeout},
};

pub const CURRENT_PROTOCOL_VERSION: &str = "overhauled.wasm.gpu.v1";
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["overhauled.wasm.gpu.v1"];
pub const DEFAULT_GPU_BROKER_ENDPOINT: &str = "127.0.0.1:9000";
pub const DEFAULT_GPU_MAX_FRAME_BYTES: usize = 64 * 1024;
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
/// Upper bound accepted for `connect_timeout`/`request_timeout`/`quiesce_timeout`
/// style configuration durations (10 minutes). Env-configured values beyond
/// this are rejected rather than silently trusted, to avoid accidental
/// multi-hour hangs from misconfiguration.
pub const MAX_CONFIG_TIMEOUT: Duration = Duration::from_secs(600);

/// Magic byte constant for WSM1 binary messages ("WSM1" in big-endian: 0x57534D31).
pub const WSM1_MAGIC: u32 = 0x57534D31;
/// Protocol version for WSM1 messages.
pub const WSM1_PROTOCOL_VERSION: u16 = 1;

/// Magic byte constant for BRK1 binary frame envelope ("BRK1" in big-endian: 0x42524B31).
pub const BRK1_MAGIC: u32 = 0x42524B31;
/// Protocol version for BRK1 frame envelope.
pub const BRK1_PROTOCOL_VERSION: u16 = 1;
/// BRK1 frame message type: Request.
pub const BRK1_MSG_REQUEST: u8 = 1;
/// BRK1 frame message type: Response.
pub const BRK1_MSG_RESPONSE: u8 = 2;

// ============================================================================
// Protocol Types (Serde Compatible)
// ============================================================================

/// Buffer memory kind for payload and GPU data descriptors.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BufferKind {
    /// Host memory accessible by the sandbox runner.
    HostMemory,
    /// Shared memory region (e.g. POSIX shared memory or IPC handle).
    SharedMemory,
    /// Inline byte array carried directly inside the message payload.
    InlineBytes,
    /// Pre-allocated GPU device buffer managed by the overhauled broker.
    GpuBuffer,
}

/// Memory access permissions for buffer descriptors.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BufferAccess {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

/// Descriptor describing an input or output buffer for GPU task processing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BufferDescriptor {
    /// Unique identifier or name of the buffer.
    pub buffer_id: String,
    /// Storage kind of the buffer.
    pub kind: BufferKind,
    /// Total buffer size in bytes.
    pub size_bytes: usize,
    /// Byte offset into the memory region.
    pub offset: usize,
    /// Read/write permissions.
    pub access: BufferAccess,
    /// Optional inline payload data for `BufferKind::InlineBytes`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inline_data: Option<Vec<u8>>,
}

impl BufferDescriptor {
    pub fn inline(buffer_id: impl Into<String>, data: Vec<u8>, access: BufferAccess) -> Self {
        let size = data.len();
        Self {
            buffer_id: buffer_id.into(),
            kind: BufferKind::InlineBytes,
            size_bytes: size,
            offset: 0,
            access,
            inline_data: Some(data),
        }
    }

    pub fn gpu_buffer(
        buffer_id: impl Into<String>,
        size_bytes: usize,
        access: BufferAccess,
    ) -> Self {
        Self {
            buffer_id: buffer_id.into(),
            kind: BufferKind::GpuBuffer,
            size_bytes,
            offset: 0,
            access,
            inline_data: None,
        }
    }

    pub fn validate(&self) -> Result<(), GpuAdapterError> {
        if self.buffer_id.trim().is_empty() {
            return Err(GpuAdapterError::InvalidRequest(
                "buffer_id must not be empty".to_string(),
            ));
        }
        if self.kind == BufferKind::InlineBytes {
            let data_len = self.inline_data.as_ref().map_or(0, |d| d.len());
            if data_len != self.size_bytes {
                return Err(GpuAdapterError::InvalidRequest(format!(
                    "inline_data length ({data_len}) does not match size_bytes ({})",
                    self.size_bytes
                )));
            }
        }
        Ok(())
    }
}

/// Handshake request sent to negotiate wire protocol versions with overhauled.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolHandshakeRequest {
    /// Magic identifier for handshake framing.
    pub magic: String,
    /// List of protocol versions supported by YuKKi-OS.
    pub supported_versions: Vec<String>,
    /// Client identifier or node name.
    pub client_id: String,
}

impl Default for ProtocolHandshakeRequest {
    fn default() -> Self {
        Self {
            magic: "OVERHAULED_WASM_GPU".to_string(),
            supported_versions: SUPPORTED_PROTOCOL_VERSIONS
                .iter()
                .map(|v| v.to_string())
                .collect(),
            client_id: "yukki_core_node".to_string(),
        }
    }
}

/// Handshake response returned by the overhauled broker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolHandshakeResponse {
    /// Status code: "ok" or "incompatible_version".
    pub status: String,
    /// Mutually agreed protocol version.
    pub negotiated_version: Option<String>,
    /// Features and capabilities supported by the broker.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Optional error details if handshake failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

/// GPU task submission request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GpuTaskRequest {
    /// Protocol version (e.g. "overhauled.wasm.gpu.v1").
    pub protocol_version: String,
    /// Unique task identifier.
    pub task_id: String,
    /// Optional idempotency key for safe retries (defaults to task_id if omitted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// Sandbox identity issuing the task.
    pub sandbox_id: String,
    /// WASM module identity.
    pub module_id: String,
    /// WASM module version string.
    pub module_version: String,
    /// Scheduling priority (0-255, higher = higher priority).
    pub priority: u8,
    /// Optional deadline epoch timestamp in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
    /// Execution timeout in milliseconds.
    pub timeout_ms: u32,
    /// Input and output buffer descriptors.
    pub buffers: Vec<BufferDescriptor>,
    /// Optional arbitrary JSON metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl GpuTaskRequest {
    pub fn validate(&self) -> Result<(), GpuAdapterError> {
        if self.protocol_version.trim().is_empty() {
            return Err(GpuAdapterError::InvalidRequest(
                "protocol_version must not be empty".to_string(),
            ));
        }
        if self.task_id.trim().is_empty() {
            return Err(GpuAdapterError::InvalidRequest(
                "task_id must not be empty".to_string(),
            ));
        }
        if self.sandbox_id.trim().is_empty() {
            return Err(GpuAdapterError::InvalidRequest(
                "sandbox_id must not be empty".to_string(),
            ));
        }
        if self.module_id.trim().is_empty() {
            return Err(GpuAdapterError::InvalidRequest(
                "module_id must not be empty".to_string(),
            ));
        }
        if self.module_version.trim().is_empty() {
            return Err(GpuAdapterError::InvalidRequest(
                "module_version must not be empty".to_string(),
            ));
        }
        if self.timeout_ms < MIN_TASK_TIMEOUT_MS {
            return Err(GpuAdapterError::InvalidRequest(format!(
                "timeout_ms must be at least {MIN_TASK_TIMEOUT_MS}ms (got {})",
                self.timeout_ms
            )));
        }
        if self.timeout_ms > MAX_TASK_TIMEOUT_MS {
            return Err(GpuAdapterError::InvalidRequest(format!(
                "timeout_ms must not exceed {MAX_TASK_TIMEOUT_MS}ms (got {})",
                self.timeout_ms
            )));
        }
        for buffer in &self.buffers {
            buffer.validate()?;
        }
        Ok(())
    }

    /// Effective idempotency key for deduplication on retry.
    pub fn effective_idempotency_key(&self) -> &str {
        self.idempotency_key.as_deref().unwrap_or(&self.task_id)
    }

    /// Heuristically derive a safe `timeout_ms` for this request rather than
    /// trusting a raw, potentially unset or out-of-range value.
    ///
    /// The heuristic scales a small base allowance by the total buffer payload
    /// size (to account for larger transfers taking proportionally longer),
    /// then clamps the result to `[MIN_TASK_TIMEOUT_MS, MAX_TASK_TIMEOUT_MS]`.
    /// This is used as a fallback/default when `timeout_ms` is zero or absent
    /// from the caller's perspective; it does not override an explicit,
    /// in-range value supplied by the caller.
    pub fn heuristic_timeout_ms(&self) -> u32 {
        const BASE_TIMEOUT_MS: u64 = 1_000;
        const PER_KIB_MS: u64 = 2;

        let total_bytes: u64 = self.buffers.iter().map(|b| b.size_bytes as u64).sum();
        let payload_allowance_ms = (total_bytes / 1024).saturating_mul(PER_KIB_MS);

        BASE_TIMEOUT_MS
            .saturating_add(payload_allowance_ms)
            .clamp(MIN_TASK_TIMEOUT_MS as u64, MAX_TASK_TIMEOUT_MS as u64) as u32
    }

    /// Returns `timeout_ms` if it is within the acceptable bounds, otherwise
    /// falls back to a heuristically derived timeout based on payload size.
    pub fn effective_timeout_ms(&self) -> u32 {
        if (MIN_TASK_TIMEOUT_MS..=MAX_TASK_TIMEOUT_MS).contains(&self.timeout_ms) {
            self.timeout_ms
        } else {
            self.heuristic_timeout_ms()
        }
    }
}

/// Execution status of a GPU task.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GpuTaskStatus {
    Completed,
    Failed,
    Cancelled,
    Rejected,
}

/// Structured broker error details.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrokerTaskError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

/// GPU task completion response returned by overhauled.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GpuTaskResponse {
    pub protocol_version: String,
    pub task_id: String,
    pub status: GpuTaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu_id: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_ms: Option<u64>,
    #[serde(default)]
    pub output_buffers: Vec<BufferDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<BrokerTaskError>,
}

impl GpuTaskResponse {
    pub fn validate_for(&self, request: &GpuTaskRequest) -> Result<(), GpuAdapterError> {
        if self.task_id != request.task_id {
            return Err(GpuAdapterError::MalformedResponse(format!(
                "response task_id '{}' did not match request task_id '{}'",
                self.task_id, request.task_id
            )));
        }
        Ok(())
    }
}

/// Task cancellation request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CancelTaskRequest {
    pub protocol_version: String,
    pub task_id: String,
    pub sandbox_id: String,
    pub reason: String,
}

/// Task cancellation response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CancelTaskResponse {
    pub task_id: String,
    pub cancelled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// ============================================================================
// WSM1 & BRK1 Protocol Definitions (Compatible with overhauled/include/wasm_sandbox.h)
// ============================================================================

/// Lifecycle action requested on the broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum WasmLifecycleAction {
    Prepare = 1,
    Drain = 2,
    Release = 3,
    Query = 4,
}

impl TryFrom<u8> for WasmLifecycleAction {
    type Error = GpuAdapterError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            1 => Ok(Self::Prepare),
            2 => Ok(Self::Drain),
            3 => Ok(Self::Release),
            4 => Ok(Self::Query),
            other => Err(GpuAdapterError::Wsm1Codec(format!(
                "unknown WasmLifecycleAction: {other}"
            ))),
        }
    }
}

/// Lifecycle state of a module version on the broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum WasmLifecycleState {
    Unknown = 0,
    Prepared = 1,
    Active = 2,
    Draining = 3,
    Stopped = 4,
    Released = 5,
}

impl TryFrom<u8> for WasmLifecycleState {
    type Error = GpuAdapterError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Active),
            3 => Ok(Self::Draining),
            4 => Ok(Self::Stopped),
            5 => Ok(Self::Released),
            other => Err(GpuAdapterError::Wsm1Codec(format!(
                "unknown WasmLifecycleState: {other}"
            ))),
        }
    }
}

/// Status code for a lifecycle operation response from the broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum WasmLifecycleStatus {
    Ok = 0,
    Rejected = 1,
    Error = 2,
    Busy = 3,
    NotFound = 4,
}

impl TryFrom<u8> for WasmLifecycleStatus {
    type Error = GpuAdapterError;

    fn try_from(val: u8) -> Result<Self, GpuAdapterError> {
        match val {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Rejected),
            2 => Ok(Self::Error),
            3 => Ok(Self::Busy),
            4 => Ok(Self::NotFound),
            other => Err(GpuAdapterError::Wsm1Codec(format!(
                "unknown WasmLifecycleStatus: {other}"
            ))),
        }
    }
}

/// Status code for a task execution response from the broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum WasmTaskStatus {
    Ok = 0,
    Rejected = 1,
    Failed = 2,
    Timeout = 3,
}

impl TryFrom<u8> for WasmTaskStatus {
    type Error = GpuAdapterError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Rejected),
            2 => Ok(Self::Failed),
            3 => Ok(Self::Timeout),
            other => Err(GpuAdapterError::Wsm1Codec(format!(
                "unknown WasmTaskStatus: {other}"
            ))),
        }
    }
}

/// Buffer descriptor in the WSM1 binary wire format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmBufferDescriptor {
    pub buffer_id: u32,
    pub flags: u32,
    pub offset: u64,
    pub length: u64,
    pub name: String,
}

/// Lifecycle operation request compatible with overhauled WSM1 protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmLifecycleRequest {
    pub action: WasmLifecycleAction,
    pub request_id: String,
    pub sandbox_id: String,
    pub module_id: String,
    pub module_version: String,
    pub target_gpu: i32,
    pub grace_period_ms: u32,
    pub ack_token: String,
    pub payload: Vec<u8>,
}

/// Lifecycle operation response compatible with overhauled WSM1 protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmLifecycleResponse {
    pub action: WasmLifecycleAction,
    pub status: WasmLifecycleStatus,
    pub protocol_version: u16,
    pub state: WasmLifecycleState,
    pub request_id: String,
    pub sandbox_id: String,
    pub module_id: String,
    pub module_version: String,
    pub assigned_gpu: i32,
    pub active_tasks: u32,
    pub lease_token: String,
    pub error: String,
}

/// Task execution request in WSM1 format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmTaskRequest {
    pub task_id: String,
    pub sandbox_id: String,
    pub module_id: String,
    pub module_version: String,
    pub task_kind: String,
    pub priority: u8,
    pub deadline_ms: u64,
    pub buffers: Vec<WasmBufferDescriptor>,
    pub payload: Vec<u8>,
}

/// Task execution response in WSM1 format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmTaskResponse {
    pub task_id: String,
    pub status: WasmTaskStatus,
    pub protocol_version: u16,
    pub selected_gpu: i32,
    pub latency_ms: u64,
    pub error: String,
    pub buffers: Vec<WasmBufferDescriptor>,
    pub result: Vec<u8>,
}

/// Decoded WSM1 message envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wsm1Message {
    TaskRequest(WasmTaskRequest),
    TaskResponse(WasmTaskResponse),
    LifecycleRequest(WasmLifecycleRequest),
    LifecycleResponse(WasmLifecycleResponse),
}

/// BRK1 broker frame envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Brk1Frame {
    pub msg_type: u8,
    pub task_id: String,
    pub source: String,
    pub destination: String,
    pub kind: String,
    pub priority: u8,
    pub timeout_ms: u32,
    pub payload: Vec<u8>,
}

/// Framing and wire format mode for lifecycle operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleWireMode {
    /// Framed within BRK1 envelope over TCP with 4-byte length prefix.
    Brk1,
    /// Raw WSM1 binary framed over TCP with 4-byte length prefix.
    RawWsm1,
    /// JSON-encoded framed over TCP with 4-byte length prefix.
    Json,
    /// Auto-detect / try BRK1 first.
    Auto,
}

/// Top-level wire envelope representing any broker message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum BrokerMessage {
    HandshakeRequest(ProtocolHandshakeRequest),
    HandshakeResponse(ProtocolHandshakeResponse),
    TaskRequest(GpuTaskRequest),
    TaskResponse(GpuTaskResponse),
    CancelRequest(CancelTaskRequest),
    CancelResponse(CancelTaskResponse),
    LifecycleRequest(WasmLifecycleRequest),
    LifecycleResponse(WasmLifecycleResponse),
}

// ============================================================================
// Errors
// ============================================================================

/// Structured error type for the GPU adapter and lifecycle manager.
#[derive(Debug, Error)]
pub enum GpuAdapterError {
    #[error("GPU adapter is disabled or not configured in environment")]
    Disabled,

    #[error("protocol version mismatch: client requires one of {expected:?}, broker returned {actual:?}")]
    VersionMismatch {
        expected: Vec<String>,
        actual: Option<String>,
    },

    #[error("version negotiation failed: {0}")]
    VersionNegotiationFailed(String),

    #[error("invalid broker configuration: {0}")]
    InvalidConfig(String),

    #[error("invalid task request: {0}")]
    InvalidRequest(String),

    #[error("malformed broker response: {0}")]
    MalformedResponse(String),

    #[error("task cancelled: task_id={task_id}, reason={reason}")]
    TaskCancelled { task_id: String, reason: String },

    #[error(
        "broker rejected task {task_id}: code={code}, message={message}, retryable={retryable}"
    )]
    BrokerRejected {
        task_id: String,
        code: String,
        message: String,
        retryable: bool,
    },

    #[error("broker task execution failed for {task_id}: code={code}, message={message}")]
    TaskExecutionFailed {
        task_id: String,
        code: String,
        message: String,
    },

    #[error("timed out connecting to broker after {0:?}")]
    ConnectTimeout(Duration),

    #[error("timed out waiting for broker response after {0:?}")]
    RequestTimeout(Duration),

    #[error("all retry attempts exhausted ({attempts} attempts): {last_error}")]
    RetriesExhausted { attempts: usize, last_error: String },

    #[error("frame size {size} exceeds maximum allowable {max} bytes")]
    FrameTooLarge { size: usize, max: usize },

    #[error("transport I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("no active module registered for '{0}'")]
    NoActiveModule(String),

    #[error("module version already exists: module_id={module_id}, version={version}")]
    ModuleAlreadyExists { module_id: String, version: String },

    #[error("module version not found: module_id={module_id}, version={version}")]
    ModuleNotFound { module_id: String, version: String },

    #[error("quiesce timeout waiting for in-flight tasks to drain: module_id={module_id}, version={version}, remaining={remaining}")]
    QuiesceTimeout {
        module_id: String,
        version: String,
        remaining: usize,
    },

    #[error("state handoff failed: {0}")]
    StateHandoffFailed(String),

    #[error("module activation failed: {0}")]
    ActivationFailed(String),

    #[error("WASM module validation error: {0}")]
    WasmValidation(String),

    #[error("sandbox execution limit exceeded: {0}")]
    SandboxLimitExceeded(String),

    #[error("WSM1 binary codec error: {0}")]
    Wsm1Codec(String),

    #[error(
        "lifecycle operation {action:?} failed for {module_id}:{version}: status={status:?}, message={message}"
    )]
    LifecycleOperationFailed {
        action: WasmLifecycleAction,
        module_id: String,
        version: String,
        status: WasmLifecycleStatus,
        message: String,
    },
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the GPU adapter and broker transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuAdapterConfig {
    /// Whether GPU task offloading is enabled. Defaults to false.
    pub enabled: bool,
    /// Broker endpoint address (e.g. "127.0.0.1:9000").
    pub endpoint: String,
    /// Protocol version string.
    pub protocol_version: String,
    /// Timeout when opening a TCP connection to the broker.
    pub connect_timeout: Duration,
    /// Timeout waiting for task completion.
    pub request_timeout: Duration,
    /// Maximum allowable message frame size in bytes.
    pub max_frame_size: usize,
    /// Maximum number of retries for retryable failures.
    pub max_retries: usize,
    /// Initial backoff delay between retries.
    pub retry_backoff: Duration,
    /// Maximum duration to wait for in-flight tasks to quiesce during hotswap.
    pub quiesce_timeout: Duration,
    /// Whether to prefer WSM1 binary lifecycle and task wire protocol. Defaults to false.
    pub use_wsm1: bool,
}

impl Default for GpuAdapterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: DEFAULT_GPU_BROKER_ENDPOINT.to_string(),
            protocol_version: CURRENT_PROTOCOL_VERSION.to_string(),
            connect_timeout: DEFAULT_GPU_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_GPU_REQUEST_TIMEOUT,
            max_frame_size: DEFAULT_GPU_MAX_FRAME_BYTES,
            max_retries: DEFAULT_GPU_MAX_RETRIES,
            retry_backoff: DEFAULT_GPU_RETRY_BACKOFF,
            quiesce_timeout: DEFAULT_GPU_QUIESCE_TIMEOUT,
            use_wsm1: false,
        }
    }
}

impl GpuAdapterConfig {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            enabled: true,
            endpoint: endpoint.into(),
            ..Self::default()
        }
    }

    pub fn from_env() -> Result<Self, GpuAdapterError> {
        let enabled = match env::var("YUKKI_GPU_ADAPTER_ENABLED") {
            Ok(v) => matches!(
                v.trim().to_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            ),
            Err(_) => false,
        };

        let endpoint = env::var("YUKKI_GPU_BROKER_ENDPOINT")
            .or_else(|_| env::var("YUKKI_BROKER_ENDPOINT"))
            .unwrap_or_else(|_| DEFAULT_GPU_BROKER_ENDPOINT.to_string());

        let connect_timeout =
            duration_from_env_ms("YUKKI_GPU_CONNECT_TIMEOUT_MS", DEFAULT_GPU_CONNECT_TIMEOUT)?;
        let request_timeout =
            duration_from_env_ms("YUKKI_GPU_REQUEST_TIMEOUT_MS", DEFAULT_GPU_REQUEST_TIMEOUT)?;
        let quiesce_timeout =
            duration_from_env_ms("YUKKI_GPU_QUIESCE_TIMEOUT_MS", DEFAULT_GPU_QUIESCE_TIMEOUT)?;
        let max_frame_size =
            usize_from_env("YUKKI_GPU_MAX_FRAME_BYTES", DEFAULT_GPU_MAX_FRAME_BYTES)?;
        let max_retries = usize_from_env("YUKKI_GPU_MAX_RETRIES", DEFAULT_GPU_MAX_RETRIES)?;
        let use_wsm1 = match env::var("YUKKI_GPU_USE_WSM1") {
            Ok(v) => matches!(
                v.trim().to_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            ),
            Err(_) => false,
        };

        let config = Self {
            enabled,
            endpoint,
            protocol_version: CURRENT_PROTOCOL_VERSION.to_string(),
            connect_timeout,
            request_timeout,
            max_frame_size,
            max_retries,
            retry_backoff: DEFAULT_GPU_RETRY_BACKOFF,
            quiesce_timeout,
            use_wsm1,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), GpuAdapterError> {
        if self.endpoint.trim().is_empty() {
            return Err(GpuAdapterError::InvalidConfig(
                "endpoint must not be empty".to_string(),
            ));
        }
        if self.connect_timeout.is_zero() {
            return Err(GpuAdapterError::InvalidConfig(
                "connect_timeout must be greater than zero".to_string(),
            ));
        }
        if self.connect_timeout > MAX_CONFIG_TIMEOUT {
            return Err(GpuAdapterError::InvalidConfig(format!(
                "connect_timeout must not exceed {MAX_CONFIG_TIMEOUT:?} (got {:?})",
                self.connect_timeout
            )));
        }
        if self.request_timeout.is_zero() {
            return Err(GpuAdapterError::InvalidConfig(
                "request_timeout must be greater than zero".to_string(),
            ));
        }
        if self.request_timeout > MAX_CONFIG_TIMEOUT {
            return Err(GpuAdapterError::InvalidConfig(format!(
                "request_timeout must not exceed {MAX_CONFIG_TIMEOUT:?} (got {:?})",
                self.request_timeout
            )));
        }
        if self.quiesce_timeout.is_zero() {
            return Err(GpuAdapterError::InvalidConfig(
                "quiesce_timeout must be greater than zero".to_string(),
            ));
        }
        if self.quiesce_timeout > MAX_CONFIG_TIMEOUT {
            return Err(GpuAdapterError::InvalidConfig(format!(
                "quiesce_timeout must not exceed {MAX_CONFIG_TIMEOUT:?} (got {:?})",
                self.quiesce_timeout
            )));
        }
        if self.max_frame_size == 0 || self.max_frame_size > u32::MAX as usize {
            return Err(GpuAdapterError::InvalidConfig(format!(
                "max_frame_size must be between 1 and {} bytes",
                u32::MAX
            )));
        }
        Ok(())
    }
}

fn duration_from_env_ms(key: &str, default: Duration) -> Result<Duration, GpuAdapterError> {
    match env::var(key) {
        Ok(val) => {
            let ms = val.parse::<u64>().map_err(|e| {
                GpuAdapterError::InvalidConfig(format!("{key} must be an unsigned integer: {e}"))
            })?;
            Ok(Duration::from_millis(ms))
        }
        Err(_) => Ok(default),
    }
}

fn usize_from_env(key: &str, default: usize) -> Result<usize, GpuAdapterError> {
    match env::var(key) {
        Ok(val) => val.parse::<usize>().map_err(|e| {
            GpuAdapterError::InvalidConfig(format!("{key} must be an unsigned integer: {e}"))
        }),
        Err(_) => Ok(default),
    }
}

// ============================================================================
// Wire Framing
// ============================================================================

async fn write_prefixed_message(
    stream: &mut TcpStream,
    message: &BrokerMessage,
    max_frame_size: usize,
) -> Result<(), GpuAdapterError> {
    let payload = serde_json::to_vec(message).map_err(GpuAdapterError::Serialization)?;
    if payload.len() > max_frame_size {
        return Err(GpuAdapterError::FrameTooLarge {
            size: payload.len(),
            max: max_frame_size,
        });
    }
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_prefixed_message(
    stream: &mut TcpStream,
    max_frame_size: usize,
) -> Result<BrokerMessage, GpuAdapterError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let length = u32::from_be_bytes(len_buf) as usize;
    if length == 0 {
        return Err(GpuAdapterError::MalformedResponse(
            "zero-length frame received from broker".to_string(),
        ));
    }
    if length > max_frame_size {
        return Err(GpuAdapterError::FrameTooLarge {
            size: length,
            max: max_frame_size,
        });
    }
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await?;
    let message =
        serde_json::from_slice::<BrokerMessage>(&body).map_err(GpuAdapterError::Serialization)?;
    Ok(message)
}

// ============================================================================
// Client Transport & Version Negotiation
// ============================================================================

/// Asynchronous client communicating with the `overhauled` broker over TCP.
pub struct GpuBrokerClient {
    config: GpuAdapterConfig,
}

impl GpuBrokerClient {
    pub fn new(config: GpuAdapterConfig) -> Result<Self, GpuAdapterError> {
        config.validate()?;
        Ok(Self { config })
    }

    pub fn config(&self) -> &GpuAdapterConfig {
        &self.config
    }

    /// Negotiate protocol version with the overhauled broker.
    pub async fn negotiate_protocol(&self) -> Result<String, GpuAdapterError> {
        if !self.config.enabled {
            return Err(GpuAdapterError::Disabled);
        }

        let mut stream = timeout(
            self.config.connect_timeout,
            TcpStream::connect(&self.config.endpoint),
        )
        .await
        .map_err(|_| GpuAdapterError::ConnectTimeout(self.config.connect_timeout))??;

        let req = BrokerMessage::HandshakeRequest(ProtocolHandshakeRequest::default());
        write_prefixed_message(&mut stream, &req, self.config.max_frame_size).await?;

        let response = timeout(
            self.config.request_timeout,
            read_prefixed_message(&mut stream, self.config.max_frame_size),
        )
        .await
        .map_err(|_| GpuAdapterError::RequestTimeout(self.config.request_timeout))??;

        match response {
            BrokerMessage::HandshakeResponse(hs) => {
                if hs.status != "ok" {
                    return Err(GpuAdapterError::VersionNegotiationFailed(
                        hs.error_message
                            .unwrap_or_else(|| "broker rejected handshake".to_string()),
                    ));
                }
                match hs.negotiated_version {
                    Some(ref ver) if SUPPORTED_PROTOCOL_VERSIONS.contains(&ver.as_str()) => {
                        Ok(ver.clone())
                    }
                    other => Err(GpuAdapterError::VersionMismatch {
                        expected: SUPPORTED_PROTOCOL_VERSIONS
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
                        actual: other,
                    }),
                }
            }
            other => Err(GpuAdapterError::MalformedResponse(format!(
                "expected HandshakeResponse, got {:?}",
                other
            ))),
        }
    }

    /// Submit a GPU task to the broker with automatic retry and idempotency protection.
    pub async fn submit_task(
        &self,
        task: &GpuTaskRequest,
    ) -> Result<GpuTaskResponse, GpuAdapterError> {
        if !self.config.enabled {
            return Err(GpuAdapterError::Disabled);
        }
        task.validate()?;

        let mut attempt = 0;

        loop {
            attempt += 1;
            match self.submit_task_single(task).await {
                Ok(resp) => return Ok(resp),
                Err(err) => {
                    let is_retryable = match &err {
                        GpuAdapterError::Io(_) => true,
                        GpuAdapterError::ConnectTimeout(_) => true,
                        GpuAdapterError::BrokerRejected { retryable, .. } => *retryable,
                        _ => false,
                    };

                    let last_error_msg = err.to_string();
                    if !is_retryable || attempt > self.config.max_retries {
                        return Err(if attempt > 1 {
                            GpuAdapterError::RetriesExhausted {
                                attempts: attempt,
                                last_error: last_error_msg,
                            }
                        } else {
                            err
                        });
                    }

                    // Exponential backoff
                    let backoff_multiplier = 2u32.saturating_pow((attempt - 1) as u32);
                    let delay = self.config.retry_backoff.saturating_mul(backoff_multiplier);
                    sleep(delay).await;
                }
            }
        }
    }

    async fn submit_task_single(
        &self,
        task: &GpuTaskRequest,
    ) -> Result<GpuTaskResponse, GpuAdapterError> {
        let mut stream = timeout(
            self.config.connect_timeout,
            TcpStream::connect(&self.config.endpoint),
        )
        .await
        .map_err(|_| GpuAdapterError::ConnectTimeout(self.config.connect_timeout))??;

        let msg = BrokerMessage::TaskRequest(task.clone());
        write_prefixed_message(&mut stream, &msg, self.config.max_frame_size).await?;

        let response = timeout(
            self.config.request_timeout,
            read_prefixed_message(&mut stream, self.config.max_frame_size),
        )
        .await
        .map_err(|_| GpuAdapterError::RequestTimeout(self.config.request_timeout))??;

        match response {
            BrokerMessage::TaskResponse(resp) => {
                resp.validate_for(task)?;
                match resp.status {
                    GpuTaskStatus::Completed => Ok(resp),
                    GpuTaskStatus::Cancelled => Err(GpuAdapterError::TaskCancelled {
                        task_id: resp.task_id,
                        reason: resp
                            .error
                            .map_or("task cancelled by broker".to_string(), |e| e.message),
                    }),
                    GpuTaskStatus::Rejected => {
                        let err = resp.error.unwrap_or(BrokerTaskError {
                            code: "REJECTED".to_string(),
                            message: "task rejected".to_string(),
                            retryable: false,
                        });
                        Err(GpuAdapterError::BrokerRejected {
                            task_id: resp.task_id,
                            code: err.code,
                            message: err.message,
                            retryable: err.retryable,
                        })
                    }
                    GpuTaskStatus::Failed => {
                        let err = resp.error.unwrap_or(BrokerTaskError {
                            code: "EXECUTION_ERROR".to_string(),
                            message: "task failed".to_string(),
                            retryable: false,
                        });
                        Err(GpuAdapterError::TaskExecutionFailed {
                            task_id: resp.task_id,
                            code: err.code,
                            message: err.message,
                        })
                    }
                }
            }
            other => Err(GpuAdapterError::MalformedResponse(format!(
                "expected TaskResponse, got {:?}",
                other
            ))),
        }
    }

    /// Request cancellation of an in-flight task on the broker.
    pub async fn cancel_task(
        &self,
        task_id: &str,
        sandbox_id: &str,
        reason: &str,
    ) -> Result<CancelTaskResponse, GpuAdapterError> {
        if !self.config.enabled {
            return Err(GpuAdapterError::Disabled);
        }

        let mut stream = timeout(
            self.config.connect_timeout,
            TcpStream::connect(&self.config.endpoint),
        )
        .await
        .map_err(|_| GpuAdapterError::ConnectTimeout(self.config.connect_timeout))??;

        let req = BrokerMessage::CancelRequest(CancelTaskRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION.to_string(),
            task_id: task_id.to_string(),
            sandbox_id: sandbox_id.to_string(),
            reason: reason.to_string(),
        });
        write_prefixed_message(&mut stream, &req, self.config.max_frame_size).await?;

        let response = timeout(
            self.config.request_timeout,
            read_prefixed_message(&mut stream, self.config.max_frame_size),
        )
        .await
        .map_err(|_| GpuAdapterError::RequestTimeout(self.config.request_timeout))??;

        match response {
            BrokerMessage::CancelResponse(resp) => Ok(resp),
            other => Err(GpuAdapterError::MalformedResponse(format!(
                "expected CancelResponse, got {:?}",
                other
            ))),
        }
    }
}

// ============================================================================
// WSM1 & BRK1 Binary Wire Format Codecs
// ============================================================================

fn write_u8(buf: &mut Vec<u8>, val: u8) {
    buf.push(val);
}

fn write_u16(buf: &mut Vec<u8>, val: u16) {
    buf.extend_from_slice(&val.to_be_bytes());
}

fn write_u32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_be_bytes());
}

fn write_i32(buf: &mut Vec<u8>, val: i32) {
    buf.extend_from_slice(&val.to_be_bytes());
}

fn write_u64(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_be_bytes());
}

fn write_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(u16::MAX as usize) as u16;
    write_u16(buf, len);
    buf.extend_from_slice(&bytes[..len as usize]);
}

fn write_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len().min(u32::MAX as usize) as u32;
    write_u32(buf, len);
    buf.extend_from_slice(&data[..len as usize]);
}

struct ByteReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> ByteReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, GpuAdapterError> {
        if self.offset + 1 > self.data.len() {
            return Err(GpuAdapterError::Wsm1Codec("unexpected EOF reading u8".to_string()));
        }
        let val = self.data[self.offset];
        self.offset += 1;
        Ok(val)
    }

    fn read_u16(&mut self) -> Result<u16, GpuAdapterError> {
        if self.offset + 2 > self.data.len() {
            return Err(GpuAdapterError::Wsm1Codec("unexpected EOF reading u16".to_string()));
        }
        let bytes: [u8; 2] = self.data[self.offset..self.offset + 2].try_into().unwrap();
        self.offset += 2;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, GpuAdapterError> {
        if self.offset + 4 > self.data.len() {
            return Err(GpuAdapterError::Wsm1Codec("unexpected EOF reading u32".to_string()));
        }
        let bytes: [u8; 4] = self.data[self.offset..self.offset + 4].try_into().unwrap();
        self.offset += 4;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_i32(&mut self) -> Result<i32, GpuAdapterError> {
        if self.offset + 4 > self.data.len() {
            return Err(GpuAdapterError::Wsm1Codec("unexpected EOF reading i32".to_string()));
        }
        let bytes: [u8; 4] = self.data[self.offset..self.offset + 4].try_into().unwrap();
        self.offset += 4;
        Ok(i32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, GpuAdapterError> {
        if self.offset + 8 > self.data.len() {
            return Err(GpuAdapterError::Wsm1Codec("unexpected EOF reading u64".to_string()));
        }
        let bytes: [u8; 8] = self.data[self.offset..self.offset + 8].try_into().unwrap();
        self.offset += 8;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_str(&mut self) -> Result<String, GpuAdapterError> {
        let len = self.read_u16()? as usize;
        if self.offset + len > self.data.len() {
            return Err(GpuAdapterError::Wsm1Codec(format!(
                "unexpected EOF reading string of length {len}"
            )));
        }
        let s = std::str::from_utf8(&self.data[self.offset..self.offset + len])
            .map_err(|e| GpuAdapterError::Wsm1Codec(format!("invalid utf8 string: {e}")))?
            .to_string();
        self.offset += len;
        Ok(s)
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>, GpuAdapterError> {
        let len = self.read_u32()? as usize;
        if self.offset + len > self.data.len() {
            return Err(GpuAdapterError::Wsm1Codec(format!(
                "unexpected EOF reading bytes of length {len}"
            )));
        }
        let slice = self.data[self.offset..self.offset + len].to_vec();
        self.offset += len;
        Ok(slice)
    }
}

/// Encode a `WasmLifecycleRequest` into WSM1 binary format.
pub fn encode_wsm1_lifecycle_request(req: &WasmLifecycleRequest) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128 + req.payload.len());
    write_u32(&mut buf, WSM1_MAGIC);
    write_u16(&mut buf, WSM1_PROTOCOL_VERSION);
    write_u8(&mut buf, 3); // 3 = LifecycleRequest
    write_u8(&mut buf, req.action as u8);
    write_str(&mut buf, &req.request_id);
    write_str(&mut buf, &req.sandbox_id);
    write_str(&mut buf, &req.module_id);
    write_str(&mut buf, &req.module_version);
    write_i32(&mut buf, req.target_gpu);
    write_u32(&mut buf, req.grace_period_ms);
    write_str(&mut buf, &req.ack_token);
    write_bytes(&mut buf, &req.payload);
    buf
}

/// Encode a `WasmLifecycleResponse` into WSM1 binary format.
pub fn encode_wsm1_lifecycle_response(resp: &WasmLifecycleResponse) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    write_u32(&mut buf, WSM1_MAGIC);
    write_u16(&mut buf, resp.protocol_version);
    write_u8(&mut buf, 4); // 4 = LifecycleResponse
    write_u8(&mut buf, resp.action as u8);
    write_u8(&mut buf, resp.status as u8);
    write_u16(&mut buf, resp.protocol_version);
    write_u8(&mut buf, resp.state as u8);
    write_str(&mut buf, &resp.request_id);
    write_str(&mut buf, &resp.sandbox_id);
    write_str(&mut buf, &resp.module_id);
    write_str(&mut buf, &resp.module_version);
    write_i32(&mut buf, resp.assigned_gpu);
    write_u32(&mut buf, resp.active_tasks);
    write_str(&mut buf, &resp.lease_token);
    write_str(&mut buf, &resp.error);
    buf
}

/// Encode a `WasmTaskRequest` into WSM1 binary format.
pub fn encode_wsm1_task_request(req: &WasmTaskRequest) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128 + req.payload.len());
    write_u32(&mut buf, WSM1_MAGIC);
    write_u16(&mut buf, WSM1_PROTOCOL_VERSION);
    write_u8(&mut buf, 1); // 1 = TaskRequest
    write_u8(&mut buf, 0); // flags
    write_str(&mut buf, &req.task_id);
    write_str(&mut buf, &req.sandbox_id);
    write_str(&mut buf, &req.module_id);
    write_str(&mut buf, &req.module_version);
    write_str(&mut buf, &req.task_kind);
    write_u8(&mut buf, req.priority);
    write_u64(&mut buf, req.deadline_ms);
    let buf_count = req.buffers.len().min(u16::MAX as usize) as u16;
    write_u16(&mut buf, buf_count);
    for b in &req.buffers[..buf_count as usize] {
        write_u32(&mut buf, b.buffer_id);
        write_u32(&mut buf, b.flags);
        write_u64(&mut buf, b.offset);
        write_u64(&mut buf, b.length);
        write_str(&mut buf, &b.name);
    }
    write_bytes(&mut buf, &req.payload);
    buf
}

/// Encode a `WasmTaskResponse` into WSM1 binary format.
pub fn encode_wsm1_task_response(resp: &WasmTaskResponse) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128 + resp.result.len());
    write_u32(&mut buf, WSM1_MAGIC);
    write_u16(&mut buf, resp.protocol_version);
    write_u8(&mut buf, 2); // 2 = TaskResponse
    write_u8(&mut buf, resp.status as u8);
    write_u16(&mut buf, resp.protocol_version);
    write_str(&mut buf, &resp.task_id);
    write_i32(&mut buf, resp.selected_gpu);
    write_u64(&mut buf, resp.latency_ms);
    write_str(&mut buf, &resp.error);
    let buf_count = resp.buffers.len().min(u16::MAX as usize) as u16;
    write_u16(&mut buf, buf_count);
    for b in &resp.buffers[..buf_count as usize] {
        write_u32(&mut buf, b.buffer_id);
        write_u32(&mut buf, b.flags);
        write_u64(&mut buf, b.offset);
        write_u64(&mut buf, b.length);
        write_str(&mut buf, &b.name);
    }
    write_bytes(&mut buf, &resp.result);
    buf
}

/// Decode any WSM1 binary message from byte slice.
pub fn decode_wsm1_message(data: &[u8]) -> Result<Wsm1Message, GpuAdapterError> {
    if data.len() < 8 {
        return Err(GpuAdapterError::Wsm1Codec(format!(
            "frame length {} too short for WSM1 header",
            data.len()
        )));
    }
    let mut r = ByteReader::new(data);
    let magic = r.read_u32()?;
    if magic != WSM1_MAGIC {
        return Err(GpuAdapterError::Wsm1Codec(format!(
            "invalid WSM1 magic: 0x{magic:08X}"
        )));
    }
    let version = r.read_u16()?;
    if version != WSM1_PROTOCOL_VERSION {
        return Err(GpuAdapterError::Wsm1Codec(format!(
            "unsupported WSM1 version: {version}"
        )));
    }
    let msg_type = r.read_u8()?;
    let action_or_flags = r.read_u8()?;

    match msg_type {
        1 => {
            let task_id = r.read_str()?;
            let sandbox_id = r.read_str()?;
            let module_id = r.read_str()?;
            let module_version = r.read_str()?;
            let task_kind = r.read_str()?;
            let priority = r.read_u8()?;
            let deadline_ms = r.read_u64()?;
            let buf_count = r.read_u16()? as usize;
            let mut buffers = Vec::with_capacity(buf_count);
            for _ in 0..buf_count {
                let buffer_id = r.read_u32()?;
                let flags = r.read_u32()?;
                let offset = r.read_u64()?;
                let length = r.read_u64()?;
                let name = r.read_str()?;
                buffers.push(WasmBufferDescriptor {
                    buffer_id,
                    flags,
                    offset,
                    length,
                    name,
                });
            }
            let payload = r.read_bytes()?;
            Ok(Wsm1Message::TaskRequest(WasmTaskRequest {
                task_id,
                sandbox_id,
                module_id,
                module_version,
                task_kind,
                priority,
                deadline_ms,
                buffers,
                payload,
            }))
        }
        2 => {
            let status = WasmTaskStatus::try_from(action_or_flags)?;
            let protocol_version = r.read_u16()?;
            let task_id = r.read_str()?;
            let selected_gpu = r.read_i32()?;
            let latency_ms = r.read_u64()?;
            let error = r.read_str()?;
            let buf_count = r.read_u16()? as usize;
            let mut buffers = Vec::with_capacity(buf_count);
            for _ in 0..buf_count {
                let buffer_id = r.read_u32()?;
                let flags = r.read_u32()?;
                let offset = r.read_u64()?;
                let length = r.read_u64()?;
                let name = r.read_str()?;
                buffers.push(WasmBufferDescriptor {
                    buffer_id,
                    flags,
                    offset,
                    length,
                    name,
                });
            }
            let result = r.read_bytes()?;
            Ok(Wsm1Message::TaskResponse(WasmTaskResponse {
                task_id,
                status,
                protocol_version,
                selected_gpu,
                latency_ms,
                error,
                buffers,
                result,
            }))
        }
        3 => {
            let action = WasmLifecycleAction::try_from(action_or_flags)?;
            let request_id = r.read_str()?;
            let sandbox_id = r.read_str()?;
            let module_id = r.read_str()?;
            let module_version = r.read_str()?;
            let target_gpu = r.read_i32()?;
            let grace_period_ms = r.read_u32()?;
            let ack_token = r.read_str()?;
            let payload = r.read_bytes()?;
            Ok(Wsm1Message::LifecycleRequest(WasmLifecycleRequest {
                action,
                request_id,
                sandbox_id,
                module_id,
                module_version,
                target_gpu,
                grace_period_ms,
                ack_token,
                payload,
            }))
        }
        4 => {
            let action = WasmLifecycleAction::try_from(action_or_flags)?;
            let status = WasmLifecycleStatus::try_from(r.read_u8()?)?;
            let protocol_version = r.read_u16()?;
            let state = WasmLifecycleState::try_from(r.read_u8()?)?;
            let request_id = r.read_str()?;
            let sandbox_id = r.read_str()?;
            let module_id = r.read_str()?;
            let module_version = r.read_str()?;
            let assigned_gpu = r.read_i32()?;
            let active_tasks = r.read_u32()?;
            let lease_token = r.read_str()?;
            let error = r.read_str()?;
            Ok(Wsm1Message::LifecycleResponse(WasmLifecycleResponse {
                action,
                status,
                protocol_version,
                state,
                request_id,
                sandbox_id,
                module_id,
                module_version,
                assigned_gpu,
                active_tasks,
                lease_token,
                error,
            }))
        }
        other => Err(GpuAdapterError::Wsm1Codec(format!(
            "unknown WSM1 message type: {other}"
        ))),
    }
}

/// Encode a `Brk1Frame` into bytes.
pub fn encode_brk1_frame(frame: &Brk1Frame) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128 + frame.payload.len());
    write_u32(&mut buf, BRK1_MAGIC);
    write_u16(&mut buf, BRK1_PROTOCOL_VERSION);
    write_u8(&mut buf, frame.msg_type);
    write_u8(&mut buf, 0); // reserved
    write_str(&mut buf, &frame.task_id);
    write_str(&mut buf, &frame.source);
    write_str(&mut buf, &frame.destination);
    write_str(&mut buf, &frame.kind);
    write_u8(&mut buf, frame.priority);
    write_u32(&mut buf, frame.timeout_ms);
    write_bytes(&mut buf, &frame.payload);
    buf
}

/// Decode a `Brk1Frame` from bytes.
pub fn decode_brk1_frame(data: &[u8]) -> Result<Brk1Frame, GpuAdapterError> {
    if data.len() < 8 {
        return Err(GpuAdapterError::Wsm1Codec("BRK1 frame too short".to_string()));
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
    let _reserved = r.read_u8()?;
    let task_id = r.read_str()?;
    let source = r.read_str()?;
    let destination = r.read_str()?;
    let kind = r.read_str()?;
    let priority = r.read_u8()?;
    let timeout_ms = r.read_u32()?;
    let payload = r.read_bytes()?;
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

async fn write_raw_frame(
    stream: &mut TcpStream,
    data: &[u8],
    max_frame_size: usize,
) -> Result<(), GpuAdapterError> {
    if data.len() > max_frame_size {
        return Err(GpuAdapterError::FrameTooLarge {
            size: data.len(),
            max: max_frame_size,
        });
    }
    stream
        .write_all(&(data.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_raw_frame(
    stream: &mut TcpStream,
    max_frame_size: usize,
) -> Result<Vec<u8>, GpuAdapterError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let length = u32::from_be_bytes(len_buf) as usize;
    if length == 0 {
        return Err(GpuAdapterError::MalformedResponse(
            "zero-length frame received from broker".to_string(),
        ));
    }
    if length > max_frame_size {
        return Err(GpuAdapterError::FrameTooLarge {
            size: length,
            max: max_frame_size,
        });
    }
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

fn parse_lifecycle_response(body: &[u8]) -> Result<WasmLifecycleResponse, GpuAdapterError> {
    if body.len() >= 4 {
        let magic = u32::from_be_bytes(body[0..4].try_into().unwrap());
        if magic == BRK1_MAGIC {
            let brk_frame = decode_brk1_frame(body)?;
            return parse_lifecycle_response(&brk_frame.payload);
        } else if magic == WSM1_MAGIC {
            let msg = decode_wsm1_message(body)?;
            if let Wsm1Message::LifecycleResponse(resp) = msg {
                return Ok(resp);
            } else {
                return Err(GpuAdapterError::MalformedResponse(format!(
                    "expected LifecycleResponse in WSM1 frame, got {:?}",
                    msg
                )));
            }
        }
    }
    // Fall back to JSON BrokerMessage or direct WasmLifecycleResponse
    if let Ok(resp) = serde_json::from_slice::<WasmLifecycleResponse>(body) {
        return Ok(resp);
    }
    if let Ok(BrokerMessage::LifecycleResponse(resp)) = serde_json::from_slice::<BrokerMessage>(body) {
        return Ok(resp);
    }
    Err(GpuAdapterError::MalformedResponse(
        "failed to parse lifecycle response as BRK1, WSM1, or JSON".to_string(),
    ))
}

fn parse_task_response(body: &[u8]) -> Result<WasmTaskResponse, GpuAdapterError> {
    if body.len() >= 4 {
        let magic = u32::from_be_bytes(body[0..4].try_into().unwrap());
        if magic == BRK1_MAGIC {
            let brk_frame = decode_brk1_frame(body)?;
            return parse_task_response(&brk_frame.payload);
        } else if magic == WSM1_MAGIC {
            let msg = decode_wsm1_message(body)?;
            if let Wsm1Message::TaskResponse(resp) = msg {
                return Ok(resp);
            } else {
                return Err(GpuAdapterError::MalformedResponse(format!(
                    "expected TaskResponse in WSM1 frame, got {:?}",
                    msg
                )));
            }
        }
    }
    // Fall back to JSON WasmTaskResponse or BrokerMessage
    if let Ok(resp) = serde_json::from_slice::<WasmTaskResponse>(body) {
        return Ok(resp);
    }
    if let Ok(BrokerMessage::TaskResponse(gpu_resp)) = serde_json::from_slice::<BrokerMessage>(body) {
        let status = match gpu_resp.status {
            GpuTaskStatus::Completed => WasmTaskStatus::Ok,
            GpuTaskStatus::Cancelled => WasmTaskStatus::Rejected,
            GpuTaskStatus::Rejected => WasmTaskStatus::Rejected,
            GpuTaskStatus::Failed => WasmTaskStatus::Failed,
        };
        let mut result = Vec::new();
        for b in gpu_resp.output_buffers {
            if let Some(data) = b.inline_data {
                result = data;
                break;
            }
        }
        return Ok(WasmTaskResponse {
            task_id: gpu_resp.task_id,
            status,
            protocol_version: 1,
            selected_gpu: gpu_resp.gpu_id.unwrap_or(0),
            latency_ms: gpu_resp.execution_ms.unwrap_or(0),
            error: gpu_resp.error.map(|e| e.message).unwrap_or_default(),
            buffers: Vec::new(),
            result,
        });
    }
    Err(GpuAdapterError::MalformedResponse(
        "failed to parse task response as BRK1, WSM1, or JSON".to_string(),
    ))
}

// ============================================================================
// LifecycleClient
// ============================================================================

/// Asynchronous client extending `GpuBrokerClient` to coordinate WSM1 lifecycle
/// operations (prepare, drain, release, query) and WSM1 binary tasks with the broker.
#[derive(Clone)]
pub struct LifecycleClient {
    broker_client: Arc<GpuBrokerClient>,
    wire_mode: LifecycleWireMode,
}

impl Deref for LifecycleClient {
    type Target = GpuBrokerClient;

    fn deref(&self) -> &Self::Target {
        &self.broker_client
    }
}

impl LifecycleClient {
    /// Create a new `LifecycleClient` from adapter configuration.
    pub fn new(config: GpuAdapterConfig) -> Result<Self, GpuAdapterError> {
        let broker_client = Arc::new(GpuBrokerClient::new(config)?);
        Ok(Self {
            broker_client,
            wire_mode: LifecycleWireMode::Auto,
        })
    }

    /// Construct a `LifecycleClient` wrapping an existing `Arc<GpuBrokerClient>`.
    pub fn from_broker_client(client: Arc<GpuBrokerClient>) -> Self {
        Self {
            broker_client: client,
            wire_mode: LifecycleWireMode::Auto,
        }
    }

    /// Set wire framing mode for lifecycle operations.
    pub fn with_wire_mode(mut self, wire_mode: LifecycleWireMode) -> Self {
        self.wire_mode = wire_mode;
        self
    }

    /// Update wire framing mode in-place.
    pub fn set_wire_mode(&mut self, wire_mode: LifecycleWireMode) {
        self.wire_mode = wire_mode;
    }

    /// Get current wire framing mode.
    pub fn wire_mode(&self) -> LifecycleWireMode {
        self.wire_mode
    }

    /// Reference to the underlying `GpuBrokerClient`.
    pub fn broker_client(&self) -> &Arc<GpuBrokerClient> {
        &self.broker_client
    }

    /// Send a lifecycle operation request to the broker.
    pub async fn send_lifecycle_request(
        &self,
        request: &WasmLifecycleRequest,
    ) -> Result<WasmLifecycleResponse, GpuAdapterError> {
        let config = self.broker_client.config();
        if !config.enabled {
            return Err(GpuAdapterError::Disabled);
        }

        let mut stream = timeout(
            config.connect_timeout,
            TcpStream::connect(&config.endpoint),
        )
        .await
        .map_err(|_| GpuAdapterError::ConnectTimeout(config.connect_timeout))??;

        let frame_bytes = match self.wire_mode {
            LifecycleWireMode::RawWsm1 => encode_wsm1_lifecycle_request(request),
            LifecycleWireMode::Json => {
                let msg = BrokerMessage::LifecycleRequest(request.clone());
                serde_json::to_vec(&msg).map_err(GpuAdapterError::Serialization)?
            }
            LifecycleWireMode::Brk1 | LifecycleWireMode::Auto => {
                let wsm1_bytes = encode_wsm1_lifecycle_request(request);
                encode_brk1_frame(&Brk1Frame {
                    msg_type: BRK1_MSG_REQUEST,
                    task_id: request.request_id.clone(),
                    source: "yukki-os".to_string(),
                    destination: "overhauled".to_string(),
                    kind: "wasm.lifecycle".to_string(),
                    priority: 1,
                    timeout_ms: config.request_timeout.as_millis().min(u32::MAX as u128) as u32,
                    payload: wsm1_bytes,
                })
            }
        };

        write_raw_frame(&mut stream, &frame_bytes, config.max_frame_size).await?;

        let response_bytes = timeout(
            config.request_timeout,
            read_raw_frame(&mut stream, config.max_frame_size),
        )
        .await
        .map_err(|_| GpuAdapterError::RequestTimeout(config.request_timeout))??;

        parse_lifecycle_response(&response_bytes)
    }

    /// Prepare a module version on the broker.
    pub async fn prepare(
        &self,
        sandbox_id: &str,
        module_id: &str,
        version: &str,
        target_gpu: i32,
    ) -> Result<WasmLifecycleResponse, GpuAdapterError> {
        let req = WasmLifecycleRequest {
            action: WasmLifecycleAction::Prepare,
            request_id: uuid::Uuid::new_v4().to_string(),
            sandbox_id: sandbox_id.to_string(),
            module_id: module_id.to_string(),
            module_version: version.to_string(),
            target_gpu,
            grace_period_ms: 0,
            ack_token: String::new(),
            payload: Vec::new(),
        };
        self.send_lifecycle_request(&req).await
    }

    /// Drain a module version on the broker.
    pub async fn drain(
        &self,
        sandbox_id: &str,
        module_id: &str,
        version: &str,
        grace_period_ms: u32,
    ) -> Result<WasmLifecycleResponse, GpuAdapterError> {
        let req = WasmLifecycleRequest {
            action: WasmLifecycleAction::Drain,
            request_id: uuid::Uuid::new_v4().to_string(),
            sandbox_id: sandbox_id.to_string(),
            module_id: module_id.to_string(),
            module_version: version.to_string(),
            target_gpu: -1,
            grace_period_ms,
            ack_token: String::new(),
            payload: Vec::new(),
        };
        self.send_lifecycle_request(&req).await
    }

    /// Release a module version on the broker.
    pub async fn release(
        &self,
        sandbox_id: &str,
        module_id: &str,
        version: &str,
        ack_token: &str,
    ) -> Result<WasmLifecycleResponse, GpuAdapterError> {
        let req = WasmLifecycleRequest {
            action: WasmLifecycleAction::Release,
            request_id: uuid::Uuid::new_v4().to_string(),
            sandbox_id: sandbox_id.to_string(),
            module_id: module_id.to_string(),
            module_version: version.to_string(),
            target_gpu: -1,
            grace_period_ms: 0,
            ack_token: ack_token.to_string(),
            payload: Vec::new(),
        };
        self.send_lifecycle_request(&req).await
    }

    /// Query the status and state of a module version on the broker.
    pub async fn query(
        &self,
        sandbox_id: &str,
        module_id: &str,
        version: &str,
    ) -> Result<WasmLifecycleResponse, GpuAdapterError> {
        let req = WasmLifecycleRequest {
            action: WasmLifecycleAction::Query,
            request_id: uuid::Uuid::new_v4().to_string(),
            sandbox_id: sandbox_id.to_string(),
            module_id: module_id.to_string(),
            module_version: version.to_string(),
            target_gpu: -1,
            grace_period_ms: 0,
            ack_token: String::new(),
            payload: Vec::new(),
        };
        self.send_lifecycle_request(&req).await
    }

    /// Submit a compute task using WSM1 binary format with automatic retry.
    pub async fn submit_wsm1_task(
        &self,
        task: &WasmTaskRequest,
    ) -> Result<WasmTaskResponse, GpuAdapterError> {
        let config = self.broker_client.config();
        if !config.enabled {
            return Err(GpuAdapterError::Disabled);
        }

        let mut attempt = 0;
        loop {
            attempt += 1;
            match self.submit_wsm1_task_single(task).await {
                Ok(resp) => return Ok(resp),
                Err(err) => {
                    let is_retryable = match &err {
                        GpuAdapterError::Io(_) => true,
                        GpuAdapterError::ConnectTimeout(_) => true,
                        _ => false,
                    };

                    let last_error_msg = err.to_string();
                    if !is_retryable || attempt > config.max_retries {
                        return Err(if attempt > 1 {
                            GpuAdapterError::RetriesExhausted {
                                attempts: attempt,
                                last_error: last_error_msg,
                            }
                        } else {
                            err
                        });
                    }

                    let backoff_multiplier = 2u32.saturating_pow((attempt - 1) as u32);
                    let delay = config.retry_backoff.saturating_mul(backoff_multiplier);
                    sleep(delay).await;
                }
            }
        }
    }

    async fn submit_wsm1_task_single(
        &self,
        task: &WasmTaskRequest,
    ) -> Result<WasmTaskResponse, GpuAdapterError> {
        let config = self.broker_client.config();
        let mut stream = timeout(
            config.connect_timeout,
            TcpStream::connect(&config.endpoint),
        )
        .await
        .map_err(|_| GpuAdapterError::ConnectTimeout(config.connect_timeout))??;

        let frame_bytes = match self.wire_mode {
            LifecycleWireMode::RawWsm1 => encode_wsm1_task_request(task),
            LifecycleWireMode::Json => {
                serde_json::to_vec(task).map_err(GpuAdapterError::Serialization)?
            }
            LifecycleWireMode::Brk1 | LifecycleWireMode::Auto => {
                let wsm1_bytes = encode_wsm1_task_request(task);
                encode_brk1_frame(&Brk1Frame {
                    msg_type: BRK1_MSG_REQUEST,
                    task_id: task.task_id.clone(),
                    source: "yukki-os".to_string(),
                    destination: "overhauled".to_string(),
                    kind: "wasm.task".to_string(),
                    priority: task.priority,
                    timeout_ms: config.request_timeout.as_millis().min(u32::MAX as u128) as u32,
                    payload: wsm1_bytes,
                })
            }
        };

        write_raw_frame(&mut stream, &frame_bytes, config.max_frame_size).await?;

        let response_bytes = timeout(
            config.request_timeout,
            read_raw_frame(&mut stream, config.max_frame_size),
        )
        .await
        .map_err(|_| GpuAdapterError::RequestTimeout(config.request_timeout))??;

        parse_task_response(&response_bytes)
    }
}

// ============================================================================
// Module Lifecycle & Safe Hotswapping
// ============================================================================

/// Lifecycle states of a registered WASM module version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleLifecycleState {
    /// Newly created, compiled, and validated; not yet receiving routing traffic.
    Prepared,
    /// Currently active and receiving incoming task executions.
    Active,
    /// Routing has transitioned away; draining existing in-flight GPU tasks.
    Quiescing,
    /// In-flight tasks reached zero.
    Drained,
    /// Old GPU and sandbox resources have been deallocated.
    Released,
    /// Activation was rolled back due to error.
    RolledBack,
}

/// Hook for exporting and importing application-level state during hotswaps.
///
/// **Safety boundary**: This hook only carries structured application state (e.g.
/// configuration, token counters, high-level embeddings). It does **NOT** migrate
/// raw WASM linear memory pages or arbitrary live CUDA device pointers.
pub trait StateHandoffHook: Send + Sync {
    /// Serialize structured state from the superseded active module.
    fn export_state(&self) -> Result<Vec<u8>, GpuAdapterError>;
    /// Restore structured state into the prepared replacement module.
    fn import_state(&self, state: &[u8]) -> Result<(), GpuAdapterError>;
}

/// Container for resources tied to a specific module version.
#[derive(Debug)]
pub struct ModuleVersionResources {
    pub module_id: String,
    pub version: String,
    pub allocated_at: std::time::Instant,
}

/// Handle tracking state and in-flight operations of a specific module version.
pub struct ModuleVersionHandle {
    pub module_id: String,
    pub version: String,
    pub wasm_bytes: Vec<u8>,
    pub state: RwLock<ModuleLifecycleState>,
    pub in_flight: AtomicUsize,
    pub resources: Mutex<Option<ModuleVersionResources>>,
    pub handoff_hook: Option<Arc<dyn StateHandoffHook>>,
    pub lease_token: Mutex<Option<String>>,
    pub assigned_gpu: AtomicI32,
}

impl std::fmt::Debug for ModuleVersionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModuleVersionHandle")
            .field("module_id", &self.module_id)
            .field("version", &self.version)
            .field("wasm_bytes_len", &self.wasm_bytes.len())
            .field("state", &*self.state.read().unwrap())
            .field("in_flight", &self.in_flight.load(Ordering::SeqCst))
            .field("resources", &*self.resources.lock().unwrap())
            .field("lease_token", &*self.lease_token.lock().unwrap())
            .field("assigned_gpu", &self.assigned_gpu.load(Ordering::SeqCst))
            .finish()
    }
}

impl ModuleVersionHandle {
    pub fn is_active(&self) -> bool {
        *self.state.read().unwrap() == ModuleLifecycleState::Active
    }

    pub fn current_in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    pub fn is_resources_allocated(&self) -> bool {
        self.resources.lock().unwrap().is_some()
    }

    pub fn lease_token(&self) -> Option<String> {
        self.lease_token.lock().unwrap().clone()
    }

    pub fn set_lease_token(&self, token: Option<String>) {
        *self.lease_token.lock().unwrap() = token;
    }

    pub fn assigned_gpu(&self) -> i32 {
        self.assigned_gpu.load(Ordering::SeqCst)
    }

    pub fn set_target_gpu(&self, gpu: i32) {
        self.assigned_gpu.store(gpu, Ordering::SeqCst);
    }
}

/// Coordinates module version registration, atomic routing switches, quiescing,
/// and drain-before-release lifecycle order.
pub struct ModuleLifecycleManager {
    /// Map of module_id -> currently active version handle.
    active_routing: RwLock<HashMap<String, Arc<ModuleVersionHandle>>>,
    /// Map of (module_id, version) -> version handle.
    version_registry: RwLock<HashMap<(String, String), Arc<ModuleVersionHandle>>>,
    /// Quiescing timeout duration.
    quiesce_timeout: Duration,
    /// Audit log of resource release events (useful for verifying drain ordering).
    release_log: Mutex<Vec<String>>,
    /// Optional LifecycleClient for coordinating lifecycle operations with the GPU broker.
    lifecycle_client: RwLock<Option<Arc<LifecycleClient>>>,
}

impl Default for ModuleLifecycleManager {
    fn default() -> Self {
        Self::new(DEFAULT_GPU_QUIESCE_TIMEOUT)
    }
}

/// RAII guard to ensure the module version's in-flight counter is decremented upon drop,
/// even if task execution is cancelled, times out, or panics.
struct InFlightGuard {
    handle: Arc<ModuleVersionHandle>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.handle.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

impl ModuleLifecycleManager {
    pub fn new(quiesce_timeout: Duration) -> Self {
        Self {
            active_routing: RwLock::new(HashMap::new()),
            version_registry: RwLock::new(HashMap::new()),
            quiesce_timeout,
            release_log: Mutex::new(Vec::new()),
            lifecycle_client: RwLock::new(None),
        }
    }

    pub fn with_lifecycle_client(self, client: Arc<LifecycleClient>) -> Self {
        *self.lifecycle_client.write().unwrap() = Some(client);
        self
    }

    pub fn set_lifecycle_client(&self, client: Arc<LifecycleClient>) {
        *self.lifecycle_client.write().unwrap() = Some(client);
    }

    pub fn lifecycle_client(&self) -> Option<Arc<LifecycleClient>> {
        self.lifecycle_client.read().unwrap().clone()
    }

    pub fn release_log(&self) -> Vec<String> {
        self.release_log.lock().unwrap().clone()
    }

    /// Prepare a new module version: validate WASM bytecode and register resources.
    pub fn prepare_version(
        &self,
        module_id: &str,
        version: &str,
        wasm_bytes: &[u8],
        handoff_hook: Option<Arc<dyn StateHandoffHook>>,
    ) -> Result<Arc<ModuleVersionHandle>, GpuAdapterError> {
        // Validate wasm bytecode
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        let engine = wasmtime::Engine::new(&config)
            .map_err(|e| GpuAdapterError::WasmValidation(e.to_string()))?;
        wasmtime::Module::new(&engine, wasm_bytes)
            .map_err(|e| GpuAdapterError::WasmValidation(e.to_string()))?;

        let key = (module_id.to_string(), version.to_string());
        let mut registry = self.version_registry.write().unwrap();
        if registry.contains_key(&key) {
            return Err(GpuAdapterError::ModuleAlreadyExists {
                module_id: module_id.to_string(),
                version: version.to_string(),
            });
        }

        let handle = Arc::new(ModuleVersionHandle {
            module_id: module_id.to_string(),
            version: version.to_string(),
            wasm_bytes: wasm_bytes.to_vec(),
            state: RwLock::new(ModuleLifecycleState::Prepared),
            in_flight: AtomicUsize::new(0),
            resources: Mutex::new(Some(ModuleVersionResources {
                module_id: module_id.to_string(),
                version: version.to_string(),
                allocated_at: std::time::Instant::now(),
            })),
            handoff_hook,
            lease_token: Mutex::new(None),
            assigned_gpu: AtomicI32::new(-1),
        });

        registry.insert(key, handle.clone());
        Ok(handle)
    }

    /// Perform a safe hotswap:
    /// 1. Orchestrates broker prepare (if LifecycleClient configured).
    /// 2. Runs state handoff from old active version (if present) to the new version.
    ///    If handoff or activation fails, aborts with **rollback**, leaving the old version active.
    /// 3. Atomically switches active routing to the new version.
    /// 4. Quiesces the old version (stops routing new tasks).
    /// 5. Drains in-flight tasks (locally and via broker) and releases old resources **only after**
    ///    in-flight tasks reach zero.
    pub async fn hotswap(&self, module_id: &str, new_version: &str) -> Result<(), GpuAdapterError> {
        let new_handle = {
            let registry = self.version_registry.read().unwrap();
            registry
                .get(&(module_id.to_string(), new_version.to_string()))
                .cloned()
                .ok_or_else(|| GpuAdapterError::ModuleNotFound {
                    module_id: module_id.to_string(),
                    version: new_version.to_string(),
                })?
        };

        let current_active = {
            let routing = self.active_routing.read().unwrap();
            routing.get(module_id).cloned()
        };

        // Guard against self-hotswap: if the version is already active, no-op
        if let Some(ref active) = current_active {
            if active.version == new_version {
                return Ok(());
            }
        }

        let lifecycle_client = self.lifecycle_client.read().unwrap().clone();

        // Step 1: Broker Prepare (if LifecycleClient is configured)
        if let Some(ref client) = lifecycle_client {
            let target_gpu = new_handle.assigned_gpu.load(Ordering::SeqCst);
            let resp = match client
                .prepare(
                    "rustasm_sandbox",
                    module_id,
                    new_version,
                    target_gpu,
                )
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    *new_handle.state.write().unwrap() = ModuleLifecycleState::RolledBack;
                    return Err(e);
                }
            };
            if resp.status != WasmLifecycleStatus::Ok {
                *new_handle.state.write().unwrap() = ModuleLifecycleState::RolledBack;
                return Err(GpuAdapterError::LifecycleOperationFailed {
                    action: WasmLifecycleAction::Prepare,
                    module_id: module_id.to_string(),
                    version: new_version.to_string(),
                    status: resp.status,
                    message: if resp.error.is_empty() {
                        format!("broker rejected prepare with status {:?}", resp.status)
                    } else {
                        resp.error
                    },
                });
            }
            if !resp.lease_token.is_empty() {
                *new_handle.lease_token.lock().unwrap() = Some(resp.lease_token.clone());
            }
            if resp.assigned_gpu >= 0 {
                new_handle
                    .assigned_gpu
                    .store(resp.assigned_gpu, Ordering::SeqCst);
            }
        }

        // Step 2: State handoff hook execution
        if let Some(ref old_handle) = current_active {
            if let (Some(ref old_hook), Some(ref new_hook)) =
                (&old_handle.handoff_hook, &new_handle.handoff_hook)
            {
                let exported = old_hook.export_state().map_err(|e| {
                    *new_handle.state.write().unwrap() = ModuleLifecycleState::RolledBack;
                    GpuAdapterError::StateHandoffFailed(format!(
                        "failed to export state from {}: {e}",
                        old_handle.version
                    ))
                })?;

                if let Err(e) = new_hook.import_state(&exported) {
                    *new_handle.state.write().unwrap() = ModuleLifecycleState::RolledBack;
                    // Release prepared replacement module from broker
                    if let Some(ref client) = lifecycle_client {
                        let token = new_handle.lease_token.lock().unwrap().clone();
                        let _ = client
                            .release(
                                "rustasm_sandbox",
                                module_id,
                                new_version,
                                token.as_deref().unwrap_or(""),
                            )
                            .await;
                    }
                    return Err(GpuAdapterError::StateHandoffFailed(format!(
                        "failed to import state into {new_version}: {e}"
                    )));
                }
            }
        }

        // Step 3: Atomic routing switch
        {
            let mut routing = self.active_routing.write().unwrap();
            routing.insert(module_id.to_string(), new_handle.clone());
            *new_handle.state.write().unwrap() = ModuleLifecycleState::Active;
        }

        // Step 4: Quiesce and drain old version
        if let Some(old_handle) = current_active {
            *old_handle.state.write().unwrap() = ModuleLifecycleState::Quiescing;

            // Notify broker to drain old version
            if let Some(ref client) = lifecycle_client {
                let grace_ms = self.quiesce_timeout.as_millis().min(u32::MAX as u128) as u32;
                let _ = client
                    .drain("rustasm_sandbox", module_id, &old_handle.version, grace_ms)
                    .await;
            }

            let drain_result = self.drain_version(&old_handle).await;
            match drain_result {
                Ok(()) => {
                    // Step 5: Release old resources only after in-flight is 0
                    if let Some(ref client) = lifecycle_client {
                        let token = old_handle.lease_token.lock().unwrap().clone();
                        let _ = client
                            .release(
                                "rustasm_sandbox",
                                module_id,
                                &old_handle.version,
                                token.as_deref().unwrap_or(""),
                            )
                            .await;
                    }
                    self.release_version_resources(&old_handle);
                }
                Err(err) => {
                    // If quiescing timed out, old resources are NOT released while tasks are in-flight!
                    return Err(err);
                }
            }
        }

        Ok(())
    }

    /// Asynchronously wait for in-flight tasks to reach zero on a quiescing version.
    async fn drain_version(&self, handle: &ModuleVersionHandle) -> Result<(), GpuAdapterError> {
        let start = std::time::Instant::now();
        while handle.in_flight.load(Ordering::SeqCst) > 0 {
            if start.elapsed() > self.quiesce_timeout {
                let remaining = handle.in_flight.load(Ordering::SeqCst);
                return Err(GpuAdapterError::QuiesceTimeout {
                    module_id: handle.module_id.clone(),
                    version: handle.version.clone(),
                    remaining,
                });
            }
            sleep(Duration::from_millis(10)).await;
        }
        *handle.state.write().unwrap() = ModuleLifecycleState::Drained;
        Ok(())
    }

    /// Releases resources for a drained version.
    fn release_version_resources(&self, handle: &ModuleVersionHandle) {
        let mut res = handle.resources.lock().unwrap();
        if let Some(r) = res.take() {
            let msg = format!("released resources for {}:{}", r.module_id, r.version);
            self.release_log.lock().unwrap().push(msg);
        }
        *handle.state.write().unwrap() = ModuleLifecycleState::Released;
    }

    /// Execute a task against the currently active module version.
    pub async fn execute_task<F, Fut, R>(&self, module_id: &str, f: F) -> Result<R, GpuAdapterError>
    where
        F: FnOnce(Arc<ModuleVersionHandle>) -> Fut,
        Fut: std::future::Future<Output = Result<R, GpuAdapterError>>,
    {
        let (handle, _guard) = {
            let routing = self.active_routing.read().unwrap();
            let handle = routing
                .get(module_id)
                .cloned()
                .ok_or_else(|| GpuAdapterError::NoActiveModule(module_id.to_string()))?;

            // Increment in_flight before checking is_active to avoid a race condition
            // with a concurrent hotswap transitioning the module to Quiescing and draining.
            handle.in_flight.fetch_add(1, Ordering::SeqCst);
            let guard = InFlightGuard {
                handle: Arc::clone(&handle),
            };

            if !handle.is_active() {
                return Err(GpuAdapterError::NoActiveModule(format!(
                    "{module_id} is not in Active state"
                )));
            }

            (handle, guard)
        };

        f(handle).await
    }

    /// Explicitly roll back active routing to a specified previous version.
    pub async fn rollback(
        &self,
        module_id: &str,
        target_version: &str,
    ) -> Result<(), GpuAdapterError> {
        let target_handle = {
            let registry = self.version_registry.read().unwrap();
            registry
                .get(&(module_id.to_string(), target_version.to_string()))
                .cloned()
                .ok_or_else(|| GpuAdapterError::ModuleNotFound {
                    module_id: module_id.to_string(),
                    version: target_version.to_string(),
                })?
        };

        // Reallocate resources if previously released
        {
            let mut res = target_handle.resources.lock().unwrap();
            if res.is_none() {
                *res = Some(ModuleVersionResources {
                    module_id: module_id.to_string(),
                    version: target_version.to_string(),
                    allocated_at: std::time::Instant::now(),
                });
            }
        }

        let current_active = {
            let routing = self.active_routing.read().unwrap();
            routing.get(module_id).cloned()
        };

        // Atomically switch routing to target version
        {
            let mut routing = self.active_routing.write().unwrap();
            routing.insert(module_id.to_string(), target_handle.clone());
            *target_handle.state.write().unwrap() = ModuleLifecycleState::Active;
        }

        // Quiesce and drain current active version
        if let Some(old_handle) = current_active {
            *old_handle.state.write().unwrap() = ModuleLifecycleState::Quiescing;
            let lifecycle_client = self.lifecycle_client.read().unwrap().clone();
            if let Some(ref client) = lifecycle_client {
                let grace_ms = self.quiesce_timeout.as_millis().min(u32::MAX as u128) as u32;
                let _ = client
                    .drain("rustasm_sandbox", module_id, &old_handle.version, grace_ms)
                    .await;
            }
            let drain_result = self.drain_version(&old_handle).await;
            if drain_result.is_ok() {
                if let Some(ref client) = lifecycle_client {
                    let token = old_handle.lease_token.lock().unwrap().clone();
                    let _ = client
                        .release(
                            "rustasm_sandbox",
                            module_id,
                            &old_handle.version,
                            token.as_deref().unwrap_or(""),
                        )
                        .await;
                }
                self.release_version_resources(&old_handle);
            }
        }

        Ok(())
    }

    /// Get current active version string for a module.
    pub fn get_active_version(&self, module_id: &str) -> Option<String> {
        let routing = self.active_routing.read().unwrap();
        routing.get(module_id).map(|h| h.version.clone())
    }

    /// Get handle for a registered version.
    pub fn get_version_handle(
        &self,
        module_id: &str,
        version: &str,
    ) -> Option<Arc<ModuleVersionHandle>> {
        let registry = self.version_registry.read().unwrap();
        registry
            .get(&(module_id.to_string(), version.to_string()))
            .cloned()
    }
}
