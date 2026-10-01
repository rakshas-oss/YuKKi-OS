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
    sync::{
        atomic::{AtomicUsize, Ordering},
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
        if self.timeout_ms == 0 {
            return Err(GpuAdapterError::InvalidRequest(
                "timeout_ms must be greater than zero".to_string(),
            ));
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
        if self.request_timeout.is_zero() {
            return Err(GpuAdapterError::InvalidConfig(
                "request_timeout must be greater than zero".to_string(),
            ));
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
        }
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
        });

        registry.insert(key, handle.clone());
        Ok(handle)
    }

    /// Perform a safe hotswap:
    /// 1. Runs state handoff from old active version (if present) to the new version.
    /// 2. If handoff or activation fails, aborts with **rollback**, leaving the old version active.
    /// 3. Atomically switches active routing to the new version.
    /// 4. Quiesces the old version (stops routing new tasks).
    /// 5. Drains in-flight tasks and releases old resources **only after** in-flight tasks reach zero.
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

        // Step 1: State handoff hook execution
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

                new_hook.import_state(&exported).map_err(|e| {
                    *new_handle.state.write().unwrap() = ModuleLifecycleState::RolledBack;
                    GpuAdapterError::StateHandoffFailed(format!(
                        "failed to import state into {new_version}: {e}"
                    ))
                })?;
            }
        }

        // Step 2: Atomic routing switch
        {
            let mut routing = self.active_routing.write().unwrap();
            routing.insert(module_id.to_string(), new_handle.clone());
            *new_handle.state.write().unwrap() = ModuleLifecycleState::Active;
        }

        // Step 3: Quiesce and drain old version
        if let Some(old_handle) = current_active {
            *old_handle.state.write().unwrap() = ModuleLifecycleState::Quiescing;

            let drain_result = self.drain_version(&old_handle).await;
            match drain_result {
                Ok(()) => {
                    // Step 4: Release old resources only after in-flight is 0
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
            let drain_result = self.drain_version(&old_handle).await;
            if drain_result.is_ok() {
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
