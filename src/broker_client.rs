use serde::{Deserialize, Serialize};
use std::{env, num::ParseIntError, time::Duration};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

pub const DEFAULT_BROKER_ENDPOINT: &str = "127.0.0.1:9000";
pub const DEFAULT_BROKER_MAX_FRAME_BYTES: usize = 64 * 1024;
pub const DEFAULT_BROKER_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
pub const DEFAULT_BROKER_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Broker transport authentication lives outside YuKKi-OS today.
///
/// Use this setting to record the expected deployment boundary and document
/// whether the broker hop is protected by an authenticated proxy or service
/// mesh. The current client transport remains raw TCP by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerTransportSecurity {
    PlaintextBoundary,
    AuthenticatedProxy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerClientConfig {
    endpoint: String,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_frame_size: usize,
    pub transport_security: BrokerTransportSecurity,
}

impl Default for BrokerClientConfig {
    fn default() -> Self {
        Self {
            endpoint: DEFAULT_BROKER_ENDPOINT.to_string(),
            connect_timeout: DEFAULT_BROKER_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_BROKER_REQUEST_TIMEOUT,
            max_frame_size: DEFAULT_BROKER_MAX_FRAME_BYTES,
            transport_security: BrokerTransportSecurity::PlaintextBoundary,
        }
    }
}

impl BrokerClientConfig {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            ..Self::default()
        }
    }

    pub fn from_env() -> Result<Self, BrokerClientError> {
        let endpoint = env::var("YUKKI_BROKER_ENDPOINT")
            .unwrap_or_else(|_| DEFAULT_BROKER_ENDPOINT.to_string());
        let connect_timeout = duration_from_env(
            "YUKKI_BROKER_CONNECT_TIMEOUT_MS",
            DEFAULT_BROKER_CONNECT_TIMEOUT,
        )?;
        let request_timeout = duration_from_env(
            "YUKKI_BROKER_REQUEST_TIMEOUT_MS",
            DEFAULT_BROKER_REQUEST_TIMEOUT,
        )?;
        let max_frame_size = usize_from_env(
            "YUKKI_BROKER_MAX_FRAME_BYTES",
            DEFAULT_BROKER_MAX_FRAME_BYTES,
        )?;
        let transport_security = match env::var("YUKKI_BROKER_TRANSPORT_SECURITY")
            .unwrap_or_else(|_| "plaintext-boundary".to_string())
            .trim()
        {
            "plaintext-boundary" => BrokerTransportSecurity::PlaintextBoundary,
            "authenticated-proxy" => BrokerTransportSecurity::AuthenticatedProxy,
            other => {
                return Err(BrokerClientError::InvalidConfig(format!(
                    "YUKKI_BROKER_TRANSPORT_SECURITY must be 'plaintext-boundary' or 'authenticated-proxy', got '{other}'"
                )))
            }
        };

        let config = Self {
            endpoint,
            connect_timeout,
            request_timeout,
            max_frame_size,
            transport_security,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn validate(&self) -> Result<(), BrokerClientError> {
        if self.endpoint.trim().is_empty() {
            return Err(BrokerClientError::InvalidConfig(
                "broker endpoint must not be empty".to_string(),
            ));
        }
        if self.connect_timeout.is_zero() {
            return Err(BrokerClientError::InvalidConfig(
                "connect timeout must be greater than zero".to_string(),
            ));
        }
        if self.request_timeout.is_zero() {
            return Err(BrokerClientError::InvalidConfig(
                "request timeout must be greater than zero".to_string(),
            ));
        }
        if self.max_frame_size == 0 || self.max_frame_size > u32::MAX as usize {
            return Err(BrokerClientError::InvalidConfig(format!(
                "max frame size must be between 1 and {} bytes",
                u32::MAX
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct BrokerTask {
    pub task_id: String,
    pub source: String,
    pub destination: String,
    pub kind: String,
    pub priority: u8,
    pub timeout_ms: u32,
    pub payload: serde_json::Value,
}

impl BrokerTask {
    pub fn validate(&self) -> Result<(), BrokerClientError> {
        if self.task_id.trim().is_empty() {
            return Err(BrokerClientError::InvalidRequest(
                "task_id must not be empty".to_string(),
            ));
        }
        if self.source.trim().is_empty() {
            return Err(BrokerClientError::InvalidRequest(
                "source must not be empty".to_string(),
            ));
        }
        if self.destination.trim().is_empty() {
            return Err(BrokerClientError::InvalidRequest(
                "destination must not be empty".to_string(),
            ));
        }
        if self.kind.trim().is_empty() {
            return Err(BrokerClientError::InvalidRequest(
                "kind must not be empty".to_string(),
            ));
        }
        if self.timeout_ms == 0 {
            return Err(BrokerClientError::InvalidRequest(
                "timeout_ms must be greater than zero".to_string(),
            ));
        }
        if self.payload.is_null() {
            return Err(BrokerClientError::InvalidRequest(
                "payload must not be null".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct BrokerResult {
    pub task_id: String,
    pub status: String,
    pub gpu_id: Option<i32>,
    pub execution_ms: Option<u64>,
    pub result: Option<serde_json::Value>,
}

impl BrokerResult {
    fn validate_for(&self, task: &BrokerTask) -> Result<(), BrokerClientError> {
        if self.task_id != task.task_id {
            return Err(BrokerClientError::MalformedResponse(format!(
                "response task_id '{}' did not match request '{}'",
                self.task_id, task.task_id
            )));
        }
        if self.status.trim().is_empty() {
            return Err(BrokerClientError::MalformedResponse(
                "response status must not be empty".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum BrokerClientError {
    #[error("invalid broker client configuration: {0}")]
    InvalidConfig(String),
    #[error("invalid broker request: {0}")]
    InvalidRequest(String),
    #[error("malformed broker response: {0}")]
    MalformedResponse(String),
    #[error("broker request frame is {size} bytes, exceeding max {max} bytes")]
    RequestTooLarge { size: usize, max: usize },
    #[error("broker response frame is {size} bytes, exceeding max {max} bytes")]
    ResponseTooLarge { size: usize, max: usize },
    #[error("timed out connecting to broker after {0:?}")]
    ConnectTimeout(Duration),
    #[error("timed out waiting for broker response after {0:?}")]
    RequestTimeout(Duration),
    #[error("could not serialize broker request: {0}")]
    SerializeRequest(#[source] serde_json::Error),
    #[error("could not deserialize broker response: {0}")]
    DeserializeResponse(#[source] serde_json::Error),
    #[error("broker transport error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct BrokerClient {
    config: BrokerClientConfig,
}

impl BrokerClient {
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            config: BrokerClientConfig::new(addr),
        }
    }

    pub fn with_config(config: BrokerClientConfig) -> Result<Self, BrokerClientError> {
        config.validate()?;
        Ok(Self { config })
    }

    pub fn config(&self) -> &BrokerClientConfig {
        &self.config
    }

    /// Submit a single broker task over a dedicated connection.
    ///
    /// Timeouts and cancellations drop the socket instead of reusing it, so
    /// partially completed reads or writes are not carried into subsequent
    /// requests.
    pub async fn submit(&self, task: &BrokerTask) -> Result<BrokerResult, BrokerClientError> {
        self.config.validate()?;
        task.validate()?;

        let request = serde_json::to_vec(task).map_err(BrokerClientError::SerializeRequest)?;
        ensure_request_size(request.len(), self.config.max_frame_size)?;

        timeout(
            self.config.request_timeout,
            self.submit_inner(task, &request),
        )
        .await
        .map_err(|_| BrokerClientError::RequestTimeout(self.config.request_timeout))?
    }

    async fn submit_inner(
        &self,
        task: &BrokerTask,
        request: &[u8],
    ) -> Result<BrokerResult, BrokerClientError> {
        let mut stream = timeout(
            self.config.connect_timeout,
            TcpStream::connect(self.config.endpoint()),
        )
        .await
        .map_err(|_| BrokerClientError::ConnectTimeout(self.config.connect_timeout))??;

        write_frame(&mut stream, request, self.config.max_frame_size).await?;
        stream.flush().await?;

        let reply = read_frame(&mut stream, self.config.max_frame_size).await?;
        let result = serde_json::from_slice::<BrokerResult>(&reply)
            .map_err(BrokerClientError::DeserializeResponse)?;
        result.validate_for(task)?;
        Ok(result)
    }
}

fn duration_from_env(key: &str, default: Duration) -> Result<Duration, BrokerClientError> {
    match env::var(key) {
        Ok(value) => {
            let millis = parse_env_usize(key, &value)?;
            Ok(Duration::from_millis(millis as u64))
        }
        Err(_) => Ok(default),
    }
}

fn usize_from_env(key: &str, default: usize) -> Result<usize, BrokerClientError> {
    match env::var(key) {
        Ok(value) => parse_env_usize(key, &value),
        Err(_) => Ok(default),
    }
}

fn parse_env_usize(key: &str, value: &str) -> Result<usize, BrokerClientError> {
    value.parse::<usize>().map_err(|error| {
        BrokerClientError::InvalidConfig(format_env_parse_error(key, value, error))
    })
}

fn format_env_parse_error(key: &str, value: &str, error: ParseIntError) -> String {
    format!("{key} must be an unsigned integer, got '{value}': {error}")
}

fn ensure_request_size(size: usize, max: usize) -> Result<(), BrokerClientError> {
    if size > max {
        return Err(BrokerClientError::RequestTooLarge { size, max });
    }
    Ok(())
}

async fn write_frame(
    stream: &mut TcpStream,
    payload: &[u8],
    max_frame_size: usize,
) -> Result<(), BrokerClientError> {
    ensure_request_size(payload.len(), max_frame_size)?;
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(payload).await?;
    Ok(())
}

async fn read_frame(
    stream: &mut TcpStream,
    max_frame_size: usize,
) -> Result<Vec<u8>, BrokerClientError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let reply_len = u32::from_be_bytes(len_buf) as usize;
    if reply_len == 0 {
        return Err(BrokerClientError::MalformedResponse(
            "response frame length must be greater than zero".to_string(),
        ));
    }
    if reply_len > max_frame_size {
        return Err(BrokerClientError::ResponseTooLarge {
            size: reply_len,
            max: max_frame_size,
        });
    }

    let mut reply_buf = vec![0u8; reply_len];
    stream.read_exact(&mut reply_buf).await?;
    Ok(reply_buf)
}
