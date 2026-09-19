use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BrokerTask {
    pub task_id: String,
    pub source: String,
    pub destination: String,
    pub kind: String,
    pub priority: u8,
    pub timeout_ms: u32,
    pub payload: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BrokerResult {
    pub task_id: String,
    pub status: String,
    pub gpu_id: Option<i32>,
    pub execution_ms: Option<u64>,
    pub result: Option<serde_json::Value>,
}

pub struct BrokerClient {
    addr: String,
}

impl BrokerClient {
    pub fn new(addr: impl Into<String>) -> Self {
        Self { addr: addr.into() }
    }

    pub async fn submit(&self, task: &BrokerTask) -> io::Result<BrokerResult> {
        let mut stream = TcpStream::connect(&self.addr).await?;

        let bytes = serde_json::to_vec(task)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let len = (bytes.len() as u32).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(&bytes).await?;
        stream.flush().await?;

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let reply_len = u32::from_be_bytes(len_buf) as usize;

        let mut reply_buf = vec![0u8; reply_len];
        stream.read_exact(&mut reply_buf).await?;

        let result: BrokerResult = serde_json::from_slice(&reply_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        Ok(result)
    }
}
