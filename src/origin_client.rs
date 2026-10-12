//! Blocking HTTP/1.1 client for the origin gateway's stream endpoints.
//!
//! [`OriginChunkClient`] implements [`ChunkSource`] so a [`StreamRelay`]
//! can mirror remote streams from `/v1/streams/{id}` and
//! `/v1/streams/{id}/chunks`. It speaks plain HTTP with an optional bearer
//! token, and bounds connect/IO time, header size, and body size. TLS is not
//! provided; run it over a trusted link or behind a TLS-terminating proxy.
//!
//! [`StreamRelay`]: crate::stream_relay::StreamRelay

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

use crate::{
    media_codec::{MediaChunk, MediaStreamMetadata, MediaType, MEDIA_MAX_STREAM_ID_BYTES},
    stream_registry::{StreamDescriptor, StreamKind, StreamStatus},
    stream_relay::{ChunkSource, RelayError, RELAY_MAX_BATCH},
};

/// Maximum response header bytes accepted.
pub const ORIGIN_MAX_HEADER_BYTES: usize = 16 * 1024;
/// Maximum response body bytes accepted (JSON-encoded chunk batches).
pub const ORIGIN_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
/// Default connect/read/write timeout.
pub const ORIGIN_DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

pub struct OriginChunkClient {
    address: SocketAddr,
    host: String,
    token: Option<String>,
    timeout: Duration,
}

impl OriginChunkClient {
    pub fn new(address: SocketAddr, token: Option<String>) -> Self {
        Self {
            address,
            host: address.to_string(),
            token,
            timeout: ORIGIN_DEFAULT_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn get(&self, path: &str) -> Result<Vec<u8>, RelayError> {
        let up = |e: std::io::Error| RelayError::Upstream(e.to_string());
        let mut socket = TcpStream::connect_timeout(&self.address, self.timeout).map_err(up)?;
        socket.set_read_timeout(Some(self.timeout)).map_err(up)?;
        socket.set_write_timeout(Some(self.timeout)).map_err(up)?;
        let auth = match &self.token {
            Some(token) if token.contains(['\r', '\n']) => {
                return Err(RelayError::Upstream("invalid bearer token".into()))
            }
            Some(token) => ["Authorization: Bearer ", token.as_str(), "\r\n"].concat(),
            None => String::new(),
        };
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\n{auth}Connection: close\r\n\r\n",
            self.host
        );
        socket.write_all(request.as_bytes()).map_err(up)?;

        // Read headers, then the body up to the configured bound.
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        let header_end = loop {
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos;
            }
            if buf.len() > ORIGIN_MAX_HEADER_BYTES {
                return Err(RelayError::Upstream("response headers too large".into()));
            }
            let n = socket.read(&mut tmp).map_err(up)?;
            if n == 0 {
                return Err(RelayError::Upstream("connection closed early".into()));
            }
            buf.extend_from_slice(&tmp[..n]);
        };
        let head = std::str::from_utf8(&buf[..header_end])
            .map_err(|_| RelayError::Upstream("invalid response headers".into()))?
            .to_owned();
        let mut lines = head.split("\r\n");
        let status: u16 = lines
            .next()
            .and_then(|l| l.split(' ').nth(1))
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| RelayError::Upstream("malformed status line".into()))?;
        let mut content_length: Option<usize> = None;
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let (name, value) = (name.trim(), value.trim());
            if name.eq_ignore_ascii_case("transfer-encoding")
                && !value.eq_ignore_ascii_case("identity")
            {
                return Err(RelayError::Upstream("unsupported transfer encoding".into()));
            }
            if name.eq_ignore_ascii_case("content-length") {
                content_length = Some(
                    value
                        .parse()
                        .map_err(|_| RelayError::Upstream("bad content-length".into()))?,
                );
            }
        }
        if status != 200 {
            return Err(RelayError::Upstream(format!(
                "origin {} returned HTTP {status} (401/403: check the bearer token; 404: stream unknown to origin)",
                self.host
            )));
        }
        if content_length.is_some_and(|len| len > ORIGIN_MAX_BODY_BYTES) {
            return Err(RelayError::Upstream("response body too large".into()));
        }
        let mut body = buf.split_off(header_end + 4);
        loop {
            if content_length.is_some_and(|len| body.len() >= len) {
                break;
            }
            let n = socket.read(&mut tmp).map_err(up)?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
            if body.len() > ORIGIN_MAX_BODY_BYTES {
                return Err(RelayError::Upstream("response body too large".into()));
            }
        }
        if let Some(len) = content_length {
            if body.len() < len {
                return Err(RelayError::Upstream("truncated response body".into()));
            }
            body.truncate(len);
        }
        Ok(body)
    }

    fn describe(&self, stream_id: &str) -> Result<StreamDescriptor, RelayError> {
        let path = stream_path(stream_id)?;
        let body = self.get(&path)?;
        serde_json::from_slice(&body).map_err(|e| RelayError::Upstream(e.to_string()))
    }
}

/// Stream ids are restricted so they can be placed in a URL path unescaped.
fn stream_path(stream_id: &str) -> Result<String, RelayError> {
    let valid = !stream_id.is_empty()
        && stream_id.len() <= MEDIA_MAX_STREAM_ID_BYTES
        && stream_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && stream_id != "."
        && stream_id != "..";
    if valid {
        Ok(format!("/v1/streams/{stream_id}"))
    } else {
        Err(RelayError::Upstream("invalid stream id".into()))
    }
}

impl ChunkSource for OriginChunkClient {
    fn metadata(&self, stream_id: &str) -> Result<MediaStreamMetadata, RelayError> {
        let descriptor = self.describe(stream_id)?;
        let media_type = match descriptor.kind {
            StreamKind::Audio => MediaType::Audio,
            StreamKind::Video => MediaType::Video,
            _ => return Err(RelayError::Upstream("unsupported stream kind".into())),
        };
        Ok(MediaStreamMetadata {
            stream_id: stream_id.to_owned(),
            media_type,
            codec: "unknown".into(),
        })
    }

    fn fetch_range(
        &self,
        stream_id: &str,
        from: u64,
        limit: u64,
    ) -> Result<Vec<MediaChunk>, RelayError> {
        // The origin rejects ranges that include chunks it does not have yet,
        // so clamp the request to what the descriptor says is available.
        let Some(latest) = self.describe(stream_id)?.latest_seq else {
            return Ok(Vec::new());
        };
        if from > latest {
            return Ok(Vec::new());
        }
        let limit = limit.clamp(1, RELAY_MAX_BATCH).min(latest - from + 1);
        let path = format!(
            "{}/chunks?from={from}&limit={limit}",
            stream_path(stream_id)?
        );
        let body = self.get(&path)?;
        let chunks: Vec<MediaChunk> =
            serde_json::from_slice(&body).map_err(|e| RelayError::Upstream(e.to_string()))?;
        if chunks.len() as u64 > limit {
            return Err(RelayError::Upstream(
                "origin returned too many chunks".into(),
            ));
        }
        Ok(chunks)
    }

    fn is_finished(&self, stream_id: &str) -> Result<bool, RelayError> {
        Ok(self.describe(stream_id)?.status == StreamStatus::Finished)
    }
}
