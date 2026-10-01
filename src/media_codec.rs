//! Bounded, codec-agnostic live media chunks and in-memory stream storage.
//!
//! Payload bytes are passed through unchanged. This module does not encode or
//! decode H.264, Opus, or any other media codec.

use std::{
    collections::{BTreeMap, HashMap},
    sync::Mutex,
};

use thiserror::Error;

use crate::broker_client::{BrokerClientError, BrokerTask};

/// ASCII `YKMC`, the magic value for an encoded media chunk.
pub const MEDIA_CHUNK_MAGIC: u32 = 0x594B_4D43;
/// Current media chunk wire version.
pub const MEDIA_CHUNK_VERSION: u8 = 1;
/// Fixed header length in the big-endian `YKMC` chunk format.
pub const MEDIA_CHUNK_HEADER_LEN: usize = 31;
/// Hard upper bound on one opaque audio/video payload.
pub const MEDIA_MAX_CHUNK_BYTES: usize = 256 * 1024;
/// Maximum stream identifier length in UTF-8 bytes.
pub const MEDIA_MAX_STREAM_ID_BYTES: usize = 128;
/// Maximum codec label length in UTF-8 bytes.
pub const MEDIA_MAX_CODEC_BYTES: usize = 64;
/// Broker task kind for one encoded media chunk.
pub const MEDIA_CHUNK_KIND: &str = "media.chunk.v1";
/// Broker JSON payload key for the YKMC byte array.
pub const MEDIA_CHUNK_BROKER_KEY: &str = "media_chunk";

/// Supported media type tags in the YKMC wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    Audio,
    Video,
}

impl MediaType {
    fn wire_value(self) -> u8 {
        match self {
            Self::Audio => 0,
            Self::Video => 1,
        }
    }

    fn from_wire(value: u8) -> Result<Self, MediaError> {
        match value {
            0 => Ok(Self::Audio),
            1 => Ok(Self::Video),
            value => Err(MediaError::InvalidMediaType(value)),
        }
    }
}

/// Immutable metadata shared by every chunk in a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaStreamMetadata {
    pub stream_id: String,
    pub media_type: MediaType,
    /// Codec name/label (for example `h264`, `opus`, or `unknown`).
    pub codec: String,
}

impl MediaStreamMetadata {
    pub fn validate(&self) -> Result<(), MediaError> {
        validate_string("stream_id", &self.stream_id, MEDIA_MAX_STREAM_ID_BYTES)?;
        validate_string("codec", &self.codec, MEDIA_MAX_CODEC_BYTES)
    }
}

/// One encoded or decoded pass-through media chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaChunk {
    pub stream_id: String,
    pub media_type: MediaType,
    pub codec: String,
    pub sequence_no: u64,
    /// Timestamp in milliseconds on the producer's media timeline.
    pub timestamp_ms: u64,
    pub is_keyframe: bool,
    /// Opaque bytes from the selected codec.
    pub payload: Vec<u8>,
}

/// Limits for an in-memory live media stream collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaStreamConfig {
    pub max_streams: usize,
    pub max_chunks_per_stream: usize,
    pub max_total_chunks: usize,
    pub max_chunk_bytes: usize,
}

impl Default for MediaStreamConfig {
    fn default() -> Self {
        Self {
            max_streams: 64,
            max_chunks_per_stream: 64,
            max_total_chunks: 256,
            max_chunk_bytes: MEDIA_MAX_CHUNK_BYTES,
        }
    }
}

impl MediaStreamConfig {
    pub fn validate(&self) -> Result<(), MediaError> {
        if self.max_streams == 0
            || self.max_chunks_per_stream == 0
            || self.max_total_chunks == 0
            || self.max_chunk_bytes == 0
            || self.max_chunk_bytes > MEDIA_MAX_CHUNK_BYTES
        {
            return Err(MediaError::InvalidConfig);
        }
        Ok(())
    }
}

/// Typed validation, codec, and stream lifecycle errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MediaError {
    #[error("media chunk is truncated: expected at least {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },
    #[error("media chunk has {actual} trailing byte(s) beyond expected {expected}")]
    TrailingBytes { expected: usize, actual: usize },
    #[error("invalid media chunk magic: expected {expected:#010x}, got {found:#010x}")]
    InvalidMagic { expected: u32, found: u32 },
    #[error("unsupported media chunk version: expected {expected}, got {found}")]
    UnsupportedVersion { expected: u8, found: u8 },
    #[error("unsupported media type tag {0}")]
    InvalidMediaType(u8),
    #[error("media chunk uses unsupported flag bits {0:#04x}")]
    InvalidFlags(u8),
    #[error("media chunk {field} is not valid UTF-8")]
    InvalidUtf8 { field: &'static str },
    #[error("media {field} must contain between 1 and {max} UTF-8 bytes")]
    InvalidMetadata { field: &'static str, max: usize },
    #[error("media payload is {size} bytes, exceeding max {max} bytes")]
    ChunkTooLarge { size: usize, max: usize },
    #[error("invalid media stream configuration")]
    InvalidConfig,
    #[error("media stream '{0}' already exists")]
    DuplicateStream(String),
    #[error("media stream '{0}' was not found")]
    StreamNotFound(String),
    #[error("media stream '{0}' is already closed")]
    StreamClosed(String),
    #[error("media stream limit ({max}) has been reached")]
    StreamLimit { max: usize },
    #[error("media chunk capacity reached; acknowledge or remove retained chunks")]
    Backpressure,
    #[error("media chunk sequence {found} duplicates an already accepted sequence")]
    DuplicateChunk { found: u64 },
    #[error("media chunk is out of order: expected sequence {expected}, got {found}")]
    OutOfOrderChunk { expected: u64, found: u64 },
    #[error("media chunk sequence {sequence} has not been ingested")]
    MissingChunk { sequence: u64 },
    #[error("media chunk sequence {sequence} has been acknowledged and is no longer retained")]
    ChunkNotRetained { sequence: u64 },
    #[error("media chunk range is invalid or exceeds the configured range limit")]
    InvalidRange,
    #[error("media chunk stream id, media type, or codec does not match stream metadata")]
    StreamMetadataMismatch,
    #[error("media sequence number space is exhausted")]
    SequenceExhausted,
    #[error("media stream state lock was poisoned")]
    LockPoisoned,
    #[error("broker task kind '{found}' does not match expected '{expected}'")]
    UnexpectedBrokerKind { expected: String, found: String },
    #[error("broker task payload is missing the '{0}' field")]
    MissingBrokerPayload(&'static str),
    #[error("broker media payload is malformed: {0}")]
    MalformedBrokerPayload(String),
}

impl From<MediaError> for BrokerClientError {
    fn from(error: MediaError) -> Self {
        BrokerClientError::InvalidRequest(error.to_string())
    }
}

impl MediaChunk {
    /// Encode this chunk using the documented big-endian YKMC v1 format.
    pub fn encode(&self) -> Result<Vec<u8>, MediaError> {
        self.validate_with_limit(MEDIA_MAX_CHUNK_BYTES)?;
        let stream_id = self.stream_id.as_bytes();
        let codec = self.codec.as_bytes();
        let stream_id_len =
            u16::try_from(stream_id.len()).map_err(|_| MediaError::InvalidMetadata {
                field: "stream_id",
                max: MEDIA_MAX_STREAM_ID_BYTES,
            })?;
        let codec_len = u16::try_from(codec.len()).map_err(|_| MediaError::InvalidMetadata {
            field: "codec",
            max: MEDIA_MAX_CODEC_BYTES,
        })?;
        let payload_len =
            u32::try_from(self.payload.len()).map_err(|_| MediaError::ChunkTooLarge {
                size: self.payload.len(),
                max: MEDIA_MAX_CHUNK_BYTES,
            })?;

        let mut bytes = Vec::with_capacity(
            MEDIA_CHUNK_HEADER_LEN + stream_id.len() + codec.len() + self.payload.len(),
        );
        bytes.extend_from_slice(&MEDIA_CHUNK_MAGIC.to_be_bytes());
        bytes.push(MEDIA_CHUNK_VERSION);
        bytes.push(self.media_type.wire_value());
        bytes.push(u8::from(self.is_keyframe));
        bytes.extend_from_slice(&stream_id_len.to_be_bytes());
        bytes.extend_from_slice(&codec_len.to_be_bytes());
        bytes.extend_from_slice(&self.sequence_no.to_be_bytes());
        bytes.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        bytes.extend_from_slice(&payload_len.to_be_bytes());
        bytes.extend_from_slice(stream_id);
        bytes.extend_from_slice(codec);
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    /// Decode one exact YKMC v1 chunk, rejecting truncation and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, MediaError> {
        Self::decode_with_limit(bytes, MEDIA_MAX_CHUNK_BYTES)
    }

    /// Wrap an encoded chunk in the existing broker's JSON task envelope.
    ///
    /// The broker's configured frame ceiling still applies; JSON byte arrays
    /// are larger than the binary chunk, so callers may need smaller chunks
    /// or an appropriately configured broker frame limit.
    pub fn to_broker_task(
        &self,
        task_id: impl Into<String>,
        source: impl Into<String>,
        destination: impl Into<String>,
        priority: u8,
        timeout_ms: u32,
    ) -> Result<BrokerTask, MediaError> {
        let encoded = self.encode()?;
        Ok(BrokerTask {
            task_id: task_id.into(),
            source: source.into(),
            destination: destination.into(),
            kind: MEDIA_CHUNK_KIND.to_string(),
            priority,
            timeout_ms,
            payload: serde_json::json!({ MEDIA_CHUNK_BROKER_KEY: encoded }),
        })
    }

    /// Decode a chunk carried by a compatible broker task.
    pub fn from_broker_task(task: &BrokerTask) -> Result<Self, MediaError> {
        if task.kind != MEDIA_CHUNK_KIND {
            return Err(MediaError::UnexpectedBrokerKind {
                expected: MEDIA_CHUNK_KIND.to_string(),
                found: task.kind.clone(),
            });
        }
        let raw = task
            .payload
            .get(MEDIA_CHUNK_BROKER_KEY)
            .ok_or(MediaError::MissingBrokerPayload(MEDIA_CHUNK_BROKER_KEY))?;
        let bytes: Vec<u8> = serde_json::from_value(raw.clone())
            .map_err(|error| MediaError::MalformedBrokerPayload(error.to_string()))?;
        Self::decode(&bytes)
    }

    fn decode_with_limit(bytes: &[u8], max_chunk_bytes: usize) -> Result<Self, MediaError> {
        if bytes.len() < MEDIA_CHUNK_HEADER_LEN {
            return Err(MediaError::Truncated {
                expected: MEDIA_CHUNK_HEADER_LEN,
                actual: bytes.len(),
            });
        }
        let magic = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        if magic != MEDIA_CHUNK_MAGIC {
            return Err(MediaError::InvalidMagic {
                expected: MEDIA_CHUNK_MAGIC,
                found: magic,
            });
        }
        let version = bytes[4];
        if version != MEDIA_CHUNK_VERSION {
            return Err(MediaError::UnsupportedVersion {
                expected: MEDIA_CHUNK_VERSION,
                found: version,
            });
        }
        let media_type = MediaType::from_wire(bytes[5])?;
        let flags = bytes[6];
        if flags & !1 != 0 {
            return Err(MediaError::InvalidFlags(flags));
        }
        let stream_id_len = u16::from_be_bytes(bytes[7..9].try_into().unwrap()) as usize;
        let codec_len = u16::from_be_bytes(bytes[9..11].try_into().unwrap()) as usize;
        let sequence_no = u64::from_be_bytes(bytes[11..19].try_into().unwrap());
        let timestamp_ms = u64::from_be_bytes(bytes[19..27].try_into().unwrap());
        let payload_len = u32::from_be_bytes(bytes[27..31].try_into().unwrap()) as usize;
        if payload_len > max_chunk_bytes {
            return Err(MediaError::ChunkTooLarge {
                size: payload_len,
                max: max_chunk_bytes,
            });
        }
        if stream_id_len > MEDIA_MAX_STREAM_ID_BYTES {
            return Err(MediaError::InvalidMetadata {
                field: "stream_id",
                max: MEDIA_MAX_STREAM_ID_BYTES,
            });
        }
        if codec_len > MEDIA_MAX_CODEC_BYTES {
            return Err(MediaError::InvalidMetadata {
                field: "codec",
                max: MEDIA_MAX_CODEC_BYTES,
            });
        }
        let expected = MEDIA_CHUNK_HEADER_LEN
            .checked_add(stream_id_len)
            .and_then(|n| n.checked_add(codec_len))
            .and_then(|n| n.checked_add(payload_len))
            .ok_or(MediaError::InvalidRange)?;
        if bytes.len() < expected {
            return Err(MediaError::Truncated {
                expected,
                actual: bytes.len(),
            });
        }
        if bytes.len() > expected {
            return Err(MediaError::TrailingBytes {
                expected,
                actual: bytes.len(),
            });
        }
        let stream_id_start = MEDIA_CHUNK_HEADER_LEN;
        let codec_start = stream_id_start + stream_id_len;
        let payload_start = codec_start + codec_len;
        let stream_id = std::str::from_utf8(&bytes[stream_id_start..codec_start])
            .map_err(|_| MediaError::InvalidUtf8 { field: "stream_id" })?
            .to_string();
        let codec = std::str::from_utf8(&bytes[codec_start..payload_start])
            .map_err(|_| MediaError::InvalidUtf8 { field: "codec" })?
            .to_string();
        let chunk = Self {
            stream_id,
            media_type,
            codec,
            sequence_no,
            timestamp_ms,
            is_keyframe: flags & 1 != 0,
            payload: bytes[payload_start..].to_vec(),
        };
        chunk.validate_with_limit(max_chunk_bytes)?;
        Ok(chunk)
    }

    fn validate_with_limit(&self, max_chunk_bytes: usize) -> Result<(), MediaError> {
        validate_string("stream_id", &self.stream_id, MEDIA_MAX_STREAM_ID_BYTES)?;
        validate_string("codec", &self.codec, MEDIA_MAX_CODEC_BYTES)?;
        if self.payload.len() > max_chunk_bytes {
            return Err(MediaError::ChunkTooLarge {
                size: self.payload.len(),
                max: max_chunk_bytes,
            });
        }
        Ok(())
    }
}

/// Thread-safe bounded collection of live media streams.
///
/// Appends are strictly sequence ordered starting at zero. Retained chunks
/// are never silently evicted: callers acknowledge old chunks or remove a
/// finished stream to release capacity.
pub struct LiveMediaStreams {
    config: MediaStreamConfig,
    state: Mutex<CollectionState>,
}

struct CollectionState {
    streams: HashMap<String, StreamState>,
    retained_chunks: usize,
}

struct StreamState {
    metadata: MediaStreamMetadata,
    chunks: BTreeMap<u64, MediaChunk>,
    next_sequence: u64,
    acknowledged_through: Option<u64>,
    closed: bool,
}

impl LiveMediaStreams {
    pub fn new(config: MediaStreamConfig) -> Result<Self, MediaError> {
        config.validate()?;
        Ok(Self {
            config,
            state: Mutex::new(CollectionState {
                streams: HashMap::new(),
                retained_chunks: 0,
            }),
        })
    }

    /// Open a stream with an explicit caller-provided identifier and metadata.
    pub fn open_stream(&self, metadata: MediaStreamMetadata) -> Result<(), MediaError> {
        metadata.validate()?;
        let mut state = self.state.lock().map_err(|_| MediaError::LockPoisoned)?;
        if state.streams.contains_key(&metadata.stream_id) {
            return Err(MediaError::DuplicateStream(metadata.stream_id));
        }
        if state.streams.len() >= self.config.max_streams {
            return Err(MediaError::StreamLimit {
                max: self.config.max_streams,
            });
        }
        state.streams.insert(
            metadata.stream_id.clone(),
            StreamState {
                metadata,
                chunks: BTreeMap::new(),
                next_sequence: 0,
                acknowledged_through: None,
                closed: false,
            },
        );
        Ok(())
    }

    /// Decode and append a wire-encoded chunk to its named stream.
    pub fn ingest_chunk(&self, bytes: &[u8]) -> Result<u64, MediaError> {
        let chunk = MediaChunk::decode_with_limit(bytes, self.config.max_chunk_bytes)?;
        let stream_id = chunk.stream_id.clone();
        self.append_chunk(&stream_id, chunk)
    }

    /// Append one already-decoded chunk, requiring contiguous sequence order.
    pub fn append_chunk(&self, stream_id: &str, chunk: MediaChunk) -> Result<u64, MediaError> {
        chunk.validate_with_limit(self.config.max_chunk_bytes)?;
        if chunk.stream_id != stream_id {
            return Err(MediaError::StreamMetadataMismatch);
        }
        let mut state = self.state.lock().map_err(|_| MediaError::LockPoisoned)?;
        let global_capacity_reached = state.retained_chunks >= self.config.max_total_chunks;
        let sequence_no = {
            let stream = state
                .streams
                .get_mut(stream_id)
                .ok_or_else(|| MediaError::StreamNotFound(stream_id.to_string()))?;
            if stream.closed {
                return Err(MediaError::StreamClosed(stream_id.to_string()));
            }
            if chunk.media_type != stream.metadata.media_type
                || chunk.codec != stream.metadata.codec
            {
                return Err(MediaError::StreamMetadataMismatch);
            }
            if chunk.sequence_no < stream.next_sequence {
                return Err(MediaError::DuplicateChunk {
                    found: chunk.sequence_no,
                });
            }
            if chunk.sequence_no > stream.next_sequence {
                return Err(MediaError::OutOfOrderChunk {
                    expected: stream.next_sequence,
                    found: chunk.sequence_no,
                });
            }
            if stream.next_sequence == u64::MAX {
                return Err(MediaError::SequenceExhausted);
            }
            if stream.chunks.len() >= self.config.max_chunks_per_stream || global_capacity_reached {
                return Err(MediaError::Backpressure);
            }
            let sequence_no = chunk.sequence_no;
            stream.chunks.insert(sequence_no, chunk);
            stream.next_sequence += 1;
            sequence_no
        };
        state.retained_chunks += 1;
        Ok(sequence_no)
    }

    /// Return one retained chunk by sequence number.
    pub fn get_chunk(&self, stream_id: &str, sequence: u64) -> Result<MediaChunk, MediaError> {
        let state = self.state.lock().map_err(|_| MediaError::LockPoisoned)?;
        let stream = state
            .streams
            .get(stream_id)
            .ok_or_else(|| MediaError::StreamNotFound(stream_id.to_string()))?;
        match stream.chunks.get(&sequence) {
            Some(chunk) => Ok(chunk.clone()),
            None if sequence >= stream.next_sequence => Err(MediaError::MissingChunk { sequence }),
            None if stream
                .acknowledged_through
                .is_some_and(|acked| sequence <= acked) =>
            {
                Err(MediaError::ChunkNotRetained { sequence })
            }
            None => Err(MediaError::MissingChunk { sequence }),
        }
    }

    /// Return all retained chunks in the inclusive sequence interval.
    pub fn get_range(
        &self,
        stream_id: &str,
        start_sequence: u64,
        end_sequence: u64,
    ) -> Result<Vec<MediaChunk>, MediaError> {
        let count = end_sequence
            .checked_sub(start_sequence)
            .and_then(|n| n.checked_add(1))
            .ok_or(MediaError::InvalidRange)?;
        if count > self.config.max_chunks_per_stream as u64 {
            return Err(MediaError::InvalidRange);
        }
        (start_sequence..=end_sequence)
            .map(|sequence| self.get_chunk(stream_id, sequence))
            .collect()
    }

    /// Release all retained chunks through an ingested sequence (inclusive).
    pub fn acknowledge_through(&self, stream_id: &str, sequence: u64) -> Result<usize, MediaError> {
        let mut state = self.state.lock().map_err(|_| MediaError::LockPoisoned)?;
        let stream = state
            .streams
            .get_mut(stream_id)
            .ok_or_else(|| MediaError::StreamNotFound(stream_id.to_string()))?;
        if sequence >= stream.next_sequence {
            return Err(MediaError::MissingChunk { sequence });
        }
        let removed = stream.chunks.range(..=sequence).count();
        stream
            .chunks
            .retain(|chunk_sequence, _| *chunk_sequence > sequence);
        stream.acknowledged_through = Some(
            stream
                .acknowledged_through
                .map_or(sequence, |previous| previous.max(sequence)),
        );
        state.retained_chunks -= removed;
        Ok(removed)
    }

    /// Finish a stream. Retained data stays readable until acknowledged or removed.
    pub fn close_stream(&self, stream_id: &str) -> Result<(), MediaError> {
        let mut state = self.state.lock().map_err(|_| MediaError::LockPoisoned)?;
        let stream = state
            .streams
            .get_mut(stream_id)
            .ok_or_else(|| MediaError::StreamNotFound(stream_id.to_string()))?;
        if stream.closed {
            return Err(MediaError::StreamClosed(stream_id.to_string()));
        }
        stream.closed = true;
        Ok(())
    }

    /// Remove a stream and free all of its retained chunk capacity.
    pub fn remove_stream(&self, stream_id: &str) -> Result<usize, MediaError> {
        let mut state = self.state.lock().map_err(|_| MediaError::LockPoisoned)?;
        let stream = state
            .streams
            .remove(stream_id)
            .ok_or_else(|| MediaError::StreamNotFound(stream_id.to_string()))?;
        let removed = stream.chunks.len();
        state.retained_chunks -= removed;
        Ok(removed)
    }

    /// Read the immutable metadata for an open or finished stream.
    pub fn stream_metadata(&self, stream_id: &str) -> Result<MediaStreamMetadata, MediaError> {
        let state = self.state.lock().map_err(|_| MediaError::LockPoisoned)?;
        state
            .streams
            .get(stream_id)
            .map(|stream| stream.metadata.clone())
            .ok_or_else(|| MediaError::StreamNotFound(stream_id.to_string()))
    }
}

fn validate_string(field: &'static str, value: &str, max: usize) -> Result<(), MediaError> {
    if value.trim().is_empty() || value.len() > max {
        return Err(MediaError::InvalidMetadata { field, max });
    }
    Ok(())
}
