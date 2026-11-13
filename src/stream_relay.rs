//! Relay for remotely discovered streams.
//!
//! A relay mirrors a remote stream into the local [`LiveMediaStreams`] store
//! through a pluggable [`ChunkSource`]. All local subscribers share one
//! upstream pull per stream (single-flight, rate limited), and because the
//! mirror is an ordinary local stream, downstream nodes can relay from this
//! node in turn, forming a fan-out tree.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::{
    media_codec::{LiveMediaStreams, MediaChunk, MediaError, MediaStreamMetadata},
    stream_registry::{RegistryError, StreamRegistry, Subscription},
};
use thiserror::Error;

/// Maximum chunks requested from upstream per call.
pub const RELAY_MAX_BATCH: u64 = 8;
/// Minimum delay between upstream pulls for one stream.
pub const RELAY_MIN_PULL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Error)]
pub enum RelayError {
    #[error(transparent)]
    Registry(#[from] RegistryError),
    #[error(transparent)]
    Media(#[from] MediaError),
    #[error("upstream source failed: {0}")]
    Upstream(String),
    #[error("relay state is poisoned")]
    Poisoned,
}

/// Upstream chunk provider, for example an HTTP client for the origin
/// gateway's `/v1/streams/{id}/chunks` endpoint. Implementations must be
/// bounded and authenticated by the caller.
pub trait ChunkSource: Send + Sync {
    fn metadata(&self, stream_id: &str) -> Result<MediaStreamMetadata, RelayError>;
    /// Return up to `limit` contiguous chunks starting at `from`; empty means
    /// nothing new yet.
    fn fetch_range(
        &self,
        stream_id: &str,
        from: u64,
        limit: u64,
    ) -> Result<Vec<MediaChunk>, RelayError>;
    /// Whether the origin has finished the stream.
    fn is_finished(&self, stream_id: &str) -> Result<bool, RelayError>;
}

struct StreamPull {
    last_pull: Mutex<Option<Instant>>,
}

pub struct StreamRelay {
    streams: Arc<LiveMediaStreams>,
    registry: StreamRegistry,
    source: Arc<dyn ChunkSource>,
    pulls: Mutex<HashMap<String, Arc<StreamPull>>>,
}

fn next_sequence(latest: Option<u64>) -> Result<u64, RelayError> {
    match latest {
        None => Ok(0),
        Some(sequence) => sequence.checked_add(1).ok_or_else(|| {
            RelayError::Upstream("stream sequence exhausted".into())
        }),
    }
}

fn validate_sequence_batch(from: u64, chunks: &[MediaChunk]) -> Result<(), RelayError> {
    if chunks.len() > RELAY_MAX_BATCH as usize {
        return Err(RelayError::Upstream(
            "upstream batch exceeds requested limit".into(),
        ));
    }
    for (index, chunk) in chunks.iter().enumerate() {
        let offset = u64::try_from(index)
            .map_err(|_| RelayError::Upstream("upstream batch index overflow".into()))?;
        let expected = from.checked_add(offset).ok_or_else(|| {
            RelayError::Upstream("stream sequence exhausted".into())
        })?;
        if chunk.sequence_no != expected {
            return Err(RelayError::Upstream(
                "non-contiguous chunk".into(),
            ));
        }
    }
    Ok(())
}

impl StreamRelay {
    pub fn new(
        streams: Arc<LiveMediaStreams>,
        registry: StreamRegistry,
        source: Arc<dyn ChunkSource>,
    ) -> Self {
        Self {
            streams,
            registry,
            source,
            pulls: Mutex::new(HashMap::new()),
        }
    }

    /// Tune in to a local or remote stream. Remote streams are mirrored first.
    pub fn tune_in(&self, stream_id: &str, from_seq: u64) -> Result<Subscription, RelayError> {
        self.registry.describe(stream_id)?;
        if self.streams.stream_metadata(stream_id).is_err() {
            let metadata = self.source.metadata(stream_id)?;
            if metadata.stream_id != stream_id {
                return Err(MediaError::StreamMetadataMismatch.into());
            }
            match self.streams.open_stream(metadata) {
                Ok(()) | Err(MediaError::DuplicateStream(_)) => {}
                Err(error) => return Err(error.into()),
            }
            self.pull_state(stream_id)?;
        }
        if self.is_mirror(stream_id) {
            self.pump(stream_id)?;
        }
        Ok(self.registry.tune_in(stream_id, from_seq)?)
    }

    /// Pull new chunks from upstream into the mirror; returns chunks appended.
    /// Concurrent callers for one stream are serialized and share the result.
    pub fn pump(&self, stream_id: &str) -> Result<usize, RelayError> {
        let pull = self
            .pulls
            .lock()
            .map_err(|_| RelayError::Poisoned)?
            .get(stream_id)
            .cloned()
            .ok_or_else(|| MediaError::StreamNotFound(stream_id.to_string()))?;
        let mut last = pull.last_pull.lock().map_err(|_| RelayError::Poisoned)?;
        if last.is_some_and(|at| at.elapsed() < RELAY_MIN_PULL_INTERVAL) {
            return Ok(0);
        }
        let snapshot = self
            .streams
            .stream_snapshots()?
            .into_iter()
            .find(|item| item.metadata.stream_id == stream_id);
        let Some(snapshot) = snapshot else {
            return Err(MediaError::StreamNotFound(stream_id.to_string()).into());
        };
        if snapshot.finished {
            return Ok(0);
        }
        let next = next_sequence(snapshot.latest_sequence)?;
        let chunks = self.source.fetch_range(stream_id, next, RELAY_MAX_BATCH);
        *last = Some(Instant::now());
        let chunks = chunks?;
        // Validate the complete untrusted batch before mutating the mirror.
        validate_sequence_batch(next, &chunks)?;
        let appended = chunks.len();
        for chunk in chunks {
            self.streams.append_chunk(stream_id, chunk)?;
        }
        if appended == 0 && self.source.is_finished(stream_id)? {
            self.streams.close_stream(stream_id)?;
        }
        Ok(appended)
    }

    fn pull_state(&self, stream_id: &str) -> Result<(), RelayError> {
        self.pulls
            .lock()
            .map_err(|_| RelayError::Poisoned)?
            .entry(stream_id.to_string())
            .or_insert_with(|| {
                Arc::new(StreamPull {
                    last_pull: Mutex::new(None),
                })
            });
        Ok(())
    }

    /// True when the stream is a relayed mirror rather than locally produced.
    pub fn is_mirror(&self, stream_id: &str) -> bool {
        self.pulls
            .lock()
            .map(|pulls| pulls.contains_key(stream_id))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod adversarial_tests {
    use super::*;

    fn chunk(sequence_no: u64) -> MediaChunk {
        MediaChunk {
            stream_id: "relay-test".into(),
            media_type: crate::media_codec::MediaType::Video,
            codec: "raw".into(),
            sequence_no,
            timestamp_ms: sequence_no,
            is_keyframe: false,
            payload: vec![0],
        }
    }

    #[test]
    fn sequence_arithmetic_rejects_u64_exhaustion() {
        assert_eq!(next_sequence(None).unwrap(), 0);
        assert_eq!(next_sequence(Some(41)).unwrap(), 42);
        assert!(matches!(
            next_sequence(Some(u64::MAX)),
            Err(RelayError::Upstream(_))
        ));
    }

    #[test]
    fn relay_batch_validation_rejects_gaps_and_oversized_batches() {
        assert!(validate_sequence_batch(10, &[chunk(10), chunk(11)]).is_ok());
        assert!(matches!(
            validate_sequence_batch(10, &[chunk(10), chunk(12)]),
            Err(RelayError::Upstream(_))
        ));
        let too_many: Vec<_> = (0..=RELAY_MAX_BATCH).map(chunk).collect();
        assert!(matches!(
            validate_sequence_batch(0, &too_many),
            Err(RelayError::Upstream(_))
        ));
    }

    #[test]
    fn relay_batch_validation_allows_last_sequence_without_wrapping() {
        assert!(validate_sequence_batch(u64::MAX, &[chunk(u64::MAX)]).is_ok());
        assert!(matches!(
            validate_sequence_batch(u64::MAX, &[chunk(u64::MAX), chunk(0)]),
            Err(RelayError::Upstream(_))
        ));
    }
}
