//! Bounded stream discovery and per-subscriber cursors for live media.

use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex, Weak},
};

use crate::media_codec::{
    LiveMediaStreams, MediaChunk, MediaError, MediaStreamSnapshot, MediaType,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const STREAM_REGISTRY_MAX_STREAMS: usize = 256;
pub const STREAM_MAX_NAME_BYTES: usize = 256;
pub const STREAM_MAX_NODE_ID_BYTES: usize = 128;
pub const STREAM_MAX_SUBSCRIBERS: usize = 128;
pub const STREAM_MAX_SUBSCRIBERS_PER_NODE: usize = 1024;
pub const STREAM_ANNOUNCEMENT_MAX_BYTES: usize = 16 * 1024;
pub const STREAM_ANNOUNCEMENT_MAX_HOPS: u8 = 8;
pub const STREAM_ANNOUNCEMENT_TTL_SECS: u64 = 120;
const SEEN_ANNOUNCEMENTS_MAX: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StreamKind {
    Audio,
    Video,
    Binary,
    Geo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StreamStatus {
    Active,
    Finished,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamDescriptor {
    pub id: String,
    pub name: String,
    pub kind: StreamKind,
    pub status: StreamStatus,
    pub origin_node: String,
    pub latest_seq: Option<u64>,
    pub updated_at: u64,
}

impl StreamDescriptor {
    pub fn validate(&self) -> Result<(), RegistryError> {
        validate_text(
            "stream id",
            &self.id,
            crate::media_codec::MEDIA_MAX_STREAM_ID_BYTES,
        )?;
        validate_text("stream name", &self.name, STREAM_MAX_NAME_BYTES)?;
        validate_text("origin node", &self.origin_node, STREAM_MAX_NODE_ID_BYTES)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamAnnouncement {
    pub message_id: String,
    pub remaining_hops: u8,
    pub descriptor: StreamDescriptor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamDigestEntry {
    pub id: String,
    pub version_hash: String,
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error(transparent)]
    Media(#[from] MediaError),
    #[error("invalid {0}")]
    Invalid(&'static str),
    #[error("stream registry is full")]
    RegistryFull,
    #[error("stream '{0}' was not found")]
    StreamNotFound(String),
    #[error("stream subscriber limit reached")]
    SubscriberLimit,
    #[error("subscription was not found")]
    SubscriptionNotFound,
    #[error("announcement is invalid, expired, or too large")]
    InvalidAnnouncement,
    #[error("subscription has already advanced past sequence {0}")]
    InvalidAcknowledgement(u64),
    #[error("stream data is no longer retained; tune in again at a retained sequence")]
    Lagged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionRead {
    Chunk(MediaChunk),
    Waiting,
    Finished,
    Lagged,
}

#[derive(Default)]
struct RegistryState {
    names: HashMap<String, String>,
    remote: HashMap<String, StreamDescriptor>,
    subscribers: HashMap<u64, SubscriberState>,
    seen: HashSet<String>,
    seen_order: VecDeque<String>,
    next_subscription_id: u64,
}

struct SubscriberState {
    stream_id: String,
    acknowledged_through: Option<u64>,
}

struct RegistryShared {
    state: Mutex<RegistryState>,
    streams: Arc<LiveMediaStreams>,
    node_id: String,
}

/// Registry metadata is derived from the live store on each query, so stream
/// open, append, finish, and remove operations are reflected without a second
/// lifecycle API.
#[derive(Clone)]
pub struct StreamRegistry {
    shared: Arc<RegistryShared>,
}

impl StreamRegistry {
    pub fn new(
        node_id: impl Into<String>,
        streams: Arc<LiveMediaStreams>,
    ) -> Result<Self, RegistryError> {
        let node_id = node_id.into();
        validate_text("node id", &node_id, STREAM_MAX_NODE_ID_BYTES)?;
        Ok(Self {
            shared: Arc::new(RegistryShared {
                state: Mutex::new(RegistryState::default()),
                streams,
                node_id,
            }),
        })
    }

    pub fn list_streams(&self) -> Result<Vec<StreamDescriptor>, RegistryError> {
        self.expire_remote()?;
        let state = self
            .shared
            .state
            .lock()
            .map_err(|_| RegistryError::Invalid("registry state"))?;
        let mut by_id = state.remote.clone();
        for snapshot in self.shared.streams.stream_snapshots()? {
            let descriptor = local_descriptor(
                &self.shared.node_id,
                &snapshot,
                state.names.get(&snapshot.metadata.stream_id),
            );
            by_id.insert(descriptor.id.clone(), descriptor);
        }
        let mut result: Vec<_> = by_id.into_values().collect();
        result.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(result)
    }

    pub fn describe(&self, id: &str) -> Result<StreamDescriptor, RegistryError> {
        validate_text(
            "stream id",
            id,
            crate::media_codec::MEDIA_MAX_STREAM_ID_BYTES,
        )?;
        if let Some(snapshot) = self
            .shared
            .streams
            .stream_snapshots()?
            .into_iter()
            .find(|snapshot| snapshot.metadata.stream_id == id)
        {
            let state = self
                .shared
                .state
                .lock()
                .map_err(|_| RegistryError::Invalid("registry state"))?;
            return Ok(local_descriptor(
                &self.shared.node_id,
                &snapshot,
                state.names.get(id),
            ));
        }
        self.expire_remote()?;
        self.shared
            .state
            .lock()
            .map_err(|_| RegistryError::Invalid("registry state"))?
            .remote
            .get(id)
            .cloned()
            .ok_or_else(|| RegistryError::StreamNotFound(id.to_string()))
    }

    pub fn set_local_name(&self, id: &str, name: &str) -> Result<(), RegistryError> {
        validate_text("stream name", name, STREAM_MAX_NAME_BYTES)?;
        self.shared.streams.stream_metadata(id)?;
        self.shared
            .state
            .lock()
            .map_err(|_| RegistryError::Invalid("registry state"))?
            .names
            .insert(id.to_string(), name.to_string());
        Ok(())
    }

    pub fn tune_in(&self, stream_id: &str, from_seq: u64) -> Result<Subscription, RegistryError> {
        let descriptor = self.describe(stream_id)?;
        if descriptor.origin_node != self.shared.node_id {
            return Err(RegistryError::Invalid("remote stream subscription"));
        }
        let snapshot = self
            .shared
            .streams
            .stream_snapshots()?
            .into_iter()
            .find(|item| item.metadata.stream_id == stream_id)
            .ok_or_else(|| RegistryError::StreamNotFound(stream_id.to_string()))?;
        if from_seq
            > snapshot
                .latest_sequence
                .map_or(0, |seq| seq.saturating_add(1))
        {
            return Err(RegistryError::Media(MediaError::MissingChunk {
                sequence: from_seq,
            }));
        }

        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| RegistryError::Invalid("registry state"))?;
        let per_stream = state
            .subscribers
            .values()
            .filter(|sub| sub.stream_id == stream_id)
            .count();
        if per_stream >= STREAM_MAX_SUBSCRIBERS
            || state.subscribers.len() >= STREAM_MAX_SUBSCRIBERS_PER_NODE
            || state.next_subscription_id == u64::MAX
        {
            return Err(RegistryError::SubscriberLimit);
        }
        state.next_subscription_id += 1;
        let id = state.next_subscription_id;
        state.subscribers.insert(
            id,
            SubscriberState {
                stream_id: stream_id.to_string(),
                acknowledged_through: from_seq.checked_sub(1),
            },
        );
        Ok(Subscription {
            id,
            stream_id: stream_id.to_string(),
            next_sequence: from_seq,
            shared: Arc::downgrade(&self.shared),
        })
    }

    pub fn tune_out(&self, subscription: &Subscription) -> Result<(), RegistryError> {
        let removed = self
            .shared
            .state
            .lock()
            .map_err(|_| RegistryError::Invalid("registry state"))?
            .subscribers
            .remove(&subscription.id);
        if removed.is_none() {
            return Err(RegistryError::SubscriptionNotFound);
        }
        release_acknowledged(&self.shared, &subscription.stream_id);
        Ok(())
    }

    /// Accept an announcement once and return the decremented copy to forward.
    /// The caller must forward it only to a bounded peer subset.
    pub fn accept_announcement(
        &self,
        announcement: StreamAnnouncement,
        now: u64,
    ) -> Result<Option<StreamAnnouncement>, RegistryError> {
        if announcement.message_id.is_empty()
            || announcement.message_id.len() > 64
            || announcement.remaining_hops == 0
            || announcement.remaining_hops > STREAM_ANNOUNCEMENT_MAX_HOPS
            || announcement.descriptor.origin_node == self.shared.node_id
            || announcement.descriptor.updated_at > now.saturating_add(60)
            || now.saturating_sub(announcement.descriptor.updated_at) > STREAM_ANNOUNCEMENT_TTL_SECS
            || serde_json::to_vec(&announcement)
                .map_or(true, |json| json.len() > STREAM_ANNOUNCEMENT_MAX_BYTES)
            || announcement.descriptor.validate().is_err()
        {
            return Err(RegistryError::InvalidAnnouncement);
        }
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| RegistryError::Invalid("registry state"))?;
        if state.seen.contains(&announcement.message_id) {
            return Ok(None);
        }
        if state.remote.len() >= STREAM_REGISTRY_MAX_STREAMS
            && !state.remote.contains_key(&announcement.descriptor.id)
        {
            return Err(RegistryError::RegistryFull);
        }
        state.seen.insert(announcement.message_id.clone());
        state.seen_order.push_back(announcement.message_id.clone());
        while state.seen_order.len() > SEEN_ANNOUNCEMENTS_MAX {
            if let Some(oldest) = state.seen_order.pop_front() {
                state.seen.remove(&oldest);
            }
        }
        state.remote.insert(
            announcement.descriptor.id.clone(),
            announcement.descriptor.clone(),
        );
        let mut forwarded = announcement;
        forwarded.remaining_hops -= 1;
        Ok((forwarded.remaining_hops > 0).then_some(forwarded))
    }

    pub fn digest(&self) -> Result<Vec<StreamDigestEntry>, RegistryError> {
        Ok(self
            .list_streams()?
            .iter()
            .map(|descriptor| StreamDigestEntry {
                id: descriptor.id.clone(),
                version_hash: descriptor_hash(descriptor),
            })
            .collect())
    }

    /// Return full descriptors only for IDs whose digest hashes differ or are absent.
    pub fn descriptors_for_digest(
        &self,
        remote_digest: &[StreamDigestEntry],
    ) -> Result<Vec<StreamDescriptor>, RegistryError> {
        if remote_digest.len() > STREAM_REGISTRY_MAX_STREAMS {
            return Err(RegistryError::Invalid("stream digest"));
        }
        let remote: HashMap<_, _> = remote_digest
            .iter()
            .map(|entry| (entry.id.as_str(), entry.version_hash.as_str()))
            .collect();
        Ok(self
            .list_streams()?
            .into_iter()
            .filter(|descriptor| {
                remote.get(descriptor.id.as_str()).copied()
                    != Some(descriptor_hash(descriptor).as_str())
            })
            .collect())
    }

    pub fn expire_remote(&self) -> Result<usize, RegistryError> {
        let now = unix_timestamp();
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| RegistryError::Invalid("registry state"))?;
        let before = state.remote.len();
        state.remote.retain(|_, descriptor| {
            now.saturating_sub(descriptor.updated_at) <= STREAM_ANNOUNCEMENT_TTL_SECS
        });
        Ok(before - state.remote.len())
    }
}

pub struct Subscription {
    id: u64,
    stream_id: String,
    next_sequence: u64,
    shared: Weak<RegistryShared>,
}

impl Subscription {
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn next_chunk(&mut self) -> Result<SubscriptionRead, RegistryError> {
        let shared = self
            .shared
            .upgrade()
            .ok_or(RegistryError::SubscriptionNotFound)?;
        match shared
            .streams
            .get_chunk(&self.stream_id, self.next_sequence)
        {
            Ok(chunk) => {
                self.next_sequence = self
                    .next_sequence
                    .checked_add(1)
                    .ok_or(RegistryError::Invalid("subscription sequence"))?;
                Ok(SubscriptionRead::Chunk(chunk))
            }
            Err(MediaError::MissingChunk { .. }) => {
                if shared
                    .streams
                    .stream_snapshots()?
                    .iter()
                    .find(|snapshot| snapshot.metadata.stream_id == self.stream_id)
                    .is_some_and(|snapshot| snapshot.finished)
                {
                    Ok(SubscriptionRead::Finished)
                } else {
                    Ok(SubscriptionRead::Waiting)
                }
            }
            Err(MediaError::ChunkNotRetained { .. }) => Ok(SubscriptionRead::Lagged),
            Err(error) => Err(error.into()),
        }
    }

    pub fn acknowledge_through(&self, sequence: u64) -> Result<(), RegistryError> {
        if sequence >= self.next_sequence {
            return Err(RegistryError::InvalidAcknowledgement(sequence));
        }
        let shared = self
            .shared
            .upgrade()
            .ok_or(RegistryError::SubscriptionNotFound)?;
        {
            let mut state = shared
                .state
                .lock()
                .map_err(|_| RegistryError::Invalid("registry state"))?;
            let subscriber = state
                .subscribers
                .get_mut(&self.id)
                .ok_or(RegistryError::SubscriptionNotFound)?;
            if subscriber
                .acknowledged_through
                .is_some_and(|previous| sequence < previous)
            {
                return Err(RegistryError::InvalidAcknowledgement(sequence));
            }
            subscriber.acknowledged_through = Some(sequence);
        }
        release_acknowledged(&shared, &self.stream_id);
        Ok(())
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.upgrade() {
            if let Ok(mut state) = shared.state.lock() {
                state.subscribers.remove(&self.id);
            }
            release_acknowledged(&shared, &self.stream_id);
        }
    }
}

fn release_acknowledged(shared: &RegistryShared, stream_id: &str) {
    let minimum = shared.state.lock().ok().and_then(|state| {
        let active: Vec<_> = state
            .subscribers
            .values()
            .filter(|sub| sub.stream_id == stream_id)
            .collect();
        if active.is_empty() || active.iter().any(|sub| sub.acknowledged_through.is_none()) {
            None
        } else {
            active
                .iter()
                .filter_map(|sub| sub.acknowledged_through)
                .min()
        }
    });
    if let Some(sequence) = minimum {
        let _ = shared.streams.acknowledge_through(stream_id, sequence);
    }
}

fn local_descriptor(
    node_id: &str,
    snapshot: &MediaStreamSnapshot,
    name: Option<&String>,
) -> StreamDescriptor {
    StreamDescriptor {
        id: snapshot.metadata.stream_id.clone(),
        name: name
            .cloned()
            .unwrap_or_else(|| snapshot.metadata.stream_id.clone()),
        kind: match snapshot.metadata.media_type {
            MediaType::Audio => StreamKind::Audio,
            MediaType::Video => StreamKind::Video,
        },
        status: if snapshot.finished {
            StreamStatus::Finished
        } else {
            StreamStatus::Active
        },
        origin_node: node_id.to_string(),
        latest_seq: snapshot.latest_sequence,
        updated_at: snapshot.updated_at,
    }
}

fn descriptor_hash(descriptor: &StreamDescriptor) -> String {
    Sha256::digest(serde_json::to_vec(descriptor).unwrap_or_default())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_text(field: &'static str, value: &str, max: usize) -> Result<(), RegistryError> {
    if value.trim().is_empty() || value.len() > max {
        return Err(RegistryError::Invalid(field));
    }
    Ok(())
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
