use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use yukkios_6_8_0_inet3::{
    LiveMediaStreams, MediaChunk, MediaStreamConfig, MediaStreamMetadata, MediaType, RegistryError,
    StreamAnnouncement, StreamKind, StreamRegistry, StreamStatus, SubscriptionRead,
    STREAM_MAX_SUBSCRIBERS,
};

fn setup(max_chunks_per_stream: usize) -> (Arc<LiveMediaStreams>, StreamRegistry) {
    let streams = Arc::new(
        LiveMediaStreams::new(MediaStreamConfig {
            max_streams: 4,
            max_chunks_per_stream,
            max_total_chunks: 8,
            max_chunk_bytes: 1024,
        })
        .unwrap(),
    );
    let registry = StreamRegistry::new("node-a", streams.clone()).unwrap();
    (streams, registry)
}

fn open_video(streams: &LiveMediaStreams, id: &str) {
    streams
        .open_stream(MediaStreamMetadata {
            stream_id: id.into(),
            media_type: MediaType::Video,
            codec: "raw".into(),
        })
        .unwrap();
}

fn ingest(streams: &LiveMediaStreams, id: &str, seq: u64) {
    streams
        .append_chunk(
            id,
            MediaChunk {
                stream_id: id.into(),
                media_type: MediaType::Video,
                codec: "raw".into(),
                sequence_no: seq,
                timestamp_ms: seq,
                is_keyframe: false,
                payload: vec![seq as u8],
            },
        )
        .unwrap();
}

#[test]
fn registry_tracks_local_lifecycle_and_validates_names() {
    let (streams, registry) = setup(4);
    open_video(&streams, "camera-1");
    let descriptor = registry.describe("camera-1").unwrap();
    assert_eq!(descriptor.name, "camera-1");
    assert_eq!(descriptor.kind, StreamKind::Video);
    assert_eq!(descriptor.status, StreamStatus::Active);

    registry.set_local_name("camera-1", "Front door").unwrap();
    assert_eq!(registry.describe("camera-1").unwrap().name, "Front door");
    assert!(registry.set_local_name("camera-1", " ").is_err());

    ingest(&streams, "camera-1", 0);
    assert_eq!(registry.describe("camera-1").unwrap().latest_seq, Some(0));
    streams.close_stream("camera-1").unwrap();
    assert_eq!(
        registry.describe("camera-1").unwrap().status,
        StreamStatus::Finished
    );
    streams.remove_stream("camera-1").unwrap();
    assert!(registry.describe("camera-1").is_err());
}

#[test]
fn slow_subscriber_retains_chunks_until_all_subscribers_ack() {
    let (streams, registry) = setup(2);
    open_video(&streams, "camera-1");
    ingest(&streams, "camera-1", 0);
    let mut fast = registry.tune_in("camera-1", 0).unwrap();
    let mut slow = registry.tune_in("camera-1", 0).unwrap();
    assert!(matches!(
        fast.next_chunk().unwrap(),
        SubscriptionRead::Chunk(_)
    ));
    assert!(matches!(
        slow.next_chunk().unwrap(),
        SubscriptionRead::Chunk(_)
    ));

    fast.acknowledge_through(0).unwrap();
    assert!(matches!(
        slow.next_chunk().unwrap(),
        SubscriptionRead::Waiting
    ));
    assert!(streams.get_chunk("camera-1", 0).is_ok());
    slow.acknowledge_through(0).unwrap();
    assert!(matches!(
        streams.get_chunk("camera-1", 0),
        Err(yukkios_6_8_0_inet3::MediaError::ChunkNotRetained { .. })
    ));
}

#[test]
fn subscriber_limit_and_finished_signal_are_bounded() {
    let (streams, registry) = setup(1);
    open_video(&streams, "camera-1");
    let subscriptions: Vec<_> = (0..STREAM_MAX_SUBSCRIBERS)
        .map(|_| registry.tune_in("camera-1", 0).unwrap())
        .collect();
    assert!(matches!(
        registry.tune_in("camera-1", 0),
        Err(RegistryError::SubscriberLimit)
    ));
    drop(subscriptions);

    streams.close_stream("camera-1").unwrap();
    assert_eq!(
        registry
            .tune_in("camera-1", 0)
            .unwrap()
            .next_chunk()
            .unwrap(),
        SubscriptionRead::Finished
    );
}

#[test]
fn announcements_are_bounded_deduplicated_and_anti_entropy_is_hash_based() {
    let (_, registry) = setup(1);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let announcement = StreamAnnouncement {
        message_id: "announcement-1".into(),
        remaining_hops: 4,
        descriptor: yukkios_6_8_0_inet3::StreamDescriptor {
            id: "remote-camera".into(),
            name: "Remote camera".into(),
            kind: StreamKind::Video,
            status: StreamStatus::Active,
            origin_node: "node-z".into(),
            latest_seq: Some(7),
            updated_at: now,
        },
    };
    let forward = registry
        .accept_announcement(announcement.clone(), now)
        .unwrap()
        .unwrap();
    assert_eq!(forward.remaining_hops, 3);
    assert!(registry
        .accept_announcement(announcement, now)
        .unwrap()
        .is_none());

    let digest = registry.digest().unwrap();
    assert_eq!(digest.len(), 1);
    assert!(registry.descriptors_for_digest(&digest).unwrap().is_empty());
    let mut stale_hash = digest;
    stale_hash[0].version_hash = "f".repeat(64);
    assert_eq!(
        registry.descriptors_for_digest(&stale_hash).unwrap().len(),
        1
    );
    assert!(registry
        .descriptors_for_digest(&[yukkios_6_8_0_inet3::StreamDigestEntry {
            id: String::new(),
            version_hash: "0".repeat(64),
        }])
        .is_err());

    let expired = StreamAnnouncement {
        message_id: "expired".into(),
        remaining_hops: 2,
        descriptor: yukkios_6_8_0_inet3::StreamDescriptor {
            id: "old".into(),
            name: "old".into(),
            kind: StreamKind::Audio,
            status: StreamStatus::Finished,
            origin_node: "node-z".into(),
            latest_seq: None,
            updated_at: now.saturating_sub(121),
        },
    };
    assert!(registry.accept_announcement(expired, now).is_err());
}
