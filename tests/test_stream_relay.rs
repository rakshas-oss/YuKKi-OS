use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

use yukkios_6_8_0_inet3::{
    ChunkSource, LiveMediaStreams, MediaChunk, MediaStreamConfig, MediaStreamMetadata, MediaType,
    RelayError, StreamAnnouncement, StreamKind, StreamRegistry, StreamRelay, StreamStatus,
    SubscriptionRead,
};

struct Origin {
    streams: Arc<LiveMediaStreams>,
    fetches: AtomicUsize,
}

impl ChunkSource for Origin {
    fn metadata(&self, id: &str) -> Result<MediaStreamMetadata, RelayError> {
        Ok(self.streams.stream_metadata(id)?)
    }
    fn fetch_range(&self, id: &str, from: u64, limit: u64) -> Result<Vec<MediaChunk>, RelayError> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        let latest = self.streams.get_chunk(id, 0).map(|_| 2u64).unwrap_or(0);
        let last = (from + limit - 1).min(latest);
        Ok(self.streams.get_range(id, from, last).unwrap_or_default())
    }
    fn is_finished(&self, _id: &str) -> Result<bool, RelayError> {
        Ok(false)
    }
}

fn store() -> Arc<LiveMediaStreams> {
    Arc::new(LiveMediaStreams::new(MediaStreamConfig::default()).unwrap())
}

#[test]
fn relay_mirrors_remote_stream_with_shared_upstream_pull() {
    let origin_streams = store();
    origin_streams
        .open_stream(MediaStreamMetadata {
            stream_id: "cam".into(),
            media_type: MediaType::Video,
            codec: "raw".into(),
        })
        .unwrap();
    for seq in 0..3u64 {
        origin_streams
            .append_chunk(
                "cam",
                MediaChunk {
                    stream_id: "cam".into(),
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
    let source = Arc::new(Origin {
        streams: origin_streams,
        fetches: AtomicUsize::new(0),
    });

    let local = store();
    let registry = StreamRegistry::new("node-b", local.clone()).unwrap();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    registry
        .accept_announcement(
            StreamAnnouncement {
                message_id: "m1".into(),
                remaining_hops: 2,
                descriptor: yukkios_6_8_0_inet3::StreamDescriptor {
                    id: "cam".into(),
                    name: "cam".into(),
                    kind: StreamKind::Video,
                    status: StreamStatus::Active,
                    origin_node: "node-a".into(),
                    latest_seq: Some(2),
                    updated_at: now,
                },
            },
            now,
        )
        .unwrap();
    assert!(registry.tune_in("cam", 0).is_err());

    let relay = StreamRelay::new(local, registry, source.clone());
    let mut first = relay.tune_in("cam", 0).unwrap();
    let mut second = relay.tune_in("cam", 0).unwrap();
    assert_eq!(source.fetches.load(Ordering::SeqCst), 1);
    for sub in [&mut first, &mut second] {
        for seq in 0..3u64 {
            match sub.next_chunk().unwrap() {
                SubscriptionRead::Chunk(chunk) => assert_eq!(chunk.sequence_no, seq),
                other => panic!("unexpected {other:?}"),
            }
        }
    }
}
