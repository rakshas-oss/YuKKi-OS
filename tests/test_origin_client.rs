use std::sync::Arc;

use yukkios_6_8_0_inet3::{
    stream_gateway::{serve, GatewayAuth},
    ChunkSource, LiveMediaStreams, MediaChunk, MediaStreamConfig, MediaStreamMetadata, MediaType,
    OriginChunkClient, StreamRegistry,
};

#[tokio::test]
async fn client_fetches_metadata_chunks_and_finish_state() {
    let streams = Arc::new(LiveMediaStreams::new(MediaStreamConfig::default()).unwrap());
    streams
        .open_stream(MediaStreamMetadata {
            stream_id: "cam".into(),
            media_type: MediaType::Video,
            codec: "raw".into(),
        })
        .unwrap();
    for seq in 0..3 {
        streams
            .append_chunk(
                "cam",
                MediaChunk {
                    stream_id: "cam".into(),
                    media_type: MediaType::Video,
                    codec: "raw".into(),
                    sequence_no: seq,
                    timestamp_ms: seq * 10,
                    is_keyframe: seq == 0,
                    payload: vec![seq as u8; 4],
                },
            )
            .unwrap();
    }
    let registry = StreamRegistry::new("origin", streams.clone()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(
        listener,
        streams.clone(),
        registry,
        GatewayAuth::Bearer("tok".into()),
    ));

    let s2 = streams.clone();
    tokio::task::spawn_blocking(move || {
        let client = OriginChunkClient::new(addr, Some("tok".into()));
        assert_eq!(client.metadata("cam").unwrap().media_type, MediaType::Video);
        let chunks = client.fetch_range("cam", 1, 8).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].sequence_no, 1);
        assert!(!client.is_finished("cam").unwrap());
        s2.close_stream("cam").unwrap();
        assert!(client.is_finished("cam").unwrap());
        assert!(client.fetch_range("../x", 0, 1).is_err());
        let bad = OriginChunkClient::new(addr, Some("wrong".into()));
        assert!(bad.fetch_range("cam", 0, 1).is_err());
    })
    .await
    .unwrap();
}
