use yukkios_6_7_0_inet3::{
    ArcGisAvenue, ArcGisError, LiveMediaStreams, MediaChunk, MediaError, MediaStreamConfig,
    MediaStreamMetadata, MediaType, Wgs84Coordinate, ARCGIS_AVENUE_KIND,
    ARCGIS_AVENUE_MAX_COORDINATES, MEDIA_CHUNK_HEADER_LEN, MEDIA_CHUNK_MAGIC, MEDIA_CHUNK_VERSION,
    MEDIA_MAX_CHUNK_BYTES,
};

fn avenue() -> ArcGisAvenue {
    ArcGisAvenue {
        feature_id: "avenue-42".to_string(),
        route_id: Some("route-7".to_string()),
        avenue_name: Some("Main Avenue".to_string()),
        coordinates: vec![
            Wgs84Coordinate {
                longitude: -122.4194,
                latitude: 37.7749,
            },
            Wgs84Coordinate {
                longitude: -122.4180,
                latitude: 37.7755,
            },
        ],
    }
}

fn chunk(sequence_no: u64) -> MediaChunk {
    MediaChunk {
        stream_id: "camera-1".to_string(),
        media_type: MediaType::Video,
        codec: "h264".to_string(),
        sequence_no,
        timestamp_ms: sequence_no * 40,
        is_keyframe: sequence_no == 0,
        payload: vec![sequence_no as u8, 0xAA, 0x55],
    }
}

fn streams(config: MediaStreamConfig) -> LiveMediaStreams {
    let streams = LiveMediaStreams::new(config).unwrap();
    streams
        .open_stream(MediaStreamMetadata {
            stream_id: "camera-1".to_string(),
            media_type: MediaType::Video,
            codec: "h264".to_string(),
        })
        .unwrap();
    streams
}

#[test]
fn arcgis_feature_round_trip_preserves_wgs84_order_and_avenue_metadata() {
    let feature = avenue();
    let bytes = feature.encode().unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["type"], "Feature");
    assert_eq!(json["geometry"]["type"], "LineString");
    assert_eq!(
        json["geometry"]["coordinates"][0],
        serde_json::json!([-122.4194, 37.7749])
    );
    assert_eq!(json["properties"]["route_id"], "route-7");
    assert_eq!(json["properties"]["avenue_name"], "Main Avenue");
    assert_eq!(ArcGisAvenue::decode(&bytes).unwrap(), feature);
}

#[test]
fn arcgis_feature_validates_geometry_and_coordinates() {
    let mut feature = avenue();
    feature.coordinates[0].longitude = 181.0;
    assert!(matches!(
        feature.encode(),
        Err(ArcGisError::InvalidLongitude { index: 0, .. })
    ));

    let mut feature = avenue();
    feature.coordinates[1].latitude = f64::NAN;
    assert!(matches!(
        feature.encode(),
        Err(ArcGisError::InvalidLatitude { index: 1, .. })
    ));

    let mut feature = avenue();
    feature.coordinates.truncate(1);
    assert_eq!(
        feature.encode().unwrap_err(),
        ArcGisError::TooFewCoordinates { found: 1 }
    );

    let mut feature = avenue();
    feature.coordinates = vec![
        Wgs84Coordinate {
            longitude: 0.0,
            latitude: 0.0,
        };
        ARCGIS_AVENUE_MAX_COORDINATES + 1
    ];
    assert_eq!(
        feature.encode().unwrap_err(),
        ArcGisError::TooManyCoordinates {
            found: ARCGIS_AVENUE_MAX_COORDINATES + 1,
            max: ARCGIS_AVENUE_MAX_COORDINATES,
        }
    );

    let malformed_geojson = br#"{"type":"Feature","id":"x","geometry":{"type":"LineString","coordinates":[[181,0],[0,0]]},"properties":{}}"#;
    assert!(matches!(
        ArcGisAvenue::decode(malformed_geojson),
        Err(ArcGisError::InvalidLongitude { index: 0, .. })
    ));
}

#[test]
fn arcgis_feature_round_trips_through_broker_json_envelope() {
    let task = avenue()
        .to_broker_task("task-arcgis", "yukki", "broker", 2, 1_000)
        .unwrap();
    assert_eq!(task.kind, ARCGIS_AVENUE_KIND);
    task.validate().unwrap();
    let decoded = ArcGisAvenue::from_broker_task(&task).unwrap();
    assert_eq!(decoded, avenue());
}

#[test]
fn media_chunk_binary_round_trip_and_broker_round_trip() {
    let frame = chunk(0);
    let bytes = frame.encode().unwrap();
    assert_eq!(&bytes[..4], &MEDIA_CHUNK_MAGIC.to_be_bytes());
    assert_eq!(bytes[4], MEDIA_CHUNK_VERSION);
    assert_eq!(bytes.len(), MEDIA_CHUNK_HEADER_LEN + 8 + 4 + 3);
    assert_eq!(MediaChunk::decode(&bytes).unwrap(), frame);

    let task = frame
        .to_broker_task("task-media", "camera", "broker", 1, 1_000)
        .unwrap();
    task.validate().unwrap();
    assert_eq!(MediaChunk::from_broker_task(&task).unwrap(), frame);
}

#[test]
fn media_chunk_decoder_rejects_malformed_and_oversized_inputs() {
    let bytes = chunk(0).encode().unwrap();
    assert!(matches!(
        MediaChunk::decode(&bytes[..MEDIA_CHUNK_HEADER_LEN - 1]),
        Err(MediaError::Truncated { .. })
    ));
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        MediaChunk::decode(&trailing),
        Err(MediaError::TrailingBytes { .. })
    ));

    let mut bad_magic = bytes.clone();
    bad_magic[0] ^= 0xFF;
    assert!(matches!(
        MediaChunk::decode(&bad_magic),
        Err(MediaError::InvalidMagic { .. })
    ));

    let mut invalid_flags = bytes.clone();
    invalid_flags[6] = 0x80;
    assert_eq!(
        MediaChunk::decode(&invalid_flags).unwrap_err(),
        MediaError::InvalidFlags(0x80)
    );

    let mut oversized = bytes;
    oversized[27..31].copy_from_slice(&((MEDIA_MAX_CHUNK_BYTES as u32) + 1).to_be_bytes());
    assert_eq!(
        MediaChunk::decode(&oversized).unwrap_err(),
        MediaError::ChunkTooLarge {
            size: MEDIA_MAX_CHUNK_BYTES + 1,
            max: MEDIA_MAX_CHUNK_BYTES,
        }
    );
}

#[test]
fn media_stream_enforces_order_duplicates_and_missing_sequence_errors() {
    let streams = streams(MediaStreamConfig::default());
    streams.append_chunk("camera-1", chunk(0)).unwrap();

    assert_eq!(
        streams.append_chunk("camera-1", chunk(0)).unwrap_err(),
        MediaError::DuplicateChunk { found: 0 }
    );
    assert_eq!(
        streams.append_chunk("camera-1", chunk(2)).unwrap_err(),
        MediaError::OutOfOrderChunk {
            expected: 1,
            found: 2
        }
    );
    assert_eq!(
        streams.get_chunk("camera-1", 1).unwrap_err(),
        MediaError::MissingChunk { sequence: 1 }
    );
    assert_eq!(
        streams.get_range("camera-1", 0, 1).unwrap_err(),
        MediaError::MissingChunk { sequence: 1 }
    );

    streams.ingest_chunk(&chunk(1).encode().unwrap()).unwrap();
    assert_eq!(
        streams
            .get_range("camera-1", 0, 1)
            .unwrap()
            .iter()
            .map(|item| item.sequence_no)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
}

#[test]
fn media_stream_backpressure_is_released_by_acknowledgement() {
    let streams = streams(MediaStreamConfig {
        max_streams: 1,
        max_chunks_per_stream: 1,
        max_total_chunks: 1,
        max_chunk_bytes: 8,
    });
    streams.append_chunk("camera-1", chunk(0)).unwrap();
    assert_eq!(
        streams.append_chunk("camera-1", chunk(1)).unwrap_err(),
        MediaError::Backpressure
    );
    assert_eq!(streams.acknowledge_through("camera-1", 0).unwrap(), 1);
    assert_eq!(
        streams.get_chunk("camera-1", 0).unwrap_err(),
        MediaError::ChunkNotRetained { sequence: 0 }
    );
    streams.append_chunk("camera-1", chunk(1)).unwrap();
}

#[test]
fn media_stream_lifecycle_retains_finished_data_until_removal() {
    let streams = streams(MediaStreamConfig::default());
    streams.append_chunk("camera-1", chunk(0)).unwrap();
    streams.close_stream("camera-1").unwrap();
    assert_eq!(
        streams.append_chunk("camera-1", chunk(1)).unwrap_err(),
        MediaError::StreamClosed("camera-1".to_string())
    );
    assert_eq!(streams.get_chunk("camera-1", 0).unwrap(), chunk(0));
    assert_eq!(streams.remove_stream("camera-1").unwrap(), 1);
    assert_eq!(
        streams.get_chunk("camera-1", 0).unwrap_err(),
        MediaError::StreamNotFound("camera-1".to_string())
    );
}

#[test]
fn media_stream_checks_metadata_limits_and_stream_capacity() {
    let config_result = LiveMediaStreams::new(MediaStreamConfig {
        max_chunk_bytes: MEDIA_MAX_CHUNK_BYTES + 1,
        ..MediaStreamConfig::default()
    });
    assert!(matches!(config_result, Err(MediaError::InvalidConfig)));

    let streams = streams(MediaStreamConfig {
        max_streams: 1,
        max_chunks_per_stream: 2,
        max_total_chunks: 2,
        max_chunk_bytes: 2,
    });
    assert_eq!(
        streams
            .open_stream(MediaStreamMetadata {
                stream_id: "other".to_string(),
                media_type: MediaType::Audio,
                codec: "opus".to_string(),
            })
            .unwrap_err(),
        MediaError::StreamLimit { max: 1 }
    );
    assert_eq!(
        streams.append_chunk("camera-1", chunk(0)).unwrap_err(),
        MediaError::ChunkTooLarge { size: 3, max: 2 }
    );

    let mut mismatched = chunk(0);
    mismatched.codec = "opus".to_string();
    mismatched.payload.truncate(2);
    assert_eq!(
        streams.append_chunk("camera-1", mismatched).unwrap_err(),
        MediaError::StreamMetadataMismatch
    );
}
