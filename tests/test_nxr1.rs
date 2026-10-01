//! Integration tests for the NXR1 geospatial frame codec and broker adapter,
//! exercised through the crate's public API surface (`src/lib.rs`).

use yukkios_6_8_0_inet3::{
    from_broker_task, to_broker_task, BrokerTask, Nxr1Error, Nxr1Frame, GEOSPATIAL_FRAME_KIND,
    NXR1_HEADER_LEN, NXR1_MAGIC, NXR1_VERSION,
};

fn sample_frame() -> Nxr1Frame {
    Nxr1Frame {
        seq_id: 7,
        x: 10.0,
        y: 20.0,
        z: 30.0,
        u: 1.0,
        v: 2.0,
        w: 3.0,
        fluidity: 0.5,
        drag: 0.25,
        divergence: 0.75,
        payload: b"interop-payload".to_vec(),
    }
}

#[test]
fn encode_starts_with_magic_and_version() {
    let frame = sample_frame();
    let encoded = frame.encode().expect("encode");
    assert_eq!(&encoded[0..4], &NXR1_MAGIC.to_be_bytes());
    assert_eq!(encoded[4], NXR1_VERSION);
    assert_eq!(encoded.len(), NXR1_HEADER_LEN + frame.payload.len());
}

#[test]
fn decode_round_trips_through_raw_bytes() {
    let frame = sample_frame();
    let encoded = frame.encode().expect("encode");
    let decoded = Nxr1Frame::decode(&encoded).expect("decode");
    assert_eq!(decoded, frame);
}

#[test]
fn broker_task_carries_geospatial_frame_kind() {
    let frame = sample_frame();
    let task: BrokerTask = to_broker_task(
        &frame,
        "nxr1-task-1",
        "yukki-node",
        "overhauled-broker",
        3,
        2_000,
    )
    .expect("to_broker_task");

    assert_eq!(task.kind, GEOSPATIAL_FRAME_KIND);
    assert_eq!(task.task_id, "nxr1-task-1");
    assert_eq!(task.source, "yukki-node");
    assert_eq!(task.destination, "overhauled-broker");

    // The task must still satisfy the existing BrokerTask invariants, so it
    // can flow unmodified through BrokerClient::submit.
    task.validate().expect("broker task invariants");
}

#[test]
fn broker_task_json_round_trip_preserves_nxr1_frame() {
    let frame = sample_frame();
    let task = to_broker_task(
        &frame,
        "nxr1-task-2",
        "yukki-node",
        "overhauled-broker",
        1,
        500,
    )
    .expect("to_broker_task");

    // Simulate the task crossing the broker's JSON transport.
    let json = serde_json::to_vec(&task).expect("serialize");
    let received: BrokerTask = serde_json::from_slice(&json).expect("deserialize");

    let decoded = from_broker_task(&received).expect("from_broker_task");
    assert_eq!(decoded, frame);
}

#[test]
fn malformed_frames_are_rejected_with_typed_errors() {
    let frame = sample_frame();
    let encoded = frame.encode().unwrap();

    // Truncated.
    let err = Nxr1Frame::decode(&encoded[..encoded.len() - 1]).unwrap_err();
    assert!(matches!(err, Nxr1Error::Truncated { .. }));

    // Trailing bytes.
    let mut with_trailer = encoded.clone();
    with_trailer.push(0xAA);
    let err = Nxr1Frame::decode(&with_trailer).unwrap_err();
    assert!(matches!(err, Nxr1Error::TrailingBytes { .. }));

    // Bad magic.
    let mut bad_magic = encoded.clone();
    bad_magic[0] = 0x00;
    let err = Nxr1Frame::decode(&bad_magic).unwrap_err();
    assert!(matches!(err, Nxr1Error::InvalidMagic { .. }));

    // Bad version.
    let mut bad_version = encoded.clone();
    bad_version[4] = 0x02;
    let err = Nxr1Frame::decode(&bad_version).unwrap_err();
    assert!(matches!(err, Nxr1Error::UnsupportedVersion { .. }));
}
