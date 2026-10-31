use yukkios_6_8_0_inet3::{
    decode_brk2_frame, encode_brk2_frame, validate_brk2_schema, Brk2BrokerRequest,
    Brk2Error, Brk2Field, Brk2Header, Brk2Limits, Brk2Message, Brk2WireType,
};

fn request() -> Brk2BrokerRequest {
    Brk2BrokerRequest {
        task_id: "task-interop-1".into(),
        source: "yukki".into(),
        destination: "overhauled".into(),
        kind: "inference".into(),
        priority: 7,
        timeout_ms: 2500,
        payload: vec![0, 1, 2, 255],
        idempotency_key: None,
        deadline_unix_ns: Some(1_900_000_000_000_000_000),
    }
}

#[test]
fn brk2_request_round_trips_through_public_api() {
    let original = request();
    let message = original.to_message(42);
    let frame = encode_brk2_frame(&message, Brk2Limits::default()).unwrap();
    let decoded = decode_brk2_frame(&frame, Brk2Limits::default()).unwrap();
    assert_eq!(decoded.header.request_id, 42);
    assert_eq!(Brk2BrokerRequest::from_message(&decoded).unwrap(), original);
}

#[test]
fn brk2_unknown_optional_field_is_preserved() {
    let mut message = request().to_message(7);
    message.push(Brk2Field::bytes(500, b"extension"));
    let decoded = decode_brk2_frame(
        &encode_brk2_frame(&message, Brk2Limits::default()).unwrap(),
        Brk2Limits::default(),
    ).unwrap();
    assert_eq!(decoded.field(500).unwrap().value, b"extension");
}

#[test]
fn brk2_schema_rejects_unknown_critical_field() {
    let mut message = request().to_message(8);
    message.push(Brk2Field::u8(600, 1).critical());
    let err = validate_brk2_schema(
        &message,
        &[(1, Brk2WireType::Utf8, true)],
    ).unwrap_err();
    assert_eq!(err, Brk2Error::UnknownCriticalField(600));
}

#[test]
fn brk2_rejects_trailing_bytes_and_oversized_frames() {
    let frame = encode_brk2_frame(&request().to_message(9), Brk2Limits::default()).unwrap();
    let mut trailing = frame.clone();
    trailing.push(0);
    assert_eq!(
        decode_brk2_frame(&trailing, Brk2Limits::default()),
        Err(Brk2Error::TrailingBytes)
    );
    let mut limits = Brk2Limits::default();
    limits.max_frame_bytes = 32;
    assert!(matches!(
        decode_brk2_frame(&frame, limits),
        Err(Brk2Error::FrameTooLarge(_))
    ));
}

#[test]
fn brk2_header_constructor_sets_version_two() {
    let header = Brk2Header::new(8, 1, 0, 0);
    assert_eq!(header.major, 2);
    assert_eq!(header.minor, 0);
}
