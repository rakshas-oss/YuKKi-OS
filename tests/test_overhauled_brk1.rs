use yukkios_6_8_0_inet3::gpu_adapter::{
    decode_brk1_response_frame, GpuAdapterError, BRK1_MAGIC, BRK1_PROTOCOL_VERSION,
};

fn sample_response() -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&BRK1_MAGIC.to_be_bytes());
    frame.extend_from_slice(&BRK1_PROTOCOL_VERSION.to_be_bytes());
    frame.push(2); // Response
    frame.push(0); // reserved
    frame.extend_from_slice(&4u16.to_be_bytes());
    frame.extend_from_slice(b"t-42");
    frame.push(0); // TaskStatus::Ok
    frame.extend_from_slice(&1i32.to_be_bytes());
    frame.extend_from_slice(&9u64.to_be_bytes());
    frame.extend_from_slice(&3u32.to_be_bytes());
    frame.extend_from_slice(b"abc");
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame
}

#[test]
fn decodes_cpp_overhauled_brk1_response_layout() {
    let decoded = decode_brk1_response_frame(&sample_response()).expect("decode BRK1 response");
    assert_eq!(decoded.task_id, "t-42");
    assert_eq!(decoded.status, 0);
    assert_eq!(decoded.selected_gpu, 1);
    assert_eq!(decoded.latency_ms, 9);
    assert_eq!(decoded.result, b"abc");
    assert_eq!(decoded.error, "");
}

#[test]
fn rejects_non_response_message_type() {
    let mut frame = sample_response();
    frame[6] = 1; // Request
    assert!(matches!(
        decode_brk1_response_frame(&frame),
        Err(GpuAdapterError::Wsm1Codec(_))
    ));
}

#[test]
fn rejects_trailing_bytes() {
    let mut frame = sample_response();
    frame.push(0);
    assert!(matches!(
        decode_brk1_response_frame(&frame),
        Err(GpuAdapterError::Wsm1Codec(_))
    ));
}

#[test]
fn rejects_invalid_status() {
    let mut frame = sample_response();
    let status_offset = 8 + 2 + 4;
    frame[status_offset] = 0xff;
    assert!(matches!(
        decode_brk1_response_frame(&frame),
        Err(GpuAdapterError::Wsm1Codec(_))
    ));
}
