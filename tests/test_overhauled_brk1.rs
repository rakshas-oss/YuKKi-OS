use yukkios_6_8_0_inet3::gpu_adapter::{
    decode_brk1_frame, decode_brk1_response_frame, decode_wsm1_message, encode_brk1_frame,
    encode_wsm1_task_request, encode_wsm1_task_response, Brk1Frame, GpuAdapterConfig, GpuAdapterError, LifecycleClient,
    LifecycleWireMode, WasmBufferDescriptor, WasmTaskRequest, WasmTaskResponse, WasmTaskStatus, Wsm1Message, BRK1_MAGIC,
    BRK1_PROTOCOL_VERSION, BRK1_MSG_REQUEST,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
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
fn request_encoder_matches_overhauled_brk1_field_order() {
    let encoded = encode_brk1_frame(&Brk1Frame {
        msg_type: BRK1_MSG_REQUEST,
        task_id: "t".into(),
        source: "y".into(),
        destination: "o".into(),
        kind: "k".into(),
        priority: 1,
        timeout_ms: 3000,
        payload: vec![0xaa, 0xbb],
    })
    .expect("encode BRK1 request");

    let expected = [
        b'B', b'R', b'K', b'1', 0, 1, 1, 0, 0, 1, b't',
        0, 1, b'y', 0, 1, b'o', 0, 1, b'k', 1, 0, 0,
        0x0b, 0xb8, 0, 0, 0, 2, 0xaa, 0xbb,
    ];
    assert_eq!(encoded, expected);
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

#[test]
fn accepts_all_overhauled_wsm1_task_status_codes() {
    assert_eq!(WasmTaskStatus::try_from(0).unwrap(), WasmTaskStatus::Ok);
    assert_eq!(WasmTaskStatus::try_from(1).unwrap(), WasmTaskStatus::Rejected);
    assert_eq!(WasmTaskStatus::try_from(2).unwrap(), WasmTaskStatus::Failed);
    assert_eq!(WasmTaskStatus::try_from(3).unwrap(), WasmTaskStatus::Timeout);
    assert_eq!(
        WasmTaskStatus::try_from(4).unwrap(),
        WasmTaskStatus::ModuleDraining
    );
    assert_eq!(
        WasmTaskStatus::try_from(5).unwrap(),
        WasmTaskStatus::ModuleNotFound
    );
    assert_eq!(
        WasmTaskStatus::try_from(6).unwrap(),
        WasmTaskStatus::VersionMismatch
    );
    assert!(WasmTaskStatus::try_from(7).is_err());
}

fn append_string(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn append_blob(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn wrap_brk1_response(task_id: &str, status: u8, result: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&BRK1_MAGIC.to_be_bytes());
    frame.extend_from_slice(&BRK1_PROTOCOL_VERSION.to_be_bytes());
    frame.push(2);
    frame.push(0);
    append_string(&mut frame, task_id);
    frame.push(status);
    frame.extend_from_slice(&1i32.to_be_bytes());
    frame.extend_from_slice(&9u64.to_be_bytes());
    append_blob(&mut frame, result);
    append_string(&mut frame, "");
    frame
}

#[tokio::test]
async fn lifecycle_client_round_trips_brk1_with_wsm1_payload() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock broker");
    let endpoint = listener.local_addr().expect("local address").to_string();

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept client");
        let mut length = [0u8; 4];
        socket.read_exact(&mut length).await.expect("read length");
        let length = u32::from_be_bytes(length) as usize;
        let mut body = vec![0u8; length];
        socket.read_exact(&mut body).await.expect("read request");

        let request = decode_brk1_frame(&body).expect("decode BRK1 request");
        assert_eq!(request.msg_type, BRK1_MSG_REQUEST);
        assert_eq!(request.kind, "wasm.task.v1");
        assert_eq!(request.task_id, "t-42");
        assert!(matches!(
            decode_wsm1_message(&request.payload).expect("decode WSM1 request"),
            Wsm1Message::TaskRequest(_)
        ));

        let wsm1_response = encode_wsm1_task_response(&WasmTaskResponse {
            task_id: "t-42".into(),
            status: WasmTaskStatus::Ok,
            protocol_version: 1,
            selected_gpu: 1,
            latency_ms: 9,
            error: String::new(),
            buffers: Vec::new(),
            result: vec![0xaa, 0xbb],
        })
        .expect("encode WSM1 response");
        let response = wrap_brk1_response("t-42", 0, &wsm1_response);
        socket
            .write_all(&(response.len() as u32).to_be_bytes())
            .await
            .expect("write response length");
        socket.write_all(&response).await.expect("write response");
    });

    let mut config = GpuAdapterConfig::new(endpoint);
    config.enabled = true;
    config.max_retries = 0;
    let client = LifecycleClient::new(config)
        .expect("create lifecycle client")
        .with_wire_mode(LifecycleWireMode::Brk1);
    let request = WasmTaskRequest {
        task_id: "t-42".into(),
        sandbox_id: "sandbox-1".into(),
        module_id: "module-1".into(),
        module_version: "1.0.0".into(),
        task_kind: "compute".into(),
        priority: 3,
        deadline_ms: 5000,
        buffers: Vec::new(),
        payload: vec![1, 2, 3],
    };

    let response = client
        .submit_wsm1_task(&request)
        .await
        .expect("BRK1/WSM1 round trip");
    assert_eq!(response.task_id, "t-42");
    assert_eq!(response.status, WasmTaskStatus::Ok);
    assert_eq!(response.result, vec![0xaa, 0xbb]);
    server.await.expect("mock broker task");
}

#[test]
fn rejects_wsm1_values_over_overhauled_limits() {
    let mut request = WasmTaskRequest {
        task_id: "t".into(),
        sandbox_id: "s".into(),
        module_id: "m".into(),
        module_version: "1".into(),
        task_kind: "compute".into(),
        priority: 0,
        deadline_ms: 0,
        buffers: Vec::new(),
        payload: Vec::new(),
    };

    request.task_id = "x".repeat(1025);
    assert!(encode_wsm1_task_request(&request).is_err());

    request.task_id = "t".into();
    request.payload = vec![0; 512 * 1024 + 1];
    assert!(encode_wsm1_task_request(&request).is_err());

    request.payload.clear();
    request.buffers = vec![
        WasmBufferDescriptor {
            buffer_id: 1,
            flags: 1,
            offset: 0,
            length: 1,
            name: "buffer".into(),
        };
        65
    ];
    assert!(encode_wsm1_task_request(&request).is_err());
}
