use std::time::Duration;

use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::sleep,
};
use yukkios_6_7_0_inet3::{
    BrokerClient, BrokerClientConfig, BrokerClientError, BrokerResult, BrokerTask,
    BrokerTransportSecurity, DEFAULT_BROKER_MAX_FRAME_BYTES,
};

fn sample_task() -> BrokerTask {
    BrokerTask {
        task_id: "task-123".to_string(),
        source: "yukki".to_string(),
        destination: "overhauled".to_string(),
        kind: "inference".to_string(),
        priority: 5,
        timeout_ms: 3_000,
        payload: json!({
            "model_id": 42,
            "tensor": [1.0, 2.0, 3.0, 4.0]
        }),
    }
}

fn sample_result(task_id: &str) -> BrokerResult {
    BrokerResult {
        task_id: task_id.to_string(),
        status: "ok".to_string(),
        gpu_id: Some(1),
        execution_ms: Some(12),
        result: Some(json!({
            "tensor": [2.0, 4.0, 6.0, 8.0]
        })),
    }
}

async fn read_prefixed_frame(stream: &mut tokio::net::TcpStream) -> (usize, Vec<u8>) {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.expect("read length");
    let length = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await.expect("read frame");
    (length, body)
}

async fn write_prefixed_frame(stream: &mut tokio::net::TcpStream, payload: &[u8]) {
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .expect("write length");
    stream.write_all(payload).await.expect("write body");
    stream.flush().await.expect("flush body");
}

#[test]
fn broker_messages_serialize_roundtrip() {
    let task = sample_task();
    let task_json = serde_json::to_string(&task).expect("serialize task");
    let decoded_task: BrokerTask = serde_json::from_str(&task_json).expect("deserialize task");
    assert_eq!(decoded_task, task);

    let result = sample_result(&task.task_id);
    let result_json = serde_json::to_string(&result).expect("serialize result");
    let decoded_result: BrokerResult =
        serde_json::from_str(&result_json).expect("deserialize result");
    assert_eq!(decoded_result, result);
}

#[test]
fn broker_client_config_exposes_transport_boundary() {
    let config = BrokerClientConfig::default();
    assert_eq!(config.endpoint(), "127.0.0.1:9000");
    assert_eq!(
        config.transport_security,
        BrokerTransportSecurity::PlaintextBoundary
    );
}

#[tokio::test]
async fn broker_client_submits_length_prefixed_request() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let task = sample_task();
    let expected_result = sample_result(&task.task_id);

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let (length, body) = read_prefixed_frame(&mut stream).await;
        assert!(length > 0);
        assert!(length <= DEFAULT_BROKER_MAX_FRAME_BYTES);
        let request: BrokerTask = serde_json::from_slice(&body).expect("decode request");
        assert_eq!(request, task);

        let response = serde_json::to_vec(&expected_result).expect("encode response");
        write_prefixed_frame(&mut stream, &response).await;
    });

    let mut config = BrokerClientConfig::new(addr.to_string());
    config.connect_timeout = Duration::from_secs(1);
    config.request_timeout = Duration::from_secs(1);
    config.max_frame_size = DEFAULT_BROKER_MAX_FRAME_BYTES;
    config.transport_security = BrokerTransportSecurity::AuthenticatedProxy;
    let client = BrokerClient::with_config(config).expect("client config");

    let result = client.submit(&sample_task()).await.expect("broker call");
    assert_eq!(result, sample_result("task-123"));
    server.await.expect("server task");
}

#[tokio::test]
async fn broker_client_rejects_oversized_request() {
    let mut task = sample_task();
    task.payload = json!({
        "blob": "x".repeat(DEFAULT_BROKER_MAX_FRAME_BYTES),
    });

    let client = BrokerClient::new("127.0.0.1:1");
    let error = client.submit(&task).await.expect_err("oversized request");
    assert!(matches!(error, BrokerClientError::RequestTooLarge { .. }));
}

#[tokio::test]
async fn broker_client_rejects_oversized_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let _ = read_prefixed_frame(&mut stream).await;
        stream
            .write_all(&((DEFAULT_BROKER_MAX_FRAME_BYTES as u32) + 1).to_be_bytes())
            .await
            .expect("write oversized length");
        stream.flush().await.expect("flush");
    });

    let mut config = BrokerClientConfig::new(addr.to_string());
    config.connect_timeout = Duration::from_secs(1);
    config.request_timeout = Duration::from_secs(1);
    config.max_frame_size = DEFAULT_BROKER_MAX_FRAME_BYTES;
    let client = BrokerClient::with_config(config).expect("client config");

    let error = client
        .submit(&sample_task())
        .await
        .expect_err("oversized response should fail");
    assert!(matches!(error, BrokerClientError::ResponseTooLarge { .. }));
    server.await.expect("server task");
}

#[tokio::test]
async fn broker_client_rejects_malformed_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let _ = read_prefixed_frame(&mut stream).await;
        write_prefixed_frame(&mut stream, br#"{"status":"ok"}"#).await;
    });

    let mut config = BrokerClientConfig::new(addr.to_string());
    config.connect_timeout = Duration::from_secs(1);
    config.request_timeout = Duration::from_secs(1);
    config.max_frame_size = DEFAULT_BROKER_MAX_FRAME_BYTES;
    let client = BrokerClient::with_config(config).expect("client config");

    let error = client
        .submit(&sample_task())
        .await
        .expect_err("malformed response should fail");
    assert!(matches!(
        error,
        BrokerClientError::DeserializeResponse(_) | BrokerClientError::MalformedResponse(_)
    ));
    server.await.expect("server task");
}

#[tokio::test]
async fn broker_client_times_out_cleanly() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let _ = read_prefixed_frame(&mut stream).await;
        sleep(Duration::from_millis(200)).await;
        let response = serde_json::to_vec(&sample_result("task-123")).expect("encode response");
        let _ = stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .await;
        let _ = stream.write_all(&response).await;
    });

    let mut config = BrokerClientConfig::new(addr.to_string());
    config.connect_timeout = Duration::from_secs(1);
    config.request_timeout = Duration::from_millis(50);
    config.max_frame_size = DEFAULT_BROKER_MAX_FRAME_BYTES;
    let client = BrokerClient::with_config(config).expect("client config");

    let error = client
        .submit(&sample_task())
        .await
        .expect_err("request timeout");
    assert!(matches!(error, BrokerClientError::RequestTimeout(_)));
    server.await.expect("server task");
}

#[test]
fn broker_task_validation_rejects_empty_fields() {
    let invalid_task = BrokerTask {
        task_id: String::new(),
        source: "yukki".to_string(),
        destination: "overhauled".to_string(),
        kind: "inference".to_string(),
        priority: 0,
        timeout_ms: 0,
        payload: serde_json::Value::Null,
    };

    let error = invalid_task.validate().expect_err("invalid task");
    assert!(matches!(error, BrokerClientError::InvalidRequest(_)));
}
