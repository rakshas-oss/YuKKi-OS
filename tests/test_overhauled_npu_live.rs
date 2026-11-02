use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use yukkios_6_8_0_inet3::{
    brk2::{
        self, BrokerRequest, Limits, MSG_RESPONSE,
    },
    gpu_adapter::{GpuAdapterConfig, GpuAdapterError, LifecycleClient},
};

fn inference_payload() -> Vec<u8> {
    [1.0_f64, 2.0_f64]
        .into_iter()
        .flat_map(f64::to_be_bytes)
        .collect()
}

fn decode_doubles(bytes: &[u8]) -> Vec<f64> {
    assert_eq!(bytes.len() % 8, 0);
    bytes
        .chunks_exact(8)
        .map(|chunk| f64::from_be_bytes(chunk.try_into().unwrap()))
        .collect()
}

async fn raw_brk2_inference(
    endpoint: &str,
    task_id: &str,
    request_id: u64,
) -> brk2::Message {
    let request = BrokerRequest {
        task_id: task_id.to_owned(),
        source: "yukki-os-ci".to_owned(),
        destination: "overhauled".to_owned(),
        kind: "inference".to_owned(),
        priority: 1,
        timeout_ms: 5_000,
        payload: inference_payload(),
        idempotency_key: None,
        deadline_unix_ns: None,
        device_preference: Some("npu".to_owned()),
    };
    let frame = brk2::encode(&request.to_message(request_id), Limits::default())
        .expect("encode BRK2 NPU request");
    let mut stream = TcpStream::connect(endpoint)
        .await
        .expect("connect to live C++ broker");
    stream.write_all(&frame).await.expect("write BRK2 request");
    stream.flush().await.expect("flush BRK2 request");

    let mut prefix = [0_u8; 4];
    stream
        .read_exact(&mut prefix)
        .await
        .expect("read BRK2 response length");
    let body_len = u32::from_be_bytes(prefix) as usize;
    let mut response = Vec::with_capacity(4 + body_len);
    response.extend_from_slice(&prefix);
    response.resize(4 + body_len, 0);
    stream
        .read_exact(&mut response[4..])
        .await
        .expect("read BRK2 response body");

    let message = brk2::decode(&response, Limits::default()).expect("decode BRK2 response");
    assert_eq!(message.header.message_type, MSG_RESPONSE);
    assert_eq!(message.header.request_id, request_id);
    assert_eq!(message.field(1).unwrap().value.as_slice(), task_id.as_bytes());
    assert_eq!(message.field(2).unwrap().value.as_slice(), &[0]);
    message
}

fn response_backend(message: &brk2::Message) -> String {
    std::str::from_utf8(&message.field(7).expect("backend field").value)
        .expect("backend is UTF-8")
        .to_owned()
}

fn response_selected_gpu(message: &brk2::Message) -> i64 {
    i64::from_be_bytes(
        message
            .field(3)
            .expect("selected_gpu field")
            .value
            .as_slice()
            .try_into()
            .expect("selected_gpu is an i64"),
    )
}

fn response_result(message: &brk2::Message) -> Vec<f64> {
    decode_doubles(&message.field(5).expect("result field").value)
}

fn npu_client(endpoint: &str) -> LifecycleClient {
    let mut config = GpuAdapterConfig::new(endpoint);
    config.enabled = true;
    config.max_retries = 0;
    config.connect_timeout = Duration::from_secs(5);
    config.request_timeout = Duration::from_secs(10);
    LifecycleClient::new(config).expect("construct NPU lifecycle client")
}

#[tokio::test]
async fn live_brk2_npu_execution_and_explicit_cpu_fallback() {
    let npu_endpoint = match std::env::var("OVERHAULED_NPU_BROKER_ENDPOINT") {
        Ok(value) => value,
        Err(_) => {
            eprintln!("skipping live NPU test: OVERHAULED_NPU_BROKER_ENDPOINT is unset");
            return;
        }
    };
    let cpu_endpoint = match std::env::var("OVERHAULED_CPU_FALLBACK_ENDPOINT") {
        Ok(value) => value,
        Err(_) => {
            eprintln!("skipping live NPU test: OVERHAULED_CPU_FALLBACK_ENDPOINT is unset");
            return;
        }
    };

    // Real TCP round trip through broker_server --npu-simulated. The executor
    // is CPU-emulated, but the wire path and backend reporting are real.
    let npu_response = raw_brk2_inference(&npu_endpoint, "npu-raw", 0x4e50550000000001).await;
    assert_eq!(response_backend(&npu_response), "npu");
    assert_eq!(response_selected_gpu(&npu_response), -1);
    assert_eq!(response_result(&npu_response), vec![3.0, 6.0]);

    // Exercise the production Rust LifecycleClient API as well. It must
    // accept an NPU backend response and return the computed payload.
    let npu_result = npu_client(&npu_endpoint)
        .submit_npu_task("npu-client", &inference_payload(), 1, 5_000)
        .await
        .expect("LifecycleClient must accept backend=npu");
    assert_eq!(decode_doubles(&npu_result), vec![3.0, 6.0]);

    // A broker with no NPU executor must truthfully report CPU fallback and
    // retain selected_gpu=-1. The high-level NPU API must reject that result
    // rather than misreporting it as NPU execution.
    let cpu_response = raw_brk2_inference(&cpu_endpoint, "cpu-fallback-raw", 0x4350550000000002).await;
    assert_eq!(response_backend(&cpu_response), "cpu");
    assert_eq!(response_selected_gpu(&cpu_response), -1);
    assert_eq!(response_result(&cpu_response), vec![2.0, 4.0]);

    let fallback = npu_client(&cpu_endpoint)
        .submit_npu_task("cpu-fallback-client", &inference_payload(), 1, 5_000)
        .await;
    assert!(matches!(
        fallback,
        Err(GpuAdapterError::MalformedResponse(message))
            if message.contains("backend 'cpu', not 'npu'")
    ));
}
