use std::{sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use yukkios::gpu_adapter::{
    GpuAdapterConfig, LifecycleClient, LifecycleWireMode, WasmLifecycleStatus, WasmTaskRequest,
    WasmTaskStatus,
};

/// This test is activated only by the CI job that starts the real C++ broker.
/// Local cargo test runs remain self-contained when the broker is not present.
#[tokio::test]
async fn rust_client_interoperates_with_live_overhauled_cpp_broker() {
    let endpoint = match std::env::var("OVERHAULED_BROKER_ENDPOINT") {
        Ok(value) => value,
        Err(_) => {
            eprintln!("skipping live C++ broker test: OVERHAULED_BROKER_ENDPOINT is unset");
            return;
        }
    };

    let mut config = GpuAdapterConfig::new(endpoint);
    config.enabled = true;
    config.max_retries = 0;
    config.connect_timeout = Duration::from_secs(5);
    config.request_timeout = Duration::from_secs(10);

    let wire_mode = match std::env::var("OVERHAULED_WIRE_MODE")
        .unwrap_or_default()
        .as_str()
    {
        "brk2" => LifecycleWireMode::Brk2,
        _ => LifecycleWireMode::Brk1,
    };
    let client = Arc::new(
        LifecycleClient::new(config)
            .expect("construct LifecycleClient")
            .with_wire_mode(wire_mode),
    );

    let mode_suffix = if wire_mode == LifecycleWireMode::Brk2 {
        "brk2"
    } else {
        "brk1"
    };
    let sandbox_id = format!("ci-live-{mode_suffix}-sandbox");
    let module_id = format!("ci-live-{mode_suffix}-module");
    let version = "1.0.0";

    let prepared = client
        .prepare(&sandbox_id, &module_id, version, -1)
        .await
        .expect("broker WSM1 Prepare request");
    assert_eq!(prepared.status, WasmLifecycleStatus::Ok);
    assert!(!prepared.lease_token.is_empty());

    // An odd-length payload exercises the broker's opaque-byte echo path,
    // avoiding architecture-specific floating-point compute behavior.
    let payload = b"live-cpp-interop!";
    let task = WasmTaskRequest {
        task_id: format!("ci-live-{mode_suffix}-task-1"),
        sandbox_id: sandbox_id.clone(),
        module_id: module_id.clone(),
        module_version: version.into(),
        task_kind: "interop-echo".into(),
        priority: 1,
        deadline_ms: 5_000,
        buffers: Vec::new(),
        payload: payload.to_vec(),
    };
    let response = client
        .submit_wsm1_task(&task)
        .await
        .expect("broker WSM1 Task request");
    assert_eq!(response.task_id, task.task_id);
    assert_eq!(response.status, WasmTaskStatus::Ok);
    assert_eq!(response.result, payload);

    // Exercise independent concurrent TCP requests and verify each response
    // remains correlated with its own task ID and opaque payload.
    let mut joins = tokio::task::JoinSet::new();
    for index in 0..12u8 {
        let client = Arc::clone(&client);
        let sandbox_id = sandbox_id.clone();
        let module_id = module_id.clone();
        joins.spawn(async move {
            let task_id = format!("ci-live-{mode_suffix}-parallel-{index}");
            let payload = format!("parallel-payload-{index}!").into_bytes();
            let task = WasmTaskRequest {
                task_id: task_id.clone(),
                sandbox_id,
                module_id,
                module_version: version.into(),
                task_kind: "interop-echo".into(),
                priority: index,
                deadline_ms: 5_000,
                buffers: Vec::new(),
                payload: payload.clone(),
            };
            let response = client
                .submit_wsm1_task(&task)
                .await
                .expect("concurrent broker task request");
            assert_eq!(response.task_id, task_id);
            assert_eq!(response.status, WasmTaskStatus::Ok);
            assert_eq!(response.result, payload);
        });
    }
    while let Some(result) = joins.join_next().await {
        result.expect("concurrent task join");
    }

    let drained = client
        .drain(&sandbox_id, &module_id, version, 1_000)
        .await
        .expect("broker WSM1 Drain request");
    assert_eq!(drained.status, WasmLifecycleStatus::Ok);

    let released = client
        .release(&sandbox_id, &module_id, version, &prepared.lease_token)
        .await
        .expect("broker WSM1 Release request");
    assert_eq!(released.status, WasmLifecycleStatus::Ok);
}

/// The C++ listener must close a peer that stalls halfway through a frame,
/// and must also release the session promptly when the peer disconnects mid-body.
#[tokio::test]
async fn live_broker_enforces_partial_frame_timeout_and_disconnect_cleanup() {
    let endpoint = match std::env::var("OVERHAULED_BROKER_ENDPOINT") {
        Ok(value) => value,
        Err(_) => {
            eprintln!("skipping live broker timeout test: OVERHAULED_BROKER_ENDPOINT is unset");
            return;
        }
    };

    // Send only half of the 4-byte frame prefix. The broker's configured
    // socket read timeout is 5 seconds; the peer should then be closed.
    let mut stalled = TcpStream::connect(&endpoint)
        .await
        .expect("connect stalled peer");
    stalled
        .write_all(&[0, 0])
        .await
        .expect("write partial prefix");
    let mut byte = [0u8; 1];
    let read = timeout(Duration::from_secs(7), stalled.read(&mut byte))
        .await
        .expect("broker must close stalled partial frame")
        .expect("read after broker timeout");
    assert_eq!(read, 0, "broker should close the timed-out peer");

    // A peer that disconnects after a valid length prefix but incomplete body
    // must not leave a worker/session waiting for the rest of the frame.
    let mut dropped = TcpStream::connect(&endpoint)
        .await
        .expect("connect disconnect peer");
    dropped
        .write_all(&100u32.to_be_bytes())
        .await
        .expect("write body length");
    dropped
        .write_all(b"BRK2")
        .await
        .expect("write partial body");
    dropped
        .shutdown()
        .await
        .expect("half-close peer write side");
    let read = timeout(Duration::from_secs(2), dropped.read(&mut byte))
        .await
        .expect("broker should clean up disconnected peer promptly")
        .expect("read after disconnect");
    assert_eq!(read, 0, "broker should close disconnected peer");
}
