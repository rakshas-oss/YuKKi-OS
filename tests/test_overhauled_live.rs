use std::time::Duration;

use yukkios_6_8_0_inet3::gpu_adapter::{
    GpuAdapterConfig, LifecycleClient, LifecycleWireMode, WasmLifecycleStatus,
    WasmTaskRequest, WasmTaskStatus,
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

    let client = LifecycleClient::new(config)
        .expect("construct LifecycleClient")
        .with_wire_mode(LifecycleWireMode::Brk1);

    let sandbox_id = "ci-live-sandbox";
    let module_id = "ci-live-module";
    let version = "1.0.0";

    let prepared = client
        .prepare(sandbox_id, module_id, version, -1)
        .await
        .expect("BRK1/WSM1 Prepare request");
    assert_eq!(prepared.status, WasmLifecycleStatus::Ok);
    assert!(!prepared.lease_token.is_empty());

    // An odd-length payload exercises the broker's opaque-byte echo path,
    // avoiding architecture-specific floating-point compute behavior.
    let payload = b"live-cpp-interop!";
    let task = WasmTaskRequest {
        task_id: "ci-live-task-1".into(),
        sandbox_id: sandbox_id.into(),
        module_id: module_id.into(),
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
        .expect("BRK1/WSM1 Task request");
    assert_eq!(response.task_id, task.task_id);
    assert_eq!(response.status, WasmTaskStatus::Ok);
    assert_eq!(response.result, payload);

    let drained = client
        .drain(sandbox_id, module_id, version, 1_000)
        .await
        .expect("BRK1/WSM1 Drain request");
    assert_eq!(drained.status, WasmLifecycleStatus::Ok);

    let released = client
        .release(sandbox_id, module_id, version, &prepared.lease_token)
        .await
        .expect("BRK1/WSM1 Release request");
    assert_eq!(released.status, WasmLifecycleStatus::Ok);
}
