use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::sleep,
};
use yukkios_6_8_0_inet3::{
    gpu_adapter::{
        decode_brk1_frame, decode_wsm1_message, encode_brk1_frame,
        encode_wsm1_lifecycle_request, encode_wsm1_lifecycle_response,
        encode_wsm1_task_request, encode_wsm1_task_response, Brk1Frame, BrokerMessage,
        BrokerTaskError, BufferAccess, BufferDescriptor, BufferKind, CancelTaskRequest,
        CancelTaskResponse, GpuAdapterConfig, GpuAdapterError, GpuBrokerClient, GpuTaskRequest,
        GpuTaskResponse, GpuTaskStatus, LifecycleClient, LifecycleWireMode,
        ModuleLifecycleManager, ModuleLifecycleState, ProtocolHandshakeRequest,
        ProtocolHandshakeResponse, StateHandoffHook, WasmBufferDescriptor,
        WasmLifecycleAction, WasmLifecycleRequest, WasmLifecycleResponse, WasmLifecycleState,
        WasmLifecycleStatus, WasmTaskRequest, WasmTaskResponse, WasmTaskStatus, Wsm1Message,
        BRK1_MAGIC, BRK1_MSG_REQUEST, BRK1_MSG_RESPONSE, CURRENT_PROTOCOL_VERSION, WSM1_MAGIC,
    },
    wasm_sandbox::RustasmSandbox,
};

// ============================================================================
// Helpers & Mock Broker Server
// ============================================================================

/// Minimal valid WebAssembly module bytecode (`(module (func (export "main") (result i32) (i32.const 42)))`).
const MINIMAL_VALID_WASM: &[u8] =
    b"\0asm\x01\0\0\0\x01\x05\x01`\0\x01\x7f\x03\x02\x01\0\x07\x08\x01\x04main\0\0\x0a\x06\x01\x04\0A*\x0b";

async fn read_prefixed_msg(stream: &mut tokio::net::TcpStream) -> BrokerMessage {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.expect("read length");
    let length = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await.expect("read frame");
    serde_json::from_slice::<BrokerMessage>(&body).expect("deserialize broker message")
}

async fn write_prefixed_msg(stream: &mut tokio::net::TcpStream, msg: &BrokerMessage) {
    let body = serde_json::to_vec(msg).expect("serialize broker message");
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .await
        .expect("write length");
    stream.write_all(&body).await.expect("write frame");
    stream.flush().await.expect("flush");
}

async fn read_raw_prefixed_opt(stream: &mut tokio::net::TcpStream) -> Option<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).await.is_err() {
        return None;
    }
    let length = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; length];
    if stream.read_exact(&mut body).await.is_err() {
        return None;
    }
    Some(body)
}

async fn read_raw_prefixed(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    read_raw_prefixed_opt(stream).await.expect("read frame")
}

async fn write_raw_prefixed(stream: &mut tokio::net::TcpStream, data: &[u8]) {
    stream
        .write_all(&(data.len() as u32).to_be_bytes())
        .await
        .expect("write length");
    stream.write_all(data).await.expect("write frame");
    stream.flush().await.expect("flush");
}

fn sample_task_request(task_id: &str) -> GpuTaskRequest {
    GpuTaskRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION.to_string(),
        task_id: task_id.to_string(),
        idempotency_key: Some(format!("idemp-{task_id}")),
        sandbox_id: "sb-42".to_string(),
        module_id: "mod-vision".to_string(),
        module_version: "1.0.0".to_string(),
        priority: 10,
        deadline_ms: Some(1700000000000),
        timeout_ms: 3000,
        buffers: vec![
            BufferDescriptor::inline("in0", vec![1, 2, 3, 4], BufferAccess::ReadOnly),
            BufferDescriptor::gpu_buffer("out0", 1024, BufferAccess::WriteOnly),
        ],
        metadata: Some(serde_json::json!({"model": "resnet50"})),
    }
}

// ============================================================================
// 1. Serialization & Encoding Tests
// ============================================================================

#[test]
fn test_task_request_serialization_roundtrip() {
    let req = sample_task_request("task-001");
    let serialized = serde_json::to_string(&req).expect("serialize");
    let deserialized: GpuTaskRequest = serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(req, deserialized);
    assert_eq!(req.effective_idempotency_key(), "idemp-task-001");
}

#[test]
fn test_handshake_serialization_roundtrip() {
    let req = ProtocolHandshakeRequest::default();
    let json_req = serde_json::to_string(&req).expect("serialize");
    let decoded_req: ProtocolHandshakeRequest =
        serde_json::from_str(&json_req).expect("deserialize");
    assert_eq!(req, decoded_req);

    let resp = ProtocolHandshakeResponse {
        status: "ok".to_string(),
        negotiated_version: Some(CURRENT_PROTOCOL_VERSION.to_string()),
        capabilities: vec!["nvlink_placement".to_string(), "cancellation".to_string()],
        error_message: None,
    };
    let json_resp = serde_json::to_string(&resp).expect("serialize");
    let decoded_resp: ProtocolHandshakeResponse =
        serde_json::from_str(&json_resp).expect("deserialize");
    assert_eq!(resp, decoded_resp);
}

#[test]
fn test_cancel_serialization_roundtrip() {
    let req = CancelTaskRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION.to_string(),
        task_id: "task-cancel-1".to_string(),
        sandbox_id: "sb-1".to_string(),
        reason: "client timeout".to_string(),
    };
    let json_req = serde_json::to_string(&req).expect("serialize");
    let decoded_req: CancelTaskRequest = serde_json::from_str(&json_req).expect("deserialize");
    assert_eq!(req, decoded_req);

    let resp = CancelTaskResponse {
        task_id: "task-cancel-1".to_string(),
        cancelled: true,
        message: Some("task aborted on GPU".to_string()),
    };
    let json_resp = serde_json::to_string(&resp).expect("serialize");
    let decoded_resp: CancelTaskResponse = serde_json::from_str(&json_resp).expect("deserialize");
    assert_eq!(resp, decoded_resp);
}

#[test]
fn test_broker_message_envelope_roundtrip() {
    let msg = BrokerMessage::TaskRequest(sample_task_request("task-env-1"));
    let json = serde_json::to_string(&msg).expect("serialize envelope");
    assert!(json.contains("\"type\":\"task_request\""));
    let decoded: BrokerMessage = serde_json::from_str(&json).expect("deserialize envelope");
    assert_eq!(msg, decoded);
}

#[test]
fn test_buffer_descriptor_validation() {
    // Empty buffer id
    let bad_buf = BufferDescriptor {
        buffer_id: "   ".to_string(),
        kind: BufferKind::HostMemory,
        size_bytes: 10,
        offset: 0,
        access: BufferAccess::ReadOnly,
        inline_data: None,
    };
    assert!(bad_buf.validate().is_err());

    // Inline length mismatch
    let mismatch_buf = BufferDescriptor {
        buffer_id: "b1".to_string(),
        kind: BufferKind::InlineBytes,
        size_bytes: 10,
        offset: 0,
        access: BufferAccess::ReadOnly,
        inline_data: Some(vec![1, 2, 3]), // 3 != 10
    };
    assert!(mismatch_buf.validate().is_err());
}

#[test]
fn test_request_validation() {
    let mut req = sample_task_request("valid");
    assert!(req.validate().is_ok());

    req.task_id = "".to_string();
    assert!(req.validate().is_err());

    req.task_id = "t".to_string();
    req.timeout_ms = 0;
    assert!(req.validate().is_err());
}

// ============================================================================
// 2. Protocol Version Negotiation Tests
// ============================================================================

#[tokio::test]
async fn test_protocol_version_negotiation_success() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let msg = read_prefixed_msg(&mut stream).await;
        if let BrokerMessage::HandshakeRequest(req) = msg {
            assert!(req
                .supported_versions
                .contains(&CURRENT_PROTOCOL_VERSION.to_string()));
            let resp = BrokerMessage::HandshakeResponse(ProtocolHandshakeResponse {
                status: "ok".to_string(),
                negotiated_version: Some(CURRENT_PROTOCOL_VERSION.to_string()),
                capabilities: vec!["nvlink_aware".to_string()],
                error_message: None,
            });
            write_prefixed_msg(&mut stream, &resp).await;
        }
    });

    let config = GpuAdapterConfig::new(addr.to_string());
    let client = GpuBrokerClient::new(config).expect("create client");
    let negotiated = client
        .negotiate_protocol()
        .await
        .expect("negotiate version");
    assert_eq!(negotiated, CURRENT_PROTOCOL_VERSION);
}

#[tokio::test]
async fn test_protocol_version_negotiation_mismatch() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let _ = read_prefixed_msg(&mut stream).await;
        let resp = BrokerMessage::HandshakeResponse(ProtocolHandshakeResponse {
            status: "ok".to_string(),
            negotiated_version: Some("overhauled.wasm.gpu.v99".to_string()), // unsupported version
            capabilities: vec![],
            error_message: None,
        });
        write_prefixed_msg(&mut stream, &resp).await;
    });

    let config = GpuAdapterConfig::new(addr.to_string());
    let client = GpuBrokerClient::new(config).expect("create client");
    let err = client.negotiate_protocol().await.unwrap_err();
    assert!(matches!(err, GpuAdapterError::VersionMismatch { .. }));
}

#[tokio::test]
async fn test_protocol_version_negotiation_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let _ = read_prefixed_msg(&mut stream).await;
        let resp = BrokerMessage::HandshakeResponse(ProtocolHandshakeResponse {
            status: "incompatible_version".to_string(),
            negotiated_version: None,
            capabilities: vec![],
            error_message: Some("broker only supports v2".to_string()),
        });
        write_prefixed_msg(&mut stream, &resp).await;
    });

    let config = GpuAdapterConfig::new(addr.to_string());
    let client = GpuBrokerClient::new(config).expect("create client");
    let err = client.negotiate_protocol().await.unwrap_err();
    assert!(matches!(err, GpuAdapterError::VersionNegotiationFailed(_)));
}

// ============================================================================
// 3. Retry and Idempotency Tests
// ============================================================================

#[tokio::test]
async fn test_retry_and_idempotency_behavior() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    let received_task_ids = Arc::new(Mutex::new(Vec::<String>::new()));
    let received_task_ids_clone = received_task_ids.clone();

    tokio::spawn(async move {
        let mut connection_count = 0;
        while let Ok((mut stream, _)) = listener.accept().await {
            connection_count += 1;
            let msg = read_prefixed_msg(&mut stream).await;
            if let BrokerMessage::TaskRequest(req) = msg {
                received_task_ids_clone
                    .lock()
                    .unwrap()
                    .push(req.task_id.clone());

                if connection_count == 1 {
                    // First attempt: return a retryable rejection
                    let resp = BrokerMessage::TaskResponse(GpuTaskResponse {
                        protocol_version: CURRENT_PROTOCOL_VERSION.to_string(),
                        task_id: req.task_id.clone(),
                        status: GpuTaskStatus::Rejected,
                        gpu_id: None,
                        execution_ms: None,
                        output_buffers: vec![],
                        error: Some(BrokerTaskError {
                            code: "GPU_BUSY".to_string(),
                            message: "all GPU streams temporarily saturated".to_string(),
                            retryable: true,
                        }),
                    });
                    write_prefixed_msg(&mut stream, &resp).await;
                } else {
                    // Second attempt: succeeds
                    let resp = BrokerMessage::TaskResponse(GpuTaskResponse {
                        protocol_version: CURRENT_PROTOCOL_VERSION.to_string(),
                        task_id: req.task_id.clone(),
                        status: GpuTaskStatus::Completed,
                        gpu_id: Some(0),
                        execution_ms: Some(15),
                        output_buffers: vec![BufferDescriptor::inline(
                            "out",
                            vec![10, 20, 30],
                            BufferAccess::WriteOnly,
                        )],
                        error: None,
                    });
                    write_prefixed_msg(&mut stream, &resp).await;
                    break;
                }
            }
        }
    });

    let mut config = GpuAdapterConfig::new(addr.to_string());
    config.retry_backoff = Duration::from_millis(10);
    config.max_retries = 3;
    let client = GpuBrokerClient::new(config).expect("create client");

    let task = sample_task_request("idempotent-task-42");
    let result = client.submit_task(&task).await.expect("submit task");

    assert_eq!(result.status, GpuTaskStatus::Completed);
    assert_eq!(result.gpu_id, Some(0));

    // Verify both attempts used the exact same task_id (idempotency preserved)
    let task_ids = received_task_ids.lock().unwrap().clone();
    assert_eq!(task_ids.len(), 2);
    assert_eq!(task_ids[0], "idempotent-task-42");
    assert_eq!(task_ids[1], "idempotent-task-42");
}

#[tokio::test]
async fn test_non_retryable_rejection_fails_fast() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let msg = read_prefixed_msg(&mut stream).await;
            if let BrokerMessage::TaskRequest(req) = msg {
                let resp = BrokerMessage::TaskResponse(GpuTaskResponse {
                    protocol_version: CURRENT_PROTOCOL_VERSION.to_string(),
                    task_id: req.task_id,
                    status: GpuTaskStatus::Rejected,
                    gpu_id: None,
                    execution_ms: None,
                    output_buffers: vec![],
                    error: Some(BrokerTaskError {
                        code: "INVALID_BUFFER_HANDLE".to_string(),
                        message: "buffer handle not found in device map".to_string(),
                        retryable: false, // Non-retryable
                    }),
                });
                write_prefixed_msg(&mut stream, &resp).await;
            }
        }
    });

    let config = GpuAdapterConfig::new(addr.to_string());
    let client = GpuBrokerClient::new(config).expect("create client");

    let task = sample_task_request("fail-fast-task");
    let err = client.submit_task(&task).await.unwrap_err();
    match err {
        GpuAdapterError::BrokerRejected {
            retryable, code, ..
        } => {
            assert!(!retryable);
            assert_eq!(code, "INVALID_BUFFER_HANDLE");
        }
        other => panic!("expected BrokerRejected, got {other:?}"),
    }
}

// ============================================================================
// 4. Cancellation Tests
// ============================================================================

#[tokio::test]
async fn test_task_cancellation() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let msg = read_prefixed_msg(&mut stream).await;
            if let BrokerMessage::CancelRequest(req) = msg {
                assert_eq!(req.task_id, "cancel-task-9");
                let resp = BrokerMessage::CancelResponse(CancelTaskResponse {
                    task_id: req.task_id,
                    cancelled: true,
                    message: Some("stream killed".to_string()),
                });
                write_prefixed_msg(&mut stream, &resp).await;
            }
        }
    });

    let config = GpuAdapterConfig::new(addr.to_string());
    let client = GpuBrokerClient::new(config).expect("create client");
    let resp = client
        .cancel_task("cancel-task-9", "sb-1", "user requested")
        .await
        .expect("cancel task");
    assert!(resp.cancelled);
    assert_eq!(resp.task_id, "cancel-task-9");
}

// ============================================================================
// 5. Sandbox Isolation & Configurable Operation Tests
// ============================================================================

#[tokio::test]
async fn test_sandbox_submit_gpu_task_disabled_by_default() {
    let sandbox = RustasmSandbox::new();
    assert!(sandbox.gpu_client().is_none());

    let err = sandbox
        .submit_gpu_task("mod", "v1", "t1", &[1, 2, 3], 1, 1000)
        .await
        .unwrap_err();
    assert!(matches!(err, GpuAdapterError::Disabled));
}

#[tokio::test]
async fn test_sandbox_submit_gpu_task_bounds_checking() {
    let sandbox = RustasmSandbox::new();
    let config = GpuAdapterConfig::new("127.0.0.1:9000");
    let client = Arc::new(GpuBrokerClient::new(config).unwrap());
    let sandbox = sandbox.with_gpu_client(client);

    // Over maximum buffer limit (64 KiB)
    let oversized = vec![0u8; 65 * 1024];
    let err = sandbox
        .submit_gpu_task("mod", "v1", "t1", &oversized, 1, 1000)
        .await
        .unwrap_err();
    assert!(matches!(err, GpuAdapterError::SandboxLimitExceeded(_)));
}

#[tokio::test]
async fn test_sandbox_submit_gpu_task_success() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let msg = read_prefixed_msg(&mut stream).await;
            if let BrokerMessage::TaskRequest(req) = msg {
                assert_eq!(req.sandbox_id, "rustasm_sandbox");
                assert_eq!(req.buffers[0].inline_data.as_ref().unwrap(), &[1, 2, 3, 4]);
                let resp = BrokerMessage::TaskResponse(GpuTaskResponse {
                    protocol_version: CURRENT_PROTOCOL_VERSION.to_string(),
                    task_id: req.task_id,
                    status: GpuTaskStatus::Completed,
                    gpu_id: Some(1),
                    execution_ms: Some(5),
                    output_buffers: vec![BufferDescriptor::inline(
                        "out",
                        vec![5, 6, 7, 8],
                        BufferAccess::WriteOnly,
                    )],
                    error: None,
                });
                write_prefixed_msg(&mut stream, &resp).await;
            }
        }
    });

    let config = GpuAdapterConfig::new(addr.to_string());
    let client = Arc::new(GpuBrokerClient::new(config).unwrap());
    let sandbox = RustasmSandbox::new().with_gpu_client(client);

    let result = sandbox
        .submit_gpu_task("mod-geo", "1.0.0", "task-sb-1", &[1, 2, 3, 4], 5, 2000)
        .await
        .expect("gpu task success");
    assert_eq!(result, vec![5, 6, 7, 8]);
}

// ============================================================================
// 6. Lifecycle: Safe Hotswapping & Drain-Before-Release Ordering
// ============================================================================

#[derive(Default)]
struct MockAppHandoffHook {
    state: Mutex<Option<Vec<u8>>>,
    export_called: AtomicBool,
    import_called: AtomicBool,
    fail_on_import: AtomicBool,
}

impl StateHandoffHook for MockAppHandoffHook {
    fn export_state(&self) -> Result<Vec<u8>, GpuAdapterError> {
        self.export_called.store(true, Ordering::SeqCst);
        let s = self.state.lock().unwrap();
        Ok(s.clone().unwrap_or_else(|| b"default_app_state".to_vec()))
    }

    fn import_state(&self, state: &[u8]) -> Result<(), GpuAdapterError> {
        self.import_called.store(true, Ordering::SeqCst);
        if self.fail_on_import.load(Ordering::SeqCst) {
            return Err(GpuAdapterError::StateHandoffFailed(
                "mock import failure".to_string(),
            ));
        }
        *self.state.lock().unwrap() = Some(state.to_vec());
        Ok(())
    }
}

#[tokio::test]
async fn test_lifecycle_drain_before_release_ordering() {
    let manager = Arc::new(ModuleLifecycleManager::new(Duration::from_secs(2)));

    // Prepare and activate v1
    let v1_handle = manager
        .prepare_version("geo_module", "1.0.0", MINIMAL_VALID_WASM, None)
        .expect("prepare v1");
    manager
        .hotswap("geo_module", "1.0.0")
        .await
        .expect("activate v1");
    assert_eq!(manager.get_active_version("geo_module").unwrap(), "1.0.0");
    assert_eq!(
        *v1_handle.state.read().unwrap(),
        ModuleLifecycleState::Active
    );

    // Prepare v2
    let v2_handle = manager
        .prepare_version("geo_module", "2.0.0", MINIMAL_VALID_WASM, None)
        .expect("prepare v2");

    // Simulate in-flight task on v1
    let task_started = Arc::new(tokio::sync::Notify::new());
    let can_task_finish = Arc::new(tokio::sync::Notify::new());
    let task_finished = Arc::new(tokio::sync::Notify::new());

    let manager_clone = manager.clone();
    let task_started_c = task_started.clone();
    let can_task_finish_c = can_task_finish.clone();
    let task_finished_c = task_finished.clone();

    tokio::spawn(async move {
        let _ = manager_clone
            .execute_task("geo_module", |handle| async move {
                assert_eq!(handle.version, "1.0.0");
                task_started_c.notify_one();
                // Block task execution until allowed to finish
                can_task_finish_c.notified().await;
                task_finished_c.notify_one();
                Ok(12345)
            })
            .await;
    });

    task_started.notified().await;
    assert_eq!(v1_handle.current_in_flight(), 1);

    // Spawn hotswap in the background while task is in-flight on v1
    let manager_for_swap = manager.clone();
    let swap_handle =
        tokio::spawn(async move { manager_for_swap.hotswap("geo_module", "2.0.0").await });

    // Allow some time for hotswap to atomically switch routing and reach quiescing phase
    sleep(Duration::from_millis(50)).await;

    // Invariant 1: Routing switched atomically to v2!
    assert_eq!(
        manager.get_active_version("geo_module").unwrap(),
        "2.0.0",
        "routing must have switched atomically to v2"
    );
    assert_eq!(
        *v2_handle.state.read().unwrap(),
        ModuleLifecycleState::Active
    );

    // Invariant 2: v1 is now Quiescing
    assert_eq!(
        *v1_handle.state.read().unwrap(),
        ModuleLifecycleState::Quiescing,
        "old module must be in Quiescing state"
    );

    // Invariant 3: DRAIN-BEFORE-RELEASE: v1 resources MUST NOT be released while task is in-flight!
    assert!(
        v1_handle.is_resources_allocated(),
        "v1 resources must NOT be released while tasks are in-flight"
    );
    assert!(
        manager.release_log().is_empty(),
        "release log must be empty before drain completes"
    );

    // Now permit the in-flight task on v1 to complete
    can_task_finish.notify_one();
    task_finished.notified().await;

    // Wait for hotswap to complete draining and release
    swap_handle.await.unwrap().expect("hotswap completed");

    // Invariant 4: v1 is now Released and resources are deallocated
    assert_eq!(
        *v1_handle.state.read().unwrap(),
        ModuleLifecycleState::Released,
        "v1 must be Released after in-flight tasks drain"
    );
    assert!(
        !v1_handle.is_resources_allocated(),
        "v1 resources must now be deallocated"
    );

    let log = manager.release_log();
    assert_eq!(log.len(), 1);
    assert!(log[0].contains("released resources for geo_module:1.0.0"));
}

// ============================================================================
// 7. Rollback on Failed Activation Tests
// ============================================================================

#[tokio::test]
async fn test_rollback_on_wasm_validation_failure() {
    let manager = ModuleLifecycleManager::default();

    // Prepare and activate v1
    manager
        .prepare_version("render_mod", "1.0.0", MINIMAL_VALID_WASM, None)
        .expect("prepare v1");
    manager
        .hotswap("render_mod", "1.0.0")
        .await
        .expect("activate v1");

    // Try to prepare an invalid WASM bytecode for v2
    let invalid_wasm = b"NOT_A_VALID_WASM_BINARY";
    let prepare_err = manager
        .prepare_version("render_mod", "2.0.0", invalid_wasm, None)
        .unwrap_err();
    assert!(matches!(prepare_err, GpuAdapterError::WasmValidation(_)));

    // Verify v1 remains active and serving without disruption
    assert_eq!(manager.get_active_version("render_mod").unwrap(), "1.0.0");
    let exec_result = manager
        .execute_task("render_mod", |h| async move {
            assert_eq!(h.version, "1.0.0");
            Ok(999)
        })
        .await
        .expect("execute on v1");
    assert_eq!(exec_result, 999);
}

#[tokio::test]
async fn test_rollback_on_failed_state_handoff() {
    let manager = ModuleLifecycleManager::default();

    let hook_v1 = Arc::new(MockAppHandoffHook::default());
    *hook_v1.state.lock().unwrap() = Some(b"weights_epoch_10".to_vec());

    manager
        .prepare_version("ml_mod", "1.0.0", MINIMAL_VALID_WASM, Some(hook_v1.clone()))
        .expect("prepare v1");
    manager
        .hotswap("ml_mod", "1.0.0")
        .await
        .expect("activate v1");

    // Prepare v2 with hook that fails on import
    let hook_v2 = Arc::new(MockAppHandoffHook::default());
    hook_v2.fail_on_import.store(true, Ordering::SeqCst);

    let v2_handle = manager
        .prepare_version("ml_mod", "2.0.0", MINIMAL_VALID_WASM, Some(hook_v2.clone()))
        .expect("prepare v2");

    // Attempt hotswap to v2
    let swap_err = manager.hotswap("ml_mod", "2.0.0").await.unwrap_err();
    assert!(matches!(swap_err, GpuAdapterError::StateHandoffFailed(_)));

    // Verify ROLLBACK guarantees:
    // 1. v2 is marked as RolledBack
    assert_eq!(
        *v2_handle.state.read().unwrap(),
        ModuleLifecycleState::RolledBack
    );

    // 2. v1 remains Active and was NOT quiesced
    assert_eq!(manager.get_active_version("ml_mod").unwrap(), "1.0.0");
    let v1_handle = manager.get_version_handle("ml_mod", "1.0.0").unwrap();
    assert_eq!(
        *v1_handle.state.read().unwrap(),
        ModuleLifecycleState::Active
    );

    // 3. v1 still handles requests normally
    let result = manager
        .execute_task("ml_mod", |h| async move {
            assert_eq!(h.version, "1.0.0");
            Ok("v1_running".to_string())
        })
        .await
        .unwrap();
    assert_eq!(result, "v1_running");
}

#[tokio::test]
async fn test_explicit_operator_rollback() {
    let manager = ModuleLifecycleManager::default();

    manager
        .prepare_version("service", "1.0.0", MINIMAL_VALID_WASM, None)
        .expect("prepare v1");
    manager
        .hotswap("service", "1.0.0")
        .await
        .expect("activate v1");
    assert_eq!(manager.get_active_version("service").unwrap(), "1.0.0");

    manager
        .prepare_version("service", "2.0.0", MINIMAL_VALID_WASM, None)
        .expect("prepare v2");
    manager
        .hotswap("service", "2.0.0")
        .await
        .expect("activate v2");
    assert_eq!(manager.get_active_version("service").unwrap(), "2.0.0");

    // Operator initiates rollback to v1
    manager
        .rollback("service", "1.0.0")
        .await
        .expect("rollback to v1");
    assert_eq!(manager.get_active_version("service").unwrap(), "1.0.0");

    let v1 = manager.get_version_handle("service", "1.0.0").unwrap();
    assert_eq!(*v1.state.read().unwrap(), ModuleLifecycleState::Active);
    assert!(v1.is_resources_allocated());
}

#[tokio::test]
async fn test_self_hotswap_is_noop_and_does_not_quiesce() {
    let manager = ModuleLifecycleManager::default();

    manager
        .prepare_version("echo_mod", "1.0.0", MINIMAL_VALID_WASM, None)
        .expect("prepare v1");
    manager
        .hotswap("echo_mod", "1.0.0")
        .await
        .expect("activate v1");

    let v1 = manager.get_version_handle("echo_mod", "1.0.0").unwrap();
    assert_eq!(*v1.state.read().unwrap(), ModuleLifecycleState::Active);
    assert!(v1.is_resources_allocated());

    // Calling hotswap with the already active version must be a no-op
    manager
        .hotswap("echo_mod", "1.0.0")
        .await
        .expect("self hotswap should succeed");

    assert_eq!(manager.get_active_version("echo_mod").unwrap(), "1.0.0");
    assert_eq!(*v1.state.read().unwrap(), ModuleLifecycleState::Active);
    assert!(
        v1.is_resources_allocated(),
        "resources must remain allocated"
    );
    assert_eq!(manager.release_log().len(), 0);
}

#[tokio::test]
async fn test_inflight_guard_decrements_on_future_cancellation() {
    let manager = Arc::new(ModuleLifecycleManager::default());

    manager
        .prepare_version("cancel_mod", "1.0.0", MINIMAL_VALID_WASM, None)
        .expect("prepare v1");
    manager
        .hotswap("cancel_mod", "1.0.0")
        .await
        .expect("activate v1");

    let v1 = manager.get_version_handle("cancel_mod", "1.0.0").unwrap();
    assert_eq!(v1.current_in_flight(), 0);

    let started = Arc::new(tokio::sync::Notify::new());
    let started_clone = started.clone();
    let manager_clone = manager.clone();

    let task_handle = tokio::spawn(async move {
        manager_clone
            .execute_task("cancel_mod", |_handle| async move {
                started_clone.notify_one();
                // Hang indefinitely
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok(())
            })
            .await
    });

    started.notified().await;
    // Counter must be 1 while task is running
    assert_eq!(v1.current_in_flight(), 1);

    // Cancel the executing task
    task_handle.abort();
    let _ = task_handle.await;

    // In-flight counter must be safely decremented to 0 by the RAII guard
    assert_eq!(
        v1.current_in_flight(),
        0,
        "in-flight counter must decrement upon cancellation"
    );
}

// ============================================================================
// 8. WSM1 & BRK1 Binary Protocol Serialization Tests
// ============================================================================

#[test]
fn test_wsm1_lifecycle_codecs_roundtrip() {
    // 1. Prepare Request & Response
    let prep_req = WasmLifecycleRequest {
        action: WasmLifecycleAction::Prepare,
        request_id: "req-prep-1".to_string(),
        sandbox_id: "sb-1".to_string(),
        module_id: "vision_mod".to_string(),
        module_version: "2.1.0".to_string(),
        target_gpu: 0,
        grace_period_ms: 0,
        ack_token: String::new(),
        payload: vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
    };

    let encoded_req = encode_wsm1_lifecycle_request(&prep_req);
    let decoded_msg = decode_wsm1_message(&encoded_req).expect("decode prepare request");
    match decoded_msg {
        Wsm1Message::LifecycleRequest(req) => {
            assert_eq!(req.action, WasmLifecycleAction::Prepare);
            assert_eq!(req.request_id, "req-prep-1");
            assert_eq!(req.sandbox_id, "sb-1");
            assert_eq!(req.module_id, "vision_mod");
            assert_eq!(req.module_version, "2.1.0");
            assert_eq!(req.target_gpu, 0);
            assert_eq!(req.payload, prep_req.payload);
        }
        _ => panic!("expected LifecycleRequest"),
    }

    let prep_resp = WasmLifecycleResponse {
        action: WasmLifecycleAction::Prepare,
        status: WasmLifecycleStatus::Ok,
        protocol_version: 1,
        state: WasmLifecycleState::Prepared,
        request_id: "req-prep-1".to_string(),
        sandbox_id: "sb-1".to_string(),
        module_id: "vision_mod".to_string(),
        module_version: "2.1.0".to_string(),
        assigned_gpu: 3,
        active_tasks: 0,
        lease_token: "lease-vision-xyz".to_string(),
        error: String::new(),
    };
    let encoded_resp = encode_wsm1_lifecycle_response(&prep_resp);
    let decoded_resp = decode_wsm1_message(&encoded_resp).expect("decode prepare response");
    match decoded_resp {
        Wsm1Message::LifecycleResponse(resp) => {
            assert_eq!(resp.action, WasmLifecycleAction::Prepare);
            assert_eq!(resp.status, WasmLifecycleStatus::Ok);
            assert_eq!(resp.state, WasmLifecycleState::Prepared);
            assert_eq!(resp.lease_token, "lease-vision-xyz");
            assert_eq!(resp.assigned_gpu, 3);
            assert_eq!(resp.error, "");
        }
        _ => panic!("expected LifecycleResponse"),
    }

    // 2. Drain and Release Request / Response
    let drain_req = WasmLifecycleRequest {
        action: WasmLifecycleAction::Drain,
        request_id: "req-drain-1".to_string(),
        sandbox_id: "sb-1".to_string(),
        module_id: "vision_mod".to_string(),
        module_version: "2.1.0".to_string(),
        target_gpu: -1,
        grace_period_ms: 1500,
        ack_token: "lease-vision-xyz".to_string(),
        payload: vec![],
    };
    let encoded_drain = encode_wsm1_lifecycle_request(&drain_req);
    match decode_wsm1_message(&encoded_drain).expect("decode drain request") {
        Wsm1Message::LifecycleRequest(req) => {
            assert_eq!(req.action, WasmLifecycleAction::Drain);
            assert_eq!(req.grace_period_ms, 1500);
            assert_eq!(req.ack_token, "lease-vision-xyz");
        }
        _ => panic!("expected LifecycleRequest"),
    }

    let rel_req = WasmLifecycleRequest {
        action: WasmLifecycleAction::Release,
        request_id: "req-rel-1".to_string(),
        sandbox_id: "sb-1".to_string(),
        module_id: "vision_mod".to_string(),
        module_version: "2.1.0".to_string(),
        target_gpu: -1,
        grace_period_ms: 0,
        ack_token: "lease-vision-xyz".to_string(),
        payload: vec![],
    };
    let encoded_rel = encode_wsm1_lifecycle_request(&rel_req);
    match decode_wsm1_message(&encoded_rel).expect("decode release request") {
        Wsm1Message::LifecycleRequest(req) => {
            assert_eq!(req.action, WasmLifecycleAction::Release);
            assert_eq!(req.ack_token, "lease-vision-xyz");
        }
        _ => panic!("expected LifecycleRequest"),
    }

    // 3. Query Request / Response
    let query_req = WasmLifecycleRequest {
        action: WasmLifecycleAction::Query,
        request_id: "req-query-1".to_string(),
        sandbox_id: "sb-1".to_string(),
        module_id: "vision_mod".to_string(),
        module_version: "2.1.0".to_string(),
        target_gpu: -1,
        grace_period_ms: 0,
        ack_token: String::new(),
        payload: vec![],
    };
    let encoded_query = encode_wsm1_lifecycle_request(&query_req);
    match decode_wsm1_message(&encoded_query).expect("decode query request") {
        Wsm1Message::LifecycleRequest(req) => {
            assert_eq!(req.action, WasmLifecycleAction::Query);
        }
        _ => panic!("expected LifecycleRequest"),
    }

    let query_resp = WasmLifecycleResponse {
        action: WasmLifecycleAction::Query,
        status: WasmLifecycleStatus::Ok,
        protocol_version: 1,
        state: WasmLifecycleState::Active,
        request_id: "req-query-1".to_string(),
        sandbox_id: "sb-1".to_string(),
        module_id: "vision_mod".to_string(),
        module_version: "2.1.0".to_string(),
        assigned_gpu: 2,
        active_tasks: 4,
        lease_token: String::new(),
        error: String::new(),
    };
    let encoded_q_resp = encode_wsm1_lifecycle_response(&query_resp);
    match decode_wsm1_message(&encoded_q_resp).expect("decode query response") {
        Wsm1Message::LifecycleResponse(resp) => {
            assert_eq!(resp.status, WasmLifecycleStatus::Ok);
            assert_eq!(resp.state, WasmLifecycleState::Active);
            assert_eq!(resp.assigned_gpu, 2);
            assert_eq!(resp.active_tasks, 4);
        }
        _ => panic!("expected LifecycleResponse"),
    }
}

#[test]
fn test_wsm1_task_codecs_roundtrip() {
    let task_req = WasmTaskRequest {
        task_id: "task-infer-99".to_string(),
        sandbox_id: "sb-1".to_string(),
        module_id: "resnet".to_string(),
        module_version: "1.0.0".to_string(),
        task_kind: "compute".to_string(),
        priority: 7,
        deadline_ms: 1700000010000,
        buffers: vec![
            WasmBufferDescriptor {
                buffer_id: 1,
                flags: 0x01,
                offset: 0,
                length: 4,
                name: "img_in".to_string(),
            },
        ],
        payload: vec![10, 20, 30, 40],
    };

    let encoded_task = encode_wsm1_task_request(&task_req);
    match decode_wsm1_message(&encoded_task).expect("decode task request") {
        Wsm1Message::TaskRequest(req) => {
            assert_eq!(req.task_id, "task-infer-99");
            assert_eq!(req.sandbox_id, "sb-1");
            assert_eq!(req.module_id, "resnet");
            assert_eq!(req.module_version, "1.0.0");
            assert_eq!(req.task_kind, "compute");
            assert_eq!(req.priority, 7);
            assert_eq!(req.deadline_ms, 1700000010000);
            assert_eq!(req.buffers.len(), 1);
            assert_eq!(req.buffers[0].name, "img_in");
            assert_eq!(req.buffers[0].buffer_id, 1);
            assert_eq!(req.payload, vec![10, 20, 30, 40]);
        }
        _ => panic!("expected TaskRequest"),
    }

    let task_resp = WasmTaskResponse {
        task_id: "task-infer-99".to_string(),
        status: WasmTaskStatus::Ok,
        protocol_version: 1,
        selected_gpu: 1,
        latency_ms: 18,
        error: String::new(),
        buffers: vec![],
        result: vec![42, 43, 44, 45],
    };

    let encoded_resp = encode_wsm1_task_response(&task_resp);
    match decode_wsm1_message(&encoded_resp).expect("decode task response") {
        Wsm1Message::TaskResponse(resp) => {
            assert_eq!(resp.task_id, "task-infer-99");
            assert_eq!(resp.status, WasmTaskStatus::Ok);
            assert_eq!(resp.selected_gpu, 1);
            assert_eq!(resp.latency_ms, 18);
            assert_eq!(resp.result, vec![42, 43, 44, 45]);
            assert_eq!(resp.error, "");
        }
        _ => panic!("expected TaskResponse"),
    }
}

#[test]
fn test_brk1_frame_envelope_roundtrip() {
    let payload = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let frame = Brk1Frame {
        msg_type: BRK1_MSG_REQUEST,
        task_id: "frame-task-01".to_string(),
        source: "client-host".to_string(),
        destination: "broker-node-0".to_string(),
        kind: "wsm1_lifecycle".to_string(),
        priority: 15,
        timeout_ms: 2500,
        payload: payload.clone(),
    };

    let encoded = encode_brk1_frame(&frame);
    let decoded = decode_brk1_frame(&encoded).expect("decode BRK1 frame");

    assert_eq!(decoded.msg_type, BRK1_MSG_REQUEST);
    assert_eq!(decoded.task_id, "frame-task-01");
    assert_eq!(decoded.source, "client-host");
    assert_eq!(decoded.destination, "broker-node-0");
    assert_eq!(decoded.kind, "wsm1_lifecycle");
    assert_eq!(decoded.priority, 15);
    assert_eq!(decoded.timeout_ms, 2500);
    assert_eq!(decoded.payload, payload);
}

#[test]
fn test_wsm1_and_brk1_malformed_rejection() {
    assert_eq!(WSM1_MAGIC, 0x57534D31);
    assert_eq!(BRK1_MAGIC, 0x42524B31);

    // Bad magic for WSM1
    let bad_wsm_magic = vec![0x11, 0x22, 0x33, 0x44, 0x00, 0x01, 0x01, 0x01];
    let err = decode_wsm1_message(&bad_wsm_magic).unwrap_err();
    assert!(matches!(err, GpuAdapterError::Wsm1Codec(_)));

    // Bad magic for BRK1
    let bad_brk_magic = vec![0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x01, 0x01, 0x00];
    let err = decode_brk1_frame(&bad_brk_magic).unwrap_err();
    assert!(matches!(err, GpuAdapterError::Wsm1Codec(_)));

    // Truncated WSM1 header
    let truncated_wsm = vec![0x57, 0x53, 0x4D, 0x31];
    let err = decode_wsm1_message(&truncated_wsm).unwrap_err();
    assert!(matches!(err, GpuAdapterError::Wsm1Codec(_)));

    // Truncated BRK1 header
    let truncated_brk = vec![0x42, 0x52, 0x4B, 0x31, 0x00];
    let err = decode_brk1_frame(&truncated_brk).unwrap_err();
    assert!(matches!(err, GpuAdapterError::Wsm1Codec(_)));
}

// ============================================================================
// 9. Mock Broker WSM1 LifecycleClient Operations Tests
// ============================================================================

#[tokio::test]
async fn test_lifecycle_client_prepare_query_drain_release() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    // Spawn mock overhauled broker handling BRK1 + WSM1 lifecycle frames
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                while let Some(frame_bytes) = read_raw_prefixed_opt(&mut stream).await {
                    let brk_frame = decode_brk1_frame(&frame_bytes).expect("decode brk1 frame");
                    let wsm_msg = decode_wsm1_message(&brk_frame.payload).expect("decode wsm1 message");

                    if let Wsm1Message::LifecycleRequest(req) = wsm_msg {
                        let resp = match req.action {
                            WasmLifecycleAction::Prepare => WasmLifecycleResponse {
                                action: req.action,
                                status: WasmLifecycleStatus::Ok,
                                protocol_version: 1,
                                state: WasmLifecycleState::Prepared,
                                request_id: req.request_id,
                                sandbox_id: req.sandbox_id,
                                module_id: req.module_id,
                                module_version: req.module_version,
                                lease_token: "lease-token-test".to_string(),
                                assigned_gpu: 1,
                                error: String::new(),
                                active_tasks: 0,
                            },
                            WasmLifecycleAction::Query => WasmLifecycleResponse {
                                action: req.action,
                                status: WasmLifecycleStatus::Ok,
                                protocol_version: 1,
                                state: WasmLifecycleState::Active,
                                request_id: req.request_id,
                                sandbox_id: req.sandbox_id,
                                module_id: req.module_id,
                                module_version: req.module_version,
                                lease_token: req.ack_token,
                                assigned_gpu: 1,
                                error: String::new(),
                                active_tasks: 2,
                            },
                            WasmLifecycleAction::Drain => WasmLifecycleResponse {
                                action: req.action,
                                status: WasmLifecycleStatus::Ok,
                                protocol_version: 1,
                                state: WasmLifecycleState::Draining,
                                request_id: req.request_id,
                                sandbox_id: req.sandbox_id,
                                module_id: req.module_id,
                                module_version: req.module_version,
                                lease_token: req.ack_token,
                                assigned_gpu: 1,
                                error: String::new(),
                                active_tasks: 0,
                            },
                            WasmLifecycleAction::Release => WasmLifecycleResponse {
                                action: req.action,
                                status: WasmLifecycleStatus::Ok,
                                protocol_version: 1,
                                state: WasmLifecycleState::Released,
                                request_id: req.request_id,
                                sandbox_id: req.sandbox_id,
                                module_id: req.module_id,
                                module_version: req.module_version,
                                lease_token: String::new(),
                                assigned_gpu: -1,
                                error: String::new(),
                                active_tasks: 0,
                            },
                        };

                        let wsm_resp_bytes = encode_wsm1_lifecycle_response(&resp);
                        let resp_brk = Brk1Frame {
                            msg_type: BRK1_MSG_RESPONSE,
                            task_id: brk_frame.task_id,
                            source: "overhauled_broker".to_string(),
                            destination: brk_frame.source,
                            kind: brk_frame.kind,
                            priority: brk_frame.priority,
                            timeout_ms: brk_frame.timeout_ms,
                            payload: wsm_resp_bytes,
                        };
                        let encoded_resp_frame = encode_brk1_frame(&resp_brk);
                        write_raw_prefixed(&mut stream, &encoded_resp_frame).await;
                    } else {
                        panic!("expected LifecycleRequest in test");
                    }
                }
            });
        }
    });

    let config = GpuAdapterConfig::new(addr.to_string());
    let mut client = LifecycleClient::new(config).expect("create lifecycle client");
    assert_eq!(client.wire_mode(), LifecycleWireMode::Auto);
    client = client.with_wire_mode(LifecycleWireMode::Auto);

    // 1. Prepare
    let prep_resp = client
        .prepare("sb_test", "mod_lifecycle", "1.0.0", 0)
        .await
        .expect("prepare succeeds");
    assert_eq!(prep_resp.status, WasmLifecycleStatus::Ok);
    assert_eq!(prep_resp.state, WasmLifecycleState::Prepared);
    assert_eq!(prep_resp.assigned_gpu, 1);
    assert_eq!(prep_resp.lease_token, "lease-token-test");

    // 2. Query
    let query_resp = client
        .query("sb_test", "mod_lifecycle", "1.0.0")
        .await
        .expect("query succeeds");
    assert_eq!(query_resp.status, WasmLifecycleStatus::Ok);
    assert_eq!(query_resp.state, WasmLifecycleState::Active);
    assert_eq!(query_resp.active_tasks, 2);

    // 3. Drain
    let drain_resp = client
        .drain("sb_test", "mod_lifecycle", "1.0.0", 2000)
        .await
        .expect("drain succeeds");
    assert_eq!(drain_resp.status, WasmLifecycleStatus::Ok);
    assert_eq!(drain_resp.state, WasmLifecycleState::Draining);

    // 4. Release
    let rel_resp = client
        .release("sb_test", "mod_lifecycle", "1.0.0", "lease-token-test")
        .await
        .expect("release succeeds");
    assert_eq!(rel_resp.status, WasmLifecycleStatus::Ok);
    assert_eq!(rel_resp.state, WasmLifecycleState::Released);
}

// ============================================================================
// 10. ModuleLifecycleManager Coordinated Hotswap with LifecycleClient
// ============================================================================

#[tokio::test]
async fn test_module_lifecycle_manager_coordinated_hotswap_with_lifecycle_client() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    let operations = Arc::new(Mutex::new(Vec::<(String, String, WasmLifecycleAction)>::new()));
    let ops_clone = operations.clone();

    tokio::spawn(async move {
        // Accept requests sequentially
        while let Ok((mut stream, _)) = listener.accept().await {
            let ops_inner = ops_clone.clone();
            tokio::spawn(async move {
                loop {
                    let mut len_buf = [0u8; 4];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        break;
                    }
                    let length = u32::from_be_bytes(len_buf) as usize;
                    let mut body = vec![0u8; length];
                    if stream.read_exact(&mut body).await.is_err() {
                        break;
                    }

                    let brk_frame = decode_brk1_frame(&body).expect("decode brk1 frame");
                    let wsm_msg = decode_wsm1_message(&brk_frame.payload).expect("decode wsm1");

                    if let Wsm1Message::LifecycleRequest(req) = wsm_msg {
                        ops_inner.lock().unwrap().push((
                            req.module_id.clone(),
                            req.module_version.clone(),
                            req.action,
                        ));

                        let resp = match req.action {
                            WasmLifecycleAction::Prepare => WasmLifecycleResponse {
                                action: req.action,
                                status: WasmLifecycleStatus::Ok,
                                protocol_version: 1,
                                state: WasmLifecycleState::Prepared,
                                request_id: req.request_id,
                                sandbox_id: req.sandbox_id,
                                module_id: req.module_id.clone(),
                                module_version: req.module_version.clone(),
                                lease_token: format!("lt-{}-{}", req.module_id, req.module_version),
                                assigned_gpu: 0,
                                error: String::new(),
                                active_tasks: 0,
                            },
                            WasmLifecycleAction::Drain => WasmLifecycleResponse {
                                action: req.action,
                                status: WasmLifecycleStatus::Ok,
                                protocol_version: 1,
                                state: WasmLifecycleState::Draining,
                                request_id: req.request_id,
                                sandbox_id: req.sandbox_id,
                                module_id: req.module_id,
                                module_version: req.module_version,
                                lease_token: req.ack_token,
                                assigned_gpu: 0,
                                error: String::new(),
                                active_tasks: 0,
                            },
                            WasmLifecycleAction::Release => WasmLifecycleResponse {
                                action: req.action,
                                status: WasmLifecycleStatus::Ok,
                                protocol_version: 1,
                                state: WasmLifecycleState::Released,
                                request_id: req.request_id,
                                sandbox_id: req.sandbox_id,
                                module_id: req.module_id,
                                module_version: req.module_version,
                                lease_token: String::new(),
                                assigned_gpu: -1,
                                error: String::new(),
                                active_tasks: 0,
                            },
                            _ => panic!("unexpected action: {:?}", req.action),
                        };

                        let wsm_resp = encode_wsm1_lifecycle_response(&resp);
                        let resp_brk = Brk1Frame {
                            msg_type: BRK1_MSG_RESPONSE,
                            task_id: brk_frame.task_id,
                            source: "overhauled_broker".to_string(),
                            destination: brk_frame.source,
                            kind: brk_frame.kind,
                            priority: brk_frame.priority,
                            timeout_ms: brk_frame.timeout_ms,
                            payload: wsm_resp,
                        };
                        let enc = encode_brk1_frame(&resp_brk);
                        write_raw_prefixed(&mut stream, &enc).await;
                    }
                }
            });
        }
    });

    let config = GpuAdapterConfig::new(addr.to_string());
    let lifecycle_client = Arc::new(LifecycleClient::new(config).expect("create client"));

    let manager = ModuleLifecycleManager::default().with_lifecycle_client(lifecycle_client);

    // Prepare and activate v1
    manager
        .prepare_version("pipeline", "1.0.0", MINIMAL_VALID_WASM, None)
        .expect("prepare v1");
    manager
        .hotswap("pipeline", "1.0.0")
        .await
        .expect("activate v1");
    assert_eq!(manager.get_active_version("pipeline").unwrap(), "1.0.0");

    // Prepare and hotswap to v2
    manager
        .prepare_version("pipeline", "2.0.0", MINIMAL_VALID_WASM, None)
        .expect("prepare v2");
    manager
        .hotswap("pipeline", "2.0.0")
        .await
        .expect("hotswap to v2");

    assert_eq!(manager.get_active_version("pipeline").unwrap(), "2.0.0");

    // Verify v1 resources are released locally
    let v1_handle = manager.get_version_handle("pipeline", "1.0.0").unwrap();
    assert_eq!(
        *v1_handle.state.read().unwrap(),
        ModuleLifecycleState::Released
    );

    // Verify broker operations occurred in exact coordinated order:
    // 1. Prepare v1 (during v1 hotswap)
    // 2. Prepare v2 (during v2 hotswap)
    // 3. Drain v1 (quiesce old version)
    // 4. Release v1 (broker release old version)
    let recorded_ops = operations.lock().unwrap().clone();
    assert_eq!(recorded_ops.len(), 4);
    assert_eq!(
        recorded_ops[0],
        ("pipeline".to_string(), "1.0.0".to_string(), WasmLifecycleAction::Prepare)
    );
    assert_eq!(
        recorded_ops[1],
        ("pipeline".to_string(), "2.0.0".to_string(), WasmLifecycleAction::Prepare)
    );
    assert_eq!(
        recorded_ops[2],
        ("pipeline".to_string(), "1.0.0".to_string(), WasmLifecycleAction::Drain)
    );
    assert_eq!(
        recorded_ops[3],
        ("pipeline".to_string(), "1.0.0".to_string(), WasmLifecycleAction::Release)
    );
}

#[tokio::test]
async fn test_module_lifecycle_manager_hotswap_rollback_on_broker_prepare_error() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                while let Ok(Some(frame_bytes)) = tokio::time::timeout(
                    Duration::from_secs(2),
                    read_raw_prefixed_opt(&mut stream),
                )
                .await
                {
                    let brk_frame = decode_brk1_frame(&frame_bytes).expect("decode brk1");
                    let wsm_msg = decode_wsm1_message(&brk_frame.payload).expect("decode wsm1");

                    if let Wsm1Message::LifecycleRequest(req) = wsm_msg {
                        let resp = if req.module_version == "1.0.0" {
                            WasmLifecycleResponse {
                                action: req.action,
                                status: WasmLifecycleStatus::Ok,
                                protocol_version: 1,
                                state: WasmLifecycleState::Prepared,
                                request_id: req.request_id,
                                sandbox_id: req.sandbox_id,
                                module_id: req.module_id,
                                module_version: req.module_version,
                                lease_token: "lease-v1".to_string(),
                                assigned_gpu: 0,
                                error: String::new(),
                                active_tasks: 0,
                            }
                        } else {
                            // Reject v2 prepare at broker
                            WasmLifecycleResponse {
                                action: req.action,
                                status: WasmLifecycleStatus::Error,
                                protocol_version: 1,
                                state: WasmLifecycleState::Stopped,
                                request_id: req.request_id,
                                sandbox_id: req.sandbox_id,
                                module_id: req.module_id,
                                module_version: req.module_version,
                                lease_token: String::new(),
                                assigned_gpu: -1,
                                error: "GPU out of memory on broker".to_string(),
                                active_tasks: 0,
                            }
                        };

                        let wsm_resp = encode_wsm1_lifecycle_response(&resp);
                        let resp_brk = Brk1Frame {
                            msg_type: BRK1_MSG_RESPONSE,
                            task_id: brk_frame.task_id,
                            source: "overhauled_broker".to_string(),
                            destination: brk_frame.source,
                            kind: brk_frame.kind,
                            priority: brk_frame.priority,
                            timeout_ms: brk_frame.timeout_ms,
                            payload: wsm_resp,
                        };
                        let enc = encode_brk1_frame(&resp_brk);
                        write_raw_prefixed(&mut stream, &enc).await;
                    }
                }
            });
        }
    });

    let config = GpuAdapterConfig::new(addr.to_string());
    let lifecycle_client = Arc::new(LifecycleClient::new(config).expect("create client"));

    let manager = ModuleLifecycleManager::default().with_lifecycle_client(lifecycle_client);

    manager
        .prepare_version("ai_worker", "1.0.0", MINIMAL_VALID_WASM, None)
        .expect("prepare v1");
    manager
        .hotswap("ai_worker", "1.0.0")
        .await
        .expect("activate v1");

    manager
        .prepare_version("ai_worker", "2.0.0", MINIMAL_VALID_WASM, None)
        .expect("prepare v2");

    let err = manager
        .hotswap("ai_worker", "2.0.0")
        .await
        .unwrap_err();

    assert!(matches!(err, GpuAdapterError::LifecycleOperationFailed { .. }));
    // v1 remains active!
    assert_eq!(manager.get_active_version("ai_worker").unwrap(), "1.0.0");
    let v2_handle = manager.get_version_handle("ai_worker", "2.0.0").unwrap();
    assert_eq!(
        *v2_handle.state.read().unwrap(),
        ModuleLifecycleState::RolledBack
    );
}

#[tokio::test]
async fn test_module_lifecycle_manager_hotswap_broker_release_on_handoff_failure() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    let released = Arc::new(AtomicBool::new(false));
    let rel_clone = released.clone();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let rel_inner = rel_clone.clone();
            tokio::spawn(async move {
                while let Ok(Some(frame_bytes)) = tokio::time::timeout(
                    Duration::from_secs(2),
                    read_raw_prefixed_opt(&mut stream),
                )
                .await
                {
                    let brk_frame = decode_brk1_frame(&frame_bytes).expect("decode brk1");
                    let wsm_msg = decode_wsm1_message(&brk_frame.payload).expect("decode wsm1");

                    if let Wsm1Message::LifecycleRequest(req) = wsm_msg {
                        let resp = match req.action {
                            WasmLifecycleAction::Prepare => WasmLifecycleResponse {
                                action: req.action,
                                status: WasmLifecycleStatus::Ok,
                                protocol_version: 1,
                                state: WasmLifecycleState::Prepared,
                                request_id: req.request_id,
                                sandbox_id: req.sandbox_id,
                                module_id: req.module_id,
                                module_version: req.module_version,
                                lease_token: "lease-v2-rollback".to_string(),
                                assigned_gpu: 0,
                                error: String::new(),
                                active_tasks: 0,
                            },
                            WasmLifecycleAction::Release => {
                                rel_inner.store(true, Ordering::SeqCst);
                                assert_eq!(req.ack_token, "lease-v2-rollback");
                                WasmLifecycleResponse {
                                    action: req.action,
                                    status: WasmLifecycleStatus::Ok,
                                    protocol_version: 1,
                                    state: WasmLifecycleState::Released,
                                    request_id: req.request_id,
                                    sandbox_id: req.sandbox_id,
                                    module_id: req.module_id,
                                    module_version: req.module_version,
                                    lease_token: String::new(),
                                    assigned_gpu: -1,
                                    error: String::new(),
                                    active_tasks: 0,
                                }
                            }
                            _ => panic!("unexpected action: {:?}", req.action),
                        };

                        let wsm_resp = encode_wsm1_lifecycle_response(&resp);
                        let resp_brk = Brk1Frame {
                            msg_type: BRK1_MSG_RESPONSE,
                            task_id: brk_frame.task_id,
                            source: "overhauled_broker".to_string(),
                            destination: brk_frame.source,
                            kind: brk_frame.kind,
                            priority: brk_frame.priority,
                            timeout_ms: brk_frame.timeout_ms,
                            payload: wsm_resp,
                        };
                        let enc = encode_brk1_frame(&resp_brk);
                        write_raw_prefixed(&mut stream, &enc).await;
                    }
                }
            });
        }
    });

    let config = GpuAdapterConfig::new(addr.to_string());
    let lifecycle_client = Arc::new(LifecycleClient::new(config).expect("create client"));

    let hook_v1 = Arc::new(MockAppHandoffHook::default());
    let failing_hook = Arc::new(MockAppHandoffHook::default());
    failing_hook.fail_on_import.store(true, Ordering::SeqCst);

    let manager = ModuleLifecycleManager::default()
        .with_lifecycle_client(lifecycle_client);

    manager
        .prepare_version("faulty_mod", "1.0.0", MINIMAL_VALID_WASM, Some(hook_v1))
        .expect("prepare v1");
    manager
        .hotswap("faulty_mod", "1.0.0")
        .await
        .expect("activate v1");

    manager
        .prepare_version("faulty_mod", "2.0.0", MINIMAL_VALID_WASM, Some(failing_hook))
        .expect("prepare v2");

    let err = manager
        .hotswap("faulty_mod", "2.0.0")
        .await
        .unwrap_err();

    assert!(matches!(err, GpuAdapterError::StateHandoffFailed(_)));
    // Broker release must have been sent to cancel the prepared lease!
    sleep(Duration::from_millis(50)).await;
    assert!(
        released.load(Ordering::SeqCst),
        "broker release must be sent when state handoff fails"
    );
}

// ============================================================================
// 11. RustasmSandbox WSM1 Task Submission & Fallback Tests
// ============================================================================

#[tokio::test]
async fn test_sandbox_submit_gpu_task_wsm1_success() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let frame_bytes = read_raw_prefixed(&mut stream).await;
            let brk_frame = decode_brk1_frame(&frame_bytes).expect("decode brk1 frame");
            let wsm_msg = decode_wsm1_message(&brk_frame.payload).expect("decode wsm1 message");

            if let Wsm1Message::TaskRequest(req) = wsm_msg {
                assert_eq!(req.module_id, "vision_wsm1");
                assert_eq!(req.module_version, "3.0.0");
                assert_eq!(req.payload, vec![1, 2, 3, 4]);

                let task_resp = WasmTaskResponse {
                    task_id: req.task_id,
                    status: WasmTaskStatus::Ok,
                    protocol_version: 1,
                    selected_gpu: 0,
                    latency_ms: 12,
                    error: String::new(),
                    buffers: vec![],
                    result: vec![99, 100, 101],
                };
                let wsm_resp = encode_wsm1_task_response(&task_resp);
                let resp_brk = Brk1Frame {
                    msg_type: BRK1_MSG_RESPONSE,
                    task_id: brk_frame.task_id,
                    source: "overhauled_broker".to_string(),
                    destination: brk_frame.source,
                    kind: brk_frame.kind,
                    priority: brk_frame.priority,
                    timeout_ms: brk_frame.timeout_ms,
                    payload: wsm_resp,
                };
                let enc = encode_brk1_frame(&resp_brk);
                write_raw_prefixed(&mut stream, &enc).await;
            }
        }
    });

    let config = GpuAdapterConfig::new(addr.to_string());
    let lifecycle_client = Arc::new(LifecycleClient::new(config).expect("create client"));

    let sandbox = RustasmSandbox::new().with_lifecycle_client(lifecycle_client);

    let result = sandbox
        .submit_gpu_task("vision_wsm1", "3.0.0", "task-wsm-1", &[1, 2, 3, 4], 5, 2000)
        .await
        .expect("wsm1 task submission succeeds");
    assert_eq!(result, vec![99, 100, 101]);
}

#[tokio::test]
async fn test_sandbox_submit_gpu_task_fallback_to_json() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        // Accept and handle handshake if any, and task requests in JSON format
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                loop {
                    let mut len_buf = [0u8; 4];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        break;
                    }
                    let length = u32::from_be_bytes(len_buf) as usize;
                    let mut body = vec![0u8; length];
                    if stream.read_exact(&mut body).await.is_err() {
                        break;
                    }

                    // If JSON received
                    if let Ok(msg) = serde_json::from_slice::<BrokerMessage>(&body) {
                        match msg {
                            BrokerMessage::HandshakeRequest(_req) => {
                                let resp = BrokerMessage::HandshakeResponse(
                                    ProtocolHandshakeResponse {
                                        status: "ok".to_string(),
                                        negotiated_version: Some(CURRENT_PROTOCOL_VERSION.to_string()),
                                        capabilities: vec![],
                                        error_message: None,
                                    },
                                );
                                write_prefixed_msg(&mut stream, &resp).await;
                            }
                            BrokerMessage::TaskRequest(req) => {
                                let resp = BrokerMessage::TaskResponse(GpuTaskResponse {
                                    protocol_version: CURRENT_PROTOCOL_VERSION.to_string(),
                                    task_id: req.task_id,
                                    status: GpuTaskStatus::Completed,
                                    gpu_id: Some(0),
                                    execution_ms: Some(8),
                                    output_buffers: vec![BufferDescriptor::inline(
                                        "out",
                                        vec![77, 88, 99],
                                        BufferAccess::WriteOnly,
                                    )],
                                    error: None,
                                });
                                write_prefixed_msg(&mut stream, &resp).await;
                            }
                            _ => {}
                        }
                    }
                }
            });
        }
    });

    let config = GpuAdapterConfig::new(addr.to_string());
    // Create GpuBrokerClient directly for JSON fallback test
    let gpu_client = Arc::new(GpuBrokerClient::new(config).expect("create client"));

    let sandbox = RustasmSandbox::new().with_gpu_client(gpu_client);

    let result = sandbox
        .submit_gpu_task("legacy_mod", "1.0.0", "task-fallback-1", &[10, 20], 3, 2000)
        .await
        .expect("json task submission succeeds");
    assert_eq!(result, vec![77, 88, 99]);
}
