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
use yukkios_6_7_0_inet3::{
    gpu_adapter::{
        BrokerMessage, BrokerTaskError, BufferAccess, BufferDescriptor, BufferKind,
        CancelTaskRequest, CancelTaskResponse, GpuAdapterConfig, GpuAdapterError, GpuBrokerClient,
        GpuTaskRequest, GpuTaskResponse, GpuTaskStatus, ModuleLifecycleManager,
        ModuleLifecycleState, ProtocolHandshakeRequest, ProtocolHandshakeResponse,
        StateHandoffHook, CURRENT_PROTOCOL_VERSION,
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
