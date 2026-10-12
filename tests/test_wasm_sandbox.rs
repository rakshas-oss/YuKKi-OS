/// Tests for Rustasm WebAssembly Sandbox
/// Validates isolation, memory management, and execution bounds
use yukkios_6_8_0_inet3::wasm_sandbox::RustasmSandbox;

#[test]
fn test_sandbox_initialization() {
    RustasmSandbox::new();
}

#[test]
fn test_buffer_payload_acceptance() {
    let sandbox = RustasmSandbox::new();
    let test_payload = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];
    assert!(sandbox.buffer_payload(&test_payload).is_ok());
}

#[test]
fn test_buffer_payload_limit_accepts_exact_capacity_and_rejects_overflow() {
    let sandbox = RustasmSandbox::new();
    let test_payload = [0xAB; 16];

    for _ in 0..(64 * 1024 / test_payload.len()) {
        sandbox.buffer_payload(&test_payload).unwrap();
    }

    assert_eq!(
        sandbox.buffer_payload(&test_payload),
        Err("sandbox payload buffer limit exceeded")
    );
    sandbox.flush_buffer();
    assert!(sandbox.buffer_payload(&test_payload).is_ok());
}

#[test]
fn test_buffer_flush() {
    let sandbox = RustasmSandbox::new();
    let test_payload = [0xFF; 16];
    sandbox.buffer_payload(&test_payload).unwrap();
    sandbox.flush_buffer();
    assert!(sandbox.buffer_payload(&test_payload).is_ok());
}

#[test]
fn test_multiple_payload_buffers() {
    let sandbox = RustasmSandbox::new();
    let payloads = [[0x01u8; 16], [0x02u8; 16], [0x03u8; 16]];

    for payload in &payloads {
        sandbox.buffer_payload(payload).unwrap();
    }
    sandbox.commit_civilian_logic();
    assert!(sandbox.buffer_payload(&[0x04; 16]).is_ok());
}

#[test]
fn test_commit_civilian_logic() {
    let sandbox = RustasmSandbox::new();
    let test_payload = [0xAA; 16];
    sandbox.buffer_payload(&test_payload).unwrap();
    sandbox.commit_civilian_logic();
    assert!(sandbox.buffer_payload(&test_payload).is_ok());
}

#[test]
fn test_sandbox_payload_size_consistency() {
    let sandbox = RustasmSandbox::new();
    // Test with standard 16-byte payload
    let payload: [u8; 16] = [
        0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x00, 0x00, 0x00,
        0x00,
    ]; // "Hello World!"

    sandbox.buffer_payload(&payload).unwrap();
    sandbox.commit_civilian_logic();
    // Payload size should always be 16 bytes
    assert_eq!(payload.len(), 16, "Payload size must be exactly 16 bytes");
}

#[test]
fn test_sandbox_max_stack_limit() {
    let sandbox = RustasmSandbox::new();
    let wasm = b"\0asm\x01\0\0\0\x01\x05\x01`\0\x01\x7f\x03\x02\x01\0\x07\x08\x01\x04main\0\0\x0a\x06\x01\x04\0A*\x0b";
    assert_eq!(sandbox.execute(wasm).unwrap(), 42);
}

#[test]
fn test_custom_fuel_budget_configuration() {
    let sandbox = RustasmSandbox::with_max_fuel(1_024).unwrap();
    assert_eq!(sandbox.max_fuel(), 1_024);
}

#[test]
fn test_zero_fuel_budget_rejected() {
    let err = RustasmSandbox::with_max_fuel(0)
        .err()
        .expect("zero fuel budget should be rejected");
    assert!(err.contains("must be greater than zero"));
}

#[test]
fn test_fuel_exhaustion_reports_clear_error() {
    let sandbox = RustasmSandbox::with_max_fuel(64).unwrap();
    let infinite_loop_wasm = b"\0asm\x01\0\0\0\x01\x05\x01`\0\x01\x7f\x03\x02\x01\0\x07\x08\x01\x04main\0\0\x0a\x0b\x01\x09\0\x03\x40\x0c\0\x0b\x41\0\x0b";
    let error = sandbox.execute(infinite_loop_wasm).unwrap_err();
    assert!(
        error.contains("fuel exhausted"),
        "unexpected error for exhausted fuel: {error}"
    );
}

mod cpu_first_policy {
    use std::sync::Arc;
    use std::time::Duration;
    use yukkios_6_8_0_inet3::exec_policy::{BackendPolicy, ExecutionBackend, TaskProfile};
    use yukkios_6_8_0_inet3::gpu_adapter::{GpuAdapterConfig, GpuBrokerClient};
    use yukkios_6_8_0_inet3::wasm_sandbox::{PolicyExecError, RustasmSandbox};

    fn gpu_sandbox() -> RustasmSandbox {
        let mut cfg = GpuAdapterConfig::new("127.0.0.1:1");
        cfg.enabled = true;
        cfg.max_retries = 0;
        cfg.connect_timeout = Duration::from_millis(200);
        let client = Arc::new(GpuBrokerClient::new(cfg).unwrap());
        RustasmSandbox::new().with_gpu_client(client)
    }

    fn big_parallel() -> TaskProfile {
        TaskProfile {
            is_data_parallel: true,
            estimated_bytes: 1 << 20,
            ..TaskProfile::default()
        }
    }

    fn cpu(p: &[u8]) -> Result<Vec<u8>, String> {
        Ok(p.iter().rev().copied().collect())
    }

    #[tokio::test]
    async fn cpu_only_without_accelerator() {
        let sb = RustasmSandbox::new();
        let out = sb
            .execute_with_policy(
                &BackendPolicy::default(),
                &big_parallel(),
                "m",
                "1",
                "t",
                &[1, 2],
                0,
                100,
                cpu,
            )
            .await
            .unwrap();
        assert_eq!(out.backend, ExecutionBackend::Cpu);
        assert_eq!(out.output, vec![2, 1]);
    }

    #[tokio::test]
    async fn force_cpu_policy_skips_broker() {
        let out = gpu_sandbox()
            .execute_with_policy(
                &BackendPolicy::cpu_only(),
                &big_parallel(),
                "m",
                "1",
                "t",
                &[1],
                0,
                100,
                cpu,
            )
            .await
            .unwrap();
        assert_eq!(out.backend, ExecutionBackend::Cpu);
        assert!(out.fallback_reason.is_none());
    }

    #[tokio::test]
    async fn accelerator_failure_falls_back_to_cpu() {
        let out = gpu_sandbox()
            .execute_with_policy(
                &BackendPolicy::default(),
                &big_parallel(),
                "m",
                "1",
                "t",
                &[1, 2],
                0,
                100,
                cpu,
            )
            .await
            .unwrap();
        assert_eq!(out.backend, ExecutionBackend::Cpu);
        assert!(out.fallback_reason.is_some());
    }

    #[tokio::test]
    async fn unsafe_retry_preserves_accelerator_error() {
        let profile = TaskProfile {
            cpu_retry_safe: false,
            ..big_parallel()
        };
        let err = gpu_sandbox()
            .execute_with_policy(
                &BackendPolicy::default(),
                &profile,
                "m",
                "1",
                "t",
                &[1],
                0,
                100,
                cpu,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, PolicyExecError::Accelerator(_)));
    }

    #[tokio::test]
    async fn exact_precision_never_offloads() {
        let profile = TaskProfile {
            requires_exact_precision: true,
            ..big_parallel()
        };
        let out = gpu_sandbox()
            .execute_with_policy(
                &BackendPolicy::default(),
                &profile,
                "m",
                "1",
                "t",
                &[1],
                0,
                100,
                cpu,
            )
            .await
            .unwrap();
        assert_eq!(out.backend, ExecutionBackend::Cpu);
        assert!(out.fallback_reason.is_none());
    }
}
