//! Browser-specific use of YuKKi-OS's existing CPU-first GPU/NPU policy.
//!
//! WebKit owns page rasterization and WebGL/WebGPU device selection. This
//! scheduler is for optional browser-adjacent compute (for example, RGBA tile
//! transforms) and model inference; it does not replace the WebView renderer.

use std::{env, sync::Arc, time::Instant};

use yukkios::{
    exec_policy::{BackendAvailability, BackendPolicy, ExecutionBackend, TaskProfile},
    gpu_adapter::{
        GpuAdapterConfig, GpuAdapterError, LifecycleClient, LifecycleWireMode,
        WasmBufferDescriptor, WasmTaskRequest, WasmTaskStatus,
    },
    WorkerDirective,
};

pub const MAX_GRAPHICS_PAYLOAD_BYTES: usize = 64 * 1024;
const DEFAULT_PRIORITY: u8 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceleratorStatus {
    pub broker_configured: bool,
    pub gpu_module_configured: bool,
    /// Operator opt-in plus broker configuration, not a hardware attestation.
    pub npu_opted_in: bool,
    pub cpu_forced: bool,
    pub gpu_offload_threshold_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct GraphicsComputeReport {
    pub requested_backend: ExecutionBackend,
    /// The GPU value is set only when BRK2 response field 7 says "gpu".
    pub actual_backend: ExecutionBackend,
    pub elapsed_ms: u128,
    pub output: Vec<u8>,
    pub fallback_reason: Option<String>,
    pub broker_queue_wait_us: Option<u64>,
    pub broker_service_time_us: Option<u64>,
    pub broker_worker_id: Option<u32>,
}

pub struct BrowserAcceleratorScheduler {
    client: Option<Arc<LifecycleClient>>,
    policy: BackendPolicy,
    graphics_module_id: Option<String>,
    graphics_module_version: Option<String>,
    npu_opted_in: bool,
}

impl BrowserAcceleratorScheduler {
    pub fn from_env() -> Result<Self, String> {
        let config = GpuAdapterConfig::from_env().map_err(|error| error.to_string())?;
        let client = if config.enabled {
            Some(Arc::new(
                LifecycleClient::new(config)
                    .map_err(|error| error.to_string())?
                    .with_wire_mode(LifecycleWireMode::Brk2),
            ))
        } else {
            None
        };

        let graphics_module_id = bounded_env("YUKKI_BROWSER_GRAPHICS_MODULE_ID", 128)?;
        let graphics_module_version = bounded_env("YUKKI_BROWSER_GRAPHICS_MODULE_VERSION", 64)?;
        let npu_opted_in = env_flag("YUKKI_NPU_AVAILABLE") && client.is_some();

        Ok(Self {
            client,
            policy: BackendPolicy::from_env(),
            graphics_module_id,
            graphics_module_version,
            npu_opted_in,
        })
    }

    pub fn status(&self) -> AcceleratorStatus {
        let broker_configured = self.client.is_some();
        let gpu_module_configured =
            broker_configured && self.graphics_module_id.is_some() && self.graphics_module_version.is_some();
        AcceleratorStatus {
            broker_configured,
            gpu_module_configured,
            npu_opted_in: self.npu_opted_in,
            cpu_forced: !self.policy.accelerators_allowed,
            gpu_offload_threshold_bytes: self.policy.offload_threshold_bytes,
        }
    }

    fn availability(&self) -> BackendAvailability {
        let status = self.status();
        BackendAvailability {
            gpu: status.gpu_module_configured,
            npu: status.npu_opted_in,
            remote: false,
        }
    }

    pub fn select_graphics_backend(&self, estimated_bytes: usize) -> ExecutionBackend {
        let profile = TaskProfile {
            is_data_parallel: true,
            estimated_bytes,
            estimated_flops: (estimated_bytes as u64).saturating_mul(3),
            cpu_retry_safe: true,
            ..TaskProfile::default()
        };
        self.policy.select(&profile, self.availability())
    }

    /// Run a bounded RGBA8 transform. GPU work requires an operator-provided,
    /// already-activated Overhauled WSM1 module implementing the documented
    /// byte contract. Any non-GPU or unattested response falls back to the
    /// identical local CPU reference implementation.
    pub async fn run_rgba_invert(
        &self,
        task_id: &str,
        rgba8: &[u8],
    ) -> Result<GraphicsComputeReport, String> {
        validate_rgba_payload(rgba8)?;
        let started = Instant::now();
        let requested_backend = self.select_graphics_backend(rgba8.len());

        if requested_backend != ExecutionBackend::Gpu {
            return Ok(cpu_report(requested_backend, rgba8, started, None));
        }

        let Some(client) = self.client.as_ref() else {
            return Ok(cpu_report(
                requested_backend,
                rgba8,
                started,
                Some("broker is not configured".to_owned()),
            ));
        };
        let module_id = self.graphics_module_id.as_deref().ok_or_else(|| {
            "GPU graphics module ID is not configured".to_owned()
        })?;
        let module_version = self.graphics_module_version.as_deref().ok_or_else(|| {
            "GPU graphics module version is not configured".to_owned()
        })?;

        let task = WasmTaskRequest {
            task_id: bounded_task_id(task_id)?,
            sandbox_id: "yukki-browser".to_owned(),
            module_id: module_id.to_owned(),
            module_version: module_version.to_owned(),
            task_kind: "compute".to_owned(),
            priority: DEFAULT_PRIORITY,
            deadline_ms: 0,
            buffers: vec![WasmBufferDescriptor {
                buffer_id: 1,
                flags: 1,
                offset: 0,
                length: rgba8.len() as u64,
                name: "rgba8_input".to_owned(),
            }],
            payload: rgba8.to_vec(),
        };

        let broker_result = client
            .submit_wsm1_task_with_device_preference(
                &task,
                &WorkerDirective::throughput(),
                "gpu",
            )
            .await;

        match broker_result {
            Ok(execution)
                if execution.response.status == WasmTaskStatus::Ok
                    && execution.backend.as_deref() == Some("gpu")
                    && execution.response.result.len() == rgba8.len() =>
            {
                let telemetry = execution.worker_telemetry;
                Ok(GraphicsComputeReport {
                    requested_backend,
                    actual_backend: ExecutionBackend::Gpu,
                    elapsed_ms: started.elapsed().as_millis(),
                    output: execution.response.result,
                    fallback_reason: None,
                    broker_queue_wait_us: telemetry.as_ref().map(|value| value.queue_wait_us),
                    broker_service_time_us: telemetry.as_ref().map(|value| value.service_time_us),
                    broker_worker_id: telemetry.as_ref().map(|value| value.worker_id),
                })
            }
            Ok(execution) => {
                let reason = match execution.backend.as_deref() {
                    Some(backend) => format!("broker selected '{backend}', not the requested GPU"),
                    None => "broker did not attest the execution backend".to_owned(),
                };
                Ok(cpu_report(
                    requested_backend,
                    rgba8,
                    started,
                    Some(reason),
                ))
            }
            Err(error) => Ok(cpu_report(
                requested_backend,
                rgba8,
                started,
                Some(error.to_string()),
            )),
        }
    }

    /// Submit a model-specific inference tensor to the optional NPU backend.
    /// The payload must match the operator's active YU85 bundle. This method
    /// never claims NPU execution unless BRK2 response field 7 says "npu".
    pub async fn run_npu_inference(
        &self,
        task_id: &str,
        tensor_payload: &[u8],
    ) -> Result<GraphicsComputeReport, String> {
        if tensor_payload.is_empty() || tensor_payload.len() > MAX_GRAPHICS_PAYLOAD_BYTES {
            return Err(format!(
                "NPU probe payload must be 1..={MAX_GRAPHICS_PAYLOAD_BYTES} bytes"
            ));
        }
        let profile = TaskProfile {
            is_inference: true,
            estimated_bytes: tensor_payload.len(),
            cpu_retry_safe: false,
            ..TaskProfile::default()
        };
        let requested_backend = self.policy.select(&profile, self.availability());
        if requested_backend != ExecutionBackend::Npu {
            return Err("NPU is not selected: enable YUKKI_NPU_AVAILABLE and configure the broker without forcing CPU".to_owned());
        }
        let client = self.client.as_ref().ok_or_else(|| "broker is not configured".to_owned())?;
        let started = Instant::now();
        let execution = client
            .submit_inference_task_with_preference(
                &bounded_task_id(task_id)?,
                tensor_payload,
                DEFAULT_PRIORITY,
                30_000,
                "npu",
            )
            .await
            .map_err(|error| error.to_string())?;
        if execution.backend.as_deref() != Some("npu") {
            return Err(format!(
                "NPU request was not attested as NPU execution (reported backend: {})",
                execution.backend.as_deref().unwrap_or("unknown")
            ));
        }
        let telemetry = execution.worker_telemetry;
        Ok(GraphicsComputeReport {
            requested_backend,
            actual_backend: ExecutionBackend::Npu,
            elapsed_ms: started.elapsed().as_millis(),
            output: execution.result,
            fallback_reason: None,
            broker_queue_wait_us: telemetry.as_ref().map(|value| value.queue_wait_us),
            broker_service_time_us: telemetry.as_ref().map(|value| value.service_time_us),
            broker_worker_id: telemetry.as_ref().map(|value| value.worker_id),
        })
    }
}

fn cpu_report(
    requested_backend: ExecutionBackend,
    rgba8: &[u8],
    started: Instant,
    fallback_reason: Option<String>,
) -> GraphicsComputeReport {
    GraphicsComputeReport {
        requested_backend,
        actual_backend: ExecutionBackend::Cpu,
        elapsed_ms: started.elapsed().as_millis(),
        output: rgba_invert_cpu(rgba8),
        fallback_reason,
        broker_queue_wait_us: None,
        broker_service_time_us: None,
        broker_worker_id: None,
    }
}

pub fn rgba_invert_cpu(rgba8: &[u8]) -> Vec<u8> {
    let mut output = rgba8.to_vec();
    for pixel in output.chunks_exact_mut(4) {
        pixel[0] = 255 - pixel[0];
        pixel[1] = 255 - pixel[1];
        pixel[2] = 255 - pixel[2];
        // Alpha is intentionally preserved.
    }
    output
}

fn validate_rgba_payload(rgba8: &[u8]) -> Result<(), String> {
    if rgba8.is_empty() || rgba8.len() > MAX_GRAPHICS_PAYLOAD_BYTES || rgba8.len() % 4 != 0 {
        return Err(format!(
            "RGBA8 payload must be non-empty, divisible by four, and no larger than {MAX_GRAPHICS_PAYLOAD_BYTES} bytes"
        ));
    }
    Ok(())
}

fn bounded_env(name: &str, max_bytes: usize) -> Result<Option<String>, String> {
    let Some(value) = env::var_os(name) else {
        return Ok(None);
    };
    let value = value
        .into_string()
        .map_err(|_| format!("{name} must be valid UTF-8"))?;
    if value.trim().is_empty() {
        return Ok(None);
    }
    if value.len() > max_bytes {
        return Err(format!("{name} exceeds {max_bytes} bytes"));
    }
    Ok(Some(value))
}

fn bounded_task_id(value: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > 128 || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)) {
        return Err("task ID must contain 1..=128 ASCII letters, digits, '-', '_' or '.'".to_owned());
    }
    Ok(value.to_owned())
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rgba_cpu_reference_preserves_alpha_and_inverts_rgb() {
        assert_eq!(
            rgba_invert_cpu(&[0, 16, 255, 7, 255, 128, 1, 255]),
            vec![255, 239, 0, 7, 0, 127, 254, 255]
        );
    }

    #[test]
    fn rgba_payload_is_bounded_and_aligned() {
        assert!(validate_rgba_payload(&[1, 2, 3, 4]).is_ok());
        assert!(validate_rgba_payload(&[]).is_err());
        assert!(validate_rgba_payload(&[1, 2, 3]).is_err());
        assert!(validate_rgba_payload(&vec![0; MAX_GRAPHICS_PAYLOAD_BYTES + 4]).is_err());
    }

    #[test]
    fn task_ids_are_bounded_and_ascii_safe() {
        assert!(bounded_task_id("browser.gfx.1").is_ok());
        assert!(bounded_task_id("../bad").is_err());
        assert!(bounded_task_id(&"x".repeat(129)).is_err());
    }
}
