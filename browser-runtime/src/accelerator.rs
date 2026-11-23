//! Browser-specific use of YuKKi-OS's CPU-first heterogeneous scheduler.
//!
//! WebKit owns page rasterization and WebGL/WebGPU device selection. This
//! module delegates bounded browser-adjacent compute and model inference to
//! local or discovered Overhauled brokers. A remote peer label is only a hint:
//! every accelerated result must be confirmed by the broker's BRK2 backend field.

use std::{
    env, fs,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use yukkios::{
    broker_discovery::{BrokerServiceRecord, BrokerServiceRegistry},
    exec_policy::{BackendAvailability, BackendPolicy, ExecutionBackend, TaskProfile},
    gpu_adapter::{
        GpuAdapterConfig, LifecycleClient, LifecycleWireMode, WasmBufferDescriptor,
        WasmTaskRequest, WasmTaskStatus,
    },
    WorkerDirective,
};

pub const MAX_GRAPHICS_PAYLOAD_BYTES: usize = 64 * 1024;
pub const MAX_DISCOVERED_PEERS: usize = 256;
pub const MAX_DIRECTORY_FILE_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_PRIORITY: u8 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceleratorStatus {
    pub broker_configured: bool,
    pub gpu_module_configured: bool,
    /// Operator opt-in plus a local broker, not a hardware attestation.
    pub npu_opted_in: bool,
    pub cpu_forced: bool,
    pub gpu_offload_threshold_bytes: usize,
    pub discovered_peer_count: usize,
    pub discovered_gpu_peer_count: usize,
    pub discovered_npu_peer_count: usize,
    pub discovered_cpu_peer_count: usize,
}

#[derive(Debug, Clone)]
pub struct GraphicsComputeReport {
    pub requested_backend: ExecutionBackend,
    /// Backend reported by BRK2 or the local CPU reference implementation.
    pub actual_backend: ExecutionBackend,
    pub elapsed_ms: u128,
    pub output: Vec<u8>,
    pub fallback_reason: Option<String>,
    pub broker_queue_wait_us: Option<u64>,
    pub broker_service_time_us: Option<u64>,
    pub broker_worker_id: Option<u32>,
    /// Set for mesh-delegated executions; absent for local execution.
    pub execution_node_id: Option<uuid::Uuid>,
    pub execution_service_id: Option<uuid::Uuid>,
}

#[derive(Clone)]
struct PeerBroker {
    record: BrokerServiceRecord,
    client: Arc<LifecycleClient>,
}

pub struct BrowserAcceleratorScheduler {
    local_client: Option<Arc<LifecycleClient>>,
    base_config: GpuAdapterConfig,
    peer_brokers: Vec<PeerBroker>,
    policy: BackendPolicy,
    graphics_module_id: Option<String>,
    graphics_module_version: Option<String>,
    npu_opted_in: bool,
    remote_enabled: bool,
    remote_cpu_enabled: bool,
}

impl BrowserAcceleratorScheduler {
    pub fn from_env() -> Result<Self, String> {
        let base_config = GpuAdapterConfig::from_env().map_err(|error| error.to_string())?;
        let local_client = if base_config.enabled {
            Some(Arc::new(
                LifecycleClient::new(base_config.clone())
                    .map_err(|error| error.to_string())?
                    .with_wire_mode(LifecycleWireMode::Brk2),
            ))
        } else {
            None
        };

        let graphics_module_id = bounded_env("YUKKI_BROWSER_GRAPHICS_MODULE_ID", 128)?;
        let graphics_module_version = bounded_env("YUKKI_BROWSER_GRAPHICS_MODULE_VERSION", 64)?;
        let remote_enabled = env_flag("YUKKI_BROWSER_REMOTE_ACCELERATION");
        let remote_cpu_enabled = remote_enabled && env_flag("YUKKI_BROWSER_REMOTE_CPU");
        let npu_opted_in = env_flag("YUKKI_NPU_AVAILABLE") && local_client.is_some();

        let mut scheduler = Self {
            local_client,
            base_config,
            peer_brokers: Vec::new(),
            policy: BackendPolicy::from_env(),
            graphics_module_id,
            graphics_module_version,
            npu_opted_in,
            remote_enabled,
            remote_cpu_enabled,
        };

        if remote_enabled {
            if let Some(path) = env::var_os("YUKKI_BROKER_DIRECTORY_FILE") {
                let records = load_peer_directory(path.as_ref())?;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                scheduler = scheduler.with_authenticated_peer_records(records, now)?;
            }
        }
        Ok(scheduler)
    }

    /// Attach broker records supplied by the local YuKKi node's authenticated
    /// peer-mesh registry. Callers must not pass records from an arbitrary
    /// network response or user-controlled source. Each record is revalidated
    /// for schema, lease, protocol and bounds before a broker client is built.
    pub fn with_authenticated_peer_records(
        mut self,
        records: Vec<BrokerServiceRecord>,
        now_unix: u64,
    ) -> Result<Self, String> {
        if !self.remote_enabled {
            return Err(
                "remote broker delegation requires YUKKI_BROWSER_REMOTE_ACCELERATION=true"
                    .to_owned(),
            );
        }
        if records.len() > MAX_DISCOVERED_PEERS {
            return Err(format!(
                "peer directory contains more than {MAX_DISCOVERED_PEERS} broker records"
            ));
        }

        let mut registry = BrokerServiceRegistry::new();
        for record in records {
            registry
                .upsert(record, now_unix)
                .map_err(|error| error.to_string())?;
        }

        let mut peers = registry.list(now_unix);
        peers.retain(|record| {
            record.protocol_versions.iter().any(|version| version == "BRK2")
                && record.capabilities.iter().any(|capability| {
                    matches!(capability.as_str(), "cpu" | "gpu" | "npu")
                })
                && record.endpoint != self.base_config.endpoint
        });
        peers.sort_by_key(|record| {
            (
                if record.capabilities.iter().any(|value| value == "gpu") {
                    0
                } else if record.capabilities.iter().any(|value| value == "npu") {
                    1
                } else {
                    2
                },
                record.service_id,
            )
        });

        let mut clients = Vec::with_capacity(peers.len());
        for record in peers {
            let mut config = self.base_config.clone();
            config.enabled = true;
            config.endpoint = record.endpoint.clone();
            config.max_frame_size = config
                .max_frame_size
                .min(record.max_frame_bytes as usize);
            let client = Arc::new(
                LifecycleClient::new(config)
                    .map_err(|error| error.to_string())?
                    .with_wire_mode(LifecycleWireMode::Brk2),
            );
            clients.push(PeerBroker { record, client });
        }
        self.peer_brokers = clients;
        Ok(self)
    }

    pub fn status(&self) -> AcceleratorStatus {
        let has_local_broker = self.local_client.is_some();
        let gpu_module_configured =
            self.graphics_module_id.is_some() && self.graphics_module_version.is_some();
        let has_remote_gpu = self.remote_enabled
            && self.peer_brokers.iter().any(|peer| has_capability(peer, "gpu"));
        let has_remote_npu = self.remote_enabled
            && self.peer_brokers.iter().any(|peer| has_capability(peer, "npu"));
        let has_remote_cpu = self.remote_enabled
            && self.peer_brokers.iter().any(|peer| has_capability(peer, "cpu"));
        AcceleratorStatus {
            broker_configured: has_local_broker || !self.peer_brokers.is_empty(),
            gpu_module_configured: gpu_module_configured
                && (has_local_broker || has_remote_gpu),
            npu_opted_in: self.npu_opted_in,
            cpu_forced: !self.policy.accelerators_allowed,
            gpu_offload_threshold_bytes: self.policy.offload_threshold_bytes,
            discovered_peer_count: self.peer_brokers.len(),
            discovered_gpu_peer_count: self
                .peer_brokers
                .iter()
                .filter(|peer| has_capability(peer, "gpu"))
                .count(),
            discovered_npu_peer_count: self
                .peer_brokers
                .iter()
                .filter(|peer| has_capability(peer, "npu"))
                .count(),
            discovered_cpu_peer_count: self
                .peer_brokers
                .iter()
                .filter(|peer| has_capability(peer, "cpu"))
                .count(),
        }
    }

    fn availability(&self) -> BackendAvailability {
        let status = self.status();
        BackendAvailability {
            gpu: status.gpu_module_configured,
            npu: self.npu_opted_in || status.discovered_npu_peer_count > 0,
            remote: status.discovered_peer_count > 0,
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
        let selected = self.policy.select(&profile, self.availability());
        if selected == ExecutionBackend::Cpu
            && self.remote_cpu_enabled
            && self.status().discovered_cpu_peer_count > 0
            && estimated_bytes >= self.policy.offload_threshold_bytes
        {
            ExecutionBackend::Remote
        } else {
            selected
        }
    }

    /// Run a bounded RGBA8 transform. The rendering engine remains WebKit;
    /// this task demonstrates browser-adjacent pixel/tile compute delegation.
    ///
    /// Dispatch order: local GPU broker, discovered GPU peers, explicitly
    /// enabled remote CPU peers, then the local CPU reference implementation.
    /// A broker result is accepted only when BRK2 attests the requested backend
    /// and the output size matches the input.
    pub async fn run_rgba_invert(
        &self,
        task_id: &str,
        rgba8: &[u8],
    ) -> Result<GraphicsComputeReport, String> {
        validate_rgba_payload(rgba8)?;
        let started = Instant::now();
        let requested_backend = self.select_graphics_backend(rgba8.len());

        if requested_backend == ExecutionBackend::Cpu {
            return Ok(cpu_report(requested_backend, rgba8, started, None));
        }

        let module_id = self.graphics_module_id.as_deref().ok_or_else(|| {
            "YUKKI_BROWSER_GRAPHICS_MODULE_ID is required for broker graphics compute".to_owned()
        })?;
        let module_version = self.graphics_module_version.as_deref().ok_or_else(|| {
            "YUKKI_BROWSER_GRAPHICS_MODULE_VERSION is required for broker graphics compute".to_owned()
        })?;
        let mut failures = Vec::new();

        if requested_backend == ExecutionBackend::Gpu {
            if let Some(client) = self.local_client.as_ref() {
                match submit_rgba(client, task_id, module_id, module_version, rgba8, "gpu").await {
                    Ok(execution) => {
                        if let Some(report) = report_for_execution(
                            requested_backend,
                            ExecutionBackend::Gpu,
                            execution,
                            rgba8.len(),
                            started,
                            None,
                            None,
                        ) {
                            return Ok(report);
                        }
                        failures.push("local broker did not attest GPU execution or returned an invalid output".to_owned());
                    }
                    Err(error) => failures.push(format!("local broker: {error}")),
                }
            }

            for peer in self.peer_brokers.iter().filter(|peer| has_capability(peer, "gpu")) {
                let peer_task_id = format!("{task_id}.{}", peer.record.service_id.simple());
                match submit_rgba(
                    &peer.client,
                    &peer_task_id,
                    module_id,
                    module_version,
                    rgba8,
                    "gpu",
                )
                .await
                {
                    Ok(execution) => {
                        if let Some(report) = report_for_execution(
                            requested_backend,
                            ExecutionBackend::Gpu,
                            execution,
                            rgba8.len(),
                            started,
                            Some(peer.record.node_id),
                            Some(peer.record.service_id),
                        ) {
                            return Ok(report);
                        }
                        failures.push(format!(
                            "peer {} did not attest GPU execution or returned an invalid output",
                            peer.record.node_id
                        ));
                    }
                    Err(error) => failures.push(format!("peer {}: {error}", peer.record.node_id)),
                }
            }
        }

        // CPU-only servers can participate when remote CPU offload is explicitly
        // enabled. This is not the default because network cost can exceed local
        // CPU time for small image tiles.
        if self.remote_cpu_enabled {
            for peer in self.peer_brokers.iter().filter(|peer| has_capability(peer, "cpu")) {
                let peer_task_id = format!("{task_id}.{}", peer.record.service_id.simple());
                match submit_rgba(
                    &peer.client,
                    &peer_task_id,
                    module_id,
                    module_version,
                    rgba8,
                    "cpu",
                )
                .await
                {
                    Ok(execution) => {
                        if let Some(report) = report_for_execution(
                            requested_backend,
                            ExecutionBackend::Cpu,
                            execution,
                            rgba8.len(),
                            started,
                            Some(peer.record.node_id),
                            Some(peer.record.service_id),
                        ) {
                            return Ok(report);
                        }
                        failures.push(format!(
                            "CPU peer {} did not attest CPU execution or returned an invalid output",
                            peer.record.node_id
                        ));
                    }
                    Err(error) => failures.push(format!("CPU peer {}: {error}", peer.record.node_id)),
                }
            }
        }

        let fallback_reason = if failures.is_empty() {
            None
        } else {
            Some(failures.join("; "))
        };
        Ok(cpu_report(
            requested_backend,
            rgba8,
            started,
            fallback_reason,
        ))
    }

    /// Submit a model-specific tensor to a local or discovered NPU broker.
    /// Physical NPU execution is reported only when BRK2 field 7 says "npu".
    /// It does not make WebKit's rendering pipeline an NPU workload.
    pub async fn run_npu_inference(
        &self,
        task_id: &str,
        tensor_payload: &[u8],
    ) -> Result<GraphicsComputeReport, String> {
        if tensor_payload.is_empty() || tensor_payload.len() > MAX_GRAPHICS_PAYLOAD_BYTES {
            return Err(format!(
                "NPU inference payload must be 1..={MAX_GRAPHICS_PAYLOAD_BYTES} bytes"
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
            return Err("NPU is not selected: opt in to NPU execution, configure a compatible NPU peer, and do not force CPU".to_owned());
        }

        let started = Instant::now();
        let bounded_id = bounded_task_id(task_id)?;
        if self.npu_opted_in {
            if let Some(client) = self.local_client.as_ref() {
                match client
                    .submit_inference_task_with_preference(
                        &bounded_id,
                        tensor_payload,
                        DEFAULT_PRIORITY,
                        30_000,
                        "npu",
                    )
                    .await
                {
                    Ok(execution) if execution.backend.as_deref() == Some("npu") => {
                        return Ok(inference_report(execution, started, None, None));
                    }
                    Ok(execution) => {
                        return Err(format!(
                            "local NPU was requested but the broker reported backend {}",
                            execution.backend.as_deref().unwrap_or("unknown")
                        ));
                    }
                    Err(error) => return Err(format!("local NPU request failed: {error}")),
                }
            }
        }

        let mut failures = Vec::new();
        for peer in self.peer_brokers.iter().filter(|peer| has_capability(peer, "npu")) {
            let peer_task_id = format!("{bounded_id}.{}", peer.record.service_id.simple());
            match peer
                .client
                .submit_inference_task_with_preference(
                    &peer_task_id,
                    tensor_payload,
                    DEFAULT_PRIORITY,
                    30_000,
                    "npu",
                )
                .await
            {
                Ok(execution) if execution.backend.as_deref() == Some("npu") => {
                    return Ok(inference_report(
                        execution,
                        started,
                        Some(peer.record.node_id),
                        Some(peer.record.service_id),
                    ));
                }
                Ok(execution) => failures.push(format!(
                    "peer {} did not attest NPU execution (reported {})",
                    peer.record.node_id,
                    execution.backend.as_deref().unwrap_or("unknown")
                )),
                Err(error) => failures.push(format!("peer {}: {error}", peer.record.node_id)),
            }
        }
        Err(if failures.is_empty() {
            "no eligible NPU peer was discovered".to_owned()
        } else {
            failures.join("; ")
        })
    }
}

fn has_capability(peer: &PeerBroker, capability: &str) -> bool {
    peer.record
        .capabilities
        .iter()
        .any(|value| value == capability)
}

fn load_peer_directory(path: &std::ffi::OsStr) -> Result<Vec<BrokerServiceRecord>, String> {
    let path = std::path::Path::new(path);
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("cannot read broker peer directory: {error}")),
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_DIRECTORY_FILE_BYTES {
        return Err("broker peer directory must be a regular file no larger than 4 MiB".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("broker peer directory file must not be group/world accessible (mode 0600)".to_owned());
        }
    }
    let bytes = fs::read(path).map_err(|error| format!("cannot read broker peer directory: {error}"))?;
    let records: Vec<BrokerServiceRecord> = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid broker peer directory JSON: {error}"))?;
    if records.len() > MAX_DISCOVERED_PEERS {
        return Err(format!(
            "broker peer directory contains more than {MAX_DISCOVERED_PEERS} records"
        ));
    }
    Ok(records)
}

async fn submit_rgba(
    client: &LifecycleClient,
    task_id: &str,
    module_id: &str,
    module_version: &str,
    rgba8: &[u8],
    device_preference: &str,
) -> Result<yukkios::gpu_adapter::WasmTaskExecution, String> {
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
    client
        .submit_wsm1_task_with_device_preference(
            &task,
            &WorkerDirective::throughput(),
            device_preference,
        )
        .await
        .map_err(|error| error.to_string())
}

fn report_for_execution(
    requested_backend: ExecutionBackend,
    actual_backend: ExecutionBackend,
    execution: yukkios::gpu_adapter::WasmTaskExecution,
    expected_output_bytes: usize,
    started: Instant,
    execution_node_id: Option<uuid::Uuid>,
    execution_service_id: Option<uuid::Uuid>,
) -> Option<GraphicsComputeReport> {
    let expected = match actual_backend {
        ExecutionBackend::Gpu => "gpu",
        ExecutionBackend::Cpu => "cpu",
        _ => return None,
    };
    if execution.response.status != WasmTaskStatus::Ok
        || execution.backend.as_deref() != Some(expected)
        || execution.response.result.len() != expected_output_bytes
    {
        return None;
    }
    let telemetry = execution.worker_telemetry;
    Some(GraphicsComputeReport {
        requested_backend,
        actual_backend,
        elapsed_ms: started.elapsed().as_millis(),
        output: execution.response.result,
        fallback_reason: None,
        broker_queue_wait_us: telemetry.as_ref().map(|value| value.queue_wait_us),
        broker_service_time_us: telemetry.as_ref().map(|value| value.service_time_us),
        broker_worker_id: telemetry.as_ref().map(|value| value.worker_id),
        execution_node_id,
        execution_service_id,
    })
}

fn inference_report(
    execution: yukkios::gpu_adapter::BrokerTaskExecution,
    started: Instant,
    execution_node_id: Option<uuid::Uuid>,
    execution_service_id: Option<uuid::Uuid>,
) -> GraphicsComputeReport {
    let telemetry = execution.worker_telemetry;
    GraphicsComputeReport {
        requested_backend: ExecutionBackend::Npu,
        actual_backend: ExecutionBackend::Npu,
        elapsed_ms: started.elapsed().as_millis(),
        output: execution.result,
        fallback_reason: None,
        broker_queue_wait_us: telemetry.as_ref().map(|value| value.queue_wait_us),
        broker_service_time_us: telemetry.as_ref().map(|value| value.service_time_us),
        broker_worker_id: telemetry.as_ref().map(|value| value.worker_id),
        execution_node_id,
        execution_service_id,
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
        execution_node_id: None,
        execution_service_id: None,
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
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    {
        return Err(
            "task ID must contain 1..=128 ASCII letters, digits, '-', '_' or '.'".to_owned(),
        );
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

    fn sample_record(now: u64, endpoint: &str, capabilities: &[&str]) -> BrokerServiceRecord {
        BrokerServiceRecord {
            schema: yukkios::broker_discovery::BROKER_SERVICE_SCHEMA,
            service_id: uuid::Uuid::new_v4(),
            node_id: uuid::Uuid::new_v4(),
            service_kind: yukkios::broker_discovery::BROKER_SERVICE_KIND.to_owned(),
            endpoint: endpoint.to_owned(),
            protocol_versions: vec!["BRK2".to_owned()],
            capabilities: capabilities.iter().map(|value| (*value).to_owned()).collect(),
            max_frame_bytes: 64 * 1024,
            issued_at_unix: now,
            expires_at_unix: now + yukkios::broker_discovery::BROKER_SERVICE_DEFAULT_LEASE_SECS,
            message_id: uuid::Uuid::new_v4(),
            remaining_hops: yukkios::broker_discovery::BROKER_SERVICE_MAX_HOPS,
        }
    }

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


    fn scheduler_for_test(remote_cpu_enabled: bool) -> BrowserAcceleratorScheduler {
        BrowserAcceleratorScheduler {
            local_client: None,
            base_config: GpuAdapterConfig::default(),
            peer_brokers: Vec::new(),
            policy: BackendPolicy::default(),
            graphics_module_id: Some("browser.graphics.rgba-invert".to_owned()),
            graphics_module_version: Some("1".to_owned()),
            npu_opted_in: false,
            remote_enabled: true,
            remote_cpu_enabled,
        }
    }

    #[test]
    fn directory_selection_distinguishes_gpu_npu_and_cpu_only_servers() {
        let now = 1_700_000_000;
        let records = vec![
            sample_record(now, "cpu-peer.internal:9090", &["cpu"]),
            sample_record(now, "gpu-peer.internal:9090", &["cpu", "gpu"]),
            sample_record(now, "npu-peer.internal:9090", &["cpu", "npu"]),
        ];
        let scheduler = scheduler_for_test(true)
            .with_authenticated_peer_records(records, now)
            .expect("accept authenticated peer snapshot");
        let status = scheduler.status();
        assert_eq!(status.discovered_peer_count, 3);
        assert_eq!(status.discovered_gpu_peer_count, 1);
        assert_eq!(status.discovered_npu_peer_count, 1);
        assert_eq!(status.discovered_cpu_peer_count, 3);
        assert_eq!(
            scheduler.select_graphics_backend(64 * 1024),
            ExecutionBackend::Gpu
        );
    }

    #[test]
    fn cpu_only_mesh_uses_remote_cpu_only_when_operator_enables_it() {
        let now = 1_700_000_000;
        let records = vec![sample_record(now, "cpu-peer.internal:9090", &["cpu"])];
        let enabled = scheduler_for_test(true)
            .with_authenticated_peer_records(records.clone(), now)
            .unwrap();
        assert_eq!(
            enabled.select_graphics_backend(64 * 1024),
            ExecutionBackend::Remote
        );

        let disabled = scheduler_for_test(false)
            .with_authenticated_peer_records(records, now)
            .unwrap();
        assert_eq!(
            disabled.select_graphics_backend(64 * 1024),
            ExecutionBackend::Cpu
        );
    }

    #[test]
    fn invalid_or_expired_peer_records_are_rejected() {
        let now = 1_700_000_000;
        let mut expired = sample_record(now - 1000, "expired.internal:9090", &["gpu"]);
        expired.expires_at_unix = now - 1;
        let result = scheduler_for_test(false)
            .with_authenticated_peer_records(vec![expired], now);
        assert!(result.is_err());
    }

    #[test]
    fn remote_delegation_requires_explicit_operator_opt_in() {
        let now = 1_700_000_000;
        let records = vec![sample_record(now, "gpu-peer.internal:9090", &["gpu"])];
        let mut scheduler = scheduler_for_test(false);
        let result = scheduler.with_authenticated_peer_records(records, now);
        assert!(result.is_err());
        scheduler.remote_enabled = true;
        assert!(scheduler.with_authenticated_peer_records(Vec::new(), now).is_ok());
    }

    #[test]
    fn discovered_peer_capabilities_distinguish_gpu_cpu_and_npu_nodes() {
        let now = 1_700_000_000;
        let cpu = sample_record(now, "cpu-peer.internal:9090", &["cpu"]);
        let gpu = sample_record(now, "gpu-peer.internal:9090", &["cpu", "gpu"]);
        let npu = sample_record(now, "npu-peer.internal:9090", &["cpu", "npu"]);
        assert!(cpu.validate(now).is_ok());
        assert!(gpu.validate(now).is_ok());
        assert!(npu.validate(now).is_ok());
        assert!(has_capability(&PeerBroker {
            record: cpu,
            client: Arc::new(
                LifecycleClient::new(GpuAdapterConfig::new("127.0.0.1:1"))
                    .unwrap()
                    .with_wire_mode(LifecycleWireMode::Brk2),
            )
        }, "cpu"));
    }
}
