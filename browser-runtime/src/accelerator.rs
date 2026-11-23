//! Browser-specific use of YuKKi-OS's CPU-first heterogeneous scheduler.
//!
//! WebKit owns page rasterization and WebGL/WebGPU device selection. This
//! module delegates bounded browser-adjacent compute and model inference to
//! local or discovered Overhauled brokers. A remote peer label is only a hint:
//! every accelerated result must be confirmed by the broker's BRK2 backend field.

use std::{
    env, fs,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use yukkios::{
    broker_discovery::{BrokerServiceRecord, BrokerServiceRegistry},
    exec_policy::{BackendAvailability, BackendPolicy, ExecutionBackend, TaskProfile},
    gpu_adapter::{GpuAdapterConfig, LifecycleClient, LifecycleWireMode},
};

pub const MAX_GRAPHICS_PAYLOAD_BYTES: usize = 64 * 1024;
pub const MAX_DISCOVERED_PEERS: usize = 256;
pub const MAX_DIRECTORY_FILE_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_PRIORITY: u8 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceleratorStatus {
    pub broker_configured: bool,
    pub gpu_acceleration_available: bool,
    /// Explicit operator opt-in plus local NPU capability advertisement;
    /// this is still not a hardware attestation.
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
    peer_brokers: RwLock<Vec<PeerBroker>>,
    peer_directory_file: Option<PathBuf>,
    last_peer_refresh: Mutex<Option<Instant>>,
    policy: BackendPolicy,
    npu_opted_in: bool,
    remote_enabled: bool,
    remote_cpu_enabled: bool,
    local_gpu_enabled: bool,
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

        let remote_enabled = env_flag("YUKKI_BROWSER_REMOTE_ACCELERATION");
        let remote_cpu_enabled = remote_enabled && env_flag("YUKKI_BROWSER_REMOTE_CPU");
        let local_capabilities = env::var("YUKKI_BROKER_CAPABILITIES").unwrap_or_else(|_| "cpu".to_owned());
        let advertises_gpu = local_capabilities.split(',').any(|value| value.trim() == "gpu");
        let advertises_npu = local_capabilities.split(',').any(|value| value.trim() == "npu");
        let local_gpu_enabled = advertises_gpu && local_client.is_some();
        let npu_opted_in =
            advertises_npu && env_flag("YUKKI_NPU_AVAILABLE") && local_client.is_some();

        let scheduler = Self {
            local_client,
            base_config,
            peer_brokers: RwLock::new(Vec::new()),
            peer_directory_file: if remote_enabled {
                env::var_os("YUKKI_BROKER_DIRECTORY_FILE").map(PathBuf::from)
            } else {
                None
            },
            last_peer_refresh: Mutex::new(None),
            policy: BackendPolicy::from_env(),
            npu_opted_in,
            remote_enabled,
            remote_cpu_enabled,
            local_gpu_enabled,
        };

        if remote_enabled {
            scheduler.refresh_peer_directory()?;
        }
        Ok(scheduler)
    }

    /// Attach broker records supplied by the local YuKKi node's authenticated
    /// peer-mesh registry. Callers must not pass records from an arbitrary
    /// network response or user-controlled source. Each record is revalidated
    /// for schema, lease, protocol and bounds before a broker client is built.
    pub fn with_authenticated_peer_records(
        self,
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

        self.replace_authenticated_peer_records(records, now_unix)?;
        *self.last_peer_refresh.lock().map_err(|_| "peer refresh lock poisoned")? =
            Some(Instant::now());
        Ok(self)
    }

    fn replace_authenticated_peer_records(
        &self,
        records: Vec<BrokerServiceRecord>,
        now_unix: u64,
    ) -> Result<(), String> {
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

        let mut records = registry.list(now_unix);
        records.retain(|record| {
            record.protocol_versions.iter().any(|version| version == "BRK2")
                && record.capabilities.iter().any(|capability| {
                    matches!(capability.as_str(), "cpu" | "gpu" | "npu")
                })
                && record.endpoint != self.base_config.endpoint
        });
        records.sort_by_key(|record| {
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

        let mut clients = Vec::with_capacity(records.len());
        for record in records {
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
        *self.peer_brokers.write().map_err(|_| "peer directory lock poisoned")? = clients;
        Ok(())
    }

    /// Refresh the authenticated peer snapshot at most once every five seconds.
    /// A node may discover a new GPU server or expire a disconnected one while
    /// the browser stays open; each browser compute request observes that change.
    pub fn refresh_peer_directory(&self) -> Result<usize, String> {
        if !self.remote_enabled {
            return Ok(0);
        }
        let Some(path) = self.peer_directory_file.as_ref() else {
            return Ok(self.peer_brokers.read().map_err(|_| "peer directory lock poisoned")?.len());
        };
        let mut last_refresh = self
            .last_peer_refresh
            .lock()
            .map_err(|_| "peer refresh lock poisoned")?;
        if last_refresh.is_some_and(|last| last.elapsed() < Duration::from_secs(5)) {
            return Ok(self.peer_brokers.read().map_err(|_| "peer directory lock poisoned")?.len());
        }

        let records = load_peer_directory(path)?;
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.replace_authenticated_peer_records(records, now_unix)?;
        *last_refresh = Some(Instant::now());
        Ok(self.peer_brokers.read().map_err(|_| "peer directory lock poisoned")?.len())
    }

    pub fn status(&self) -> AcceleratorStatus {
        let has_local_broker = self.local_client.is_some();
        let peers = self.peer_brokers.read().expect("peer directory lock poisoned");
        let has_remote_gpu = self.remote_enabled
            && peers.iter().any(|peer| has_capability(peer, "gpu"));
        AcceleratorStatus {
            broker_configured: has_local_broker || !peers.is_empty(),
            gpu_acceleration_available: self.local_gpu_enabled || has_remote_gpu,
            npu_opted_in: self.npu_opted_in,
            cpu_forced: !self.policy.accelerators_allowed,
            gpu_offload_threshold_bytes: self.policy.offload_threshold_bytes,
            discovered_peer_count: peers.len(),
            discovered_gpu_peer_count: peers
                .iter()
                .filter(|peer| has_capability(peer, "gpu"))
                .count(),
            discovered_npu_peer_count: peers
                .iter()
                .filter(|peer| has_capability(peer, "npu"))
                .count(),
            discovered_cpu_peer_count: peers
                .iter()
                .filter(|peer| has_capability(peer, "cpu"))
                .count(),
        }
    }

    fn availability(&self) -> BackendAvailability {
        let status = self.status();
        BackendAvailability {
            gpu: status.gpu_acceleration_available,
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
            && self.policy.accelerators_allowed
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
    pub async fn run_rgba_gain(
        &self,
        task_id: &str,
        rgba8: &[u8],
    ) -> Result<GraphicsComputeReport, String> {
        validate_rgba_payload(rgba8)?;
        let started = Instant::now();
        self.refresh_peer_directory()?;
        let peers = self.peer_brokers.read().map_err(|_| "peer directory lock poisoned")?.clone();
        let requested_backend = self.select_graphics_backend(rgba8.len());

        if requested_backend == ExecutionBackend::Cpu {
            return Ok(cpu_report(requested_backend, rgba8, started, None));
        }

        let broker_payload = rgba_channels_to_f64_payload(rgba8)?;
        let mut failures = Vec::new();

        if requested_backend == ExecutionBackend::Gpu {
            if self.local_gpu_enabled {
                if let Some(client) = self.local_client.as_ref() {
                    match submit_rgba(client, task_id, &broker_payload, "gpu").await {
                    Ok(execution) => {
                        if let Some(report) = report_for_execution(
                            requested_backend,
                            ExecutionBackend::Gpu,
                            execution,
                            rgba8,
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
            }

            for peer in peers.iter().filter(|peer| has_capability(peer, "gpu")) {
                let peer_task_id = format!("{task_id}.{}", peer.record.service_id.simple());
                match submit_rgba(
                    &peer.client,
                    &peer_task_id,
                    &broker_payload,
                    "gpu",
                )
                .await
                {
                    Ok(execution) => {
                        if let Some(report) = report_for_execution(
                            requested_backend,
                            ExecutionBackend::Gpu,
                            execution,
                            rgba8,
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
            for peer in peers.iter().filter(|peer| has_capability(peer, "cpu")) {
                let peer_task_id = format!("{task_id}.{}", peer.record.service_id.simple());
                match submit_rgba(
                    &peer.client,
                    &peer_task_id,
                    &broker_payload,
                    "cpu",
                )
                .await
                {
                    Ok(execution) => {
                        if let Some(report) = report_for_execution(
                            requested_backend,
                            ExecutionBackend::Cpu,
                            execution,
                            rgba8,
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
        if tensor_payload.is_empty()
            || tensor_payload.len() > MAX_GRAPHICS_PAYLOAD_BYTES
            || tensor_payload.len() % std::mem::size_of::<f64>() != 0
        {
            return Err(format!(
                "NPU inference payload must be 1..={MAX_GRAPHICS_PAYLOAD_BYTES} bytes and aligned to an 8-byte f64 vector"
            ));
        }
        let profile = TaskProfile {
            is_inference: true,
            estimated_bytes: tensor_payload.len(),
            cpu_retry_safe: false,
            ..TaskProfile::default()
        };
        self.refresh_peer_directory()?;
        let peers = self.peer_brokers.read().map_err(|_| "peer directory lock poisoned")?.clone();
        let requested_backend = self.policy.select(&profile, self.availability());
        if requested_backend != ExecutionBackend::Npu {
            return Err("NPU is not selected: opt in to NPU execution, configure a compatible NPU peer, and do not force CPU".to_owned());
        }

        let started = Instant::now();
        let bounded_id = bounded_task_id(task_id)?;
        let mut failures = Vec::new();
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
                    Ok(execution) => failures.push(format!(
                        "local NPU was not attested (reported {})",
                        execution.backend.as_deref().unwrap_or("unknown")
                    )),
                    Err(error) => failures.push(format!("local NPU: {error}")),
                }
            }
        }

        for peer in peers.iter().filter(|peer| has_capability(peer, "npu")) {
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

fn load_peer_directory(path: &std::path::Path) -> Result<Vec<BrokerServiceRecord>, String> {
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
    broker_payload: &[u8],
    device_preference: &str,
) -> Result<yukkios::gpu_adapter::BrokerTaskExecution, String> {
    client
        .submit_inference_task_with_preference(
            &bounded_task_id(task_id)?,
            broker_payload,
            DEFAULT_PRIORITY,
            30_000,
            device_preference,
        )
        .await
        .map_err(|error| error.to_string())
}

fn report_for_execution(
    requested_backend: ExecutionBackend,
    actual_backend: ExecutionBackend,
    execution: yukkios::gpu_adapter::BrokerTaskExecution,
    original_rgba8: &[u8],
    started: Instant,
    execution_node_id: Option<uuid::Uuid>,
    execution_service_id: Option<uuid::Uuid>,
) -> Option<GraphicsComputeReport> {
    let expected = match actual_backend {
        ExecutionBackend::Gpu => "gpu",
        ExecutionBackend::Cpu => "cpu",
        _ => return None,
    };
    if execution.backend.as_deref() != Some(expected) {
        return None;
    }
    let output = rgba_gain_from_f64_payload(original_rgba8, &execution.result)?;
    let telemetry = execution.worker_telemetry;
    Some(GraphicsComputeReport {
        requested_backend,
        actual_backend,
        elapsed_ms: started.elapsed().as_millis(),
        output,
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
        output: rgba_gain_cpu(rgba8),
        fallback_reason,
        broker_queue_wait_us: None,
        broker_service_time_us: None,
        broker_worker_id: None,
        execution_node_id: None,
        execution_service_id: None,
    }
}

/// CPU reference for the broker's deterministic scalar multiply-by-two
/// kernel, applied to RGB channels and clamped back to RGBA8. Alpha is preserved.
pub fn rgba_gain_cpu(rgba8: &[u8]) -> Vec<u8> {
    let mut output = rgba8.to_vec();
    for pixel in output.chunks_exact_mut(4) {
        pixel[0] = pixel[0].saturating_mul(2);
        pixel[1] = pixel[1].saturating_mul(2);
        pixel[2] = pixel[2].saturating_mul(2);
        // Alpha is intentionally preserved.
    }
    output
}

/// Encode RGB channels as network-order IEEE-754 binary64 values for the
/// Overhauled generic BRK2 compute path. Alpha remains local and unchanged.
fn rgba_channels_to_f64_payload(rgba8: &[u8]) -> Result<Vec<u8>, String> {
    validate_rgba_payload(rgba8)?;
    let rgb_values = rgba8.len() / 4 * 3;
    let mut payload = Vec::with_capacity(rgb_values * 8);
    for pixel in rgba8.chunks_exact(4) {
        for channel in &pixel[..3] {
            payload.extend_from_slice(&f64::from(*channel).to_be_bytes());
        }
    }
    if payload.len() > yukkios::gpu_adapter::OVERHAULED_MAX_PAYLOAD_BYTES {
        return Err("encoded RGB compute payload exceeds the broker's 512 KiB limit".to_owned());
    }
    Ok(payload)
}

/// Decode broker f64 results to RGBA8. Reject non-finite or malformed output.
fn rgba_gain_from_f64_payload(rgba8: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
    let expected = rgba8.len() / 4 * 3 * 8;
    if payload.len() != expected {
        return None;
    }
    let mut output = rgba8.to_vec();
    let mut cursor = 0usize;
    for pixel in output.chunks_exact_mut(4) {
        for channel in &mut pixel[..3] {
            let value = f64::from_be_bytes(payload[cursor..cursor + 8].try_into().ok()?);
            if !value.is_finite() {
                return None;
            }
            *channel = value.round().clamp(0.0, 255.0) as u8;
            cursor += 8;
        }
        // The local alpha byte is left unchanged.
    }
    Some(output)
}

fn validate_rgba_payload(rgba8: &[u8]) -> Result<(), String> {
    if rgba8.is_empty() || rgba8.len() > MAX_GRAPHICS_PAYLOAD_BYTES || rgba8.len() % 4 != 0 {
        return Err(format!(
            "RGBA8 payload must be non-empty, divisible by four, and no larger than {MAX_GRAPHICS_PAYLOAD_BYTES} bytes"
        ));
    }
    Ok(())
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
            max_frame_bytes: 1024 * 1024,
            issued_at_unix: now,
            expires_at_unix: now + yukkios::broker_discovery::BROKER_SERVICE_DEFAULT_LEASE_SECS,
            message_id: uuid::Uuid::new_v4(),
            remaining_hops: yukkios::broker_discovery::BROKER_SERVICE_MAX_HOPS,
        }
    }

    #[test]
    fn rgba_cpu_reference_preserves_alpha_and_applies_broker_gain() {
        assert_eq!(
            rgba_gain_cpu(&[0, 16, 255, 7, 255, 128, 1, 255]),
            vec![0, 32, 255, 7, 255, 255, 2, 255]
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
    fn rgba_f64_wire_payload_roundtrips_the_broker_gain() {
        let input = [10, 20, 30, 7, 200, 120, 40, 255];
        let encoded = rgba_channels_to_f64_payload(&input).unwrap();
        assert_eq!(encoded.len(), 6 * 8);
        let doubled: Vec<u8> = encoded
            .chunks_exact(8)
            .flat_map(|chunk| {
                let value = f64::from_be_bytes(chunk.try_into().unwrap()) * 2.0;
                value.to_be_bytes()
            })
            .collect();
        assert_eq!(
            rgba_gain_from_f64_payload(&input, &doubled).unwrap(),
            vec![20, 40, 60, 7, 255, 240, 80, 255]
        );
        assert!(rgba_gain_from_f64_payload(&input, &[0; 7]).is_none());
    }

    #[test]
    fn encoded_graphics_payload_stays_inside_default_brk2_payload_limit() {
        let input = vec![127; MAX_GRAPHICS_PAYLOAD_BYTES];
        let encoded = rgba_channels_to_f64_payload(&input).unwrap();
        assert!(encoded.len() <= yukkios::brk2::DEFAULT_MAX_PAYLOAD);
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
            peer_brokers: RwLock::new(Vec::new()),
            peer_directory_file: None,
            last_peer_refresh: Mutex::new(None),
            policy: BackendPolicy::default(),
            npu_opted_in: false,
            remote_enabled: true,
            remote_cpu_enabled,
            local_gpu_enabled: false,
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
        scheduler.remote_enabled = false;
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
