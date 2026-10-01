use std::{
    env,
    sync::{Arc, Mutex},
};
use wasmtime::{Config, Engine, Instance, Module, Store, StoreLimits, StoreLimitsBuilder};
use zeroize::Zeroize;

use crate::gpu_adapter::{
    BufferAccess, BufferDescriptor, GpuAdapterError, GpuBrokerClient, GpuTaskRequest,
    LifecycleClient, WasmBufferDescriptor, WasmTaskRequest, WasmTaskStatus,
    CURRENT_PROTOCOL_VERSION,
};

pub struct RustasmSandbox {
    engine: Engine,
    execution_buffer: Mutex<Vec<u8>>,
    max_fuel: u64,
    gpu_client: Option<Arc<GpuBrokerClient>>,
    lifecycle_client: Option<Arc<LifecycleClient>>,
}

struct SandboxState {
    limits: StoreLimits,
}

impl RustasmSandbox {
    const MAX_BUFFER_BYTES: usize = 64 * 1024;
    const MAX_MEMORY_BYTES: usize = 16 * 1024 * 1024;
    const DEFAULT_MAX_FUEL: u64 = 10_000_000;
    const MAX_FUEL_ENV: &'static str = "YUKKI_WASM_MAX_FUEL";

    pub fn new() -> Self {
        let max_fuel = match env::var(Self::MAX_FUEL_ENV) {
            Ok(value) => match value.parse::<u64>() {
                Ok(fuel) if fuel > 0 => fuel,
                _ => {
                    eprintln!(
                        "ignoring invalid {} value; expected positive integer, using default {}",
                        Self::MAX_FUEL_ENV,
                        Self::DEFAULT_MAX_FUEL
                    );
                    Self::DEFAULT_MAX_FUEL
                }
            },
            Err(_) => Self::DEFAULT_MAX_FUEL,
        };
        Self::with_max_fuel(max_fuel).expect("validated Wasm fuel configuration")
    }

    pub fn with_max_fuel(max_fuel: u64) -> Result<Self, String> {
        if max_fuel == 0 {
            return Err("Wasm fuel budget must be greater than zero".to_string());
        }
        let mut config = Config::new();
        config.consume_fuel(true);
        config.max_wasm_stack(512 * 1024);
        Ok(Self {
            engine: Engine::new(&config).expect("valid Wasmtime configuration"),
            execution_buffer: Mutex::new(Vec::with_capacity(960)),
            max_fuel,
            gpu_client: None,
            lifecycle_client: None,
        })
    }

    pub fn with_gpu_client(mut self, client: Arc<GpuBrokerClient>) -> Self {
        if client.config().use_wsm1 && self.lifecycle_client.is_none() {
            self.lifecycle_client = Some(Arc::new(LifecycleClient::from_broker_client(client.clone())));
        }
        self.gpu_client = Some(client);
        self
    }

    pub fn with_lifecycle_client(mut self, client: Arc<LifecycleClient>) -> Self {
        self.lifecycle_client = Some(client);
        self
    }

    pub fn gpu_client(&self) -> Option<&Arc<GpuBrokerClient>> {
        self.gpu_client.as_ref()
    }

    pub fn lifecycle_client(&self) -> Option<&Arc<LifecycleClient>> {
        self.lifecycle_client.as_ref()
    }

    /// Submit a GPU compute task to the overhauled broker on behalf of the sandbox.
    ///
    /// Preserves sandbox isolation: Sandboxes cannot issue raw CUDA or GPU memory
    /// commands directly. Instead, payloads are bound to `MAX_BUFFER_BYTES`, validated,
    /// and wrapped in high-level descriptors mediated by the host adapter.
    ///
    /// When `LifecycleClient` or WSM1 support is available, encodes the task using the
    /// WSM1 binary wire format, falling back to JSON framing if WSM1 is rejected or unsupported.
    pub async fn submit_gpu_task(
        &self,
        module_id: &str,
        module_version: &str,
        task_id: &str,
        payload: &[u8],
        priority: u8,
        timeout_ms: u32,
    ) -> Result<Vec<u8>, GpuAdapterError> {
        if payload.len() > Self::MAX_BUFFER_BYTES {
            return Err(GpuAdapterError::SandboxLimitExceeded(format!(
                "payload size {} exceeds maximum allowable buffer bytes {}",
                payload.len(),
                Self::MAX_BUFFER_BYTES
            )));
        }

        // 1. Try WSM1 encoding if LifecycleClient is available
        if let Some(lc) = self.lifecycle_client.as_ref() {
            let wsm_req = WasmTaskRequest {
                task_id: task_id.to_string(),
                sandbox_id: "rustasm_sandbox".to_string(),
                module_id: module_id.to_string(),
                module_version: module_version.to_string(),
                task_kind: "compute".to_string(),
                priority,
                deadline_ms: 0,
                buffers: vec![WasmBufferDescriptor {
                    buffer_id: 1,
                    flags: 1, // ReadOnly
                    offset: 0,
                    length: payload.len() as u64,
                    name: "input_buf".to_string(),
                }],
                payload: payload.to_vec(),
            };

            match lc.submit_wsm1_task(&wsm_req).await {
                Ok(resp) => match resp.status {
                    WasmTaskStatus::Ok => return Ok(resp.result),
                    WasmTaskStatus::Rejected => {
                        return Err(GpuAdapterError::BrokerRejected {
                            task_id: resp.task_id,
                            code: "REJECTED".to_string(),
                            message: resp.error,
                            retryable: false,
                        });
                    }
                    WasmTaskStatus::Failed | WasmTaskStatus::Timeout => {
                        return Err(GpuAdapterError::TaskExecutionFailed {
                            task_id: resp.task_id,
                            code: format!("{:?}", resp.status),
                            message: resp.error,
                        });
                    }
                },
                Err(err) => {
                    // If the adapter is disabled, fail fast without attempting fallback.
                    if matches!(err, GpuAdapterError::Disabled) {
                        return Err(err);
                    }
                    // For protocol mismatches or legacy brokers that fail binary WSM1,
                    // proceed to the JSON fallback below.
                }
            }
        }

        // 2. Fallback to JSON via GpuBrokerClient
        let client = self
            .gpu_client
            .as_ref()
            .or_else(|| self.lifecycle_client.as_ref().map(|l| l.broker_client()))
            .ok_or(GpuAdapterError::Disabled)?;

        let request = GpuTaskRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION.to_string(),
            task_id: task_id.to_string(),
            idempotency_key: Some(task_id.to_string()),
            sandbox_id: "rustasm_sandbox".to_string(),
            module_id: module_id.to_string(),
            module_version: module_version.to_string(),
            priority,
            deadline_ms: None,
            timeout_ms,
            buffers: vec![BufferDescriptor::inline(
                "input_buf",
                payload.to_vec(),
                BufferAccess::ReadOnly,
            )],
            metadata: None,
        };

        let response = client.submit_task(&request).await?;
        for buf in response.output_buffers {
            if let Some(data) = buf.inline_data {
                return Ok(data);
            }
        }
        Ok(Vec::new())
    }

    pub fn max_fuel(&self) -> u64 {
        self.max_fuel
    }

    fn classify_wasm_error(message: String) -> String {
        if message.contains("all fuel consumed by WebAssembly") || message.contains("out of fuel") {
            "wasm execution aborted: fuel exhausted".to_string()
        } else {
            message
        }
    }

    pub fn buffer_payload(&self, payload: &[u8; 16]) -> Result<(), &'static str> {
        let mut buf = self.execution_buffer.lock().unwrap();
        if buf.len() + payload.len() > Self::MAX_BUFFER_BYTES {
            return Err("sandbox payload buffer limit exceeded");
        }

        buf.extend_from_slice(payload);
        Ok(())
    }

    pub fn flush_buffer(&self) {
        let mut buf = self.execution_buffer.lock().unwrap();
        buf.zeroize();
        buf.clear();
    }

    pub fn execute(&self, wasm_bytes: &[u8]) -> Result<i32, String> {
        let module = Module::new(&self.engine, wasm_bytes).map_err(|error| error.to_string())?;
        let limits = StoreLimitsBuilder::new()
            .memory_size(Self::MAX_MEMORY_BYTES)
            .build();
        let mut store = Store::new(&self.engine, SandboxState { limits });
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.max_fuel)
            .map_err(|error| Self::classify_wasm_error(error.to_string()))?;
        let instance = Instance::new(&mut store, &module, &[])
            .map_err(|error| Self::classify_wasm_error(error.to_string()))?;
        let main = instance
            .get_typed_func::<(), i32>(&mut store, "main")
            .map_err(|error| Self::classify_wasm_error(error.to_string()))?;
        match main.call(&mut store, ()) {
            Ok(result) => Ok(result),
            Err(error) => {
                if matches!(store.get_fuel(), Ok(0)) {
                    Err("wasm execution aborted: fuel exhausted".to_string())
                } else {
                    Err(Self::classify_wasm_error(error.to_string()))
                }
            }
        }
    }

    pub fn commit_civilian_logic(&self) {
        let mut buf = self.execution_buffer.lock().unwrap();
        buf.zeroize();
        buf.clear();
    }
}

impl Default for RustasmSandbox {
    fn default() -> Self {
        Self::new()
    }
}
