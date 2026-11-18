//! Bounded composition of multiple core-Wasm modules into versioned live programs.
//!
//! A program is a dependency-ordered set of modules. Each module is compiled once
//! (with a bounded digest cache), instantiated into one Wasmtime Store, and made
//! available to downstream modules under its manifest module ID. A policy pipeline
//! then invokes exported \`(i64) -> i64\` functions in order. Several program IDs
//! and versions can coexist in one manager.
//!
//! This is module linking and function composition, not binary rewriting: the
//! source modules remain separate compiled Wasmtime modules linked at instantiation.
//! Host imports are denied in v1; modules may import only from declared modules in
//! the same bundle.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Condvar, Mutex, RwLock,
    },
    time::{Duration, Instant},
};
use thiserror::Error;
use wasmtime::{
    Config, Engine, ExternType, Instance, Linker, Module, Store, StoreLimits,
    StoreLimitsBuilder, TypedFunc,
};

pub const WASM_PROGRAM_SCHEMA_VERSION: u16 = 1;
pub const MAX_PROGRAM_MODULES: usize = 8;
pub const MAX_PROGRAM_VERSIONS: usize = 8;
pub const MAX_POLICY_STEPS: usize = 32;
pub const MAX_MODULE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PROGRAM_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_LINEAR_MEMORY_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_MEMORIES_PER_PROGRAM: usize = 4;
pub const MAX_TABLES_PER_PROGRAM: usize = 4;
pub const MAX_TABLE_ELEMENTS: usize = 4096;
pub const DEFAULT_PROGRAM_FUEL: u64 = 10_000_000;
pub const MAX_COMPILED_MODULE_CACHE_ENTRIES: usize = 64;

/// A digest-pinned composition manifest. \`depends_on\` names other module IDs
/// whose exports satisfy this module's imports. Cycles are rejected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WasmProgramManifest {
    pub schema_version: u16,
    pub program_id: String,
    pub version: String,
    pub modules: Vec<WasmModuleDescriptor>,
    pub policy: Vec<WasmPolicyStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WasmModuleDescriptor {
    pub module_id: String,
    /// Lowercase or uppercase hexadecimal SHA-256 digest of the Wasm bytes.
    pub sha256: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
}

/// One policy stage. Each export must have the exact Wasm type \`(i64) -> i64\`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WasmPolicyStep {
    pub module_id: String,
    pub export: String,
}

/// The executable bytes are supplied separately from the manifest, and matched
/// by module_id plus SHA-256 before compilation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmModuleArtifact {
    pub module_id: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmProgramState {
    Prepared,
    Active,
    Draining,
    Drained,
    Released,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmProgramSnapshot {
    pub program_id: String,
    pub version: String,
    pub state: WasmProgramState,
    pub in_flight: usize,
    pub module_count: usize,
    pub policy_step_count: usize,
    pub artifact_digest: String,
}

/// \`old_drained == false\` means the replacement is already active, but the old
/// version still has in-flight invocations and remains retained in Draining state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmProgramActivation {
    pub program_id: String,
    pub active_version: String,
    pub retired_version: Option<String>,
    pub old_drained: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompilationCacheStats {
    pub entries: usize,
    pub hits: usize,
    pub misses: usize,
}

#[derive(Debug, Error)]
pub enum WasmCompositionError {
    #[error("invalid program manifest: {0}")]
    InvalidManifest(String),
    #[error("too many program versions are prepared (limit {MAX_PROGRAM_VERSIONS})")]
    ProgramVersionLimit,
    #[error("program version already exists: {program_id}:{version}")]
    ProgramAlreadyExists { program_id: String, version: String },
    #[error("program version not found: {program_id}:{version}")]
    ProgramNotFound { program_id: String, version: String },
    #[error("no active version for program '{0}'")]
    NoActiveProgram(String),
    #[error("module artifact missing for '{0}'")]
    MissingArtifact(String),
    #[error("unexpected module artifact '{0}'")]
    UnexpectedArtifact(String),
    #[error("duplicate module ID or artifact: '{0}'")]
    DuplicateModule(String),
    #[error("module '{module_id}' is {size} bytes; limit is {MAX_MODULE_BYTES}")]
    ModuleTooLarge { module_id: String, size: usize },
    #[error("program is {size} bytes; limit is {MAX_PROGRAM_BYTES}")]
    ProgramTooLarge { size: usize },
    #[error("SHA-256 mismatch for module '{module_id}': expected {expected}, got {actual}")]
    HashMismatch {
        module_id: String,
        expected: String,
        actual: String,
    },
    #[error("module '{module_id}' declares missing dependency '{dependency}'")]
    MissingDependency {
        module_id: String,
        dependency: String,
    },
    #[error("module '{module_id}' imports '{dependency}', which is not a declared dependency")]
    UndeclaredImport {
        module_id: String,
        dependency: String,
    },
    #[error("module '{module_id}' has an import from '{namespace}', which is not an earlier module in this bundle; host imports are disabled")]
    DisallowedImport {
        module_id: String,
        namespace: String,
    },
    #[error("module dependency graph contains a cycle")]
    DependencyCycle,
    #[error("module '{module_id}' uses shared-memory or memory64, which this composition profile does not allow")]
    UnsupportedMemory { module_id: String },
    #[error("failed to compile module '{module_id}': {reason}")]
    Compile { module_id: String, reason: String },
    #[error("failed to link/instantiate module '{module_id}': {reason}")]
    Link { module_id: String, reason: String },
    #[error("policy stage {index} references unknown module '{module_id}'")]
    PolicyModuleMissing { index: usize, module_id: String },
    #[error("policy export '{module_id}.{export}' is missing or is not typed (i64) -> i64")]
    InvalidPolicyExport { module_id: String, export: String },
    #[error("policy pipeline must contain 1..={MAX_POLICY_STEPS} stages")]
    InvalidPolicyLength,
    #[error("program '{program_id}' version '{version}' is not in a state that can be activated")]
    NotActivatable { program_id: String, version: String },
    #[error("program '{program_id}' version '{version}' is still active or has in-flight work")]
    ProgramBusy { program_id: String, version: String },
    #[error("program '{program_id}' version '{version}' is draining and cannot be released yet")]
    ProgramDraining { program_id: String, version: String },
    #[error("program '{program_id}' version '{version}' has already been released")]
    ProgramReleased { program_id: String, version: String },
    #[error("failed to initialize Wasmtime engine: {0}")]
    Engine(String),
    #[error("failed to reset Wasmtime fuel budget: {0}")]
    Fuel(String),
    #[error("policy execution failed at '{module_id}.{export}': {reason}")]
    Execution {
        module_id: String,
        export: String,
        reason: String,
    },
}

struct ProgramStoreState {
    limits: StoreLimits,
}

struct ProgramRuntime {
    store: Store<ProgramStoreState>,
    pipeline: Vec<(WasmPolicyStep, TypedFunc<i64, i64>)>,
    // Keep the compiled modules alive with the linked instances. The bounded
    // global cache may evict only its own references; active programs retain theirs.
    _compiled_modules: Vec<Arc<Module>>,
    fuel_per_execution: u64,
}

impl ProgramRuntime {
    fn execute(&mut self, input: i64) -> Result<i64, WasmCompositionError> {
        self.store
            .set_fuel(self.fuel_per_execution)
            .map_err(|error| WasmCompositionError::Fuel(error.to_string()))?;

        let mut value = input;
        for (step, function) in &self.pipeline {
            value = function
                .call(&mut self.store, value)
                .map_err(|error| WasmCompositionError::Execution {
                    module_id: step.module_id.clone(),
                    export: step.export.clone(),
                    reason: error.to_string(),
                })?;
        }
        Ok(value)
    }
}

struct ProgramLifecycle {
    state: WasmProgramState,
    in_flight: usize,
}

struct ProgramVersion {
    manifest: WasmProgramManifest,
    artifact_digest: String,
    runtime: Mutex<ProgramRuntime>,
    lifecycle: Mutex<ProgramLifecycle>,
    drained: Condvar,
}

struct ProgramRegistry {
    versions: HashMap<(String, String), Arc<ProgramVersion>>,
    active: HashMap<String, Arc<ProgramVersion>>,
}

/// Owns several independently routed programs. Every program version has its own
/// linked Wasmtime Store and bounded resource limits; compiled module code is
/// deduplicated by digest within this manager.
pub struct WasmProgramManager {
    engine: Engine,
    fuel_per_execution: u64,
    registry: RwLock<ProgramRegistry>,
    compiled_cache: Mutex<HashMap<String, Arc<Module>>>,
    cache_hits: AtomicUsize,
    cache_misses: AtomicUsize,
}

struct ProgramExecutionGuard {
    program: Arc<ProgramVersion>,
}

impl Drop for ProgramExecutionGuard {
    fn drop(&mut self) {
        let mut lifecycle = self.program.lifecycle.lock().unwrap();
        lifecycle.in_flight = lifecycle.in_flight.saturating_sub(1);
        if lifecycle.in_flight == 0 {
            self.program.drained.notify_all();
        }
    }
}
impl WasmProgramManager {
    /// Construct a manager with the default 10-million-fuel budget per complete
    /// policy pipeline invocation.
    pub fn new() -> Result<Self, WasmCompositionError> {
        Self::with_fuel(DEFAULT_PROGRAM_FUEL)
    }

    pub fn with_fuel(fuel_per_execution: u64) -> Result<Self, WasmCompositionError> {
        if fuel_per_execution == 0 {
            return Err(WasmCompositionError::InvalidManifest(
                "fuel_per_execution must be positive".to_string(),
            ));
        }
        let mut config = Config::new();
        config.consume_fuel(true);
        config.wasm_threads(false);
        config.max_wasm_stack(512 * 1024);
        let engine = Engine::new(&config)
            .map_err(|error| WasmCompositionError::Engine(error.to_string()))?;
        Ok(Self {
            engine,
            fuel_per_execution,
            registry: RwLock::new(ProgramRegistry {
                versions: HashMap::new(),
                active: HashMap::new(),
            }),
            compiled_cache: Mutex::new(HashMap::new()),
            cache_hits: AtomicUsize::new(0),
            cache_misses: AtomicUsize::new(0),
        })
    }

    /// Compile, link and instantiate a candidate version without routing traffic
    /// to it. The module dependency graph and policy pipeline are validated before
    /// the version is registered as Prepared.
    pub fn prepare_program(
        &self,
        manifest: WasmProgramManifest,
        artifacts: &[WasmModuleArtifact],
    ) -> Result<WasmProgramSnapshot, WasmCompositionError> {
        validate_manifest_header(&manifest)?;
        let key = (manifest.program_id.clone(), manifest.version.clone());
        {
            let registry = self.registry.read().unwrap();
            if registry.versions.contains_key(&key) {
                return Err(WasmCompositionError::ProgramAlreadyExists {
                    program_id: key.0,
                    version: key.1,
                });
            }
            if registry.versions.len() >= MAX_PROGRAM_VERSIONS {
                return Err(WasmCompositionError::ProgramVersionLimit);
            }
        }

        let (module_bytes, total_bytes) = match_artifacts(&manifest, artifacts)?;
        if total_bytes > MAX_PROGRAM_BYTES {
            return Err(WasmCompositionError::ProgramTooLarge { size: total_bytes });
        }

        let descriptors: HashMap<&str, &WasmModuleDescriptor> = manifest
            .modules
            .iter()
            .map(|descriptor| (descriptor.module_id.as_str(), descriptor))
            .collect();
        let order = dependency_order(&manifest.modules)?;

        let mut compiled = HashMap::<String, Arc<Module>>::new();
        for descriptor in &manifest.modules {
            let bytes = module_bytes
                .get(descriptor.module_id.as_str())
                .expect("artifact matching validated");
            let actual = sha256_hex(bytes);
            if !actual.eq_ignore_ascii_case(&descriptor.sha256) {
                return Err(WasmCompositionError::HashMismatch {
                    module_id: descriptor.module_id.clone(),
                    expected: descriptor.sha256.clone(),
                    actual,
                });
            }
            let module = self.compile_cached(&descriptor.module_id, bytes, &actual)?;
            validate_memory_types(&descriptor.module_id, &module)?;
            compiled.insert(descriptor.module_id.clone(), module);
        }

        let limits = StoreLimitsBuilder::new()
            .memory_size(MAX_LINEAR_MEMORY_BYTES)
            .memories(MAX_MEMORIES_PER_PROGRAM)
            .tables(MAX_TABLES_PER_PROGRAM)
            .table_elements(MAX_TABLE_ELEMENTS)
            .instances(MAX_PROGRAM_MODULES)
            .build();
        let mut store = Store::new(&self.engine, ProgramStoreState { limits });
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.fuel_per_execution)
            .map_err(|error| WasmCompositionError::Fuel(error.to_string()))?;

        let mut linker = Linker::new(&self.engine);
        let mut instances = HashMap::<String, Instance>::new();
        let mut compiled_modules = Vec::with_capacity(order.len());
        let mut instantiated = HashSet::<String>::new();

        for module_id in order {
            let descriptor = descriptors
                .get(module_id.as_str())
                .expect("topological order contains manifest IDs");
            let module = compiled
                .get(&module_id)
                .expect("every descriptor was compiled");

            for import in module.imports() {
                let namespace = import.module();
                if !descriptor.depends_on.iter().any(|dependency| dependency == namespace) {
                    return Err(WasmCompositionError::UndeclaredImport {
                        module_id: module_id.clone(),
                        dependency: namespace.to_string(),
                    });
                }
                if !instantiated.contains(namespace) {
                    return Err(WasmCompositionError::DisallowedImport {
                        module_id: module_id.clone(),
                        namespace: namespace.to_string(),
                    });
                }
            }

            let instance = linker
                .instantiate(&mut store, module.as_ref())
                .map_err(|error| WasmCompositionError::Link {
                    module_id: module_id.clone(),
                    reason: error.to_string(),
                })?;
            linker
                .instance(&mut store, &module_id, instance)
                .map_err(|error| WasmCompositionError::Link {
                    module_id: module_id.clone(),
                    reason: error.to_string(),
                })?;
            instances.insert(module_id.clone(), instance);
            instantiated.insert(module_id);
            compiled_modules.push(module.clone());
        }

        let mut pipeline = Vec::with_capacity(manifest.policy.len());
        for (index, step) in manifest.policy.iter().enumerate() {
            let instance = instances.get(&step.module_id).ok_or_else(|| {
                WasmCompositionError::PolicyModuleMissing {
                    index,
                    module_id: step.module_id.clone(),
                }
            })?;
            let function = instance
                .get_typed_func::<i64, i64>(&mut store, &step.export)
                .map_err(|_| WasmCompositionError::InvalidPolicyExport {
                    module_id: step.module_id.clone(),
                    export: step.export.clone(),
                })?;
            pipeline.push((step.clone(), function));
        }

        let artifact_digest = program_digest(&manifest);
        let program = Arc::new(ProgramVersion {
            manifest: manifest.clone(),
            artifact_digest,
            runtime: Mutex::new(ProgramRuntime {
                store,
                pipeline,
                _compiled_modules: compiled_modules,
                fuel_per_execution: self.fuel_per_execution,
            }),
            lifecycle: Mutex::new(ProgramLifecycle {
                state: WasmProgramState::Prepared,
                in_flight: 0,
            }),
            drained: Condvar::new(),
        });

        let mut registry = self.registry.write().unwrap();
        if registry.versions.contains_key(&key) {
            return Err(WasmCompositionError::ProgramAlreadyExists {
                program_id: key.0,
                version: key.1,
            });
        }
        if registry.versions.len() >= MAX_PROGRAM_VERSIONS {
            return Err(WasmCompositionError::ProgramVersionLimit);
        }
        registry.versions.insert(key, program.clone());
        Ok(snapshot(&program))
    }

    /// Atomically route new calls to a prepared version, then wait for the
    /// superseded version's in-flight policy invocations. On timeout, the new
    /// version remains active and the old one remains retained in Draining state.
    pub fn activate_program(
        &self,
        program_id: &str,
        version: &str,
        drain_timeout: Duration,
    ) -> Result<WasmProgramActivation, WasmCompositionError> {
        let (candidate, previous) = {
            let mut registry = self.registry.write().unwrap();
            let candidate = registry
                .versions
                .get(&(program_id.to_string(), version.to_string()))
                .cloned()
                .ok_or_else(|| WasmCompositionError::ProgramNotFound {
                    program_id: program_id.to_string(),
                    version: version.to_string(),
                })?;
            if registry
                .active
                .get(program_id)
                .is_some_and(|active| Arc::ptr_eq(active, &candidate))
            {
                return Ok(WasmProgramActivation {
                    program_id: program_id.to_string(),
                    active_version: version.to_string(),
                    retired_version: None,
                    old_drained: true,
                });
            }

            let previous = registry.active.get(program_id).cloned();
            {
                let mut candidate_state = candidate.lifecycle.lock().unwrap();
                if !matches!(
                    candidate_state.state,
                    WasmProgramState::Prepared | WasmProgramState::Drained
                ) {
                    return Err(WasmCompositionError::NotActivatable {
                        program_id: program_id.to_string(),
                        version: version.to_string(),
                    });
                }
                candidate_state.state = WasmProgramState::Active;
            }
            if let Some(old) = previous.as_ref() {
                let mut old_state = old.lifecycle.lock().unwrap();
                if old_state.state == WasmProgramState::Active {
                    old_state.state = WasmProgramState::Draining;
                }
            }
            registry.active.insert(program_id.to_string(), candidate.clone());
            (candidate, previous)
        };

        let old_drained = if let Some(old) = previous.as_ref() {
            wait_until_drained(old, drain_timeout)
        } else {
            true
        };

        Ok(WasmProgramActivation {
            program_id: candidate.manifest.program_id.clone(),
            active_version: candidate.manifest.version.clone(),
            retired_version: previous.map(|program| program.manifest.version.clone()),
            old_drained,
        })
    }
