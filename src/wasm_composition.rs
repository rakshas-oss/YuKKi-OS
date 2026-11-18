//! Host-side composition of multiple core-Wasm modules into live programs.
//!
//! Composition is performed in YuKKi-OS, not in the Overhauled broker.
//! Modules are compiled by one Wasmtime Engine, function imports are linked
//! by namespace, and each program receives its own Store and instance graph.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
};
use thiserror::Error;
use wasmtime::{
    Config, Engine, ExternType, Func, FuncType, Instance, Linker, Module, Store, StoreLimits,
    StoreLimitsBuilder, Val, ValType,
};

pub const COMPOSITION_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_FUEL_PER_CALL: u64 = 10_000_000;
pub const DEFAULT_MAX_MODULE_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_TOTAL_MODULE_BYTES: usize = 32 * 1024 * 1024;
pub const DEFAULT_MAX_LINEAR_MEMORY_BYTES: usize = 64 * 1024 * 1024;
const MAX_WASM_STACK_BYTES: usize = 512 * 1024;

/// Resource and validation ceilings for one composition runtime.
#[derive(Debug, Clone)]
pub struct CompositionLimits {
    pub max_manifest_bytes: usize,
    pub max_programs: usize,
    pub max_modules_per_program: usize,
    pub max_module_bytes: usize,
    pub max_total_module_bytes: usize,
    pub max_linear_memory_bytes: usize,
    pub fuel_per_call: u64,
    pub max_entrypoint_arity: usize,
}

impl Default for CompositionLimits {
    fn default() -> Self {
        Self {
            max_manifest_bytes: 64 * 1024,
            max_programs: 16,
            max_modules_per_program: 32,
            max_module_bytes: DEFAULT_MAX_MODULE_BYTES,
            max_total_module_bytes: DEFAULT_MAX_TOTAL_MODULE_BYTES,
            max_linear_memory_bytes: DEFAULT_MAX_LINEAR_MEMORY_BYTES,
            fuel_per_call: DEFAULT_FUEL_PER_CALL,
            max_entrypoint_arity: 8,
        }
    }
}

/// Versioned manifest describing one atomic deployment with one or more
/// independently addressable executable programs.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionManifest {
    pub schema_version: u32,
    pub deployment_id: String,
    pub release_id: String,
    pub programs: Vec<ProgramSpec>,
}

/// One program is a directed acyclic graph of core-Wasm modules.
///
/// bindings maps a WebAssembly import namespace to the module ID that provides
/// its imported functions. For example, namespace "math" can map to
/// module ID "math-kernel".
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramSpec {
    pub program_id: String,
    pub modules: Vec<ModuleRef>,
    #[serde(default)]
    pub bindings: BTreeMap<String, String>,
    pub entrypoint: EntrypointSpec,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct ModuleRef {
    pub module_id: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntrypointSpec {
    pub module_id: String,
    pub export: String,
    /// Number of i32 arguments accepted by the entrypoint. The result is one
    /// i32. Keeping this ABI small makes policy dispatch predictable.
    pub params: usize,
}

/// Wasm bytes are supplied out-of-band from the JSON manifest. The same
/// artifact can be referenced by several programs in one deployment.
#[derive(Debug, Clone)]
pub struct ModuleArtifact {
    pub module_id: String,
    pub version: String,
    pub wasm: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum CompositionError {
    #[error("invalid composition manifest: {0}")]
    InvalidManifest(String),
    #[error("composition manifest is {actual} bytes; limit is {max}")]
    ManifestTooLarge { actual: usize, max: usize },
    #[error("module artifact {module_id}:{version} is missing")]
    MissingArtifact { module_id: String, version: String },
    #[error("duplicate module artifact {module_id}:{version}")]
    DuplicateArtifact { module_id: String, version: String },
    #[error("module {module_id}:{version} is {actual} bytes; limit is {max}")]
    ModuleTooLarge {
        module_id: String,
        version: String,
        actual: usize,
        max: usize,
    },
    #[error("composition contains {actual} artifact bytes; limit is {max}")]
    TotalModuleBytesExceeded { actual: usize, max: usize },
    #[error("module {module_id}:{version} failed Wasmtime compilation: {message}")]
    Compile {
        module_id: String,
        version: String,
        message: String,
    },
    #[error("program '{program_id}' references duplicate module ID '{module_id}'")]
    DuplicateProgramModule {
        program_id: String,
        module_id: String,
    },
    #[error("program '{program_id}' has invalid module binding namespace '{namespace}'")]
    InvalidNamespace {
        program_id: String,
        namespace: String,
    },
    #[error("program '{program_id}' binding '{namespace}' targets missing module '{module_id}'")]
    BindingTargetMissing {
        program_id: String,
        namespace: String,
        module_id: String,
    },
    #[error("program '{program_id}' module '{module_id}' imports unbound namespace '{namespace}'")]
    UnboundImport {
        program_id: String,
        module_id: String,
        namespace: String,
    },
    #[error("program '{program_id}' module '{module_id}' imports unsupported non-function item '{namespace}.{name}'")]
    UnsupportedImportKind {
        program_id: String,
        module_id: String,
        namespace: String,
        name: String,
    },
    #[error("program '{program_id}' module '{module_id}' depends on missing export '{namespace}.{name}' from '{provider}'")]
    MissingDependencyExport {
        program_id: String,
        module_id: String,
        namespace: String,
        name: String,
        provider: String,
    },
    #[error("program '{program_id}' import signature mismatch for '{namespace}.{name}' from '{provider}'")]
    ImportSignatureMismatch {
        program_id: String,
        namespace: String,
        name: String,
        provider: String,
    },
    #[error("program '{program_id}' contains a cyclic module dependency")]
    DependencyCycle { program_id: String },
    #[error("program '{program_id}' declares unused binding namespace '{namespace}'")]
    UnusedBinding {
        program_id: String,
        namespace: String,
    },
    #[error("program '{program_id}' entrypoint module '{module_id}' is not in the program")]
    EntrypointModuleMissing {
        program_id: String,
        module_id: String,
    },
    #[error("program '{program_id}' is missing function export '{export}' in module '{module_id}'")]
    EntrypointMissing {
        program_id: String,
        module_id: String,
        export: String,
    },
    #[error("program '{program_id}' entrypoint '{module_id}.{export}' must have {params} i32 parameters and one i32 result")]
    EntrypointSignature {
        program_id: String,
        module_id: String,
        export: String,
        params: usize,
    },
    #[error("program '{program_id}' expects {expected} arguments but received {actual}")]
    ArgumentCount {
        program_id: String,
        expected: usize,
        actual: usize,
    },
    #[error("deployment '{deployment_id}' is not active")]
    DeploymentNotActive { deployment_id: String },
    #[error("program '{program_id}' is not present in active deployment '{deployment_id}'")]
    ProgramNotActive {
        deployment_id: String,
        program_id: String,
    },
    #[error("Wasmtime execution failed for program '{program_id}': {message}")]
    Execution { program_id: String, message: String },
    #[error("composition runtime lock was poisoned")]
    LockPoisoned,
}

struct StoreState {
    limits: StoreLimits,
}

struct CompiledArtifact {
    module: Arc<Module>,
}

struct LiveProgram {
    store: Mutex<Store<StoreState>>,
    _instances: Vec<Instance>,
    entrypoint: Func,
    expected_arity: usize,
    program_id: String,
}

impl LiveProgram {
    fn call(&self, args: &[i32], fuel: u64) -> Result<i32, CompositionError> {
        if args.len() != self.expected_arity {
            return Err(CompositionError::ArgumentCount {
                program_id: self.program_id.clone(),
                expected: self.expected_arity,
                actual: args.len(),
            });
        }

        let mut store = self
            .store
            .lock()
            .map_err(|_| CompositionError::LockPoisoned)?;
        store
            .set_fuel(fuel)
            .map_err(|error| CompositionError::Execution {
                program_id: self.program_id.clone(),
                message: error.to_string(),
            })?;

        let params: Vec<Val> = args.iter().copied().map(Val::I32).collect();
        let mut results = [Val::I32(0)];
        self.entrypoint
            .call(&mut *store, &params, &mut results)
            .map_err(|error| CompositionError::Execution {
                program_id: self.program_id.clone(),
                message: error.to_string(),
            })?;

        match &results[0] {
            Val::I32(value) => Ok(*value),
            _ => Err(CompositionError::Execution {
                program_id: self.program_id.clone(),
                message: "entrypoint returned a value outside the declared i32 ABI".to_string(),
            }),
        }
    }
}

struct ProgramSet {
    deployment_id: String,
    release_id: String,
    programs: BTreeMap<String, Arc<LiveProgram>>,
    in_flight: AtomicUsize,
}

impl ProgramSet {
    fn program_ids(&self) -> Vec<String> {
        self.programs.keys().cloned().collect()
    }
}

struct InFlightGuard(Arc<ProgramSet>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A fully compiled and instantiated deployment that has not yet been made
/// visible to callers.
pub struct PreparedProgramSet {
    inner: Arc<ProgramSet>,
}

impl PreparedProgramSet {
    pub fn deployment_id(&self) -> &str {
        &self.inner.deployment_id
    }

    pub fn release_id(&self) -> &str {
        &self.inner.release_id
    }

    pub fn program_ids(&self) -> Vec<String> {
        self.inner.program_ids()
    }
}

/// Result of the single routing-map update that activates every program in a
/// deployment together.
#[derive(Debug, Clone)]
pub struct ActivationReceipt {
    pub deployment_id: String,
    pub active_release: String,
    pub replaced_release: Option<String>,
    pub program_ids: Vec<String>,
}

/// Wasmtime module composition and live-program routing.
///
/// Compiled modules are cached by SHA-256 of their source bytes for the
/// lifetime of this runtime. Each program is instantiated in a separate Store,
/// so programs can reuse code without sharing mutable guest memory, globals,
/// or tables.
pub struct CompositionRuntime {
    engine: Engine,
    limits: CompositionLimits,
    compiled: Mutex<HashMap<[u8; 32], CompiledArtifact>>,
    active: RwLock<HashMap<String, Arc<ProgramSet>>>,
}

impl CompositionRuntime {
    pub fn new(limits: CompositionLimits) -> Result<Self, CompositionError> {
        if limits.max_manifest_bytes == 0
            || limits.max_programs == 0
            || limits.max_modules_per_program == 0
            || limits.max_module_bytes == 0
            || limits.max_total_module_bytes == 0
            || limits.max_linear_memory_bytes == 0
            || limits.fuel_per_call == 0
        {
            return Err(CompositionError::InvalidManifest(
                "all resource limits must be positive".to_string(),
            ));
        }

        let mut config = Config::new();
        config.consume_fuel(true);
        config.max_wasm_stack(MAX_WASM_STACK_BYTES);
        let engine = Engine::new(&config).map_err(|error| CompositionError::Compile {
            module_id: "<engine>".to_string(),
            version: "runtime".to_string(),
            message: error.to_string(),
        })?;

        Ok(Self {
            engine,
            limits,
            compiled: Mutex::new(HashMap::new()),
            active: RwLock::new(HashMap::new()),
        })
    }

    pub fn with_defaults() -> Self {
        Self::new(CompositionLimits::default())
            .expect("default Wasmtime composition limits are valid")
    }

    /// Parse a bounded JSON manifest and stage the complete deployment.
    pub fn prepare_json(
        &self,
        manifest_bytes: &[u8],
        artifacts: &[ModuleArtifact],
    ) -> Result<PreparedProgramSet, CompositionError> {
        if manifest_bytes.len() > self.limits.max_manifest_bytes {
            return Err(CompositionError::ManifestTooLarge {
                actual: manifest_bytes.len(),
                max: self.limits.max_manifest_bytes,
            });
        }
        let manifest: CompositionManifest = serde_json::from_slice(manifest_bytes)
            .map_err(|error| CompositionError::InvalidManifest(error.to_string()))?;
        self.prepare(&manifest, artifacts)
    }

    /// Compile, validate, link, and instantiate every program before returning
    /// a prepared release. No program is routed until activate is called.
    pub fn prepare(
        &self,
        manifest: &CompositionManifest,
        artifacts: &[ModuleArtifact],
    ) -> Result<PreparedProgramSet, CompositionError> {
        validate_identifier("deployment_id", &manifest.deployment_id)?;
        validate_identifier("release_id", &manifest.release_id)?;
        if manifest.schema_version != COMPOSITION_SCHEMA_VERSION {
            return Err(CompositionError::InvalidManifest(format!(
                "unsupported schema_version {}; expected {}",
                manifest.schema_version, COMPOSITION_SCHEMA_VERSION
            )));
        }
        if manifest.programs.is_empty() || manifest.programs.len() > self.limits.max_programs {
            return Err(CompositionError::InvalidManifest(format!(
                "program count must be in 1..={}",
                self.limits.max_programs
            )));
        }

        let mut artifact_index: HashMap<(String, String), &ModuleArtifact> = HashMap::new();
        let mut total_bytes = 0usize;
        for artifact in artifacts {
            validate_identifier("module_id", &artifact.module_id)?;
            validate_identifier("module_version", &artifact.version)?;
            if artifact.wasm.len() > self.limits.max_module_bytes {
                return Err(CompositionError::ModuleTooLarge {
                    module_id: artifact.module_id.clone(),
                    version: artifact.version.clone(),
                    actual: artifact.wasm.len(),
                    max: self.limits.max_module_bytes,
                });
            }
            total_bytes = total_bytes
                .checked_add(artifact.wasm.len())
                .ok_or_else(|| CompositionError::TotalModuleBytesExceeded {
                    actual: usize::MAX,
                    max: self.limits.max_total_module_bytes,
                })?;
            if total_bytes > self.limits.max_total_module_bytes {
                return Err(CompositionError::TotalModuleBytesExceeded {
                    actual: total_bytes,
                    max: self.limits.max_total_module_bytes,
                });
            }
            let key = (artifact.module_id.clone(), artifact.version.clone());
            if artifact_index.insert(key.clone(), artifact).is_some() {
                return Err(CompositionError::DuplicateArtifact {
                    module_id: key.0,
                    version: key.1,
                });
            }
        }

        let mut programs = BTreeMap::new();
        let mut referenced_artifacts = BTreeSet::new();
        for spec in &manifest.programs {
            validate_identifier("program_id", &spec.program_id)?;
            if spec.modules.is_empty()
                || spec.modules.len() > self.limits.max_modules_per_program
            {
                return Err(CompositionError::InvalidManifest(format!(
                    "program '{}' module count must be in 1..={}",
                    spec.program_id, self.limits.max_modules_per_program
                )));
            }
            if programs.contains_key(&spec.program_id) {
                return Err(CompositionError::InvalidManifest(format!(
                    "duplicate program_id '{}'",
                    spec.program_id
                )));
            }

            let mut compiled_by_id = BTreeMap::new();
            let mut refs_by_id = BTreeMap::new();
            for module_ref in &spec.modules {
                validate_identifier("module_id", &module_ref.module_id)?;
                validate_identifier("module_version", &module_ref.version)?;
                if refs_by_id
                    .insert(module_ref.module_id.clone(), module_ref.version.clone())
                    .is_some()
                {
                    return Err(CompositionError::DuplicateProgramModule {
                        program_id: spec.program_id.clone(),
                        module_id: module_ref.module_id.clone(),
                    });
                }
                let key = (module_ref.module_id.clone(), module_ref.version.clone());
                let artifact = artifact_index.get(&key).ok_or_else(|| {
                    CompositionError::MissingArtifact {
                        module_id: module_ref.module_id.clone(),
                        version: module_ref.version.clone(),
                    }
                })?;
                referenced_artifacts.insert(key);
                let compiled = self.compile_cached(artifact)?;
                compiled_by_id.insert(module_ref.module_id.clone(), compiled);
            }

            for (namespace, target) in &spec.bindings {
                validate_identifier("binding namespace", namespace).map_err(|_| {
                    CompositionError::InvalidNamespace {
                        program_id: spec.program_id.clone(),
                        namespace: namespace.clone(),
                    }
                })?;
                if !compiled_by_id.contains_key(target) {
                    return Err(CompositionError::BindingTargetMissing {
                        program_id: spec.program_id.clone(),
                        namespace: namespace.clone(),
                        module_id: target.clone(),
                    });
                }
            }

            let order =
                validate_and_order_modules(&spec.program_id, &compiled_by_id, &spec.bindings)?;
            let store_limits = StoreLimitsBuilder::new()
                .memory_size(self.limits.max_linear_memory_bytes)
                .build();
            let mut store = Store::new(
                &self.engine,
                StoreState {
                    limits: store_limits,
                },
            );
            store.limiter(|state| &mut state.limits);
            store
                .set_fuel(self.limits.fuel_per_call)
                .map_err(|error| CompositionError::Execution {
                    program_id: spec.program_id.clone(),
                    message: error.to_string(),
                })?;

            let mut linker = Linker::new(&self.engine);
            let mut instances_by_id = BTreeMap::new();
            let mut instances = Vec::with_capacity(order.len());

            for module_id in order {
                let compiled = compiled_by_id.get(&module_id).ok_or_else(|| {
                    CompositionError::InvalidManifest(format!(
                        "internal module lookup failed for '{}'",
                        module_id
                    ))
                })?;
                let instance = linker
                    .instantiate(&mut store, &compiled.module)
                    .map_err(|error| CompositionError::Execution {
                        program_id: spec.program_id.clone(),
                        message: format!("instantiate module '{}': {error}", module_id),
                    })?;

                // Expose a provider instance under each namespace that targets it.
                for (namespace, target) in &spec.bindings {
                    if target == &module_id {
                        linker
                            .instance(&mut store, namespace, instance)
                            .map_err(|error| CompositionError::Execution {
                                program_id: spec.program_id.clone(),
                                message: format!(
                                    "register namespace '{}' for module '{}': {error}",
                                    namespace, module_id
                                ),
                            })?;
                    }
                }

                instances_by_id.insert(module_id, instance);
                instances.push(instance);
            }

            if !compiled_by_id.contains_key(&spec.entrypoint.module_id) {
                return Err(CompositionError::EntrypointModuleMissing {
                    program_id: spec.program_id.clone(),
                    module_id: spec.entrypoint.module_id.clone(),
                });
            }
            if spec.entrypoint.params > self.limits.max_entrypoint_arity {
                return Err(CompositionError::InvalidManifest(format!(
                    "program '{}' entrypoint arity exceeds {}",
                    spec.program_id, self.limits.max_entrypoint_arity
                )));
            }
            let entry_instance = instances_by_id
                .get(&spec.entrypoint.module_id)
                .ok_or_else(|| CompositionError::EntrypointModuleMissing {
                    program_id: spec.program_id.clone(),
                    module_id: spec.entrypoint.module_id.clone(),
                })?;
            let entrypoint = entry_instance
                .get_func(&mut store, &spec.entrypoint.export)
                .ok_or_else(|| CompositionError::EntrypointMissing {
                    program_id: spec.program_id.clone(),
                    module_id: spec.entrypoint.module_id.clone(),
                    export: spec.entrypoint.export.clone(),
                })?;
            validate_entrypoint_signature(
                &spec.program_id,
                &spec.entrypoint,
                &entrypoint.ty(&store),
            )?;

            programs.insert(
                spec.program_id.clone(),
                Arc::new(LiveProgram {
                    store: Mutex::new(store),
                    _instances: instances,
                    entrypoint,
                    expected_arity: spec.entrypoint.params,
                    program_id: spec.program_id.clone(),
                }),
            );
        }

        if referenced_artifacts.len() != artifact_index.len() {
            let unused = artifact_index
                .keys()
                .find(|key| !referenced_artifacts.contains(*key))
                .expect("length mismatch means an unused artifact exists");
            return Err(CompositionError::InvalidManifest(format!(
                "unused artifact {}:{} is not referenced by this deployment",
                unused.0, unused.1
            )));
        }

        Ok(PreparedProgramSet {
            inner: Arc::new(ProgramSet {
                deployment_id: manifest.deployment_id.clone(),
                release_id: manifest.release_id.clone(),
                programs,
                in_flight: AtomicUsize::new(0),
            }),
        })
    }

    /// Atomically make every program in a prepared release visible under one
    /// deployment ID. Calls already admitted to the previous release keep
    /// their old Store and instances alive until those calls return.
    pub fn activate(
        &self,
        prepared: PreparedProgramSet,
    ) -> Result<ActivationReceipt, CompositionError> {
        let deployment_id = prepared.inner.deployment_id.clone();
        let release_id = prepared.inner.release_id.clone();
        let program_ids = prepared.inner.program_ids();
        let mut active = self.active.write().map_err(|_| CompositionError::LockPoisoned)?;
        let previous = active.insert(deployment_id.clone(), prepared.inner);

        Ok(ActivationReceipt {
            deployment_id,
            active_release: release_id,
            replaced_release: previous.map(|set| set.release_id.clone()),
            program_ids,
        })
    }

    /// Execute an active program using the scalar policy ABI. The deployment
    /// routing lock is held only while acquiring the selected release.
    pub fn call(
        &self,
        deployment_id: &str,
        program_id: &str,
        args: &[i32],
    ) -> Result<i32, CompositionError> {
        let (set, program) = {
            let active = self.active.read().map_err(|_| CompositionError::LockPoisoned)?;
            let set = active.get(deployment_id).cloned().ok_or_else(|| {
                CompositionError::DeploymentNotActive {
                    deployment_id: deployment_id.to_string(),
                }
            })?;
            let program = set.programs.get(program_id).cloned().ok_or_else(|| {
                CompositionError::ProgramNotActive {
                    deployment_id: deployment_id.to_string(),
                    program_id: program_id.to_string(),
                }
            })?;
            // Increment under the read lock. Activation cannot swap the
            // deployment until this admitted call is counted.
            set.in_flight.fetch_add(1, Ordering::AcqRel);
            (set, program)
        };

        let _guard = InFlightGuard(set);
        program.call(args, self.limits.fuel_per_call)
    }

    pub fn active_release(&self, deployment_id: &str) -> Result<Option<String>, CompositionError> {
        let active = self.active.read().map_err(|_| CompositionError::LockPoisoned)?;
        Ok(active.get(deployment_id).map(|set| set.release_id.clone()))
    }

    pub fn active_program_ids(
        &self,
        deployment_id: &str,
    ) -> Result<Vec<String>, CompositionError> {
        let active = self.active.read().map_err(|_| CompositionError::LockPoisoned)?;
        Ok(active
            .get(deployment_id)
            .map(|set| set.program_ids())
            .unwrap_or_default())
    }

    pub fn active_in_flight(
        &self,
        deployment_id: &str,
    ) -> Result<Option<usize>, CompositionError> {
        let active = self.active.read().map_err(|_| CompositionError::LockPoisoned)?;
        Ok(active
            .get(deployment_id)
            .map(|set| set.in_flight.load(Ordering::Acquire)))
    }

    pub fn cached_module_count(&self) -> Result<usize, CompositionError> {
        let cache = self.compiled.lock().map_err(|_| CompositionError::LockPoisoned)?;
        Ok(cache.len())
    }

    fn compile_cached(
        &self,
        artifact: &ModuleArtifact,
    ) -> Result<CompiledArtifact, CompositionError> {
        let digest: [u8; 32] = Sha256::digest(&artifact.wasm).into();
        let mut cache = self.compiled.lock().map_err(|_| CompositionError::LockPoisoned)?;
        if let Some(compiled) = cache.get(&digest) {
            return Ok(CompiledArtifact {
                module: Arc::clone(&compiled.module),
            });
        }

        let module = Module::new(&self.engine, &artifact.wasm).map_err(|error| {
            CompositionError::Compile {
                module_id: artifact.module_id.clone(),
                version: artifact.version.clone(),
                message: error.to_string(),
            }
        })?;
        let module = Arc::new(module);
        cache.insert(
            digest,
            CompiledArtifact {
                module: Arc::clone(&module),
            },
        );
        Ok(CompiledArtifact { module })
    }
}

fn validate_identifier(field: &str, value: &str) -> Result<(), CompositionError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(CompositionError::InvalidManifest(format!(
            "{field} must be 1..=128 ASCII letters, digits, '.', '_' or '-'"
        )))
    }
}

fn validate_and_order_modules(
    program_id: &str,
    modules: &BTreeMap<String, CompiledArtifact>,
    bindings: &BTreeMap<String, String>,
) -> Result<Vec<String>, CompositionError> {
    let mut dependencies: BTreeMap<String, BTreeSet<String>> = modules
        .keys()
        .map(|module_id| (module_id.clone(), BTreeSet::new()))
        .collect();
    let mut used_namespaces = BTreeSet::new();

    for (module_id, compiled) in modules {
        for import in compiled.module.imports() {
            let namespace = import.module();
            let name = import.name();
            used_namespaces.insert(namespace.to_string());
            let provider_id = bindings.get(namespace).ok_or_else(|| {
                CompositionError::UnboundImport {
                    program_id: program_id.to_string(),
                    module_id: module_id.clone(),
                    namespace: namespace.to_string(),
                }
            })?;
            if provider_id == module_id {
                return Err(CompositionError::DependencyCycle {
                    program_id: program_id.to_string(),
                });
            }
            let provider = modules.get(provider_id).ok_or_else(|| {
                CompositionError::BindingTargetMissing {
                    program_id: program_id.to_string(),
                    namespace: namespace.to_string(),
                    module_id: provider_id.clone(),
                }
            })?;

            let required_type = match import.ty() {
                ExternType::Func(func_type) => func_type,
                _ => {
                    return Err(CompositionError::UnsupportedImportKind {
                        program_id: program_id.to_string(),
                        module_id: module_id.clone(),
                        namespace: namespace.to_string(),
                        name: name.to_string(),
                    });
                }
            };
            let provided_type = provider
                .module
                .exports()
                .find(|export| export.name() == name)
                .map(|export| export.ty());
            match provided_type {
                Some(ExternType::Func(func_type)) if FuncType::eq(&required_type, &func_type) => {}
                Some(ExternType::Func(_)) => {
                    return Err(CompositionError::ImportSignatureMismatch {
                        program_id: program_id.to_string(),
                        namespace: namespace.to_string(),
                        name: name.to_string(),
                        provider: provider_id.clone(),
                    });
                }
                _ => {
                    return Err(CompositionError::MissingDependencyExport {
                        program_id: program_id.to_string(),
                        module_id: module_id.clone(),
                        namespace: namespace.to_string(),
                        name: name.to_string(),
                        provider: provider_id.clone(),
                    });
                }
            }

            dependencies
                .get_mut(module_id)
                .expect("module dependency entry exists")
                .insert(provider_id.clone());
        }
    }

    for namespace in bindings.keys() {
        if !used_namespaces.contains(namespace) {
            return Err(CompositionError::UnusedBinding {
                program_id: program_id.to_string(),
                namespace: namespace.clone(),
            });
        }
    }

    // Stable Kahn topological sort: providers are instantiated before
    // consumers, and cyclic imports are rejected.
    let mut pending: BTreeSet<String> = modules.keys().cloned().collect();
    let mut completed = BTreeSet::new();
    let mut order = Vec::with_capacity(modules.len());

    while !pending.is_empty() {
        let ready = pending
            .iter()
            .find(|module_id| {
                dependencies
                    .get(*module_id)
                    .is_some_and(|required| required.is_subset(&completed))
            })
            .cloned();

        let Some(module_id) = ready else {
            return Err(CompositionError::DependencyCycle {
                program_id: program_id.to_string(),
            });
        };
        pending.remove(&module_id);
        completed.insert(module_id.clone());
        order.push(module_id);
    }

    Ok(order)
}

fn validate_entrypoint_signature(
    program_id: &str,
    entrypoint: &EntrypointSpec,
    function_type: &FuncType,
) -> Result<(), CompositionError> {
    let params: Vec<ValType> = function_type.params().collect();
    let results: Vec<ValType> = function_type.results().collect();
    let valid = params.len() == entrypoint.params
        && params.iter().all(|ty| matches!(ty, ValType::I32))
        && results.len() == 1
        && matches!(results.first(), Some(ValType::I32));

    if valid {
        Ok(())
    } else {
        Err(CompositionError::EntrypointSignature {
            program_id: program_id.to_string(),
            module_id: entrypoint.module_id.clone(),
            export: entrypoint.export.clone(),
            params: entrypoint.params,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(module_id: &str, version: &str, wat_source: &str) -> ModuleArtifact {
        ModuleArtifact {
            module_id: module_id.to_string(),
            version: version.to_string(),
            wasm: wat::parse_str(wat_source).expect("valid WAT"),
        }
    }

    fn program(
        program_id: &str,
        modules: &[(&str, &str)],
        entry_module: &str,
        export: &str,
        params: usize,
    ) -> ProgramSpec {
        ProgramSpec {
            program_id: program_id.to_string(),
            modules: modules
                .iter()
                .map(|(module_id, version)| ModuleRef {
                    module_id: (*module_id).to_string(),
                    version: (*version).to_string(),
                })
                .collect(),
            bindings: BTreeMap::new(),
            entrypoint: EntrypointSpec {
                module_id: entry_module.to_string(),
                export: export.to_string(),
                params,
            },
        }
    }

    fn manifest(release: &str, programs: Vec<ProgramSpec>) -> CompositionManifest {
        CompositionManifest {
            schema_version: COMPOSITION_SCHEMA_VERSION,
            deployment_id: "risk-engine".to_string(),
            release_id: release.to_string(),
            programs,
        }
    }

    #[test]
    fn links_multiple_modules_and_runs_the_composed_entrypoint() {
        let mut main = program(
            "quality-policy",
            &[("math-kernel", "1.0.0"), ("quality-main", "1.0.0")],
            "quality-main",
            "run",
            1,
        );
        main.bindings.insert("math".to_string(), "math-kernel".to_string());

        let manifest = manifest("r1", vec![main]);
        let artifacts = vec![
            artifact(
                "math-kernel",
                "1.0.0",
                r#"(module
                    (func (export "add_ten") (param i32) (result i32)
                        local.get 0
                        i32.const 10
                        i32.add))"#,
            ),
            artifact(
                "quality-main",
                "1.0.0",
                r#"(module
                    (import "math" "add_ten" (func $add_ten (param i32) (result i32)))
                    (func (export "run") (param i32) (result i32)
                        local.get 0
                        call $add_ten))"#,
            ),
        ];

        let runtime = CompositionRuntime::with_defaults();
        let prepared = runtime.prepare(&manifest, &artifacts).expect("prepare");
        runtime.activate(prepared).expect("activate");
        assert_eq!(runtime.call("risk-engine", "quality-policy", &[32]).unwrap(), 42);
    }

    #[test]
    fn one_compiled_module_can_back_multiple_state_isolated_programs() {
        let counter = artifact(
            "counter",
            "1.0.0",
            r#"(module
                (global $value (mut i32) (i32.const 0))
                (func (export "step") (result i32)
                    global.get $value
                    i32.const 1
                    i32.add
                    global.set $value
                    global.get $value))"#,
        );
        let manifest = manifest(
            "r1",
            vec![
                program("program-a", &[("counter", "1.0.0")], "counter", "step", 0),
                program("program-b", &[("counter", "1.0.0")], "counter", "step", 0),
            ],
        );
        let runtime = CompositionRuntime::with_defaults();
        let prepared = runtime.prepare(&manifest, &[counter]).expect("prepare");
        assert_eq!(runtime.cached_module_count().unwrap(), 1);
        runtime.activate(prepared).unwrap();

        assert_eq!(runtime.call("risk-engine", "program-a", &[]).unwrap(), 1);
        assert_eq!(runtime.call("risk-engine", "program-a", &[]).unwrap(), 2);
        assert_eq!(runtime.call("risk-engine", "program-b", &[]).unwrap(), 1);
    }

    #[test]
    fn activation_switches_all_programs_in_a_release_together() {
        let runtime = CompositionRuntime::with_defaults();

        let release_one = manifest(
            "r1",
            vec![
                program("alpha", &[("policy", "1.0.0")], "policy", "run", 1),
                program("beta", &[("policy", "1.0.0")], "policy", "run", 1),
            ],
        );
        let first_artifact = artifact(
            "policy",
            "1.0.0",
            r#"(module
                (func (export "run") (param i32) (result i32)
                    local.get 0
                    i32.const 1
                    i32.add))"#,
        );
        runtime
            .activate(runtime.prepare(&release_one, &[first_artifact]).unwrap())
            .unwrap();
        assert_eq!(runtime.call("risk-engine", "alpha", &[10]).unwrap(), 11);
        assert_eq!(runtime.call("risk-engine", "beta", &[10]).unwrap(), 11);

        let release_two = manifest(
            "r2",
            vec![
                program("alpha", &[("policy", "2.0.0")], "policy", "run", 1),
                program("beta", &[("policy", "2.0.0")], "policy", "run", 1),
            ],
        );
        let second_artifact = artifact(
            "policy",
            "2.0.0",
            r#"(module
                (func (export "run") (param i32) (result i32)
                    local.get 0
                    i32.const 2
                    i32.add))"#,
        );
        let prepared = runtime.prepare(&release_two, &[second_artifact]).unwrap();
        let receipt = runtime.activate(prepared).unwrap();

        assert_eq!(receipt.replaced_release.as_deref(), Some("r1"));
        assert_eq!(runtime.active_release("risk-engine").unwrap().as_deref(), Some("r2"));
        assert_eq!(runtime.call("risk-engine", "alpha", &[10]).unwrap(), 12);
        assert_eq!(runtime.call("risk-engine", "beta", &[10]).unwrap(), 12);
    }

    #[test]
    fn rejects_import_signature_mismatch_before_activation() {
        let mut consumer = program(
            "consumer",
            &[("provider", "1.0.0"), ("consumer", "1.0.0")],
            "consumer",
            "run",
            1,
        );
        consumer.bindings.insert("provider".to_string(), "provider".to_string());
        let manifest = manifest("r1", vec![consumer]);
        let artifacts = vec![
            artifact(
                "provider",
                "1.0.0",
                r#"(module (func (export "convert") (param i64) (result i64)
                    local.get 0))"#,
            ),
            artifact(
                "consumer",
                "1.0.0",
                r#"(module
                    (import "provider" "convert" (func $convert (param i32) (result i32)))
                    (func (export "run") (param i32) (result i32)
                        local.get 0 call $convert))"#,
            ),
        ];
        let runtime = CompositionRuntime::with_defaults();
        assert!(matches!(
            runtime.prepare(&manifest, &artifacts),
            Err(CompositionError::ImportSignatureMismatch { .. })
        ));
        assert_eq!(runtime.active_release("risk-engine").unwrap(), None);
    }

    #[test]
    fn rejects_cyclic_module_dependencies() {
        let mut cycle = program("cycle", &[("a", "1"), ("b", "1")], "a", "run", 0);
        cycle.bindings.insert("b".to_string(), "b".to_string());
        cycle.bindings.insert("a".to_string(), "a".to_string());
        let artifacts = vec![
            artifact(
                "a",
                "1",
                r#"(module (import "b" "f" (func $f)) (func (export "run") call $f))"#,
            ),
            artifact(
                "b",
                "1",
                r#"(module (import "a" "f" (func $f)) (func (export "f") call $f))"#,
            ),
        ];
        let runtime = CompositionRuntime::with_defaults();
        assert!(matches!(
            runtime.prepare(&manifest("r1", vec![cycle]), &artifacts),
            Err(CompositionError::DependencyCycle { .. })
        ));
    }

    #[test]
    fn applies_fuel_budget_to_each_program_invocation() {
        let runtime = CompositionRuntime::new(CompositionLimits {
            fuel_per_call: 1_000,
            ..CompositionLimits::default()
        })
        .unwrap();
        let infinite = artifact(
            "spin",
            "1",
            r#"(module
                (func (export "run") (result i32)
                    (loop $again
                        br $again)
                    i32.const 0))"#,
        );
        let manifest = manifest(
            "r1",
            vec![program("spin-program", &[("spin", "1")], "spin", "run", 0)],
        );
        runtime
            .activate(runtime.prepare(&manifest, &[infinite]).unwrap())
            .unwrap();
        assert!(matches!(
            runtime.call("risk-engine", "spin-program", &[]),
            Err(CompositionError::Execution { .. })
        ));
    }
}
