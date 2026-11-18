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
