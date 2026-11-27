//! User-directed execution over crawler-ingested bytes.
//!
//! This executor is deliberately separate from HTML extraction. A caller must
//! explicitly provide a reviewed WebAssembly processor; page content is passed
//! as opaque bytes and is never interpreted as code by the host.

use sha2::{Digest, Sha256};
use thiserror::Error;
use wasmtime::{Config, Engine, Instance, Module, Store, StoreLimits, StoreLimitsBuilder};

pub const CRAWLER_DATA_EXEC_ABI: &str = "YCE1";
pub const MAX_DATA_EXEC_MODULE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_DATA_EXEC_INPUT_BYTES: usize = 1_048_576;
pub const MAX_DATA_EXEC_OUTPUT_BYTES: usize = 1_048_576;
pub const MAX_DATA_EXEC_MEMORY_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_DATA_EXEC_FUEL: u64 = 10_000_000;
pub const MAX_DATA_EXEC_FUEL: u64 = 1_000_000_000;

#[derive(Debug, Error)]
pub enum CrawlerDataExecError {
    #[error("processor module is empty or exceeds 4194304 bytes")]
    ModuleSize,
    #[error("processor fuel must be in 1..={MAX_DATA_EXEC_FUEL}")]
    InvalidFuel,
    #[error("processor compilation failed: {0}")]
    Compile(String),
    #[error("processor imports are forbidden; YCE1 modules must be capability-free")]
    ImportsForbidden,
    #[error("processor module is invalid: {0}")]
    InvalidModule(String),
    #[error("input is {actual} bytes; maximum is 1048576")]
    InputTooLarge { actual: usize },
    #[error("processor execution failed: {0}")]
    Execution(String),
    #[error("processor output is invalid: {0}")]
    InvalidOutput(String),
}

/// A compiled, capability-free processor. It can be reused, but every call
/// receives a fresh Store and instance so guest state cannot leak between jobs.
#[derive(Clone)]
pub struct CrawlerDataExecutor {
    engine: Engine,
    module: Module,
    fuel_per_call: u64,
    module_sha256: String,
}

struct ExecutionState {
    limits: StoreLimits,
}

impl CrawlerDataExecutor {
    /// Compile a user-selected processor. Only modules reviewed/authorized by
    /// the caller should be supplied; compilation is not publisher validation.
    pub fn from_bytes(wasm: &[u8], fuel_per_call: u64) -> Result<Self, CrawlerDataExecError> {
        if wasm.is_empty() || wasm.len() > MAX_DATA_EXEC_MODULE_BYTES {
            return Err(CrawlerDataExecError::ModuleSize);
        }
        if fuel_per_call == 0 || fuel_per_call > MAX_DATA_EXEC_FUEL {
            return Err(CrawlerDataExecError::InvalidFuel);
        }

        let mut config = Config::new();
        config.consume_fuel(true);
        config.max_wasm_stack(256 * 1024);
        let engine = Engine::new(&config)
            .map_err(|error| CrawlerDataExecError::Compile(error.to_string()))?;
        let module = Module::from_binary(&engine, wasm)
            .map_err(|error| CrawlerDataExecError::Compile(error.to_string()))?;
        if module.imports().next().is_some() {
            return Err(CrawlerDataExecError::ImportsForbidden);
        }

        Ok(Self {
            engine,
            module,
            fuel_per_call,
            module_sha256: digest_hex(wasm),
        })
    }

    /// SHA-256 of the exact core-Wasm artifact supplied by the caller.
    pub fn module_sha256(&self) -> &str {
        &self.module_sha256
    }

    pub fn with_defaults(wasm: &[u8]) -> Result<Self, CrawlerDataExecError> {
        Self::from_bytes(wasm, DEFAULT_DATA_EXEC_FUEL)
    }

    /// Execute one bounded payload and return the processor's bounded output.
    ///
    /// Required exports: memory, alloc(i32)->i32, execute(i32,i32)->i64.
    /// The i64 result packs output length in its high 32 bits and output
    /// pointer in its low 32 bits. No host imports are linked.
    pub fn execute(&self, input: &[u8]) -> Result<Vec<u8>, CrawlerDataExecError> {
        if input.is_empty() || input.len() > MAX_DATA_EXEC_INPUT_BYTES {
            return Err(CrawlerDataExecError::InputTooLarge { actual: input.len() });
        }

        let limits = StoreLimitsBuilder::new()
            .memory_size(MAX_DATA_EXEC_MEMORY_BYTES)
            .instances(1)
            .memories(1)
            .tables(1)
            .build();
        let mut store = Store::new(&self.engine, ExecutionState { limits });
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.fuel_per_call)
            .map_err(|error| CrawlerDataExecError::Execution(error.to_string()))?;

        let instance = Instance::new(&mut store, &self.module, &[])
            .map_err(|error| CrawlerDataExecError::Execution(error.to_string()))?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| CrawlerDataExecError::InvalidModule("missing memory export".into()))?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "alloc")
            .map_err(|error| CrawlerDataExecError::InvalidModule(error.to_string()))?;
        let execute = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "execute")
            .map_err(|error| CrawlerDataExecError::InvalidModule(error.to_string()))?;

        let input_ptr = alloc
            .call(&mut store, input.len() as i32)
            .map_err(|error| CrawlerDataExecError::Execution(error.to_string()))?;
        if input_ptr <= 0 {
            return Err(CrawlerDataExecError::InvalidModule(
                "alloc returned a non-positive pointer".into(),
            ));
        }
        memory
            .write(&mut store, input_ptr as usize, input)
            .map_err(|error| CrawlerDataExecError::Execution(error.to_string()))?;

        let packed = execute
            .call(&mut store, (input_ptr, input.len() as i32))
            .map_err(|error| CrawlerDataExecError::Execution(error.to_string()))?
            as u64;
        let output_ptr = (packed & 0xffff_ffff) as usize;
        let output_len = (packed >> 32) as usize;
        let memory_len = memory.data_size(&store);
        if output_len > MAX_DATA_EXEC_OUTPUT_BYTES
            || (output_len == 0 && output_ptr != 0)
            || (output_len > 0
                && (output_ptr == 0
                    || output_ptr
                        .checked_add(output_len)
                        .filter(|end| *end <= memory_len)
                        .is_none()))
        {
            return Err(CrawlerDataExecError::InvalidOutput(
                "output pointer or length is outside the permitted range".into(),
            ));
        }

        let mut output = vec![0u8; output_len];
        memory
            .read(&store, output_ptr, &mut output)
            .map_err(|error| CrawlerDataExecError::Execution(error.to_string()))?;
        Ok(output)
    }
}

fn digest_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_stable_processor_artifact_digest() {
        let wasm = wat::parse_str(
            r#"(module
                (memory (export "memory") 1 256)
                (func (export "alloc") (param i32) (result i32) (i32.const 1024))
                (func (export "execute") (param i32 i32) (result i64) (i64.const 0)))"#,
        )
        .unwrap();
        let executor = CrawlerDataExecutor::with_defaults(&wasm).unwrap();
        assert_eq!(executor.module_sha256().len(), 64);
        assert!(executor.module_sha256().bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn executes_explicit_processor_in_fresh_sandbox() {
        let wasm = wat::parse_str(
            r#"(module
                (memory (export "memory") 1 256)
                (func (export "alloc") (param i32) (result i32) (i32.const 1024))
                (data (i32.const 2048) "done")
                (func (export "execute") (param i32 i32) (result i64)
                    (i64.const 17179871232)))"#,
        )
        .unwrap();
        let executor = CrawlerDataExecutor::with_defaults(&wasm).unwrap();
        assert_eq!(executor.execute(b"untrusted page data").unwrap(), b"done");
        assert_eq!(executor.execute(b"another record").unwrap(), b"done");
    }

    #[test]
    fn rejects_modules_with_imports() {
        let wasm = wat::parse_str(
            r#"(module
                (import "wasi_snapshot_preview1" "fd_write"
                    (func (param i32 i32 i32 i32) (result i32))))"#,
        )
        .unwrap();
        assert!(matches!(
            CrawlerDataExecutor::with_defaults(&wasm),
            Err(CrawlerDataExecError::ImportsForbidden)
        ));
    }

    #[test]
    fn rejects_oversized_input_before_execution() {
        let wasm = wat::parse_str(
            r#"(module
                (memory (export "memory") 1 256)
                (func (export "alloc") (param i32) (result i32) (i32.const 1024))
                (func (export "execute") (param i32 i32) (result i64) (i64.const 0)))"#,
        )
        .unwrap();
        let executor = CrawlerDataExecutor::with_defaults(&wasm).unwrap();
        let input = vec![0; MAX_DATA_EXEC_INPUT_BYTES + 1];
        assert!(matches!(
            executor.execute(&input),
            Err(CrawlerDataExecError::InputTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_out_of_bounds_output() {
        let wasm = wat::parse_str(
            r#"(module
                (memory (export "memory") 1 256)
                (func (export "alloc") (param i32) (result i32) (i32.const 1024))
                (func (export "execute") (param i32 i32) (result i64)
                    (i64.const 4294967296000)))"#,
        )
        .unwrap();
        let executor = CrawlerDataExecutor::with_defaults(&wasm).unwrap();
        assert!(matches!(
            executor.execute(b"input"),
            Err(CrawlerDataExecError::InvalidOutput(_))
        ));
    }
}
