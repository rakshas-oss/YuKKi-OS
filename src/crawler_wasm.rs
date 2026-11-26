//! Bounded, capability-free Wasmtime execution for crawler extraction plugins.
//!
//! Plugins receive document bytes through linear memory and return a compact
//! YCR1 record. Imports are rejected: crawler plugins cannot open sockets,
//! access files, or import WASI/host functions.

use thiserror::Error;
use wasmtime::{Config, Engine, Instance, Module, Store, StoreLimits, StoreLimitsBuilder};

pub const CRAWLER_WASM_ABI: &str = "YCR1";
pub const MAX_CRAWLER_INPUT_BYTES: usize = 1_048_576;
pub const MAX_CRAWLER_OUTPUT_BYTES: usize = 300_000;
pub const MAX_CRAWLER_WASM_MEMORY_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_CRAWLER_FUEL: u64 = 5_000_000;
pub const MAX_EXTRACTED_LINKS: usize = 128;

#[derive(Debug, Error)]
pub enum CrawlerWasmError {
    #[error("crawler WASM module is empty or exceeds the {max}-byte limit")]
    ModuleSize { max: usize },
    #[error("crawler WASM compilation failed: {0}")]
    Compile(String),
    #[error("crawler WASM imports are not permitted")]
    ImportsForbidden,
    #[error("crawler WASM instance is invalid: {0}")]
    InvalidModule(String),
    #[error("crawler input is {actual} bytes; maximum is {max}")]
    InputTooLarge { actual: usize, max: usize },
    #[error("crawler WASM execution failed: {0}")]
    Execution(String),
    #[error("crawler WASM output violates the YCR1 ABI: {0}")]
    InvalidOutput(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HtmlExtraction {
    pub document_bytes: u32,
    pub title: String,
    pub links: Vec<String>,
}

#[derive(Clone)]
pub struct WasmHtmlExtractor {
    engine: Engine,
    module: Module,
    fuel_per_call: u64,
    max_memory_bytes: usize,
}

struct StoreState {
    limits: StoreLimits,
}

impl WasmHtmlExtractor {
    pub fn from_bytes(
        wasm: &[u8],
        fuel_per_call: u64,
        max_memory_bytes: usize,
    ) -> Result<Self, CrawlerWasmError> {
        if wasm.is_empty() || wasm.len() > 4 * 1024 * 1024 || fuel_per_call == 0
            || !(64 * 1024..=MAX_CRAWLER_WASM_MEMORY_BYTES).contains(&max_memory_bytes)
        {
            return Err(CrawlerWasmError::ModuleSize { max: 4 * 1024 * 1024 });
        }

        let mut config = Config::new();
        config.consume_fuel(true);
        config.max_wasm_stack(256 * 1024);
        let engine = Engine::new(&config)
            .map_err(|error| CrawlerWasmError::Compile(error.to_string()))?;
        let module = Module::from_binary(&engine, wasm)
            .map_err(|error| CrawlerWasmError::Compile(error.to_string()))?;
        if module.imports().next().is_some() {
            return Err(CrawlerWasmError::ImportsForbidden);
        }

        Ok(Self { engine, module, fuel_per_call, max_memory_bytes })
    }

    pub fn with_defaults(wasm: &[u8]) -> Result<Self, CrawlerWasmError> {
        Self::from_bytes(wasm, DEFAULT_CRAWLER_FUEL, MAX_CRAWLER_WASM_MEMORY_BYTES)
    }

    pub fn extract(&self, document: &[u8]) -> Result<HtmlExtraction, CrawlerWasmError> {
        if document.is_empty() || document.len() > MAX_CRAWLER_INPUT_BYTES {
            return Err(CrawlerWasmError::InputTooLarge {
                actual: document.len(),
                max: MAX_CRAWLER_INPUT_BYTES,
            });
        }

        let limits = StoreLimitsBuilder::new()
            .memory_size(self.max_memory_bytes)
            .instances(1)
            .memories(1)
            .tables(1)
            .build();
        let mut store = Store::new(&self.engine, StoreState { limits });
        store.limiter(|state| &mut state.limits);
        store.set_fuel(self.fuel_per_call)
            .map_err(|error| CrawlerWasmError::Execution(error.to_string()))?;

        let instance = Instance::new(&mut store, &self.module, &[])
            .map_err(|error| CrawlerWasmError::Execution(error.to_string()))?;
        let memory = instance.get_memory(&mut store, "memory")
            .ok_or_else(|| CrawlerWasmError::InvalidModule("missing exported memory".into()))?;
        let alloc = instance.get_typed_func::<i32, i32>(&mut store, "alloc")
            .map_err(|error| CrawlerWasmError::InvalidModule(error.to_string()))?;
        let process = instance.get_typed_func::<(i32, i32), i64>(&mut store, "process")
            .map_err(|error| CrawlerWasmError::InvalidModule(error.to_string()))?;

        let input_ptr = alloc.call(&mut store, document.len() as i32)
            .map_err(|error| CrawlerWasmError::Execution(error.to_string()))?;
        if input_ptr <= 0 {
            return Err(CrawlerWasmError::InvalidModule("alloc returned an invalid pointer".into()));
        }
        memory.write(&mut store, input_ptr as usize, document)
            .map_err(|error| CrawlerWasmError::Execution(error.to_string()))?;

        let packed = process.call(&mut store, (input_ptr, document.len() as i32))
            .map_err(|error| CrawlerWasmError::Execution(error.to_string()))? as u64;
        let output_ptr = (packed & 0xffff_ffff) as usize;
        let output_len = (packed >> 32) as usize;
        let memory_len = memory.data_size(&store);
        if output_ptr == 0 || !(12..=MAX_CRAWLER_OUTPUT_BYTES).contains(&output_len)
            || output_ptr.checked_add(output_len).filter(|end| *end <= memory_len).is_none()
        {
            return Err(CrawlerWasmError::InvalidOutput("output pointer or length is out of bounds".into()));
        }

        let mut output = vec![0u8; output_len];
        memory.read(&store, output_ptr, &mut output)
            .map_err(|error| CrawlerWasmError::Execution(error.to_string()))?;
        decode_ycr1(&output, document.len())
    }
}

fn read_u16(bytes: &[u8], at: usize) -> Result<u16, CrawlerWasmError> {
    let slice = bytes.get(at..at + 2)
        .ok_or_else(|| CrawlerWasmError::InvalidOutput("truncated u16".into()))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32, CrawlerWasmError> {
    let slice = bytes.get(at..at + 4)
        .ok_or_else(|| CrawlerWasmError::InvalidOutput("truncated u32".into()))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn decode_ycr1(bytes: &[u8], expected_document_bytes: usize) -> Result<HtmlExtraction, CrawlerWasmError> {
    if bytes.get(0..4) != Some(b"YCR1") {
        return Err(CrawlerWasmError::InvalidOutput("bad magic".into()));
    }
    let document_bytes = read_u32(bytes, 4)?;
    if document_bytes as usize != expected_document_bytes {
        return Err(CrawlerWasmError::InvalidOutput("document length does not match input".into()));
    }
    let link_count = read_u16(bytes, 8)? as usize;
    let title_len = read_u16(bytes, 10)? as usize;
    if link_count > MAX_EXTRACTED_LINKS || title_len > 256 {
        return Err(CrawlerWasmError::InvalidOutput("title or link count exceeds ABI limits".into()));
    }
    let mut cursor = 12usize;
    let title_end = cursor.checked_add(title_len)
        .ok_or_else(|| CrawlerWasmError::InvalidOutput("title length overflow".into()))?;
    let title_bytes = bytes.get(cursor..title_end)
        .ok_or_else(|| CrawlerWasmError::InvalidOutput("truncated title".into()))?;
    let title = String::from_utf8_lossy(title_bytes).trim().to_string();
    cursor = title_end;

    let mut links = Vec::with_capacity(link_count);
    for _ in 0..link_count {
        let length = read_u16(bytes, cursor)? as usize;
        cursor = cursor.checked_add(2)
            .ok_or_else(|| CrawlerWasmError::InvalidOutput("link offset overflow".into()))?;
        if length == 0 || length > 2048 {
            return Err(CrawlerWasmError::InvalidOutput("invalid link length".into()));
        }
        let end = cursor.checked_add(length)
            .ok_or_else(|| CrawlerWasmError::InvalidOutput("link length overflow".into()))?;
        let value = bytes.get(cursor..end)
            .ok_or_else(|| CrawlerWasmError::InvalidOutput("truncated link".into()))?;
        let link = String::from_utf8_lossy(value).trim().to_string();
        if !link.is_empty() {
            links.push(link);
        }
        cursor = end;
    }
    if cursor != bytes.len() {
        return Err(CrawlerWasmError::InvalidOutput("trailing bytes".into()));
    }
    Ok(HtmlExtraction { document_bytes, title, links })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executes_capability_free_ycr1_module() {
        let wasm = wat::parse_str(r#"
            (module
              (memory (export "memory") 1 64)
              (func (export "alloc") (param i32) (result i32) (i32.const 1024))
              (data (i32.const 2048) "YCR1\05\00\00\00\00\00\00\00")
              (func (export "process") (param i32 i32) (result i64)
                (i64.const 51539609600)))
        "#).unwrap();
        let extractor = WasmHtmlExtractor::with_defaults(&wasm).unwrap();
        let output = extractor.extract(b"hello").unwrap();
        assert_eq!(output.document_bytes, 5);
        assert!(output.title.is_empty());
        assert!(output.links.is_empty());
    }

    #[test]
    fn rejects_modules_with_imports() {
        let wasm = wat::parse_str(r#"
            (module
              (import "wasi_snapshot_preview1" "fd_write"
                (func (param i32 i32 i32 i32) (result i32))))
        "#).unwrap();
        assert!(matches!(
            WasmHtmlExtractor::with_defaults(&wasm),
            Err(CrawlerWasmError::ImportsForbidden)
        ));
    }

    #[test]
    fn rejects_oversized_documents_before_wasm_execution() {
        let wasm = wat::parse_str(r#"
            (module (memory (export "memory") 1 64)
              (func (export "alloc") (param i32) (result i32) (i32.const 1024))
              (func (export "process") (param i32 i32) (result i64) (i64.const 0)))
        "#).unwrap();
        let extractor = WasmHtmlExtractor::with_defaults(&wasm).unwrap();
        let input = vec![0u8; MAX_CRAWLER_INPUT_BYTES + 1];
        assert!(matches!(
            extractor.extract(&input),
            Err(CrawlerWasmError::InputTooLarge { .. })
        ));
    }
}
