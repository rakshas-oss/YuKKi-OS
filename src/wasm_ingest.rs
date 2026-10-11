//! Safe ingest and execution of guest Wasm workers (`POST /v1/sandbox/deploy`).
//!
//! [`handle_deploy`] is a pure request handler; an integrating front end must
//! authenticate the caller before invoking it.

use crate::media_codec::{LiveMediaStreams, MediaError, MEDIA_MAX_STREAM_ID_BYTES};
use std::{collections::HashMap, sync::Arc, thread, time::Duration};
use wasmtime::{
    Config, Engine, ExternType, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder,
    TypedFunc, ValType,
};

pub const MAX_MODULE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TENSOR_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_MEMORY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_XPU_TIMEOUT_MS: u32 = 30_000;
pub const DEFAULT_FUEL: u64 = 10_000_000;
pub const EXECUTION_TIMEOUT: Duration = Duration::from_secs(10);
pub const CHANNEL_SIZE: usize = 48;
pub const CHANNEL_ALIGN: usize = 16;
pub const IMPORT_MODULE: &str = "env";
pub const IMPORT_NAME: &str = "wasmtime_yield_xpu";
pub const SELECT_STREAM_IMPORT_NAME: &str = "yukki_select_stream";
pub const EXPORT_NAME: &str = "execute_inference_pipeline";
const WASM_MAGIC: &[u8; 4] = b"\0asm";
const WASM_PAGE: usize = 65536;

/// Host-side bridge status codes returned to the guest.
pub const STATUS_BAD_CHANNEL: i32 = -1;
pub const STATUS_MISALIGNED: i32 = -3;
pub const STATUS_CHANNEL_MISMATCH: i32 = -8;
pub const STATUS_STREAMS_UNAVAILABLE: i32 = -20;
pub const STATUS_BAD_STREAM_ID: i32 = -21;
pub const STATUS_STREAM_NOT_FOUND: i32 = -22;
pub const STATUS_STREAM_BUFFER_TOO_SMALL: i32 = -23;
pub const STATUS_STREAM_WAITING: i32 = -24;
pub const STATUS_STREAM_FINISHED: i32 = -25;
pub const STATUS_STREAM_LAGGED: i32 = -26;
const MAX_STREAM_CHUNK_FRAME: usize = crate::media_codec::MEDIA_CHUNK_HEADER_LEN
    + MEDIA_MAX_STREAM_ID_BYTES
    + crate::media_codec::MEDIA_MAX_CODEC_BYTES
    + crate::media_codec::MEDIA_MAX_CHUNK_BYTES;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IngestError {
    #[error("module larger than {MAX_MODULE_BYTES} bytes")]
    TooLarge,
    #[error("missing \\0asm header")]
    BadMagic,
    #[error("invalid module: {0}")]
    Invalid(String),
    #[error("disallowed import {0}")]
    DisallowedImport(String),
    #[error("missing or mistyped export {EXPORT_NAME}")]
    MissingExport,
    #[error("invalid channel id header")]
    BadChannelId,
    #[error("execution failed: {0}")]
    Execution(String),
}

/// Parse `X-YuKKi-Channel-Id` (hex u64, optional `0x` prefix).
pub fn parse_channel_id(header: &str) -> Result<u64, IngestError> {
    let h = header.trim();
    let digits = h
        .strip_prefix("0x")
        .or_else(|| h.strip_prefix("0X"))
        .unwrap_or(h);
    if digits.is_empty() || digits.len() > 16 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(IngestError::BadChannelId);
    }
    u64::from_str_radix(digits, 16).map_err(|_| IngestError::BadChannelId)
}

fn make_engine() -> Engine {
    let mut config = Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    config.max_wasm_stack(512 * 1024);
    Engine::new(&config).expect("valid Wasmtime configuration")
}

/// Validate size, header, imports and exports of a guest module.
pub fn validate_module(engine: &Engine, bytes: &[u8]) -> Result<Module, IngestError> {
    if bytes.len() > MAX_MODULE_BYTES {
        return Err(IngestError::TooLarge);
    }
    if bytes.len() < 4 || &bytes[..4] != WASM_MAGIC {
        return Err(IngestError::BadMagic);
    }
    let module = Module::new(engine, bytes).map_err(|e| IngestError::Invalid(e.to_string()))?;
    for import in module.imports() {
        let expected_params = match import.name() {
            IMPORT_NAME => Some(2),
            SELECT_STREAM_IMPORT_NAME => Some(4),
            _ => None,
        };
        let ok = import.module() == IMPORT_MODULE
            && expected_params.is_some()
            && matches!(import.ty(), ExternType::Func(f)
                if f.params().len() == expected_params.unwrap()
                    && f.params().all(|p| matches!(p, ValType::I32))
                    && f.results().len() == 1
                    && f.results().all(|r| matches!(r, ValType::I32)));
        if !ok {
            return Err(IngestError::DisallowedImport(format!(
                "{}::{}",
                import.module(),
                import.name()
            )));
        }
    }
    let export_ok = module.exports().any(|e| {
        e.name() == EXPORT_NAME
            && matches!(e.ty(), ExternType::Func(f)
                if f.params().len() == 3
                    && f.params().all(|p| matches!(p, ValType::I32))
                    && f.results().len() == 1
                    && f.results().all(|r| matches!(r, ValType::I32)))
    });
    let has_memory = module
        .exports()
        .any(|e| e.name() == "memory" && matches!(e.ty(), ExternType::Memory(_)));
    if !export_ok || !has_memory {
        return Err(IngestError::MissingExport);
    }
    Ok(module)
}

/// Validate that a guest channel pointer lies fully inside linear memory and
/// is 16-byte aligned. Never dereferences anything.
pub fn validate_channel_ptr(mem_len: usize, ptr: u32) -> Result<usize, i32> {
    let ptr = ptr as usize;
    if ptr == 0 {
        return Err(STATUS_BAD_CHANNEL);
    }
    if ptr % CHANNEL_ALIGN != 0 {
        return Err(STATUS_MISALIGNED);
    }
    match ptr.checked_add(CHANNEL_SIZE) {
        Some(end) if end <= mem_len => Ok(ptr),
        _ => Err(STATUS_BAD_CHANNEL),
    }
}

/// Handler invoked when the guest yields: `(channel_id, timeout_ms) -> status`.
/// Production wires this to the Ethos-U85 IRQ wait; tests mock it.
pub type XpuHandler = Arc<dyn Fn(u64, u32) -> i32 + Send + Sync>;

struct GuestState {
    limits: StoreLimits,
    channel_id: u64,
    handler: XpuHandler,
    streams: Option<Arc<LiveMediaStreams>>,
    stream_cursors: HashMap<String, u64>,
}

fn bridge(mut caller: wasmtime::Caller<'_, GuestState>, ptr: i32, timeout_ms: i32) -> i32 {
    let Some(mem) = caller.get_export("memory").and_then(|e| e.into_memory()) else {
        return STATUS_BAD_CHANNEL;
    };
    let data = mem.data(&caller);
    let ptr = match validate_channel_ptr(data.len(), ptr as u32) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let guest_id = u64::from_le_bytes(data[ptr..ptr + 8].try_into().expect("8 bytes"));
    let expected = caller.data().channel_id;
    if guest_id != expected {
        return STATUS_CHANNEL_MISMATCH;
    }
    let timeout = (timeout_ms as u32).clamp(1, MAX_XPU_TIMEOUT_MS);
    let handler = caller.data().handler.clone();
    handler(expected, timeout)
}

fn select_stream(
    mut caller: wasmtime::Caller<'_, GuestState>,
    id_ptr: i32,
    id_len: i32,
    output_ptr: i32,
    output_capacity: i32,
) -> i32 {
    let Some(memory) = caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
    else {
        return STATUS_BAD_STREAM_ID;
    };
    let memory_len = memory.data(&caller).len();
    let Some(id_range) = guest_range(memory_len, id_ptr, id_len, MEDIA_MAX_STREAM_ID_BYTES) else {
        return STATUS_BAD_STREAM_ID;
    };
    let stream_id = match std::str::from_utf8(&memory.data(&caller)[id_range]) {
        Ok(id) if !id.trim().is_empty() => id.to_string(),
        _ => return STATUS_BAD_STREAM_ID,
    };
    let Some(output_range) = guest_range(
        memory_len,
        output_ptr,
        output_capacity,
        MAX_STREAM_CHUNK_FRAME,
    ) else {
        return STATUS_BAD_STREAM_ID;
    };
    let Some(streams) = caller.data().streams.clone() else {
        return STATUS_STREAMS_UNAVAILABLE;
    };
    let sequence = *caller.data().stream_cursors.get(&stream_id).unwrap_or(&0);
    let chunk = match streams.get_chunk(&stream_id, sequence) {
        Ok(chunk) => chunk,
        Err(MediaError::MissingChunk { .. }) => {
            return if streams.stream_snapshots().ok().is_some_and(|snapshots| {
                snapshots
                    .iter()
                    .any(|snapshot| snapshot.metadata.stream_id == stream_id && snapshot.finished)
            }) {
                STATUS_STREAM_FINISHED
            } else {
                STATUS_STREAM_WAITING
            };
        }
        Err(MediaError::ChunkNotRetained { .. }) => return STATUS_STREAM_LAGGED,
        Err(MediaError::StreamNotFound(_)) => return STATUS_STREAM_NOT_FOUND,
        Err(_) => return STATUS_BAD_STREAM_ID,
    };
    let encoded = match chunk.encode() {
        Ok(encoded) => encoded,
        Err(_) => return STATUS_BAD_STREAM_ID,
    };
    if encoded.len() > output_range.len() {
        return STATUS_STREAM_BUFFER_TOO_SMALL;
    }
    if memory
        .write(&mut caller, output_range.start, &encoded)
        .is_err()
    {
        return STATUS_BAD_STREAM_ID;
    }
    if streams.acknowledge_through(&stream_id, sequence).is_err() {
        return STATUS_BAD_STREAM_ID;
    }
    let Some(next_sequence) = sequence.checked_add(1) else {
        return STATUS_STREAM_LAGGED;
    };
    caller
        .data_mut()
        .stream_cursors
        .insert(stream_id, next_sequence);
    i32::try_from(encoded.len()).unwrap_or(STATUS_STREAM_BUFFER_TOO_SMALL)
}

fn guest_range(
    memory_len: usize,
    ptr: i32,
    len: i32,
    max_len: usize,
) -> Option<std::ops::Range<usize>> {
    if ptr <= 0 || len <= 0 {
        return None;
    }
    let start = ptr as usize;
    let length = len as usize;
    if length > max_len {
        return None;
    }
    let end = start.checked_add(length)?;
    (end <= memory_len).then_some(start..end)
}

/// Run `execute_inference_pipeline` in a fresh, resource-limited instance.
/// Returns the guest's i32 result.
pub fn run_guest(
    wasm: &[u8],
    channel_id: u64,
    tensor: &[u8],
    handler: XpuHandler,
) -> Result<i32, IngestError> {
    run_guest_with_streams(wasm, channel_id, tensor, handler, None)
}

/// Run a guest with access to bounded binary chunks in the host media store.
/// Guests request a stream by ID and receive one encoded YKMC chunk per import
/// call; no native pointer or store reference crosses the Wasm boundary.
pub fn run_guest_with_streams(
    wasm: &[u8],
    channel_id: u64,
    tensor: &[u8],
    handler: XpuHandler,
    streams: Option<Arc<LiveMediaStreams>>,
) -> Result<i32, IngestError> {
    if tensor.len() > MAX_TENSOR_BYTES {
        return Err(IngestError::TooLarge);
    }
    let engine = make_engine();
    let module = validate_module(&engine, wasm)?;
    let exec = |e: String| IngestError::Execution(e);
    let mut linker = Linker::new(&engine);
    linker
        .func_wrap(IMPORT_MODULE, IMPORT_NAME, bridge)
        .map_err(|e| exec(e.to_string()))?;
    linker
        .func_wrap(IMPORT_MODULE, SELECT_STREAM_IMPORT_NAME, select_stream)
        .map_err(|e| exec(e.to_string()))?;
    let limits = StoreLimitsBuilder::new()
        .memory_size(MAX_MEMORY_BYTES)
        .build();
    let mut store = Store::new(
        &engine,
        GuestState {
            limits,
            channel_id,
            handler,
            streams,
            stream_cursors: HashMap::new(),
        },
    );
    store.limiter(|s| &mut s.limits);
    store
        .set_fuel(DEFAULT_FUEL)
        .map_err(|e| exec(e.to_string()))?;
    store.set_epoch_deadline(1);
    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| exec(e.to_string()))?;
    let memory: Memory = instance
        .get_memory(&mut store, "memory")
        .ok_or(IngestError::MissingExport)?;
    let func: TypedFunc<(i32, i32, i32), i32> = instance
        .get_typed_func(&mut store, EXPORT_NAME)
        .map_err(|_| IngestError::MissingExport)?;

    // Place channel + tensor in freshly grown pages so guest data is untouched.
    let needed = CHANNEL_SIZE + CHANNEL_ALIGN + tensor.len();
    let pages = needed.div_ceil(WASM_PAGE) as u64;
    let base = memory
        .grow(&mut store, pages)
        .map_err(|e| exec(e.to_string()))? as usize
        * WASM_PAGE;
    let tensor_off = base + CHANNEL_SIZE + CHANNEL_ALIGN;
    {
        let data = memory.data_mut(&mut store);
        data[base..base + 8].copy_from_slice(&channel_id.to_le_bytes());
        data[tensor_off..tensor_off + tensor.len()].copy_from_slice(tensor);
    }
    let (base_i, tensor_i) = (
        i32::try_from(base).map_err(|_| IngestError::TooLarge)?,
        i32::try_from(tensor_off).map_err(|_| IngestError::TooLarge)?,
    );

    // Epoch watchdog bounds wall-clock time; thread exits when guest finishes.
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let wd_engine = engine.clone();
    let watchdog = thread::spawn(move || {
        if done_rx.recv_timeout(EXECUTION_TIMEOUT).is_err() {
            wd_engine.increment_epoch();
        }
    });
    let result = func.call(&mut store, (base_i, tensor_i, tensor.len() as i32));
    let _ = done_tx.send(());
    let _ = watchdog.join();
    result.map_err(|e| exec(e.to_string()))
}

#[derive(Debug, PartialEq, Eq)]
pub struct DeployResponse {
    pub status: u16,
    pub body: String,
}

/// Handle `POST /v1/sandbox/deploy`. Callers MUST authenticate first.
pub fn handle_deploy(
    content_type: Option<&str>,
    channel_header: Option<&str>,
    body: &[u8],
    handler: XpuHandler,
) -> DeployResponse {
    let resp = |status: u16, body: &str| DeployResponse {
        status,
        body: body.to_string(),
    };
    if content_type.map(|c| c.trim().eq_ignore_ascii_case("application/wasm")) != Some(true) {
        return resp(415, "Content-Type must be application/wasm");
    }
    let channel_id = match channel_header.map(parse_channel_id) {
        Some(Ok(id)) => id,
        _ => return resp(400, "missing or invalid X-YuKKi-Channel-Id (hex u64)"),
    };
    let engine = make_engine();
    match validate_module(&engine, body) {
        Ok(_) => {}
        Err(IngestError::TooLarge) => return resp(413, "module too large"),
        Err(e) => return resp(422, &e.to_string()),
    }
    // Smoke-run with a minimal tensor to confirm the module executes within limits.
    match run_guest(body, channel_id, &[0u8; 16], handler) {
        Ok(0) => resp(200, "deployed"),
        Ok(code) => DeployResponse {
            status: 422,
            body: format!("guest returned {code}"),
        },
        Err(e) => resp(422, &e.to_string()),
    }
}
