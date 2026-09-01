use std::sync::Mutex;
use wasmtime::{Config, Engine, Instance, Module, Store, StoreLimits, StoreLimitsBuilder};
use zeroize::Zeroize;

pub struct RustasmSandbox {
    engine: Engine,
    execution_buffer: Mutex<Vec<u8>>,
}

struct SandboxState {
    limits: StoreLimits,
}

impl RustasmSandbox {
    const MAX_BUFFER_BYTES: usize = 64 * 1024;
    const MAX_MEMORY_BYTES: usize = 16 * 1024 * 1024;
    const MAX_FUEL: u64 = 10_000_000;

    pub fn new() -> Self {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.max_wasm_stack(512 * 1024);
        Self {
            engine: Engine::new(&config).expect("valid Wasmtime configuration"),
            execution_buffer: Mutex::new(Vec::with_capacity(960)),
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
            .add_fuel(Self::MAX_FUEL)
            .map_err(|error| error.to_string())?;
        let instance =
            Instance::new(&mut store, &module, &[]).map_err(|error| error.to_string())?;
        let main = instance
            .get_typed_func::<(), i32>(&mut store, "main")
            .map_err(|error| error.to_string())?;
        main.call(&mut store, ()).map_err(|error| error.to_string())
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
