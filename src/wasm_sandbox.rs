use std::{env, sync::Mutex};
use wasmtime::{Config, Engine, Instance, Module, Store, StoreLimits, StoreLimitsBuilder};
use zeroize::Zeroize;

pub struct RustasmSandbox {
    engine: Engine,
    execution_buffer: Mutex<Vec<u8>>,
    max_fuel: u64,
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
        })
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
