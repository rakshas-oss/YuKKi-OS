// YuKKi-OS v6.8.0 Async Ethos-U85 Driver Extension
use core::sync::atomic::{AtomicBool, Ordering};
use crate::arch::cache::{clean_dcache_range, invalidate_dcache_range};

#[repr(C, align(16))]
pub struct EthosU85Job {
    pub cmd_stream_ptr: *const u8,
    pub cmd_stream_size: usize,
    pub sram_base_addr: usize,
    pub is_completed: AtomicBool,
}

impl EthosU85Job {
    pub fn new(cmd_stream: &[u8], sram_buffer: usize) -> Self {
        Self {
            cmd_stream_ptr: cmd_stream.as_ptr(),
            cmd_stream_size: cmd_stream.len(),
            sram_base_addr: sram_buffer,
            is_completed: AtomicBool::new(false),
        }
    }

    /// Dispatches command stream to Ethos-U85 NPU DMA without blocking host thread.
    pub unsafe fn dispatch_async(&self) -> Result<(), u32> {
        // Clean cache lines before hardware DMA fetch
        clean_dcache_range(self.cmd_stream_ptr as usize, self.cmd_stream_size);
        
        // Register async interrupt callback
        ethosu_register_irq_handler(self.sram_base_addr, || {
            self.is_completed.store(true, Ordering::Release);
            crate::sched::wake_yielded_wasm_guest(self.sram_base_addr);
        });

        // Trigger hardware start signal
        ethosu_invoke_async_hw(self.cmd_stream_ptr, self.cmd_stream_size);
        Ok(())
    }
}

extern "C" {
    fn ethosu_invoke_async_hw(ptr: *const u8, size: usize);
    fn ethosu_register_irq_handler(id: usize, cb: fn());
}
