// YuKKi-OS v6.8.0 Wasmtime Host Execution Bridge Patch
use crate::sched::{yield_current_thread, ThreadState};
use wasmtime::Caller;

/// Host call invoked by Wasm guest when delegating compute to Ethos-U85 or XPU.
/// Yields execution immediately without burning guest execution fuel.
pub fn wasmtime_yield_xpu<T>(
    mut caller: Caller<'_, T>,
    channel_id: u64,
) -> Result<(), wasmtime::Error> {
    let current_pid = caller.data_mut();
    
    // Put guest thread into Sleeping state waiting on IRQ channel
    crate::sched::set_thread_state(current_pid, ThreadState::WaitingOnXpu(channel_id));
    
    // Yield CPU cycles back to microkernel scheduler
    yield_current_thread();
    
    Ok(())
}

#[no_mangle]
pub extern "C" fn sys_resume_wasm_guest(channel_id: u64) {
    // Invoked by Ethos-U85 IRQ handler to wake Wasm guest
    crate::sched::wake_by_channel_id(channel_id);
}
