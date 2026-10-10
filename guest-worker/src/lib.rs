//! YuKKi-OS user-safe Wasm guest worker.
//!
//! Exports `execute_inference_pipeline`, which hashes a tensor, publishes the
//! hash to the shared [`Nxr1StateChannel`], and yields to the host XPU
//! (Ethos-U85) bridge via the `wasmtime_yield_xpu` import.
//!
//! # Error codes (returned as `i32`)
//!
//! | code | meaning |
//! |------|---------|
//! |  0   | success |
//! | -1   | invalid (null / overflowing) pointer |
//! | -2   | channel lock contention |
//! | -3   | channel pointer not 16-byte aligned |
//! | -4   | tensor larger than [`MAX_TENSOR_BYTES`] |
//! | -5   | empty tensor |
//! | -6   | XPU timeout |
//! | -7   | other non-zero host status (mapped) |
//!
//! Host statuses `<= -64` are passed through unchanged.
#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use core::mem::{align_of, size_of};
use core::sync::atomic::{AtomicU32, Ordering};

/// Maximum accepted tensor size (16 MiB).
pub const MAX_TENSOR_BYTES: usize = 16 * 1024 * 1024;
/// Default XPU wait.
pub const DEFAULT_TIMEOUT_MS: u32 = 5000;
/// Upper bound for any XPU wait.
pub const MAX_TIMEOUT_MS: u32 = 30_000;
/// Required channel alignment.
pub const CHANNEL_ALIGN: usize = 16;

const LOCK_FREE: u32 = 0;
const LOCK_HELD: u32 = 1;
const HOST_STATUS_PASSTHROUGH_MAX: i32 = -64;

/// Shared state channel; layout must match the host's `Nxr1StateChannel`.
#[repr(C, align(16))]
pub struct Nxr1StateChannel {
    pub channel_id: u64,
    pub bitmask: u64,
    pub payload_hash: [u8; 16],
    pub lock: AtomicU32,
}

const _: () = assert!(size_of::<Nxr1StateChannel>() == 48);
const _: () = assert!(align_of::<Nxr1StateChannel>() == CHANNEL_ALIGN);

/// Typed error with fixed negative codes (see crate docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerError {
    InvalidPointer,
    LockContention,
    Misaligned,
    TensorTooLarge,
    EmptyTensor,
    XpuTimeout,
    HostStatus(i32),
}

impl WorkerError {
    pub const fn code(self) -> i32 {
        match self {
            WorkerError::InvalidPointer => -1,
            WorkerError::LockContention => -2,
            WorkerError::Misaligned => -3,
            WorkerError::TensorTooLarge => -4,
            WorkerError::EmptyTensor => -5,
            WorkerError::XpuTimeout => -6,
            WorkerError::HostStatus(s) if s <= HOST_STATUS_PASSTHROUGH_MAX => s,
            WorkerError::HostStatus(_) => -7,
        }
    }

    /// Map a non-zero host status to an error.
    pub const fn from_host_status(status: i32) -> Self {
        if status == -6 {
            WorkerError::XpuTimeout
        } else {
            WorkerError::HostStatus(status)
        }
    }
}

/// 128-bit FNV-1a style mix (two lanes with distinct bases/primes, length
/// folded in). For integrity/telemetry only; NOT cryptographically secure.
pub fn hash128(data: &[u8]) -> [u8; 16] {
    let mut a: u64 = 0xcbf2_9ce4_8422_2325;
    let mut b: u64 = 0x8422_2325_cbf2_9ce4;
    for &byte in data {
        a = (a ^ byte as u64).wrapping_mul(0x0000_0100_0000_01b3);
        b = (b ^ byte as u64).wrapping_mul(0x0000_0001_0000_01b3 | 1 << 40);
        b = b.rotate_left(23) ^ a;
    }
    a ^= (data.len() as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    b = (b ^ a.rotate_left(31)).wrapping_mul(0xff51_afd7_ed55_8ccd);
    a = (a ^ (b >> 29)).wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&a.to_le_bytes());
    out[8..].copy_from_slice(&b.to_le_bytes());
    out
}

/// Clamp a requested timeout into `[1, MAX_TIMEOUT_MS]`.
pub const fn clamp_timeout(timeout_ms: u32) -> u32 {
    if timeout_ms == 0 {
        1
    } else if timeout_ms > MAX_TIMEOUT_MS {
        MAX_TIMEOUT_MS
    } else {
        timeout_ms
    }
}

/// Validate raw pointer/length arguments without dereferencing anything.
pub fn validate_args(channel_addr: usize, tensor_addr: usize, tensor_len: usize) -> Result<(), WorkerError> {
    if channel_addr == 0 || tensor_addr == 0 {
        return Err(WorkerError::InvalidPointer);
    }
    if channel_addr % CHANNEL_ALIGN != 0 {
        return Err(WorkerError::Misaligned);
    }
    if tensor_len == 0 {
        return Err(WorkerError::EmptyTensor);
    }
    if tensor_len > MAX_TENSOR_BYTES {
        return Err(WorkerError::TensorTooLarge);
    }
    tensor_addr.checked_add(tensor_len).ok_or(WorkerError::InvalidPointer)?;
    channel_addr
        .checked_add(size_of::<Nxr1StateChannel>())
        .ok_or(WorkerError::InvalidPointer)?;
    Ok(())
}

/// RAII guard: lock is released on every exit path.
struct LockGuard<'a>(&'a AtomicU32);

impl<'a> LockGuard<'a> {
    fn acquire(lock: &'a AtomicU32) -> Result<Self, WorkerError> {
        lock.compare_exchange(LOCK_FREE, LOCK_HELD, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| LockGuard(lock))
            .map_err(|_| WorkerError::LockContention)
    }

    fn still_held(&self) -> bool {
        self.0.load(Ordering::Acquire) == LOCK_HELD
    }
}

impl Drop for LockGuard<'_> {
    fn drop(&mut self) {
        self.0.store(LOCK_FREE, Ordering::Release);
    }
}

/// Safe pipeline logic. `yield_xpu` receives the clamped timeout and returns
/// the host status.
pub fn run_pipeline(
    channel: &mut Nxr1StateChannel,
    tensor: &[u8],
    timeout_ms: u32,
    yield_xpu: impl FnOnce(u32) -> i32,
) -> Result<(), WorkerError> {
    if tensor.is_empty() {
        return Err(WorkerError::EmptyTensor);
    }
    if tensor.len() > MAX_TENSOR_BYTES {
        return Err(WorkerError::TensorTooLarge);
    }
    let Nxr1StateChannel { bitmask, payload_hash, lock, .. } = channel;
    let guard = LockGuard::acquire(lock)?;
    *payload_hash = hash128(tensor);
    *bitmask = 1;
    let status = yield_xpu(clamp_timeout(timeout_ms));
    if status != 0 {
        return Err(WorkerError::from_host_status(status));
    }
    if !guard.still_held() {
        return Err(WorkerError::LockContention);
    }
    Ok(())
}

/// # Safety
/// `ptr` must be non-null, 16-byte aligned, point to a live
/// `Nxr1StateChannel`, and be exclusively accessed for `'a`.
unsafe fn channel_from_raw<'a>(ptr: *mut Nxr1StateChannel) -> &'a mut Nxr1StateChannel {
    // SAFETY: guaranteed by the caller contract above.
    unsafe { &mut *ptr }
}

/// # Safety
/// `ptr..ptr+len` must be a valid readable range that is not mutated for `'a`.
unsafe fn tensor_from_raw<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    // SAFETY: guaranteed by the caller contract above.
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

#[cfg(target_arch = "wasm32")]
mod host {
    use super::Nxr1StateChannel;
    extern "C" {
        /// Yields to the host XPU until the Ethos-U85 IRQ fires.
        pub fn wasmtime_yield_xpu(channel_ptr: *mut Nxr1StateChannel, timeout_ms: u32) -> i32;
    }
}

/// Host-side stand-in so the crate links and tests run on non-wasm targets.
#[cfg(not(target_arch = "wasm32"))]
mod host {
    use super::Nxr1StateChannel;
    pub unsafe fn wasmtime_yield_xpu(_channel_ptr: *mut Nxr1StateChannel, _timeout_ms: u32) -> i32 {
        0
    }
}

/// Entry point invoked by the YuKKi-OS sandbox runtime.
#[no_mangle]
pub extern "C" fn execute_inference_pipeline(
    channel_ptr: *mut Nxr1StateChannel,
    tensor_data_ptr: *const u8,
    tensor_len: usize,
) -> i32 {
    if let Err(e) = validate_args(channel_ptr as usize, tensor_data_ptr as usize, tensor_len) {
        return e.code();
    }
    // SAFETY: pointers are non-null, the channel is 16-byte aligned, the length
    // is bounded and the ranges do not overflow (validate_args); the host
    // guarantees they refer to live guest linear memory.
    let (channel, tensor) = unsafe {
        (channel_from_raw(channel_ptr), tensor_from_raw(tensor_data_ptr, tensor_len))
    };
    let raw = channel_ptr;
    let result = run_pipeline(channel, tensor, DEFAULT_TIMEOUT_MS, |timeout| {
        // SAFETY: the host import only receives the address; it validates it
        // against guest memory before use.
        unsafe { host::wasmtime_yield_xpu(raw, timeout) }
    });
    match result {
        Ok(()) => 0,
        Err(e) => e.code(),
    }
}

/// Trap instead of spinning on panic.
#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chan() -> Nxr1StateChannel {
        Nxr1StateChannel { channel_id: 7, bitmask: 0, payload_hash: [0; 16], lock: AtomicU32::new(0) }
    }

    #[test]
    fn codes_are_stable() {
        assert_eq!(WorkerError::InvalidPointer.code(), -1);
        assert_eq!(WorkerError::LockContention.code(), -2);
        assert_eq!(WorkerError::Misaligned.code(), -3);
        assert_eq!(WorkerError::TensorTooLarge.code(), -4);
        assert_eq!(WorkerError::EmptyTensor.code(), -5);
        assert_eq!(WorkerError::XpuTimeout.code(), -6);
        assert_eq!(WorkerError::from_host_status(-6), WorkerError::XpuTimeout);
        assert_eq!(WorkerError::from_host_status(3).code(), -7);
        assert_eq!(WorkerError::from_host_status(-100).code(), -100);
    }

    #[test]
    fn validation() {
        assert_eq!(validate_args(0, 16, 1), Err(WorkerError::InvalidPointer));
        assert_eq!(validate_args(16, 0, 1), Err(WorkerError::InvalidPointer));
        assert_eq!(validate_args(24, 16, 1), Err(WorkerError::Misaligned));
        assert_eq!(validate_args(16, 16, 0), Err(WorkerError::EmptyTensor));
        assert_eq!(validate_args(16, 16, MAX_TENSOR_BYTES + 1), Err(WorkerError::TensorTooLarge));
        assert_eq!(validate_args(16, usize::MAX, 1), Err(WorkerError::InvalidPointer));
        assert_eq!(validate_args(16, 32, 4), Ok(()));
    }

    #[test]
    fn hash_is_deterministic_and_sensitive() {
        assert_eq!(hash128(b"abc"), hash128(b"abc"));
        assert_ne!(hash128(b"abc"), hash128(b"abd"));
        assert_ne!(hash128(b"a"), hash128(b"a\0"));
        assert_ne!(hash128(b""), [0; 16]);
    }

    #[test]
    fn timeout_clamped() {
        assert_eq!(clamp_timeout(0), 1);
        assert_eq!(clamp_timeout(u32::MAX), MAX_TIMEOUT_MS);
        assert_eq!(clamp_timeout(5000), 5000);
    }

    #[test]
    fn pipeline_success_releases_lock() {
        let mut c = chan();
        assert_eq!(run_pipeline(&mut c, b"tensor", u32::MAX, |t| { assert_eq!(t, MAX_TIMEOUT_MS); 0 }), Ok(()));
        assert_eq!(c.bitmask, 1);
        assert_eq!(c.payload_hash, hash128(b"tensor"));
        assert_eq!(c.lock.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn pipeline_contention_and_host_errors() {
        let mut c = chan();
        c.lock.store(1, Ordering::SeqCst);
        assert_eq!(run_pipeline(&mut c, b"x", 1, |_| 0), Err(WorkerError::LockContention));
        assert_eq!(c.lock.load(Ordering::SeqCst), 1, "foreign lock untouched");
        c.lock.store(0, Ordering::SeqCst);
        assert_eq!(run_pipeline(&mut c, b"x", 1, |_| -6), Err(WorkerError::XpuTimeout));
        assert_eq!(c.lock.load(Ordering::SeqCst), 0);
        assert_eq!(run_pipeline(&mut c, &[], 1, |_| 0), Err(WorkerError::EmptyTensor));
    }

    #[test]
    fn host_stealing_lock_is_contention() {
        let mut c = chan();
        let lockp: *const AtomicU32 = &c.lock;
        // SAFETY: test-only; lockp points at c.lock, which outlives the call.
        let r = run_pipeline(&mut c, b"x", 1, |_| { unsafe { (*lockp).store(0, Ordering::SeqCst) }; 0 });
        assert_eq!(r, Err(WorkerError::LockContention));
    }

    #[test]
    fn entry_point_rejects_bad_args() {
        assert_eq!(execute_inference_pipeline(core::ptr::null_mut(), core::ptr::null(), 4), -1);
        let mut c = chan();
        let data = [1u8; 8];
        assert_eq!(execute_inference_pipeline(&mut c, data.as_ptr(), 0), -5);
        assert_eq!(execute_inference_pipeline(&mut c, data.as_ptr(), 8), 0);
    }
}
