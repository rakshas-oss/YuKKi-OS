// YuKKi-OS v6.8.0 16-byte Aligned NXR1 State Channel Buffer
#[repr(C, align(16))]
pub struct Nxr1StateChannel {
    pub channel_id: u64,
    pub bitmask: u64,
    pub payload_hash: [u8; 16],
    pub lock: core::sync::atomic::AtomicU32,
}

impl Nxr1StateChannel {
    pub const fn new(id: u64, mask: u64) -> Self {
        Self {
            channel_id: id,
            bitmask: mask,
            payload_hash: [0u8; 16],
            lock: core::sync::atomic::AtomicU32::new(0),
        }
    }

    #[inline(always)]
    pub fn sync_zero_copy_sram(&mut self, source_ptr: *const u8, len: usize) {
        unsafe {
            core::ptr::copy_nonoverlapping(source_ptr, self.payload_hash.as_mut_ptr(), len.min(16));
            crate::arch::cache::invalidate_dcache_range(
                self.payload_hash.as_ptr() as usize,
                16,
            );
        }
    }
}
