// YuKKi-OS v6.9.0 16-byte Aligned NXR1 State Channel Buffer
#[repr(C, align(16))]
pub struct Nxr1StateChannel {
    pub channel_id: u64,
    pub bitmask: u64,
    pub payload_hash: [u8; 16],
    pub lock: core::sync::atomic::AtomicU32,
}
impl Nxr1StateChannel {
    pub const fn new(id: u64, mask: u64) -> Self {
        Self { channel_id: id, bitmask: mask, payload_hash: [0u8; 16],
            lock: core::sync::atomic::AtomicU32::new(0) }
    }
    /// Copies at most 16 bytes from a valid slice and zero-pads short inputs.
    #[inline]
    pub fn sync_zero_copy_sram(&mut self, source: &[u8]) {
        let len = source.len().min(self.payload_hash.len());
        self.payload_hash[..len].copy_from_slice(&source[..len]);
        self.payload_hash[len..].fill(0);
        crate::arch::cache::invalidate_dcache_range(self.payload_hash.as_ptr() as usize, 16);
    }
    /// Raw hardware/FFI boundary. Caller guarantees source_ptr is readable for len bytes.
    #[inline]
    pub unsafe fn sync_zero_copy_sram_raw(&mut self, source_ptr: *const u8, len: usize) {
        if len == 0 {
            self.payload_hash.fill(0);
            crate::arch::cache::invalidate_dcache_range(self.payload_hash.as_ptr() as usize, 16);
        } else if source_ptr.is_null() {
            self.payload_hash.fill(0);
            crate::arch::cache::invalidate_dcache_range(self.payload_hash.as_ptr() as usize, 16);
        } else {
            let bytes = core::slice::from_raw_parts(source_ptr, len);
            self.sync_zero_copy_sram(bytes);
        }
    }
}
