/// YuKKi OS v6.6.4 — Library Interface
/// Exports core modules for testing and external use

pub mod adi_auto_tune;
pub mod wasm_sandbox;

use std::marker::PhantomData;

#[repr(C, packed(8))]
#[derive(Debug, Clone, Copy)]
pub struct SpatiotemporalFrame {
    pub seq_id: u64,
    pub x: f64,
    pub y: f64,
    pub z: f64,
    pub u: f64,
    pub v: f64,
    pub w: f64,
    pub fluidity: f32,
    pub drag: f32,
    pub divergence: f64,
    pub payload: [u8; 16],
}

/// FFI-safe marker for null pointer checks
pub struct FFISafetyMarker {
    _phantom: PhantomData<()>,
}

impl FFISafetyMarker {
    pub fn verify_non_null<T>(ptr: *const T) -> bool {
        !ptr.is_null()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spatiotemporal_frame_layout() {
        assert_eq!(std::mem::size_of::<SpatiotemporalFrame>(), 88);
    }
}
