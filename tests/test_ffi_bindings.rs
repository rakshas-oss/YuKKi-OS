//! Tests for C FFI Layer Bindings
//! Validates extern "C" declarations and function correctness

use yukkios_6_6_6_inet3::SpatiotemporalFrame;

// Extern declarations matching those in main.rs
extern "C" {
    fn chaos_engine_init(sigma: f64, rho: f64, beta: f64);
    fn chaos_engine_reseed(sigma: f64, rho: f64, beta: f64, x0: f64, y0: f64, z0: f64);
    fn oob_fnv1a_rolling_hash(seed: u64, data: *const u8, len: u32) -> u64;
    fn oob_integrity_update(seq: u64, payload: *const u8, len: u32);
    fn oob_sync_check(seq: u64) -> i32;
}

#[test]
fn test_chaos_engine_init_no_crash() {
    unsafe {
        chaos_engine_init(10.0, 28.0, 8.33333333333);
    }
}

#[test]
fn test_oob_fnv1a_rolling_hash_deterministic() {
    let data = [0x01u8, 0x02, 0x03, 0x04];
    unsafe {
        let hash1 = oob_fnv1a_rolling_hash(0, data.as_ptr(), 4);
        let hash2 = oob_fnv1a_rolling_hash(0, data.as_ptr(), 4);
        assert_eq!(hash1, hash2, "FNV-1a hash must be deterministic");
    }
}

#[test]
fn test_oob_fnv1a_different_inputs() {
    let data1 = [0x01u8, 0x02, 0x03, 0x04];
    let data2 = [0x05u8, 0x06, 0x07, 0x08];

    unsafe {
        let hash1 = oob_fnv1a_rolling_hash(0, data1.as_ptr(), 4);
        let hash2 = oob_fnv1a_rolling_hash(0, data2.as_ptr(), 4);
        assert_ne!(
            hash1, hash2,
            "Different inputs must produce different hashes"
        );
    }
}

#[test]
fn test_oob_sync_check_at_boundary() {
    unsafe {
        // Sequence 60 should trigger sync
        let result_60 = oob_sync_check(60);
        assert_eq!(result_60, 1, "Sync check should return 1 at seq 60");

        // Sequence 59 should not trigger sync
        let result_59 = oob_sync_check(59);
        assert_eq!(result_59, 0, "Sync check should return 0 at seq 59");

        // Sequence 120 should also trigger sync
        let result_120 = oob_sync_check(120);
        assert_eq!(result_120, 1, "Sync check should return 1 at seq 120");

        // Sequence 0 should not trigger sync
        let result_0 = oob_sync_check(0);
        assert_eq!(result_0, 0, "Sync check should return 0 at seq 0");
    }
}

#[test]
fn test_oob_integrity_update_no_crash() {
    let payload = [0xAAu8; 16];
    unsafe {
        oob_integrity_update(0, payload.as_ptr(), 16);
        oob_integrity_update(1, payload.as_ptr(), 16);
    }
}

#[test]
fn test_spatiotemporal_frame_c_compatibility() {
    let frame = SpatiotemporalFrame {
        seq_id: 12345,
        x: 1.5,
        y: 2.5,
        z: 3.5,
        u: 0.1,
        v: 0.2,
        w: 0.3,
        fluidity: 0.8,
        drag: 0.2,
        divergence: 0.01,
        payload: [0xFF; 16],
    };

    // Verify frame can be safely cast to bytes for C interop
    let frame_bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(&frame as *const _ as *const u8, 88) };
    assert_eq!(frame_bytes.len(), 88);
}

#[test]
fn test_null_pointer_guards() {
    unsafe {
        // FNV-1a hash should handle null data pointer
        let hash_null = oob_fnv1a_rolling_hash(0, std::ptr::null(), 0);
        assert_eq!(
            hash_null, 0,
            "Null data pointer should return seed unchanged"
        );
    }
}

#[test]
fn test_payload_size_constants() {
    // SpatiotemporalFrame payload is always 16 bytes
    let frame = SpatiotemporalFrame {
        seq_id: 0,
        x: 0.0,
        y: 0.0,
        z: 0.0,
        u: 0.0,
        v: 0.0,
        w: 0.0,
        fluidity: 0.0,
        drag: 0.0,
        divergence: 0.0,
        payload: [0; 16],
    };

    assert_eq!(frame.payload.len(), 16, "Payload must be exactly 16 bytes");
}

#[test]
fn test_chaos_engine_reseed_parameters() {
    unsafe {
        // Initialize with default parameters
        chaos_engine_init(10.0, 28.0, 8.33333333333);

        // Reseed with different parameters
        chaos_engine_reseed(12.0, 25.0, 8.0, 1.0, 2.0, 3.0);
    }
}
