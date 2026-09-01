//! Tests for SpatiotemporalFrame
//! Validates ABI stability, memory layout, and FFI correctness

use yukkios_6_6_6_inet3::SpatiotemporalFrame;

#[test]
fn test_spatiotemporal_frame_size() {
    let frame_size = std::mem::size_of::<SpatiotemporalFrame>();
    assert_eq!(
        frame_size, 88,
        "SpatiotemporalFrame must be exactly 88 bytes, got {}",
        frame_size
    );
}

#[test]
fn test_spatiotemporal_frame_alignment() {
    let frame_size = std::mem::size_of::<SpatiotemporalFrame>();
    assert_eq!(
        frame_size % 8,
        0,
        "Frame size {} must be 8-byte aligned",
        frame_size
    );
}

#[test]
fn test_spatiotemporal_frame_field_offsets() {
    use std::mem::offset_of;

    // Verify field layout matches C FFI expectations
    // seq_id: u64 @ offset 0
    assert_eq!(offset_of!(SpatiotemporalFrame, seq_id), 0);

    // x, y, z: f64×3 @ offset 8
    assert_eq!(offset_of!(SpatiotemporalFrame, x), 8);
    assert_eq!(offset_of!(SpatiotemporalFrame, y), 16);
    assert_eq!(offset_of!(SpatiotemporalFrame, z), 24);

    // u, v, w: f64×3 @ offset 32
    assert_eq!(offset_of!(SpatiotemporalFrame, u), 32);
    assert_eq!(offset_of!(SpatiotemporalFrame, v), 40);
    assert_eq!(offset_of!(SpatiotemporalFrame, w), 48);

    // fluidity: f32 @ offset 56
    assert_eq!(offset_of!(SpatiotemporalFrame, fluidity), 56);

    // drag: f32 @ offset 60
    assert_eq!(offset_of!(SpatiotemporalFrame, drag), 60);

    // divergence: f64 @ offset 64
    assert_eq!(offset_of!(SpatiotemporalFrame, divergence), 64);

    // payload: [u8; 16] @ offset 72
    assert_eq!(offset_of!(SpatiotemporalFrame, payload), 72);
}

#[test]
fn test_spatiotemporal_frame_field_sizes() {
    assert_eq!(std::mem::size_of::<u64>(), 8);
    assert_eq!(std::mem::size_of::<f64>(), 8);
    assert_eq!(std::mem::size_of::<f32>(), 4);

    // Verify composite size: 8 + 24 + 24 + 4 + 4 + 8 + 16 = 88
    let expected = 8 + (8 * 3) + (8 * 3) + 4 + 4 + 8 + 16;
    assert_eq!(expected, 88);
}

#[test]
fn test_spatiotemporal_frame_initialization() {
    let frame = SpatiotemporalFrame {
        seq_id: 42,
        x: 1.0,
        y: 2.0,
        z: 3.0,
        u: 0.125,
        v: 0.25,
        w: 0.5,
        fluidity: 0.9,
        drag: 0.1,
        divergence: 0.0,
        payload: [0xFF; 16],
    };

    assert_eq!(frame.seq_id, 42);
    assert_eq!(frame.x, 1.0);
    assert_eq!(frame.y, 2.0);
    assert_eq!(frame.z, 3.0);
    assert_eq!(frame.fluidity, 0.9);
    assert_eq!(frame.payload[0], 0xFF);
    assert_eq!(frame.payload[15], 0xFF);
}

#[test]
fn test_spatiotemporal_frame_repr_c_packed() {
    // Verify that the struct has no padding due to repr(C, packed)
    // Actual field layout should match the declaration order
    let frame = SpatiotemporalFrame {
        seq_id: 0x0102030405060708,
        x: 0.0,
        y: 0.0,
        z: 0.0,
        u: 0.0,
        v: 0.0,
        w: 0.0,
        fluidity: 0.0,
        drag: 0.0,
        divergence: 0.0,
        payload: [0u8; 16],
    };

    // Cast to bytes and check first 8 bytes match seq_id
    let bytes: &[u8] = unsafe { std::slice::from_raw_parts(&frame as *const _ as *const u8, 88) };

    // Verify seq_id bytes (little-endian interpretation)
    let seq_id_bytes = &bytes[0..8];
    assert_eq!(
        u64::from_le_bytes([
            seq_id_bytes[0],
            seq_id_bytes[1],
            seq_id_bytes[2],
            seq_id_bytes[3],
            seq_id_bytes[4],
            seq_id_bytes[5],
            seq_id_bytes[6],
            seq_id_bytes[7]
        ]),
        0x0102030405060708
    );
}

#[test]
fn test_spatiotemporal_frame_payload_independence() {
    let mut frame1 = SpatiotemporalFrame {
        seq_id: 1,
        x: 0.0,
        y: 0.0,
        z: 0.0,
        u: 0.0,
        v: 0.0,
        w: 0.0,
        fluidity: 0.0,
        drag: 0.0,
        divergence: 0.0,
        payload: [0xAA; 16],
    };

    let frame2 = SpatiotemporalFrame {
        seq_id: 2,
        x: 0.0,
        y: 0.0,
        z: 0.0,
        u: 0.0,
        v: 0.0,
        w: 0.0,
        fluidity: 0.0,
        drag: 0.0,
        divergence: 0.0,
        payload: [0xBB; 16],
    };

    // Payloads should not interfere
    frame1.payload[0] = 0xCC;
    assert_eq!(frame2.payload[0], 0xBB);
    assert_eq!(frame1.payload[0], 0xCC);
}
