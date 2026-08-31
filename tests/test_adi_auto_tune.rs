/// Tests for ADI Auto-Tuning Suite
/// Validates hardware calibration, throughput, and queueing efficiency

use yukkios_6_6_6_inet3::adi_auto_tune::ADIAutoTuner;
use yukkios_6_6_6_inet3::SpatiotemporalFrame;

#[test]
fn test_adi_auto_tuner_initialization() {
    let tuner = ADIAutoTuner::new();
    assert_eq!(tuner.optimal_queue_depth, 60, "Default queue depth should be 60");
    assert_eq!(
        tuner.active_hardware_profile,
        "64-BIT_ELECTRICAL_FLAT",
        "Default hardware profile mismatch"
    );
}

#[test]
fn test_encoding_throughput_passes() {
    let tuner = ADIAutoTuner::new();
    let result = tuner.test_encoding_throughput();
    assert!(result, "Encoding throughput test should pass on modern hardware");
}

#[test]
fn test_enquing_efficiency_adjusts_queue_depth() {
    let mut tuner = ADIAutoTuner::new();
    let initial_depth = tuner.optimal_queue_depth;
    tuner.test_enquing_efficiency();
    // Queue depth should either remain at 60 or increase to 120
    assert!(
        tuner.optimal_queue_depth == 60 || tuner.optimal_queue_depth == 120,
        "Queue depth should be 60 or 120, got {}",
        tuner.optimal_queue_depth
    );
}

#[test]
fn test_data_acquisition_alignment() {
    let tuner = ADIAutoTuner::new();
    let result = tuner.test_data_acquisition();
    assert!(
        result,
        "Data acquisition must pass 8-byte alignment check"
    );
}

#[test]
fn test_hardware_calibration_completes() {
    let mut tuner = ADIAutoTuner::new();
    tuner.execute_hardware_calibration();
    // After calibration, queue depth must be set
    assert!(
        tuner.optimal_queue_depth > 0,
        "Queue depth should be positive after calibration"
    );
}

#[test]
fn test_frame_size_calculation() {
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
        payload: [0u8; 16],
    };

    let frame_size = std::mem::size_of::<SpatiotemporalFrame>();
    assert_eq!(frame_size, 88, "SpatiotemporalFrame must be exactly 88 bytes");

    // Verify alignment
    assert_eq!(
        frame_size % 8,
        0,
        "Frame size must be 8-byte aligned"
    );
}

#[test]
fn test_queue_depth_scaling() {
    let mut tuner = ADIAutoTuner::new();
    tuner.test_enquing_efficiency();

    let depth = tuner.optimal_queue_depth;
    let frame_size = std::mem::size_of::<SpatiotemporalFrame>();
    let total_bytes = depth * frame_size;

    // Sanity check: queue should not exceed 64 KB for typical 60-120 depth
    assert!(
        total_bytes < 64 * 1024,
        "Queue memory footprint too large: {} bytes",
        total_bytes
    );
}
