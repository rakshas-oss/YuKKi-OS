//! ADI Auto-Tuner Heuristics & Throughput Benchmarks
//!
//! Measures the performance of the RIU ADI Dynamic Integration Suite:
//! encoding throughput simulation, queue allocation, and data acquisition.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use yukkios_6_6_6_inet3::adi_auto_tune::ADIAutoTuner;
use yukkios_6_6_6_inet3::SpatiotemporalFrame;

fn bench_encoding_throughput(c: &mut Criterion) {
    let tuner = ADIAutoTuner::new();
    c.bench_function("adi_encoding_throughput", |b| {
        b.iter(|| black_box(tuner.test_encoding_throughput()))
    });
}

fn bench_enquing_efficiency(c: &mut Criterion) {
    c.bench_function("adi_enquing_efficiency", |b| {
        b.iter(|| {
            let mut tuner = ADIAutoTuner::new();
            black_box(tuner.test_enquing_efficiency())
        })
    });
}

fn bench_data_acquisition(c: &mut Criterion) {
    let tuner = ADIAutoTuner::new();
    c.bench_function("adi_data_acquisition", |b| {
        b.iter(|| black_box(tuner.test_data_acquisition()))
    });
}

fn bench_full_hardware_calibration(c: &mut Criterion) {
    c.bench_function("adi_full_hardware_calibration", |b| {
        b.iter(|| {
            let mut tuner = ADIAutoTuner::new();
            tuner.execute_hardware_calibration();
            black_box(tuner.optimal_queue_depth)
        })
    });
}

/// Heuristic: measure queue build-up at varying depths to find the knee point.
fn bench_queue_depth_heuristic(c: &mut Criterion) {
    let frame = SpatiotemporalFrame {
        seq_id: 1,
        x: 0.1,
        y: 0.2,
        z: 0.3,
        u: 0.0,
        v: 0.0,
        w: 0.0,
        fluidity: 0.9,
        drag: 0.1,
        divergence: 0.0,
        payload: [0x00; 16],
    };

    let mut group = c.benchmark_group("queue_depth_heuristic");
    for depth in [60usize, 120, 240, 480] {
        group.bench_with_input(format!("depth_{}", depth), &depth, |b, &d| {
            b.iter(|| {
                let mut q = Vec::with_capacity(d);
                for _ in 0..d {
                    q.push(black_box(frame));
                }
                black_box(q.len())
            })
        });
    }
    group.finish();
}

/// Heuristic: black_box loop scaled to simulate 10 k frame-encoding passes.
fn bench_encoding_loop_heuristic(c: &mut Criterion) {
    let mut group = c.benchmark_group("encoding_loop_heuristic");
    for count in [1_000usize, 5_000, 10_000] {
        group.bench_with_input(format!("frames_{}", count), &count, |b, &n| {
            b.iter(|| {
                for _ in 0..n {
                    std::hint::black_box(0u64);
                }
            })
        });
    }
    group.finish();
}

criterion_group!(
    adi_benches,
    bench_encoding_throughput,
    bench_enquing_efficiency,
    bench_data_acquisition,
    bench_full_hardware_calibration,
    bench_queue_depth_heuristic,
    bench_encoding_loop_heuristic,
);
criterion_main!(adi_benches);
