/// SpatiotemporalFrame Operations Benchmarks
///
/// Measures frame construction, copy throughput, payload isolation,
/// and memory footprint heuristics at various queue depths.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use yukkios_6_6_6_inet3::SpatiotemporalFrame;

fn make_frame(seq: u64) -> SpatiotemporalFrame {
    SpatiotemporalFrame {
        seq_id: seq,
        x: seq as f64 * 0.01,
        y: seq as f64 * 0.02,
        z: seq as f64 * 0.03,
        u: 0.0,
        v: 0.0,
        w: 0.0,
        fluidity: 0.9,
        drag: 0.1,
        divergence: 0.0,
        payload: [seq as u8; 16],
    }
}

fn bench_frame_construction(c: &mut Criterion) {
    c.bench_function("frame_construction", |b| {
        b.iter(|| black_box(make_frame(black_box(42))))
    });
}

fn bench_frame_copy(c: &mut Criterion) {
    let frame = make_frame(1);
    c.bench_function("frame_copy", |b| {
        b.iter(|| {
            let copy = black_box(frame);
            black_box(copy)
        })
    });
}

/// Heuristic: build a queue of N frames and measure throughput.
fn bench_frame_queue_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_queue_build");
    for depth in [60usize, 120, 240, 480, 960] {
        group.bench_with_input(BenchmarkId::from_parameter(depth), &depth, |b, &d| {
            b.iter(|| {
                let mut queue = Vec::with_capacity(d);
                for i in 0..d {
                    queue.push(black_box(make_frame(i as u64)));
                }
                black_box(queue)
            })
        });
    }
    group.finish();
}

/// Heuristic: measure the cost of iterating over a frame queue (simulate drain).
fn bench_frame_queue_drain(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_queue_drain");
    for depth in [60usize, 120, 240] {
        let queue: Vec<SpatiotemporalFrame> = (0..depth).map(|i| make_frame(i as u64)).collect();
        group.bench_with_input(BenchmarkId::from_parameter(depth), &queue, |b, q| {
            b.iter(|| {
                let mut sum = 0u64;
                for frame in q.iter() {
                    sum = sum.wrapping_add(black_box(frame.seq_id));
                }
                black_box(sum)
            })
        });
    }
    group.finish();
}

/// Heuristic: verify 8-byte alignment check cost (mirrors data-acquisition test).
fn bench_alignment_check(c: &mut Criterion) {
    c.bench_function("frame_alignment_check", |b| {
        b.iter(|| {
            let size = std::mem::size_of::<SpatiotemporalFrame>();
            black_box(size % 8 == 0)
        })
    });
}

/// Heuristic: Lorenz state step cost per frame.
fn bench_lorenz_step(c: &mut Criterion) {
    c.bench_function("lorenz_step", |b| {
        let sigma = 10.0f64;
        let rho = 28.0f64;
        let beta = 8.0f64 / 3.0;
        let dt = 0.001f64;
        let mut x = 1.0f64;
        let mut y = 1.0f64;
        let mut z = 1.0f64;
        b.iter(|| {
            x += dt * sigma * (y - x);
            y += dt * (x * (rho - z) - y);
            z += dt * (x * y - beta * z);
            black_box((x, y, z))
        })
    });
}

criterion_group!(
    frame_benches,
    bench_frame_construction,
    bench_frame_copy,
    bench_frame_queue_build,
    bench_frame_queue_drain,
    bench_alignment_check,
    bench_lorenz_step,
);
criterion_main!(frame_benches);
