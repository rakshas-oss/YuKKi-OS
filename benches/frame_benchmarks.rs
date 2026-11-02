//! SpatiotemporalFrame Operations Benchmarks
//!
//! Measures frame construction, copy throughput, payload isolation,
//! and memory footprint heuristics at various queue depths.

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use yukkios::SpatiotemporalFrame;

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
    c.bench_function("spatiotemporal_frame_construction", |b| {
        b.iter(|| black_box(make_frame(black_box(42))))
    });
}

criterion_group!(frame_benches, bench_frame_construction);
criterion_main!(frame_benches);
