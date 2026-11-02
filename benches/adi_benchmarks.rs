//! ADI Auto-Tuner Heuristics & Throughput Benchmarks
//!
//! Measures the performance of the RIU ADI Dynamic Integration Suite:
//! encoding throughput simulation, queue allocation, and data acquisition.

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use yukkios::adi_auto_tune::ADIAutoTuner;

fn bench_encoding_throughput(c: &mut Criterion) {
    let tuner = ADIAutoTuner::new();
    c.bench_function("adi_encoding_throughput", |b| {
        b.iter(|| black_box(tuner.test_encoding_throughput()))
    });
}

criterion_group!(adi_benches, bench_encoding_throughput);
criterion_main!(adi_benches);
