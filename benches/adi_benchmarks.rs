//! ADI Auto-Tuner Heuristics & Throughput Benchmarks
//!
//! Measures real NXR1 frame serialization and decoding throughput.

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use yukkios::Nxr1Frame;

fn benchmark_frame() -> Nxr1Frame {
    Nxr1Frame {
        seq_id: 42,
        x: 0.1,
        y: 0.2,
        z: 0.3,
        u: 0.0,
        v: 0.0,
        w: 0.0,
        fluidity: 0.9,
        drag: 0.1,
        divergence: 0.0,
        payload: vec![0xA5; 256],
    }
}

fn bench_nxr1_encoding(c: &mut Criterion) {
    let frame = benchmark_frame();
    c.bench_function("adi_nxr1_encode_256b", |b| {
        b.iter(|| black_box(frame.encode().expect("encode NXR1 frame")))
    });
}

fn bench_nxr1_decoding(c: &mut Criterion) {
    let encoded = benchmark_frame().encode().expect("encode benchmark frame");
    c.bench_function("adi_nxr1_decode_256b", |b| {
        b.iter(|| black_box(Nxr1Frame::decode(black_box(&encoded)).expect("decode NXR1 frame")))
    });
}

criterion_group!(adi_benches, bench_nxr1_encoding, bench_nxr1_decoding);
criterion_main!(adi_benches);
