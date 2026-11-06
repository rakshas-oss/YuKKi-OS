//! SpatiotemporalFrame Operations Benchmarks
//!
//! Measures frame construction, copy throughput, payload isolation,
//! and memory footprint heuristics at various queue depths.

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use yukkios::{
    to_broker_task, Nxr1Frame, SequencePolicy, SpatiotemporalFrame,
    SpatiotemporalPayloadResolver,
};

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

fn bench_nxr1_resolver_dispatch(c: &mut Criterion) {
    let resolver = SpatiotemporalPayloadResolver::new();
    let receiver = resolver
        .register_destination("benchmark-component", 64, None, SequencePolicy::AllowAll)
        .expect("register benchmark destination");
    let frame = Nxr1Frame {
        seq_id: 42, x: 1.0, y: 2.0, z: 3.0,
        u: 0.1, v: 0.2, w: 0.3,
        fluidity: 0.9, drag: 0.1, divergence: 0.0,
        payload: vec![0xA5; 256],
    };
    let task = to_broker_task(
        &frame, "resolver-benchmark", "benchmark-source",
        "benchmark-component", 1, 1000,
    ).expect("encode benchmark task");

    c.bench_function("nxr1_resolver_decode_and_component_dispatch_256b", |b| {
        b.iter(|| {
            let sequence = resolver.resolve_and_enqueue(black_box(&task))
                .expect("resolve and enqueue");
            let resolved = receiver.try_recv().expect("receive dispatched frame");
            black_box((sequence, resolved));
        })
    });
}

criterion_group!(frame_benches, bench_frame_construction, bench_nxr1_resolver_dispatch);
criterion_main!(frame_benches);
