//! Frame construction and NXR1 resolver dispatch benchmarks.
//!
//! Benchmark inputs are loaded from benches/datasets/native-v1.json so the
//! fixture, rather than benchmark source literals, is the source of test data.

use criterion::{criterion_group, criterion_main, Criterion};
use serde_json::Value;
use std::hint::black_box;
use yukkios::{
    to_broker_task, Nxr1Frame, SequencePolicy, SpatiotemporalFrame, SpatiotemporalPayloadResolver,
};

fn dataset() -> Value {
    serde_json::from_str(include_str!("datasets/native-v1.json"))
        .expect("parse native benchmark dataset")
}

fn vector3(value: &Value) -> [f64; 3] {
    let values = value.as_array().expect("three-vector fixture");
    assert_eq!(values.len(), 3, "three-vector fixture length");
    [
        values[0].as_f64().expect("x"),
        values[1].as_f64().expect("y"),
        values[2].as_f64().expect("z"),
    ]
}

fn make_frame(config: &Value) -> SpatiotemporalFrame {
    let position = vector3(&config["position"]);
    let velocity = vector3(&config["velocity"]);
    let payload_byte = config["payload_byte"].as_u64().expect("payload byte") as u8;
    let payload_bytes = config["payload_bytes"].as_u64().expect("payload bytes");
    assert_eq!(payload_bytes, 16, "SpatiotemporalFrame uses a fixed 16-byte payload");
    SpatiotemporalFrame {
        seq_id: config["seq_id"].as_u64().expect("sequence"),
        x: position[0],
        y: position[1],
        z: position[2],
        u: velocity[0],
        v: velocity[1],
        w: velocity[2],
        fluidity: config["fluidity"].as_f64().expect("fluidity") as f32,
        drag: config["drag"].as_f64().expect("drag") as f32,
        divergence: config["divergence"].as_f64().expect("divergence"),
        payload: [payload_byte; 16],
    }
}

fn make_nxr1_frame(config: &Value) -> Nxr1Frame {
    let position = vector3(&config["position"]);
    let velocity = vector3(&config["velocity"]);
    let payload_byte = config["payload_byte"].as_u64().expect("payload byte") as u8;
    let payload_bytes = config["payload_bytes"].as_u64().expect("payload bytes") as usize;
    Nxr1Frame {
        seq_id: config["seq_id"].as_u64().expect("sequence"),
        x: position[0],
        y: position[1],
        z: position[2],
        u: velocity[0],
        v: velocity[1],
        w: velocity[2],
        fluidity: config["fluidity"].as_f64().expect("fluidity"),
        drag: config["drag"].as_f64().expect("drag"),
        divergence: config["divergence"].as_f64().expect("divergence"),
        payload: vec![payload_byte; payload_bytes],
    }
}

fn bench_frame_construction(c: &mut Criterion) {
    let data = dataset();
    let config = &data["spatiotemporal_frame"];
    c.bench_function("spatiotemporal_frame_construction", |b| {
        b.iter(|| black_box(make_frame(black_box(config))))
    });
}

fn bench_nxr1_resolver_dispatch(c: &mut Criterion) {
    let data = dataset();
    let resolver_config = &data["resolver"];
    let resolver = SpatiotemporalPayloadResolver::new();
    let destination = resolver_config["destination"].as_str().expect("destination");
    let source = resolver_config["source"].as_str().expect("source");
    let capacity = resolver_config["queue_capacity"].as_u64().expect("capacity") as usize;
    let priority = resolver_config["priority"].as_u64().expect("priority") as u8;
    let timeout_ms = resolver_config["timeout_ms"].as_u64().expect("timeout") as u32;
    let receiver = resolver
        .register_destination(destination, capacity, None, SequencePolicy::AllowAll)
        .expect("register benchmark destination");
    let frame = make_nxr1_frame(&data["nxr1_frame"]);
    let payload_bytes = frame.payload.len();
    let task = to_broker_task(
        &frame,
        "resolver-benchmark",
        source,
        destination,
        priority,
        timeout_ms,
    )
    .expect("encode benchmark task");

    c.bench_function(
        &format!("nxr1_resolver_decode_and_component_dispatch_{}b", payload_bytes),
        |b| {
            b.iter(|| {
                let sequence = resolver
                    .resolve_and_enqueue(black_box(&task))
                    .expect("resolve and enqueue");
                let resolved = receiver.try_recv().expect("receive dispatched frame");
                black_box((sequence, resolved));
            })
        },
    );
}

criterion_group!(
    frame_benches,
    bench_frame_construction,
    bench_nxr1_resolver_dispatch
);
criterion_main!(frame_benches);
