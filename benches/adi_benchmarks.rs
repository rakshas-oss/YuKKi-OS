//! NXR1 frame serialization and decoding benchmarks.
//!
//! The benchmark fixture is shared with the other native Criterion suites.

use criterion::{criterion_group, criterion_main, Criterion};
use serde_json::Value;
use std::hint::black_box;
use yukkios::Nxr1Frame;

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

fn benchmark_frame(config: &Value) -> Nxr1Frame {
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

fn bench_nxr1_encoding(c: &mut Criterion) {
    let data = dataset();
    let frame = benchmark_frame(&data["nxr1_frame"]);
    let payload_bytes = frame.payload.len();
    c.bench_function(&format!("adi_nxr1_encode_{}b", payload_bytes), |b| {
        b.iter(|| black_box(frame.encode().expect("encode NXR1 frame")))
    });
}

fn bench_nxr1_decoding(c: &mut Criterion) {
    let data = dataset();
    let frame = benchmark_frame(&data["nxr1_frame"]);
    let payload_bytes = frame.payload.len();
    let encoded = frame.encode().expect("encode benchmark frame");
    c.bench_function(&format!("adi_nxr1_decode_{}b", payload_bytes), |b| {
        b.iter(|| black_box(Nxr1Frame::decode(black_box(&encoded)).expect("decode NXR1 frame")))
    });
}

criterion_group!(adi_benches, bench_nxr1_encoding, bench_nxr1_decoding);
criterion_main!(adi_benches);
