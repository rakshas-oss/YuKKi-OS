use std::{
    fs,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn eigensolver_cli_benchmarks_all_manifest_domains() {
    let manifest =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/benchmark-datasets/manifest.json");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let output_dir = std::env::temp_dir().join(format!(
        "yukki-eigensolver-cli-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&output_dir).unwrap();
    let output = output_dir.join("eigensolver-results.json");

    let status = Command::new(env!("CARGO_BIN_EXE_yukki_eigensolver_bench"))
        .arg("--manifest")
        .arg(&manifest)
        .arg("--dataset")
        .arg("all")
        .arg("--profile")
        .arg("all")
        .arg("--output")
        .arg(&output)
        .status()
        .expect("eigensolver benchmark CLI must start");
    assert!(status.success(), "eigensolver benchmark CLI failed");

    let report: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    let results = report["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    for result in results {
        assert_eq!(result["matrix_dimension"], 9);
        assert_eq!(result["candidates"].as_array().unwrap().len(), 9);
        assert!(result["recommended"]["solves_per_second"].as_f64().unwrap() > 0.0);
        assert!(
            result["recommended"]["max_relative_residual"]
                .as_f64()
                .unwrap()
                < 1.0e-8
        );
        assert!(
            result["recommended"]["max_orthogonality_error"]
                .as_f64()
                .unwrap()
                < 1.0e-8
        );
    }
    for domain in ["drone", "finance", "environment"] {
        assert!(results.iter().any(|result| result["domain"] == domain));
    }
    fs::remove_dir_all(output_dir).unwrap();
}
