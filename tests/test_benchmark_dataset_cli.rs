use std::{
    fs,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn native_benchmark_cli_runs_all_manifest_domains_and_emits_policy() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples/benchmark-datasets/manifest.json");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let output_dir = std::env::temp_dir().join(format!(
        "yukki-dataset-cli-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&output_dir).unwrap();
    let output = output_dir.join("benchmark-results.json");

    let status = Command::new(env!("CARGO_BIN_EXE_yukki_dataset_bench"))
        .arg("--manifest")
        .arg(&manifest)
        .arg("--dataset")
        .arg("all")
        .arg("--profile")
        .arg("all")
        .arg("--output")
        .arg(&output)
        .status()
        .expect("native dataset benchmark CLI must start");

    assert!(status.success(), "native dataset benchmark CLI failed");
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    let results = report["results"].as_array().unwrap();
    let policies = report["applied_policies"].as_array().unwrap();

    assert_eq!(results.len(), 11);
    assert_eq!(policies.len(), results.len());
    for domain in ["drone", "finance", "environment"] {
        assert!(results.iter().any(|result| result["domain"] == domain));
    }
    assert!(results.iter().any(|result| {
        result["objective"] == "geospatial" && result["domain"] == "drone"
    }));
    assert!(results.iter().any(|result| {
        result["objective"] == "geospatial" && result["domain"] == "environment"
    }));
    assert!(!results.iter().any(|result| {
        result["objective"] == "geospatial" && result["domain"] == "finance"
    }));

    for policy in policies {
        let depth = policy["native_queue_depth"].as_u64().unwrap();
        assert!((1..=1024).contains(&depth));
        assert!(policy["batch_size"].as_u64().unwrap() > 0);
        assert!(policy["workers"].as_u64().unwrap() > 0);
    }

    fs::remove_dir_all(output_dir).unwrap();
}
