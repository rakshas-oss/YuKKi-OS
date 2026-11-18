use std::{
    env,
    fs,
    path::PathBuf,
    process::ExitCode,
};

use serde::Serialize;
use yukkios::{
    adi_auto_tune::ADIAutoTuner,
    benchmark_dataset::{BenchmarkDatasetRunner, DatasetBenchmarkResult},
};

#[derive(Serialize)]
struct AppliedPolicy {
    dataset_id: String,
    benchmark_profile: String,
    batch_size: usize,
    workers: usize,
    native_queue_depth: usize,
    active_hardware_profile: String,
}

#[derive(Serialize)]
struct BenchmarkCommandReport {
    manifest_version: u32,
    results: Vec<DatasetBenchmarkResult>,
    applied_policies: Vec<AppliedPolicy>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("yukki_dataset_bench: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let mut manifest: Option<PathBuf> = None;
    let mut dataset = "all".to_string();
    let mut profile = "all".to_string();
    let mut output: Option<PathBuf> = None;

    while let Some(argument) = args.next() {
        let value = |args: &mut std::iter::Skip<std::env::Args>, name: &str| {
            args.next()
                .ok_or_else(|| format!("missing value after {name}"))
        };
        match argument.as_str() {
            "--manifest" => manifest = Some(PathBuf::from(value(&mut args, "--manifest")?)),
            "--dataset" => dataset = value(&mut args, "--dataset")?,
            "--profile" => profile = value(&mut args, "--profile")?,
            "--output" => output = Some(PathBuf::from(value(&mut args, "--output")?)),
            "--help" | "-h" => {
                println!(
                    "Usage: yukki_dataset_bench --manifest PATH [--dataset ID|all] [--profile ID|all] [--output PATH]"
                );
                return Ok(());
            }
            other => return Err(format!("unknown argument '{other}' (use --help)").into()),
        }
    }

    let manifest = manifest.ok_or(
        "a dataset manifest is required; pass --manifest PATH (see docs/BENCHMARK_DRIVEN_DATASETS.md)",
    )?;
    let results = BenchmarkDatasetRunner::run_manifest(
        &manifest,
        Some(&dataset),
        Some(&profile),
    )?;

    let mut policies = Vec::with_capacity(results.len());
    for result in &results {
        let mut tuner = ADIAutoTuner {
            optimal_queue_depth: 60,
            active_hardware_profile: "unconfigured-native-profile".to_string(),
        };
        tuner.apply_dataset_benchmark(result);
        policies.push(AppliedPolicy {
            dataset_id: result.dataset_id.clone(),
            benchmark_profile: result.profile_id.clone(),
            batch_size: result.recommended.batch_size,
            workers: result.recommended.workers,
            native_queue_depth: tuner.optimal_queue_depth,
            active_hardware_profile: tuner.active_hardware_profile,
        });
    }

    let report = BenchmarkCommandReport {
        manifest_version: 1,
        results,
        applied_policies: policies,
    };
    let json = serde_json::to_vec_pretty(&report)?;
    if let Some(path) = output {
        fs::write(path, json)?;
    } else {
        println!("{}", String::from_utf8(json)?);
    }
    Ok(())
}
