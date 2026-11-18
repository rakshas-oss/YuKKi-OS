//! Dataset-driven benchmark for the bounded symmetric eigensolver.
//!
//! It consumes the same JSONL dataset definitions as yukki_dataset_bench.
//! Eigensolver profiles are deliberately separate from transport/geospatial
//! profiles because they describe matrix work rather than broker scheduling.

use std::{
    env, fs,
    io::{BufRead, BufReader},
    path::{Component, Path, PathBuf},
    process::ExitCode,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Mutex,
    },
    thread,
    time::Instant,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use yukkios::symmetric_eigen::{
    symmetric_eigen_decomposition_with_options, DEFAULT_MAX_SWEEPS, DEFAULT_TOLERANCE,
    MAX_EIGEN_DIMENSION,
};

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_DATASET_BYTES: u64 = 512 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_RECORDS: usize = 1_000_000;
const MAX_ITERATIONS_PER_BATCH: usize = 100_000;
const MAX_WORKERS: usize = 64;
const MAX_TOTAL_SOLVES: usize = 1_000_000;

#[derive(Debug, Deserialize)]
struct Manifest {
    version: u32,
    datasets: Vec<DatasetSpec>,
    #[serde(default)]
    eigensolver_profiles: Vec<EigensolverProfile>,
}

#[derive(Debug, Deserialize)]
struct DatasetSpec {
    id: String,
    domain: String,
    source: PathBuf,
    feature_fields: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct EigensolverProfile {
    id: String,
    objective: String,
    warmup_records: usize,
    sample_records: usize,
    batch_sizes: Vec<usize>,
    worker_counts: Vec<usize>,
    iterations_per_batch: usize,
    #[serde(default = "default_tolerance")]
    tolerance: f64,
    #[serde(default = "default_max_sweeps")]
    max_sweeps: usize,
    #[serde(default)]
    max_p95_solve_us: Option<f64>,
    #[serde(default)]
    applicable_domains: Option<Vec<String>>,
}

fn default_tolerance() -> f64 {
    DEFAULT_TOLERANCE
}
fn default_max_sweeps() -> usize {
    DEFAULT_MAX_SWEEPS
}

#[derive(Clone, Debug, Serialize)]
struct Candidate {
    batch_size: usize,
    workers: usize,
    matrix_dimension: usize,
    batches: usize,
    solves: usize,
    elapsed_ms: f64,
    solves_per_second: f64,
    mean_solve_us: f64,
    p95_solve_us: f64,
    max_relative_residual: f64,
    max_orthogonality_error: f64,
    checksum: u64,
}

#[derive(Debug, Serialize)]
struct DatasetResult {
    dataset_id: String,
    domain: String,
    profile_id: String,
    objective: String,
    source_records: usize,
    warmup_records: usize,
    sampled_records: usize,
    matrix_dimension: usize,
    candidates: Vec<Candidate>,
    recommended: Candidate,
    met_latency_target: bool,
}

#[derive(Debug, Serialize)]
struct Report {
    manifest_version: u32,
    results: Vec<DatasetResult>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("yukki_eigensolver_bench: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let mut manifest = None;
    let mut dataset_filter = "all".to_string();
    let mut profile_filter = "all".to_string();
    let mut output = None;
    while let Some(argument) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value after {argument}"))?;
        match argument.as_str() {
            "--manifest" => manifest = Some(PathBuf::from(value)),
            "--dataset" => dataset_filter = value,
            "--profile" => profile_filter = value,
            "--output" => output = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown argument '{argument}'").into()),
        }
    }
    let manifest_path =
        manifest.ok_or("pass --manifest PATH; see docs/BENCHMARK_DRIVEN_DATASETS.md")?;
    let metadata = fs::metadata(&manifest_path)?;
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err("manifest exceeds 1 MiB".into());
    }
    let manifest_bytes = fs::read(&manifest_path)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
    validate_manifest(&manifest)?;

    let selected_datasets: Vec<_> = manifest
        .datasets
        .iter()
        .filter(|item| dataset_filter == "all" || item.id == dataset_filter)
        .collect();
    let selected_profiles: Vec<_> = manifest
        .eigensolver_profiles
        .iter()
        .filter(|item| profile_filter == "all" || item.id == profile_filter)
        .collect();
    if selected_datasets.is_empty() {
        return Err(format!("unknown dataset '{dataset_filter}'").into());
    }
    if selected_profiles.is_empty() {
        return Err(format!("unknown eigensolver profile '{profile_filter}'").into());
    }

    let base = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let mut results = Vec::new();
    for dataset in selected_datasets {
        let source = safe_source_path(base, &dataset.source)?;
        let records = load_records(dataset, &source)?;
        for profile in &selected_profiles {
            if profile
                .applicable_domains
                .as_ref()
                .is_some_and(|domains| !domains.iter().any(|domain| domain == &dataset.domain))
            {
                continue;
            }
            results.push(run_dataset_profile(dataset, profile, &records)?);
        }
    }
    if results.is_empty() {
        return Err("no selected eigensolver profiles apply to the selected datasets".into());
    }
    let report = Report {
        manifest_version: manifest.version,
        results,
    };
    let encoded = serde_json::to_vec_pretty(&report)?;
    if let Some(path) = output {
        fs::write(path, encoded)?;
    } else {
        println!("{}", String::from_utf8(encoded)?);
    }
    Ok(())
}

fn validate_manifest(manifest: &Manifest) -> Result<(), Box<dyn std::error::Error>> {
    if manifest.version != 1 || manifest.datasets.is_empty() || manifest.datasets.len() > 256 {
        return Err("manifest version must be 1 and dataset count must be 1..=256".into());
    }
    if manifest.eigensolver_profiles.is_empty() || manifest.eigensolver_profiles.len() > 64 {
        return Err("eigensolver_profiles must contain 1..=64 profiles".into());
    }
    for dataset in &manifest.datasets {
        if dataset.id.is_empty()
            || dataset.id.len() > 128
            || dataset.domain.is_empty()
            || dataset.domain.len() > 64
            || dataset.feature_fields.is_empty()
            || dataset.feature_fields.len() > MAX_EIGEN_DIMENSION
        {
            return Err(format!(
                "dataset '{}' has invalid metadata or feature dimension",
                dataset.id
            )
            .into());
        }
        let mut unique = std::collections::HashSet::new();
        if dataset
            .feature_fields
            .iter()
            .any(|field| field.is_empty() || field.len() > 128 || !unique.insert(field))
        {
            return Err(format!(
                "dataset '{}' has invalid or duplicate feature fields",
                dataset.id
            )
            .into());
        }
    }
    let mut ids = std::collections::HashSet::new();
    for profile in &manifest.eigensolver_profiles {
        if profile.id.is_empty() || profile.id.len() > 128 || !ids.insert(&profile.id) {
            return Err("eigensolver profile IDs must be unique and non-empty".into());
        }
        if profile.objective != "throughput" && profile.objective != "latency" {
            return Err(format!(
                "profile '{}' objective must be throughput or latency",
                profile.id
            )
            .into());
        }
        if profile.sample_records == 0
            || profile.sample_records > MAX_RECORDS
            || profile.warmup_records > MAX_RECORDS
            || profile.iterations_per_batch == 0
            || profile.iterations_per_batch > MAX_ITERATIONS_PER_BATCH
            || profile.batch_sizes.is_empty()
            || profile.batch_sizes.len() > 16
            || profile
                .batch_sizes
                .iter()
                .any(|size| *size == 0 || *size > MAX_RECORDS)
            || profile.worker_counts.is_empty()
            || profile.worker_counts.len() > 16
            || profile
                .worker_counts
                .iter()
                .any(|workers| *workers == 0 || *workers > MAX_WORKERS)
            || !profile.tolerance.is_finite()
            || profile.tolerance <= 0.0
            || profile.tolerance >= 1.0
            || profile.max_sweeps == 0
            || profile.max_sweeps > 1024
            || profile
                .max_p95_solve_us
                .is_some_and(|limit| !limit.is_finite() || limit <= 0.0)
        {
            return Err(format!("profile '{}' contains an invalid tolerance, iteration, batch, worker or latency limit", profile.id).into());
        }
        if profile.applicable_domains.as_ref().is_some_and(|domains| {
            domains.is_empty()
                || domains
                    .iter()
                    .any(|domain| domain.is_empty() || domain.len() > 64)
        }) {
            return Err(format!("profile '{}' has invalid applicable_domains", profile.id).into());
        }
    }
    Ok(())
}

fn safe_source_path(base: &Path, source: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if source.is_absolute()
        || source.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err("dataset source must be a relative path without parent traversal".into());
    }
    Ok(base.join(source))
}

fn load_records(
    dataset: &DatasetSpec,
    path: &Path,
) -> Result<Vec<Vec<f64>>, Box<dyn std::error::Error>> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_DATASET_BYTES {
        return Err(format!("dataset '{}' exceeds 512 MiB", dataset.id).into());
    }
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut records = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        let length = reader.read_until(b'\n', &mut line)?;
        if length == 0 {
            break;
        }
        if line.len() > MAX_RECORD_BYTES {
            return Err(
                format!("dataset '{}' contains a JSONL row over 64 KiB", dataset.id).into(),
            );
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if records.len() >= MAX_RECORDS {
            return Err(format!("dataset '{}' exceeds one million records", dataset.id).into());
        }
        let value: Value = serde_json::from_slice(&line)?;
        let object = value
            .as_object()
            .ok_or("dataset record must be a JSON object")?;
        let mut row = Vec::with_capacity(dataset.feature_fields.len());
        for field in &dataset.feature_fields {
            let number = object
                .get(field)
                .and_then(Value::as_f64)
                .filter(|value| value.is_finite() && value.abs() <= 1.0e150)
                .ok_or_else(|| {
                    format!(
                        "dataset '{}' field '{}' must be finite and |value| <= 1e150",
                        dataset.id, field
                    )
                })?;
            row.push(number);
        }
        records.push(row);
    }
    if records.is_empty() {
        return Err(format!("dataset '{}' contains no records", dataset.id).into());
    }
    Ok(records)
}

fn correlation_matrix(rows: &[Vec<f64>], dimension: usize) -> Vec<f64> {
    let global_scale = rows
        .iter()
        .flatten()
        .fold(0.0_f64, |max, value| max.max(value.abs()));
    let scale = if global_scale == 0.0 {
        1.0
    } else {
        global_scale
    };
    let mut means = vec![0.0; dimension];
    for row in rows {
        for column in 0..dimension {
            means[column] += row[column] / scale;
        }
    }
    for mean in &mut means {
        *mean /= rows.len() as f64;
    }
    let mut covariance = vec![0.0; dimension * dimension];
    for row in rows {
        for left in 0..dimension {
            let x = row[left] / scale - means[left];
            for right in left..dimension {
                covariance[left * dimension + right] += x * (row[right] / scale - means[right]);
            }
        }
    }
    let denominator = rows.len().saturating_sub(1).max(1) as f64;
    for left in 0..dimension {
        for right in left..dimension {
            let value = covariance[left * dimension + right] / denominator;
            covariance[left * dimension + right] = value;
            covariance[right * dimension + left] = value;
        }
    }
    let variances: Vec<f64> = (0..dimension)
        .map(|index| covariance[index * dimension + index].max(0.0))
        .collect();
    let mut correlation = vec![0.0; dimension * dimension];
    for left in 0..dimension {
        for right in left..dimension {
            let denominator = (variances[left] * variances[right]).sqrt();
            let value = if denominator > f64::EPSILON {
                (covariance[left * dimension + right] / denominator).clamp(-1.0, 1.0)
            } else {
                0.0
            };
            correlation[left * dimension + right] = value;
            correlation[right * dimension + left] = value;
        }
    }
    correlation
}

fn percentile_us(sorted: &[u64], percentile: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = ((sorted.len() - 1) as f64 * percentile).ceil() as usize;
    sorted[index.min(sorted.len() - 1)] as f64 / 1000.0
}

fn measure_candidate(
    matrices: &[Vec<f64>],
    dimension: usize,
    batch_size: usize,
    workers: usize,
    profile: &EigensolverProfile,
) -> Result<Candidate, Box<dyn std::error::Error>> {
    let solve_count = matrices
        .len()
        .checked_mul(profile.iterations_per_batch)
        .filter(|count| *count <= MAX_TOTAL_SOLVES)
        .ok_or("candidate exceeds the one-million-solve safety limit")?;
    let next = AtomicUsize::new(0);
    let checksum = AtomicU64::new(0);
    let durations = Mutex::new(Vec::<u64>::with_capacity(solve_count));
    let residuals = Mutex::new((0.0_f64, 0.0_f64));
    let started = Instant::now();

    thread::scope(|scope| -> Result<(), Box<dyn std::error::Error>> {
        let mut handles = Vec::new();
        for _ in 0..workers.min(solve_count).max(1) {
            handles.push(scope.spawn(|| -> Result<(), String> {
                loop {
                    let task = next.fetch_add(1, Ordering::Relaxed);
                    if task >= solve_count {
                        break;
                    }
                    let matrix_index = task % matrices.len();
                    let before = Instant::now();
                    let decomposition = symmetric_eigen_decomposition_with_options(
                        &matrices[matrix_index],
                        dimension,
                        profile.tolerance,
                        profile.max_sweeps,
                    )
                    .map_err(|error| error.to_string())?;
                    let elapsed = before.elapsed().as_nanos().min(u64::MAX as u128) as u64;
                    let hash = decomposition
                        .eigenvalues
                        .iter()
                        .fold(0_u64, |hash, value| hash.rotate_left(7) ^ value.to_bits());
                    checksum.fetch_add(hash.wrapping_add(task as u64), Ordering::Relaxed);
                    durations
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .push(elapsed);
                    let mut quality = residuals.lock().unwrap_or_else(|p| p.into_inner());
                    quality.0 = quality.0.max(decomposition.relative_residual);
                    quality.1 = quality.1.max(decomposition.orthogonality_error);
                }
                Ok(())
            }));
        }
        for handle in handles {
            handle
                .join()
                .map_err(|_| "eigensolver benchmark worker panicked")?
                .map_err(|error| format!("eigensolver failed: {error}"))?;
        }
        Ok(())
    })?;

    let elapsed = started.elapsed();
    let mut times = durations.into_inner().unwrap_or_else(|p| p.into_inner());
    times.sort_unstable();
    let total_ns: u128 = times.iter().map(|time| *time as u128).sum();
    let mean_solve_us = if times.is_empty() {
        0.0
    } else {
        total_ns as f64 / times.len() as f64 / 1000.0
    };
    let quality = residuals.into_inner().unwrap_or_else(|p| p.into_inner());
    Ok(Candidate {
        batch_size,
        workers,
        matrix_dimension: dimension,
        batches: matrices.len(),
        solves: times.len(),
        elapsed_ms: elapsed.as_secs_f64() * 1000.0,
        solves_per_second: times.len() as f64 / elapsed.as_secs_f64().max(f64::MIN_POSITIVE),
        mean_solve_us,
        p95_solve_us: percentile_us(&times, 0.95),
        max_relative_residual: quality.0,
        max_orthogonality_error: quality.1,
        checksum: checksum.load(Ordering::Relaxed),
    })
}

fn run_dataset_profile(
    dataset: &DatasetSpec,
    profile: &EigensolverProfile,
    records: &[Vec<f64>],
) -> Result<DatasetResult, Box<dyn std::error::Error>> {
    let start = profile.warmup_records.min(records.len());
    let available = &records[start..];
    let sample_count = profile.sample_records.min(available.len());
    if sample_count == 0 {
        return Err(format!("dataset '{}' has no sample rows after warmup", dataset.id).into());
    }
    let sample = &available[..sample_count];
    let dimension = dataset.feature_fields.len();
    let mut candidates = Vec::new();
    for batch_size in &profile.batch_sizes {
        let matrices: Vec<Vec<f64>> = sample
            .chunks(*batch_size)
            .map(|batch| correlation_matrix(batch, dimension))
            .collect();
        for workers in &profile.worker_counts {
            candidates.push(measure_candidate(
                &matrices,
                dimension,
                *batch_size,
                *workers,
                profile,
            )?);
        }
    }
    let eligible: Vec<&Candidate> = candidates
        .iter()
        .filter(|candidate| {
            profile
                .max_p95_solve_us
                .is_none_or(|limit| candidate.p95_solve_us <= limit)
        })
        .collect();
    let met_latency_target = !eligible.is_empty() || profile.max_p95_solve_us.is_none();
    let pool: Vec<&Candidate> = if eligible.is_empty() {
        candidates.iter().collect()
    } else {
        eligible
    };
    let recommended = if profile.objective == "latency" {
        pool.into_iter()
            .min_by(|a, b| {
                a.p95_solve_us
                    .total_cmp(&b.p95_solve_us)
                    .then_with(|| b.solves_per_second.total_cmp(&a.solves_per_second))
            })
            .unwrap()
    } else {
        pool.into_iter()
            .max_by(|a, b| {
                a.solves_per_second
                    .total_cmp(&b.solves_per_second)
                    .then_with(|| b.p95_solve_us.total_cmp(&a.p95_solve_us))
            })
            .unwrap()
    }
    .clone();
    Ok(DatasetResult {
        dataset_id: dataset.id.clone(),
        domain: dataset.domain.clone(),
        profile_id: profile.id.clone(),
        objective: profile.objective.clone(),
        source_records: records.len(),
        warmup_records: start,
        sampled_records: sample_count,
        matrix_dimension: dimension,
        candidates,
        recommended,
        met_latency_target,
    })
}
