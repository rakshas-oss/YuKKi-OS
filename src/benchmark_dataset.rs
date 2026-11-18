//! Native benchmark-led dataset execution.
//!
//! Manifest-declared JSONL datasets are the benchmark input. Profiles control
//! warmup/sample windows, candidate batches, worker counts, and the selected
//! runtime recommendation. Data is never replaced with random benchmark data.

use std::{
    collections::HashSet,
    fs,
    io::{self, BufRead, BufReader},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Mutex,
    },
    thread,
    time::Instant,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::nxr1::Nxr1Frame;

pub const MANIFEST_VERSION: u32 = 1;
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
pub const MAX_DATASET_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
pub const MAX_RECORDS: usize = 1_000_000;
pub const MAX_DATASETS: usize = 256;
pub const MAX_PROFILES: usize = 64;
pub const MAX_FEATURE_FIELDS: usize = 64;
pub const MAX_BATCH_SIZE: usize = 1024;
pub const MAX_WORKERS: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetManifest {
    pub version: u32,
    pub datasets: Vec<DatasetDefinition>,
    pub profiles: Vec<BenchmarkProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetDefinition {
    pub id: String,
    pub domain: String,
    pub source: PathBuf,
    pub sequence_field: String,
    pub timestamp_ns_field: String,
    #[serde(default)]
    pub latitude_field: Option<String>,
    #[serde(default)]
    pub longitude_field: Option<String>,
    #[serde(default)]
    pub altitude_m_field: Option<String>,
    pub feature_fields: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkObjective {
    Latency,
    Throughput,
    Memory,
    Geospatial,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkProfile {
    pub id: String,
    pub objective: BenchmarkObjective,
    pub warmup_records: usize,
    pub sample_records: usize,
    pub batch_sizes: Vec<usize>,
    pub worker_counts: Vec<usize>,
    #[serde(default)]
    pub max_p95_batch_ms: Option<f64>,
    #[serde(default)]
    pub geometric_tolerance_m: Option<f64>,
    #[serde(default)]
    pub max_turn_degrees: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateMetrics {
    pub batch_size: usize,
    pub workers: usize,
    pub records_processed: usize,
    pub batches_processed: usize,
    pub elapsed_ms: f64,
    pub records_per_second: f64,
    pub mean_batch_ms: f64,
    pub p50_batch_ms: f64,
    pub p95_batch_ms: f64,
    pub p99_batch_ms: f64,
    pub estimated_peak_working_set_bytes: u64,
    pub encoded_bytes: u64,
    pub checksum: u64,
    pub geometry_input_points: usize,
    pub geometry_output_points: usize,
    pub geometry_reduction_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetBenchmarkResult {
    pub dataset_id: String,
    pub domain: String,
    pub profile_id: String,
    pub objective: BenchmarkObjective,
    pub source_rows: usize,
    pub warmup_records: usize,
    pub sampled_records: usize,
    pub dataset_load_ms: f64,
    pub candidates: Vec<CandidateMetrics>,
    pub recommended: CandidateMetrics,
    pub met_latency_target: bool,
}

#[derive(Debug, Error)]
pub enum DatasetBenchmarkError {
    #[error("I/O error at '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("manifest JSON is invalid: {0}")]
    ManifestJson(#[from] serde_json::Error),
    #[error("invalid dataset manifest: {0}")]
    InvalidManifest(String),
    #[error("dataset '{0}' is not present in the manifest")]
    UnknownDataset(String),
    #[error("benchmark profile '{0}' is not present in the manifest")]
    UnknownProfile(String),
    #[error("dataset '{dataset_id}' row {row}: {reason}")]
    InvalidRecord {
        dataset_id: String,
        row: usize,
        reason: String,
    },
    #[error("dataset '{0}' has no records available for measurement")]
    NoSampleRows(String),
    #[error("NXR1 encode/decode failed: {0}")]
    Codec(String),
    #[error("a benchmark worker panicked")]
    WorkerPanic,
}

#[derive(Debug, Clone)]
struct DatasetRecord {
    sequence: u64,
    timestamp_ns: u64,
    position: Option<[f64; 3]>,
    features: Vec<f64>,
    raw_json: Vec<u8>,
}

impl DatasetRecord {
    fn to_frame(&self) -> Result<Nxr1Frame, DatasetBenchmarkError> {
        // NXR1 x/y/z and dynamics are generic numeric fields. Geographic
        // coordinates are processed separately by the geospatial benchmark
        // and remain available in the opaque JSON payload.
        let fluidity = self.feature(6) as f32;
        let drag = self.feature(7) as f32;
        if !fluidity.is_finite() || !drag.is_finite() {
            return Err(DatasetBenchmarkError::Codec(
                "numeric feature exceeds the NXR1 f32 range".to_string(),
            ));
        }
        Ok(Nxr1Frame {
            seq_id: self.sequence,
            x: self.feature(0),
            y: self.feature(1),
            z: self.feature(2),
            u: self.feature(3),
            v: self.feature(4),
            w: self.feature(5),
            fluidity,
            drag,
            divergence: self.feature(8),
            payload: self.raw_json.clone(),
        })
    }

    fn feature(&self, index: usize) -> f64 {
        self.features.get(index).copied().unwrap_or(0.0)
    }

    fn feature_at(&self, index: usize) -> f64 {
        self.features.get(index).copied().unwrap_or(0.0)
    }
}

pub struct BenchmarkDatasetRunner;

impl BenchmarkDatasetRunner {
    pub fn run_manifest(
        manifest_path: impl AsRef<Path>,
        dataset_filter: Option<&str>,
        profile_filter: Option<&str>,
    ) -> Result<Vec<DatasetBenchmarkResult>, DatasetBenchmarkError> {
        let manifest_path = manifest_path.as_ref();
        let manifest = load_manifest(manifest_path)?;
        validate_manifest(&manifest)?;
        let datasets: Vec<_> = manifest
            .datasets
            .iter()
            .filter(|item| {
                dataset_filter.is_none_or(|wanted| wanted == "all" || item.id == wanted)
            })
            .collect();
        let profiles: Vec<_> = manifest
            .profiles
            .iter()
            .filter(|item| {
                profile_filter.is_none_or(|wanted| wanted == "all" || item.id == wanted)
            })
            .collect();
        if datasets.is_empty() {
            return Err(DatasetBenchmarkError::UnknownDataset(
                dataset_filter.unwrap_or("all").to_string(),
            ));
        }
        if profiles.is_empty() {
            return Err(DatasetBenchmarkError::UnknownProfile(
                profile_filter.unwrap_or("all").to_string(),
            ));
        }

        let base = manifest_path.parent().unwrap_or_else(|| Path::new("."));
        let mut results = Vec::with_capacity(datasets.len() * profiles.len());
        for dataset in datasets {
            let source = if dataset.source.is_absolute() {
                dataset.source.clone()
            } else {
                base.join(&dataset.source)
            };
            let started = Instant::now();
            let (records, source_rows) = load_dataset(dataset, &source)?;
            let load_ms = started.elapsed().as_secs_f64() * 1000.0;
            for profile in &profiles {
                results.push(run_profile(
                    dataset,
                    profile,
                    &records,
                    source_rows,
                    load_ms,
                )?);
            }
        }
        Ok(results)
    }
}

fn load_manifest(path: &Path) -> Result<DatasetManifest, DatasetBenchmarkError> {
    let metadata = fs::metadata(path).map_err(|source| DatasetBenchmarkError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.len() > MAX_MANIFEST_BYTES as u64 {
        return Err(DatasetBenchmarkError::InvalidManifest(format!(
            "manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let bytes = fs::read(path).map_err(|source| DatasetBenchmarkError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn validate_manifest(manifest: &DatasetManifest) -> Result<(), DatasetBenchmarkError> {
    if manifest.version != MANIFEST_VERSION {
        return Err(DatasetBenchmarkError::InvalidManifest(format!(
            "unsupported version {}; expected {MANIFEST_VERSION}",
            manifest.version
        )));
    }
    if manifest.datasets.is_empty() || manifest.datasets.len() > MAX_DATASETS {
        return Err(DatasetBenchmarkError::InvalidManifest(format!(
            "dataset count must be 1..={MAX_DATASETS}"
        )));
    }
    if manifest.profiles.is_empty() || manifest.profiles.len() > MAX_PROFILES {
        return Err(DatasetBenchmarkError::InvalidManifest(format!(
            "profile count must be 1..={MAX_PROFILES}"
        )));
    }

    let mut dataset_ids = HashSet::new();
    for dataset in &manifest.datasets {
        if dataset.id.trim().is_empty()
            || dataset.id.len() > 128
            || dataset.domain.trim().is_empty()
            || dataset.domain.len() > 64
            || dataset.source.as_os_str().is_empty()
            || dataset.feature_fields.is_empty()
            || dataset.feature_fields.len() > MAX_FEATURE_FIELDS
        {
            return Err(DatasetBenchmarkError::InvalidManifest(format!(
                "dataset '{}' has missing or out-of-range metadata",
                dataset.id
            )));
        }
        if !dataset_ids.insert(dataset.id.as_str()) {
            return Err(DatasetBenchmarkError::InvalidManifest(format!(
                "duplicate dataset id '{}'",
                dataset.id
            )));
        }
        if dataset.latitude_field.is_some() != dataset.longitude_field.is_some() {
            return Err(DatasetBenchmarkError::InvalidManifest(format!(
                "dataset '{}' must map latitude and longitude together",
                dataset.id
            )));
        }
        if dataset.altitude_m_field.is_some() && dataset.latitude_field.is_none() {
            return Err(DatasetBenchmarkError::InvalidManifest(format!(
                "dataset '{}' maps altitude without latitude/longitude",
                dataset.id
            )));
        }
        let mut fields = HashSet::new();
        for field in std::iter::once(&dataset.sequence_field)
            .chain(std::iter::once(&dataset.timestamp_ns_field))
            .chain(dataset.latitude_field.iter())
            .chain(dataset.longitude_field.iter())
            .chain(dataset.altitude_m_field.iter())
            .chain(dataset.feature_fields.iter())
        {
            if field.trim().is_empty() || field.len() > 128 || !fields.insert(field.as_str()) {
                return Err(DatasetBenchmarkError::InvalidManifest(format!(
                    "dataset '{}' has an empty, oversized, or duplicate field mapping",
                    dataset.id
                )));
            }
        }
    }

    let mut profile_ids = HashSet::new();
    for profile in &manifest.profiles {
        if profile.id.trim().is_empty() || profile.id.len() > 128 {
            return Err(DatasetBenchmarkError::InvalidManifest(
                "profile id must be non-empty and at most 128 bytes".to_string(),
            ));
        }
        if !profile_ids.insert(profile.id.as_str()) {
            return Err(DatasetBenchmarkError::InvalidManifest(format!(
                "duplicate profile id '{}'",
                profile.id
            )));
        }
        if profile.sample_records == 0
            || profile.sample_records > MAX_RECORDS
            || profile.warmup_records > MAX_RECORDS
            || profile.batch_sizes.is_empty()
            || profile.batch_sizes.len() > 16
            || profile.batch_sizes.iter().any(|value| *value == 0 || *value > MAX_BATCH_SIZE)
            || profile.worker_counts.is_empty()
            || profile.worker_counts.len() > 16
            || profile.worker_counts.iter().any(|value| *value == 0 || *value > MAX_WORKERS)
        {
            return Err(DatasetBenchmarkError::InvalidManifest(format!(
                "profile '{}' contains an invalid sample, batch, or worker range",
                profile.id
            )));
        }
        if profile.max_p95_batch_ms.is_some_and(|value| !value.is_finite() || value <= 0.0) {
            return Err(DatasetBenchmarkError::InvalidManifest(format!(
                "profile '{}' max_p95_batch_ms must be finite and positive",
                profile.id
            )));
        }
        if profile.objective == BenchmarkObjective::Geospatial
            && (profile.geometric_tolerance_m.is_none_or(|value| !value.is_finite() || value < 0.0)
                || profile.max_turn_degrees.is_none_or(|value| !value.is_finite() || value <= 0.0 || value > 180.0))
        {
            return Err(DatasetBenchmarkError::InvalidManifest(format!(
                "geospatial profile '{}' requires a non-negative geometric_tolerance_m and max_turn_degrees in (0, 180]",
                profile.id
            )));
        }
    }
    Ok(())
}

fn load_dataset(
    dataset: &DatasetDefinition,
    source: &Path,
) -> Result<(Vec<DatasetRecord>, usize), DatasetBenchmarkError> {
    let metadata = fs::metadata(source).map_err(|source_error| DatasetBenchmarkError::Io {
        path: source.to_path_buf(),
        source: source_error,
    })?;
    if metadata.len() > MAX_DATASET_BYTES {
        return Err(DatasetBenchmarkError::InvalidManifest(format!(
            "dataset '{}' exceeds {} bytes",
            dataset.id, MAX_DATASET_BYTES
        )));
    }
    let file = fs::File::open(source).map_err(|source_error| DatasetBenchmarkError::Io {
        path: source.to_path_buf(),
        source: source_error,
    })?;
    let mut reader = BufReader::new(file);
    let mut records = Vec::new();
    let mut row = 0usize;
    while let Some(line) = read_bounded_line(&mut reader, MAX_RECORD_BYTES).map_err(|source_error| {
        DatasetBenchmarkError::Io {
            path: source.to_path_buf(),
            source: source_error,
        }
    })? {
        row += 1;
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if row > MAX_RECORDS {
            return Err(DatasetBenchmarkError::InvalidManifest(format!(
                "dataset '{}' exceeds {MAX_RECORDS} JSONL rows",
                dataset.id
            )));
        }
        let value: Value = serde_json::from_slice(&line).map_err(|error| {
            invalid_record(dataset, row, format!("invalid JSONL object: {error}"))
        })?;
        let object = value.as_object().ok_or_else(|| {
            invalid_record(dataset, row, "record must be a JSON object".to_string())
        })?;
        let sequence = required_u64(object, &dataset.sequence_field)
            .map_err(|reason| invalid_record(dataset, row, reason))?;
        let timestamp_ns = required_u64(object, &dataset.timestamp_ns_field)
            .map_err(|reason| invalid_record(dataset, row, reason))?;

        let position = match (&dataset.latitude_field, &dataset.longitude_field) {
            (Some(latitude_field), Some(longitude_field)) => {
                let latitude = required_f64(object, latitude_field)
                    .map_err(|reason| invalid_record(dataset, row, reason))?;
                let longitude = required_f64(object, longitude_field)
                    .map_err(|reason| invalid_record(dataset, row, reason))?;
                let altitude = match &dataset.altitude_m_field {
                    Some(field) => required_f64(object, field)
                        .map_err(|reason| invalid_record(dataset, row, reason))?,
                    None => 0.0,
                };
                if !(-90.0..=90.0).contains(&latitude)
                    || !(-180.0..=180.0).contains(&longitude)
                {
                    return Err(invalid_record(
                        dataset,
                        row,
                        "latitude/longitude is outside WGS84 bounds".to_string(),
                    ));
                }
                Some([longitude, latitude, altitude])
            }
            _ => None,
        };
        let mut features = Vec::with_capacity(dataset.feature_fields.len());
        for field in &dataset.feature_fields {
            features.push(
                required_f64(object, field)
                    .map_err(|reason| invalid_record(dataset, row, reason))?,
            );
        }
        records.push(DatasetRecord {
            sequence,
            timestamp_ns,
            position,
            features,
            raw_json: line,
        });
    }
    if records.is_empty() {
        return Err(DatasetBenchmarkError::InvalidManifest(format!(
            "dataset '{}' contains no JSONL records",
            dataset.id
        )));
    }
    let source_rows = records.len();
    Ok((records, source_rows))
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            break;
        }
        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            if line.len() + newline > max_bytes {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "JSONL row too large"));
            }
            line.extend_from_slice(&available[..newline]);
            reader.consume(newline + 1);
            break;
        }
        let length = available.len();
        if line.len() + length > max_bytes {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "JSONL row too large"));
        }
        line.extend_from_slice(available);
        reader.consume(length);
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(Some(line))
}

fn required_u64(object: &serde_json::Map<String, Value>, field: &str) -> Result<u64, String> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("field '{field}' must be an unsigned integer"))
}

fn required_f64(object: &serde_json::Map<String, Value>, field: &str) -> Result<f64, String> {
    object
        .get(field)
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
        .ok_or_else(|| format!("field '{field}' must be a finite number"))
}

fn invalid_record(
    dataset: &DatasetDefinition,
    row: usize,
    reason: String,
) -> DatasetBenchmarkError {
    DatasetBenchmarkError::InvalidRecord {
        dataset_id: dataset.id.clone(),
        row,
        reason,
    }
}

fn select_sample(
    dataset_id: &str,
    records: &[DatasetRecord],
    profile: &BenchmarkProfile,
) -> Result<Vec<DatasetRecord>, DatasetBenchmarkError> {
    let start = profile.warmup_records.min(records.len());
    let available = records.len().saturating_sub(start);
    if available == 0 {
        return Err(DatasetBenchmarkError::NoSampleRows(dataset_id.to_string()));
    }
    let count = profile.sample_records.min(available);
    let mut sample = Vec::with_capacity(count);
    for index in 0..count {
        let relative = if count == 1 {
            0
        } else {
            index * (available - 1) / (count - 1)
        };
        sample.push(records[start + relative].clone());
    }
    Ok(sample)
}

fn run_profile(
    dataset: &DatasetDefinition,
    profile: &BenchmarkProfile,
    records: &[DatasetRecord],
    source_rows: usize,
    dataset_load_ms: f64,
) -> Result<DatasetBenchmarkResult, DatasetBenchmarkError> {
    if profile.objective == BenchmarkObjective::Geospatial
        && dataset.latitude_field.is_none()
    {
        return Err(DatasetBenchmarkError::InvalidManifest(format!(
            "profile '{}' requires geospatial fields on dataset '{}'",
            profile.id, dataset.id
        )));
    }

    let warmup_count = profile.warmup_records.min(records.len());
    for record in &records[..warmup_count] {
        let frame = record.to_frame()?;
        let bytes = frame
            .encode()
            .map_err(|error| DatasetBenchmarkError::Codec(error.to_string()))?;
        let decoded = Nxr1Frame::decode(&bytes)
            .map_err(|error| DatasetBenchmarkError::Codec(error.to_string()))?;
        std::hint::black_box(decoded);
    }

    let sample = select_sample(&dataset.id, records, profile)?;
    let mut candidates = Vec::new();
    for batch_size in &profile.batch_sizes {
        for workers in &profile.worker_counts {
            candidates.push(measure_candidate(&sample, *batch_size, *workers, profile)?);
        }
    }
    let eligible: Vec<&CandidateMetrics> = candidates
        .iter()
        .filter(|candidate| {
            profile
                .max_p95_batch_ms
                .is_none_or(|limit| candidate.p95_batch_ms <= limit)
        })
        .collect();
    let met_latency_target = !eligible.is_empty() || profile.max_p95_batch_ms.is_none();
    let pool: Vec<&CandidateMetrics> = if eligible.is_empty() {
        candidates.iter().collect()
    } else {
        eligible
    };
    let recommended = choose_candidate(&pool, profile.objective).clone();

    Ok(DatasetBenchmarkResult {
        dataset_id: dataset.id.clone(),
        domain: dataset.domain.clone(),
        profile_id: profile.id.clone(),
        objective: profile.objective,
        source_rows,
        warmup_records: warmup_count,
        sampled_records: sample.len(),
        dataset_load_ms,
        candidates,
        recommended,
        met_latency_target,
    })
}

fn measure_candidate(
    records: &[DatasetRecord],
    batch_size: usize,
    workers: usize,
    profile: &BenchmarkProfile,
) -> Result<CandidateMetrics, DatasetBenchmarkError> {
    let batch_count = records.len().div_ceil(batch_size);
    let worker_count = workers.min(batch_count).max(1);
    let next_batch = AtomicUsize::new(0);
    let encoded_bytes = AtomicU64::new(0);
    let checksum = AtomicU64::new(0);
    let latencies = Mutex::new(Vec::<u64>::with_capacity(batch_count));
    let geometry_input_points = AtomicUsize::new(0);
    let geometry_output_points = AtomicUsize::new(0);
    let max_record_bytes = records
        .iter()
        .map(|record| record.raw_json.len())
        .max()
        .unwrap_or(0);
    let started = Instant::now();

    let worker_result = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            handles.push(scope.spawn(|| -> Result<(), DatasetBenchmarkError> {
                loop {
                    let batch_index = next_batch.fetch_add(1, Ordering::Relaxed);
                    if batch_index >= batch_count {
                        break;
                    }
                    let begin = batch_index * batch_size;
                    let end = (begin + batch_size).min(records.len());
                    let batch_started = Instant::now();
                    let mut local_bytes = 0u64;
                    let mut local_checksum = 0u64;
                    for record in &records[begin..end] {
                        let frame = record.to_frame()?;
                        let bytes = frame
                            .encode()
                            .map_err(|error| DatasetBenchmarkError::Codec(error.to_string()))?;
                        let decoded = Nxr1Frame::decode(&bytes)
                            .map_err(|error| DatasetBenchmarkError::Codec(error.to_string()))?;
                        local_bytes = local_bytes.saturating_add(bytes.len() as u64);
                        local_checksum ^= decoded.seq_id ^ record.timestamp_ns ^ decoded.payload.len() as u64;
                        std::hint::black_box(decoded);
                    }
                    if profile.objective == BenchmarkObjective::Geospatial {
                        let tolerance = profile.geometric_tolerance_m.unwrap_or(0.0);
                        let max_turn = profile.max_turn_degrees.unwrap_or(45.0);
                        let path = records[begin..end]
                            .iter()
                            .map(|record| to_ecef(record.position.expect("geospatial profile requires positions")))
                            .collect::<Vec<_>>();
                        let retained = simplify_arc_secant_tangent(&path, tolerance, max_turn);
                        geometry_input_points.fetch_add(path.len(), Ordering::Relaxed);
                        geometry_output_points.fetch_add(retained, Ordering::Relaxed);
                        local_checksum ^= retained as u64;
                    }
                    encoded_bytes.fetch_add(local_bytes, Ordering::Relaxed);
                    checksum.fetch_xor(local_checksum, Ordering::Relaxed);
                    latencies
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .push(batch_started.elapsed().as_nanos().min(u64::MAX as u128) as u64);
                }
                Ok(())
            }));
        }
        for handle in handles {
            match handle.join() {
                Ok(result) => result?,
                Err(_) => return Err(DatasetBenchmarkError::WorkerPanic),
            }
        }
        Ok(())
    });
    worker_result?;

    let elapsed = started.elapsed();
    let mut times = latencies
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    times.sort_unstable();
    let elapsed_seconds = elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
    let mean_ns = if times.is_empty() {
        0.0
    } else {
        times.iter().map(|value| *value as f64).sum::<f64>() / times.len() as f64
    };
    let estimated_peak_working_set_bytes = (max_record_bytes as u64)
        .saturating_mul(batch_size as u64)
        .saturating_mul(worker_count as u64);

    Ok(CandidateMetrics {
        batch_size,
        workers: worker_count,
        records_processed: records.len(),
        batches_processed: batch_count,
        elapsed_ms: elapsed.as_secs_f64() * 1000.0,
        records_per_second: records.len() as f64 / elapsed_seconds,
        mean_batch_ms: mean_ns / 1_000_000.0,
        p50_batch_ms: percentile_ms(&times, 0.50),
        p95_batch_ms: percentile_ms(&times, 0.95),
        p99_batch_ms: percentile_ms(&times, 0.99),
        estimated_peak_working_set_bytes,
        encoded_bytes: encoded_bytes.load(Ordering::Relaxed),
        checksum: checksum.load(Ordering::Relaxed),
        geometry_input_points: geometry_input_points.load(Ordering::Relaxed),
        geometry_output_points: geometry_output_points.load(Ordering::Relaxed),
        geometry_reduction_percent: {
            let input = geometry_input_points.load(Ordering::Relaxed);
            let output = geometry_output_points.load(Ordering::Relaxed);
            if input == 0 { 0.0 } else { 100.0 * input.saturating_sub(output) as f64 / input as f64 }
        },
    })
}


#[derive(Clone, Copy)]
struct EcefPoint {
    x: f64,
    y: f64,
    z: f64,
}

fn to_ecef([longitude, latitude, altitude]: [f64; 3]) -> EcefPoint {
    const A: f64 = 6_378_137.0;
    const E2: f64 = 0.006_694_379_990_14;
    let latitude = latitude.to_radians();
    let longitude = longitude.to_radians();
    let (sin_lat, cos_lat) = latitude.sin_cos();
    let (sin_lon, cos_lon) = longitude.sin_cos();
    let n = A / (1.0 - E2 * sin_lat * sin_lat).sqrt();
    EcefPoint {
        x: (n + altitude) * cos_lat * cos_lon,
        y: (n + altitude) * cos_lat * sin_lon,
        z: (n * (1.0 - E2) + altitude) * sin_lat,
    }
}

fn subtract(a: EcefPoint, b: EcefPoint) -> EcefPoint {
    EcefPoint { x: a.x - b.x, y: a.y - b.y, z: a.z - b.z }
}

fn dot(a: EcefPoint, b: EcefPoint) -> f64 {
    a.x * b.x + a.y * b.y + a.z * b.z
}

fn distance(a: EcefPoint, b: EcefPoint) -> f64 {
    let delta = subtract(a, b);
    dot(delta, delta).sqrt()
}

/// Iterative arc/secant/tangent reducer. Arc excess and perpendicular secant
/// distance bound geometric error; a separate tangent guard preserves turns.
fn simplify_arc_secant_tangent(
    points: &[EcefPoint],
    tolerance_m: f64,
    max_turn_degrees: f64,
) -> usize {
    if points.len() <= 2 {
        return points.len();
    }
    let mut keep = vec![false; points.len()];
    keep[0] = true;
    keep[points.len() - 1] = true;
    let cosine_limit = max_turn_degrees.to_radians().cos();
    let tolerance = tolerance_m.max(1.0e-9);
    let mut stack = vec![(0usize, points.len() - 1)];

    while let Some((start, end)) = stack.pop() {
        if end <= start + 1 {
            continue;
        }
        let a = points[start];
        let b = points[end];
        let chord = subtract(b, a);
        let chord_sq = dot(chord, chord);
        let chord_len = chord_sq.sqrt();
        let mut worst_score = 1.0;
        let mut worst_index = None;

        for index in (start + 1)..end {
            let point = points[index];
            let from_start = subtract(point, a);
            let to_end = subtract(b, point);
            let projection = if chord_sq > 1.0e-18 {
                (dot(from_start, chord) / chord_sq).clamp(0.0, 1.0)
            } else {
                0.0
            };
            let nearest = EcefPoint {
                x: a.x + chord.x * projection,
                y: a.y + chord.y * projection,
                z: a.z + chord.z * projection,
            };
            let perpendicular = distance(point, nearest);
            let left_len = dot(from_start, from_start).sqrt();
            let right_len = dot(to_end, to_end).sqrt();
            let arc_excess = (left_len + right_len - chord_len).max(0.0);
            let distance_score = perpendicular.max(arc_excess * 0.5) / tolerance;
            let tangent_cosine = if left_len > 1.0e-9 && right_len > 1.0e-9 {
                dot(from_start, to_end) / (left_len * right_len)
            } else {
                1.0
            };
            let tangent_score = if tangent_cosine < cosine_limit {
                2.0 + (cosine_limit - tangent_cosine).max(0.0)
                    + left_len.min(right_len) / (left_len.min(right_len) + tolerance)
            } else {
                0.0
            };
            let score = distance_score.max(tangent_score);
            if score > worst_score {
                worst_score = score;
                worst_index = Some(index);
            }
        }

        if let Some(split) = worst_index {
            keep[split] = true;
            stack.push((start, split));
            stack.push((split, end));
        }
    }
    keep.into_iter().filter(|retain| *retain).count()
}

fn percentile_ms(sorted_ns: &[u64], percentile: f64) -> f64 {
    if sorted_ns.is_empty() {
        return 0.0;
    }
    let index = ((sorted_ns.len() - 1) as f64 * percentile).ceil() as usize;
    sorted_ns[index.min(sorted_ns.len() - 1)] as f64 / 1_000_000.0
}

fn choose_candidate(
    candidates: &[&CandidateMetrics],
    objective: BenchmarkObjective,
) -> &CandidateMetrics {
    match objective {
        BenchmarkObjective::Latency => candidates
            .iter()
            .copied()
            .min_by(|left, right| {
                left.p95_batch_ms
                    .total_cmp(&right.p95_batch_ms)
                    .then_with(|| right.records_per_second.total_cmp(&left.records_per_second))
            })
            .expect("validated profile has candidates"),
        BenchmarkObjective::Throughput | BenchmarkObjective::Geospatial => candidates
            .iter()
            .copied()
            .max_by(|left, right| {
                left.records_per_second
                    .total_cmp(&right.records_per_second)
                    .then_with(|| right.p95_batch_ms.total_cmp(&left.p95_batch_ms))
            })
            .expect("validated profile has candidates"),
        BenchmarkObjective::Memory => candidates
            .iter()
            .copied()
            .min_by(|left, right| {
                left.estimated_peak_working_set_bytes
                    .cmp(&right.estimated_peak_working_set_bytes)
                    .then_with(|| right.records_per_second.total_cmp(&left.records_per_second))
            })
            .expect("validated profile has candidates"),
    }
}

impl crate::adi_auto_tune::ADIAutoTuner {
    /// Make measured dataset results authoritative for the next native queue policy.
    pub fn apply_dataset_benchmark(&mut self, result: &DatasetBenchmarkResult) {
        self.optimal_queue_depth = result
            .recommended
            .batch_size
            .saturating_mul(result.recommended.workers)
            .clamp(1, 1024);
        self.active_hardware_profile = format!(
            "benchmark:{}:{}:{}x{}",
            result.dataset_id,
            objective_name(result.objective),
            result.recommended.batch_size,
            result.recommended.workers
        );
    }
}

fn objective_name(objective: BenchmarkObjective) -> &'static str {
    match objective {
        BenchmarkObjective::Latency => "latency",
        BenchmarkObjective::Throughput => "throughput",
        BenchmarkObjective::Memory => "memory",
        BenchmarkObjective::Geospatial => "geospatial",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_directory() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "yukki-benchmark-datasets-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn profiles_sweep_real_jsonl_rows_and_select_a_queue_policy() {
        let root = temporary_directory();
        fs::create_dir_all(&root).unwrap();
        let manifest = serde_json::json!({
            "version": 1,
            "datasets": [{
                "id": "drone-fixture",
                "domain": "drone",
                "source": "drone.jsonl",
                "sequence_field": "sequence",
                "timestamp_ns_field": "timestamp_ns",
                "latitude_field": "latitude",
                "longitude_field": "longitude",
                "altitude_m_field": "altitude_m",
                "feature_fields": ["velocity", "heading", "battery"]
            }],
            "profiles": [{
                "id": "geo-throughput",
                "objective": "geospatial",
                "warmup_records": 1,
                "sample_records": 3,
                "batch_sizes": [1, 2],
                "worker_counts": [1, 2],
                "max_p95_batch_ms": 1000.0,
                "geometric_tolerance_m": 2.0,
                "max_turn_degrees": 30.0
            }]
        });
        fs::write(root.join("manifest.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
        let rows = [
            r#"{"sequence":1,"timestamp_ns":100,"latitude":43.65,"longitude":-79.38,"altitude_m":100,"velocity":12.0,"heading":90.0,"battery":99.0}"#,
            r#"{"sequence":2,"timestamp_ns":200,"latitude":43.651,"longitude":-79.381,"altitude_m":101,"velocity":13.0,"heading":91.0,"battery":98.0}"#,
            r#"{"sequence":3,"timestamp_ns":300,"latitude":43.652,"longitude":-79.382,"altitude_m":102,"velocity":14.0,"heading":92.0,"battery":97.0}"#,
            r#"{"sequence":4,"timestamp_ns":400,"latitude":43.653,"longitude":-79.383,"altitude_m":103,"velocity":15.0,"heading":93.0,"battery":96.0}"#,
        ]
        .join("\n");
        fs::write(root.join("drone.jsonl"), rows).unwrap();

        let results = BenchmarkDatasetRunner::run_manifest(
            root.join("manifest.json"),
            Some("drone-fixture"),
            Some("geo-throughput"),
        )
        .unwrap();
        assert_eq!(results.len(), 1);
        let result = &results[0];
        assert_eq!(result.sampled_records, 3);
        assert_eq!(result.warmup_records, 1);
        assert_eq!(result.candidates.len(), 4);
        assert!(result.recommended.records_per_second > 0.0);
        assert!(result.recommended.encoded_bytes > 0);
        assert!(result.met_latency_target);

        let mut tuner = crate::adi_auto_tune::ADIAutoTuner::default();
        tuner.apply_dataset_benchmark(result);
        assert_eq!(
            tuner.active_hardware_profile,
            format!(
                "benchmark:drone-fixture:geospatial:{}x{}",
                result.recommended.batch_size, result.recommended.workers
            )
        );
        assert_eq!(
            tuner.optimal_queue_depth,
            (result.recommended.batch_size * result.recommended.workers).clamp(1, 1024)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn geospatial_profile_rejects_a_finance_only_dataset() {
        let root = temporary_directory();
        fs::create_dir_all(&root).unwrap();
        let manifest = serde_json::json!({
            "version": 1,
            "datasets": [{
                "id": "finance-fixture",
                "domain": "finance",
                "source": "finance.jsonl",
                "sequence_field": "sequence",
                "timestamp_ns_field": "timestamp_ns",
                "feature_fields": ["price", "volume"]
            }],
            "profiles": [{
                "id": "spatial",
                "objective": "geospatial",
                "warmup_records": 0,
                "sample_records": 1,
                "batch_sizes": [1],
                "worker_counts": [1]
            }]
        });
        fs::write(root.join("manifest.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
        fs::write(
            root.join("finance.jsonl"),
            "{\"sequence\":1,\"timestamp_ns\":1,\"price\":123.4,\"volume\":1000}\n",
        )
        .unwrap();
        let result = BenchmarkDatasetRunner::run_manifest(
            root.join("manifest.json"),
            Some("finance-fixture"),
            Some("spatial"),
        );
        assert!(matches!(result, Err(DatasetBenchmarkError::InvalidManifest(_))));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_arc_secant_tangent_simplifier_reduces_straight_tracks() {
        let points = [
            EcefPoint { x: 0.0, y: 0.0, z: 0.0 },
            EcefPoint { x: 1.0, y: 0.0, z: 0.0 },
            EcefPoint { x: 2.0, y: 0.0, z: 0.0 },
            EcefPoint { x: 3.0, y: 0.0, z: 0.0 },
            EcefPoint { x: 4.0, y: 0.0, z: 0.0 },
        ];
        assert_eq!(simplify_arc_secant_tangent(&points, 1.0, 45.0), 2);
    }

    #[test]
    fn native_arc_secant_tangent_simplifier_preserves_sharp_turns() {
        let points = [
            EcefPoint { x: 0.0, y: 0.0, z: 0.0 },
            EcefPoint { x: 1.0, y: 0.0, z: 0.0 },
            EcefPoint { x: 1.0, y: 1.0, z: 0.0 },
        ];
        assert_eq!(simplify_arc_secant_tangent(&points, 100.0, 30.0), 3);
    }

    #[test]
    fn line_reader_rejects_oversized_records() {
        let mut reader = io::Cursor::new(b"123456\n".to_vec());
        let error = read_bounded_line(&mut reader, 5).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
