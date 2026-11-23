use std::{
    env,
    error::Error,
    fs,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use serde::Serialize;
use tokio::task::JoinSet;
use yukki_browser_runtime::accelerator::{
    rgba_gain_cpu, BrowserAcceleratorScheduler, GraphicsComputeReport, MAX_GRAPHICS_PAYLOAD_BYTES,
};
use yukkios::exec_policy::ExecutionBackend;

const TILE_EDGE: usize = 128;
const DEFAULT_CONCURRENCY: usize = 4;
const MAX_CONCURRENCY: usize = 8;

#[derive(Serialize)]
struct FrameBenchmark {
    width: usize,
    height: usize,
    frame_bytes: usize,
    tile_edge: usize,
    tile_count: usize,
    iterations: usize,
    cpu_reference_median_ms: f64,
    delegated_median_ms: f64,
    delegated_p95_ms: f64,
    backend_counts: BackendCounts,
    remote_execution_count: usize,
    remote_nodes: Vec<String>,
    output_verified: bool,
}

#[derive(Default, Serialize)]
struct BackendCounts {
    local_cpu: usize,
    local_gpu: usize,
    remote_cpu: usize,
    remote_gpu: usize,
}

#[derive(Serialize)]
struct NpuBenchmark {
    input_bytes: usize,
    iterations: usize,
    median_ms: f64,
    p95_ms: f64,
    backend: String,
    worker_ids: Vec<u32>,
    remote_nodes: Vec<String>,
}

#[derive(Serialize)]
struct BenchmarkReport {
    schema: u16,
    benchmark: &'static str,
    os: &'static str,
    architecture: &'static str,
    remote_delegation_enabled: bool,
    remote_cpu_enabled: bool,
    discovered_peers: usize,
    discovered_gpu_peers: usize,
    discovered_cpu_peers: usize,
    discovered_npu_peers: usize,
    max_in_flight: usize,
    frame_results: Vec<FrameBenchmark>,
    npu_result: Option<NpuBenchmark>,
    notes: Vec<&'static str>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    let quick = args.iter().any(|arg| arg == "--quick");
    let cpu_only = args.iter().any(|arg| arg == "--cpu-only");
    let iterations = parse_value(&args, "--iterations").unwrap_or(if quick { 1 } else { 3 });
    let concurrency = parse_value(&args, "--concurrency").unwrap_or(DEFAULT_CONCURRENCY);
    let output_path = parse_path(&args, "--output");
    let npu_input = parse_path(&args, "--npu-input");

    if !(1..=10).contains(&iterations) {
        return Err("--iterations must be between 1 and 10".into());
    }
    if !(1..=MAX_CONCURRENCY).contains(&concurrency) {
        return Err(format!("--concurrency must be between 1 and {MAX_CONCURRENCY}").into());
    }
    if cpu_only {
        env::set_var("YUKKI_FORCE_CPU_FALLBACK", "true");
    }

    let scheduler =
        Arc::new(BrowserAcceleratorScheduler::from_env().map_err(std::io::Error::other)?);
    let status = scheduler.status();
    let dimensions: &[(usize, usize)] = if quick {
        &[(128, 128), (320, 240)]
    } else {
        &[(320, 240), (1280, 720), (1920, 1080), (3840, 2160)]
    };

    let mut frame_results = Vec::with_capacity(dimensions.len());
    for &(width, height) in dimensions {
        frame_results.push(
            benchmark_frame(scheduler.clone(), width, height, iterations, concurrency).await?,
        );
    }

    let npu_result = if let Some(path) = npu_input {
        let metadata = fs::metadata(&path)?;
        if !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_GRAPHICS_PAYLOAD_BYTES as u64
            || metadata.len() % 8 != 0
        {
            return Err(format!(
                "NPU input file must be a regular file containing 8-byte-aligned f64 values and 1..={MAX_GRAPHICS_PAYLOAD_BYTES} bytes"
            )
            .into());
        }
        let payload = fs::read(&path)?;
        Some(benchmark_npu(scheduler.clone(), &payload, iterations).await?)
    } else {
        None
    };

    let report = BenchmarkReport {
        schema: 1,
        benchmark: "yukki-browser-graphics-delegation",
        os: env::consts::OS,
        architecture: env::consts::ARCH,
        remote_delegation_enabled: env_flag("YUKKI_BROWSER_REMOTE_ACCELERATION"),
        remote_cpu_enabled: env_flag("YUKKI_BROWSER_REMOTE_ACCELERATION")
            && env_flag("YUKKI_BROWSER_REMOTE_CPU"),
        discovered_peers: status.discovered_peer_count,
        discovered_gpu_peers: status.discovered_gpu_peer_count,
        discovered_cpu_peers: status.discovered_cpu_peer_count,
        discovered_npu_peers: status.discovered_npu_peer_count,
        max_in_flight: concurrency,
        frame_results,
        npu_result,
        notes: vec![
            "WebKit remains responsible for browser page rasterization and WebGL/WebGPU rendering.",
            "RGBA results measure a bounded auxiliary RGB channel-gain transform using the broker's deterministic multiply-by-two kernel, not full-page rendering.",
            "Accelerator execution is counted only when the broker response attests the backend.",
            "Peer capability labels are discovery hints; they are not hardware attestations.",
            "The benchmark uses bounded concurrency and never opens more than --concurrency tasks at once.",
            "NPU measurements require --npu-input containing network-order f64 values compatible with the active NPU executor/model bundle.",
        ],
    };

    let json = serde_json::to_vec_pretty(&report)?;
    if let Some(path) = output_path {
        fs::write(path, &json)?;
    }
    println!("{}", String::from_utf8(json)?);
    Ok(())
}

async fn benchmark_frame(
    scheduler: Arc<BrowserAcceleratorScheduler>,
    width: usize,
    height: usize,
    iterations: usize,
    concurrency: usize,
) -> Result<FrameBenchmark, Box<dyn Error>> {
    let frame = make_frame(width, height);
    let tiles = split_tiles(&frame, width, height);
    let mut cpu_samples = Vec::with_capacity(iterations);
    let mut delegated_samples = Vec::with_capacity(iterations);
    let mut counts = BackendCounts::default();
    let mut remote_nodes = std::collections::BTreeSet::new();
    let mut remote_execution_count = 0usize;
    let mut output_verified = true;

    for _ in 0..iterations {
        let cpu_start = Instant::now();
        let cpu_output = rgba_gain_cpu(&frame);
        cpu_samples.push(cpu_start.elapsed());
        if cpu_output.len() != frame.len() {
            return Err("CPU reference returned an invalid output length".into());
        }

        let scheduled_start = Instant::now();
        let reports =
            run_tiles_bounded(scheduler.clone(), &tiles, width, height, concurrency).await?;
        delegated_samples.push(scheduled_start.elapsed());

        for (index, report) in reports {
            let expected = rgba_gain_cpu(&tiles[index]);
            if report.output != expected {
                output_verified = false;
                return Err(format!(
                    "tile {index} for {width}x{height} did not match the CPU reference"
                )
                .into());
            }
            match (report.actual_backend, report.execution_node_id) {
                (ExecutionBackend::Gpu, Some(node)) => {
                    counts.remote_gpu += 1;
                    remote_execution_count += 1;
                    remote_nodes.insert(node.to_string());
                }
                (yukki_browser_runtime::accelerator::ExecutionBackend::Gpu, None) => {
                    counts.local_gpu += 1;
                }
                (ExecutionBackend::Cpu, Some(node)) => {
                    counts.remote_cpu += 1;
                    remote_execution_count += 1;
                    remote_nodes.insert(node.to_string());
                }
                (yukki_browser_runtime::accelerator::ExecutionBackend::Cpu, None) => {
                    counts.local_cpu += 1;
                }
                _ => {}
            }
        }
    }

    let cpu_median = median(&cpu_samples).as_secs_f64() * 1000.0;
    let delegated_median = median(&delegated_samples).as_secs_f64() * 1000.0;
    let delegated_p95 = percentile(&delegated_samples, 95).as_secs_f64() * 1000.0;

    Ok(FrameBenchmark {
        width,
        height,
        frame_bytes: frame.len(),
        tile_edge: TILE_EDGE,
        tile_count: tiles.len(),
        iterations,
        cpu_reference_median_ms: cpu_median,
        delegated_median_ms: delegated_median,
        delegated_p95_ms: delegated_p95,
        backend_counts: counts,
        remote_execution_count,
        remote_nodes: remote_nodes.into_iter().collect(),
        output_verified,
    })
}

async fn run_tiles_bounded(
    scheduler: Arc<BrowserAcceleratorScheduler>,
    tiles: &[Vec<u8>],
    width: usize,
    height: usize,
    concurrency: usize,
) -> Result<Vec<(usize, GraphicsComputeReport)>, Box<dyn Error>> {
    let mut tasks = JoinSet::new();
    let mut next = 0usize;
    let mut completed = Vec::with_capacity(tiles.len());

    while next < tiles.len() || !tasks.is_empty() {
        while next < tiles.len() && tasks.len() < concurrency {
            let scheduler = scheduler.clone();
            let tile = tiles[next].clone();
            let index = next;
            let task_id = format!("gfx-{width}x{height}-{index}");
            tasks.spawn(async move {
                let report = scheduler.run_rgba_gain(&task_id, &tile).await?;
                Ok::<_, String>((index, report))
            });
            next += 1;
        }

        if let Some(joined) = tasks.join_next().await {
            let result = joined.map_err(std::io::Error::other)?;
            completed.push(result.map_err(std::io::Error::other)?);
        }
    }

    completed.sort_by_key(|(index, _)| *index);
    Ok(completed)
}

async fn benchmark_npu(
    scheduler: Arc<BrowserAcceleratorScheduler>,
    payload: &[u8],
    iterations: usize,
) -> Result<NpuBenchmark, Box<dyn Error>> {
    let mut samples = Vec::with_capacity(iterations);
    let mut worker_ids = std::collections::BTreeSet::new();
    let mut remote_nodes = std::collections::BTreeSet::new();

    for index in 0..iterations {
        let task_id = format!("gfx-npu-{index}");
        let started = Instant::now();
        let report = scheduler
            .run_npu_inference(&task_id, payload)
            .await
            .map_err(std::io::Error::other)?;
        samples.push(started.elapsed());
        if let Some(worker) = report.broker_worker_id {
            worker_ids.insert(worker);
        }
        if let Some(node) = report.execution_node_id {
            remote_nodes.insert(node.to_string());
        }
    }

    Ok(NpuBenchmark {
        input_bytes: payload.len(),
        iterations,
        median_ms: median(&samples).as_secs_f64() * 1000.0,
        p95_ms: percentile(&samples, 95).as_secs_f64() * 1000.0,
        backend: "npu (BRK2-attested)".to_owned(),
        worker_ids: worker_ids.into_iter().collect(),
        remote_nodes: remote_nodes.into_iter().collect(),
    })
}

fn make_frame(width: usize, height: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; width * height * 4];
    for (index, pixel) in bytes.chunks_exact_mut(4).enumerate() {
        pixel[0] = (index.wrapping_mul(17) & 0xff) as u8;
        pixel[1] = (index.wrapping_mul(31) & 0xff) as u8;
        pixel[2] = ((index ^ (index >> 3)) & 0xff) as u8;
        pixel[3] = 255;
    }
    bytes
}

fn split_tiles(frame: &[u8], width: usize, height: usize) -> Vec<Vec<u8>> {
    let mut tiles = Vec::new();
    for top in (0..height).step_by(TILE_EDGE) {
        let tile_height = (height - top).min(TILE_EDGE);
        for left in (0..width).step_by(TILE_EDGE) {
            let tile_width = (width - left).min(TILE_EDGE);
            let mut tile = Vec::with_capacity(tile_width * tile_height * 4);
            for row in top..(top + tile_height) {
                let start = (row * width + left) * 4;
                let end = start + tile_width * 4;
                tile.extend_from_slice(&frame[start..end]);
            }
            debug_assert!(tile.len() <= MAX_GRAPHICS_PAYLOAD_BYTES);
            tiles.push(tile);
        }
    }
    tiles
}

fn median(samples: &[Duration]) -> Duration {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}

fn percentile(samples: &[Duration], percentile: usize) -> Duration {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let index = ((sorted.len() - 1) * percentile).div_ceil(100);
    sorted[index]
}

fn parse_value(args: &[String], name: &str) -> Option<usize> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|index| args.get(index + 1))
        .and_then(|value| value.parse().ok())
}

fn parse_path(args: &[String], name: &str) -> Option<PathBuf> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|index| args.get(index + 1))
        .map(PathBuf::from)
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}
