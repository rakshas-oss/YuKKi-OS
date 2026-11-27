use std::{
    env,
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use uuid::Uuid;

use yukkios::{
    crawler::{Crawler, CrawlerConfig, CrawlerExecutionOutputSink},
    crawler_data_exec::{CrawlerDataExecutor, DEFAULT_DATA_EXEC_FUEL},
};

struct DirectoryOutputSink {
    directory: PathBuf,
    run_id: String,
}

impl DirectoryOutputSink {
    fn new(directory: impl AsRef<Path>) -> Result<Self, Box<dyn Error>> {
        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory)?;
        Ok(Self {
            directory,
            run_id: Uuid::new_v4().simple().to_string(),
        })
    }
}

impl CrawlerExecutionOutputSink for DirectoryOutputSink {
    fn store(
        &self,
        page_key_sha256: &str,
        _input_sha256: &str,
        output_sha256: &str,
        output: &[u8],
    ) -> Result<String, String> {
        // Both names are host-generated lowercase SHA-256 values, not guest
        // strings or URLs. create_new prevents following/replacing a symlink.
        let filename = format!("{}-{page_key_sha256}-{output_sha256}.bin", self.run_id);
        let path = self.directory.join(&filename);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
        if let Err(error) = file.write_all(output).and_then(|_| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(&path);
            return Err(format!("cannot persist {}: {error}", path.display()));
        }
        Ok(filename)
    }
}

fn usage() {
    eprintln!(
        "Usage: yukki_crawl --seed URL --allow-domain DOMAIN --wasm FILE [options]\n\
         Options:\n\
           --seed URL                  Seed URL (repeatable)\n\
           --allow-domain DOMAIN       Allowed DNS domain/subdomains (repeatable)\n\
           --wasm FILE                 Compiled crawler-wasm extractor guest (.wasm)\n\
           --output FILE               JSON report path (default crawl-report.json)\n\
           --execute-wasm FILE         Explicitly run this processor on each fetched page\n\
           --execution-output-dir DIR  Store processor results (default crawler-execution-output)\n\
           --execution-fuel N          Fuel per page (default 10000000; max 1000000000)\n\
           --max-pages N               Maximum attempted pages (default 100)\n\
           --depth N                   Link-discovery depth (default 2)\n\
           --concurrency N             Parallel fetch/extraction jobs (default 8)\n\
           --max-page-bytes N          Maximum HTML bytes per page (default 1048576)\n\
           --max-total-bytes N         Crawl-wide downloaded byte ceiling (default 67108864)\n\
           --delay-ms N                Minimum delay between requests per host (default 500)\n\
           --timeout-secs N            Per-request timeout (default 15)\n\
         Processor outputs are separate binary files; crawled page scripts are never executed."
    );
}

fn value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, Box<dyn Error>> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut seeds = Vec::new();
    let mut domains = Vec::new();
    let mut wasm_path = None;
    let mut execute_wasm_path = None;
    let mut execution_output_dir = "crawler-execution-output".to_string();
    let mut execution_output_dir_supplied = false;
    let mut execution_fuel = DEFAULT_DATA_EXEC_FUEL;
    let mut execution_fuel_supplied = false;
    let mut output = "crawl-report.json".to_string();
    let mut config = CrawlerConfig::default();
    let mut args = env::args().skip(1);

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--help" | "-h" => {
                usage();
                return Ok(());
            }
            "--seed" => seeds.push(value(&mut args, "--seed")?),
            "--allow-domain" => domains.push(value(&mut args, "--allow-domain")?),
            "--wasm" => wasm_path = Some(value(&mut args, "--wasm")?),
            "--execute-wasm" => execute_wasm_path = Some(value(&mut args, "--execute-wasm")?),
            "--execution-output-dir" => {
                execution_output_dir = value(&mut args, "--execution-output-dir")?;
                execution_output_dir_supplied = true;
            }
            "--execution-fuel" => {
                execution_fuel = value(&mut args, "--execution-fuel")?.parse()?;
                execution_fuel_supplied = true;
            }
            "--output" => output = value(&mut args, "--output")?,
            "--max-pages" => config.max_pages = value(&mut args, "--max-pages")?.parse()?,
            "--depth" => config.max_depth = value(&mut args, "--depth")?.parse()?,
            "--concurrency" => {
                config.max_concurrency = value(&mut args, "--concurrency")?.parse()?
            }
            "--max-page-bytes" => {
                config.max_page_bytes = value(&mut args, "--max-page-bytes")?.parse()?
            }
            "--max-total-bytes" => {
                config.max_total_bytes = value(&mut args, "--max-total-bytes")?.parse()?
            }
            "--delay-ms" => {
                config.per_domain_delay =
                    std::time::Duration::from_millis(value(&mut args, "--delay-ms")?.parse()?)
            }
            "--timeout-secs" => {
                config.request_timeout =
                    std::time::Duration::from_secs(value(&mut args, "--timeout-secs")?.parse()?)
            }
            unknown => return Err(format!("unknown argument: {unknown}").into()),
        }
    }

    let wasm_path = match wasm_path {
        Some(path) => path,
        None => {
            usage();
            return Err("--wasm is required".into());
        }
    };
    if execute_wasm_path.is_none() && (execution_output_dir_supplied || execution_fuel_supplied) {
        return Err("--execution-output-dir and --execution-fuel require --execute-wasm".into());
    }
    if execute_wasm_path.is_some() && !(1..=1_000_000_000).contains(&execution_fuel) {
        return Err("--execution-fuel must be in 1..=1000000000".into());
    }

    config.allowed_domains = domains;
    let extractor_wasm = fs::read(&wasm_path)?;
    let crawler = Crawler::new(config, &extractor_wasm)?;

    let report = if let Some(processor_path) = execute_wasm_path {
        let processor_wasm = fs::read(&processor_path)?;
        let processor = CrawlerDataExecutor::from_bytes(&processor_wasm, execution_fuel)?;
        let processor_sha256 = processor.module_sha256().to_string();
        let output_sink = Arc::new(DirectoryOutputSink::new(&execution_output_dir)?);
        let report = crawler
            .crawl_with_processor(&seeds, processor, output_sink)
            .await?;
        let executions = report
            .records
            .iter()
            .filter_map(|record| record.execution.as_ref())
            .collect::<Vec<_>>();
        let succeeded = executions
            .iter()
            .filter(|execution| execution.output_reference.is_some() && execution.error.is_none())
            .count();
        let failed = executions.len().saturating_sub(succeeded);
        println!(
            "Processor complete: sha256={} runs={} succeeded={} failed={} output_dir={}",
            processor_sha256,
            executions.len(),
            succeeded,
            failed,
            execution_output_dir
        );
        report
    } else {
        crawler.crawl(&seeds).await?
    };

    let serialized = serde_json::to_vec_pretty(&report)?;
    fs::write(&output, serialized)?;

    println!(
        "Crawl complete: attempted={} succeeded={} failed={} bytes={} links={} output={}",
        report.metrics.pages_attempted,
        report.metrics.pages_succeeded,
        report.metrics.pages_failed,
        report.metrics.total_document_bytes,
        report.metrics.total_links,
        output
    );
    Ok(())
}
