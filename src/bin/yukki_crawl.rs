use std::{env, error::Error, fs};

use yukkios::crawler::{Crawler, CrawlerConfig};

fn usage() {
    eprintln!(
        "Usage: yukki_crawl --seed URL --allow-domain DOMAIN --wasm FILE [options]\n\
         Options:\n\
           --seed URL                  Seed URL (repeatable)\n\
           --allow-domain DOMAIN       Allowed DNS domain/subdomains (repeatable)\n\
           --wasm FILE                 Compiled crawler-wasm guest (.wasm)\n\
           --output FILE               JSON report path (default crawl-report.json)\n\
           --max-pages N               Maximum attempted pages (default 100)\n\
           --depth N                   Link-discovery depth (default 2)\n\
           --concurrency N             Parallel fetch/extraction jobs (default 8)\n\
           --max-page-bytes N          Maximum HTML bytes per page (default 1048576)\n\
           --max-total-bytes N         Crawl-wide downloaded byte ceiling (default 67108864)\n\
           --delay-ms N                Minimum delay between requests per host (default 500)\n\
           --timeout-secs N            Per-request timeout (default 15)\n"
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
    config.allowed_domains = domains;
    let wasm = fs::read(&wasm_path)?;
    let crawler = Crawler::new(config, &wasm)?;
    let report = crawler.crawl(&seeds).await?;
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
