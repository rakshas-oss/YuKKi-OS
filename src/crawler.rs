//! Bounded, polite public-web crawler backed by native async I/O and sandboxed WASM extraction.
//!
//! Network access stays in the host. The guest receives at most one bounded HTML
//! document and has no imports, WASI, sockets, filesystem, or secrets.

use crate::{
    crawler_data_exec::CrawlerDataExecutor,
    crawler_wasm::{CrawlerWasmError, WasmHtmlExtractor, MAX_CRAWLER_INPUT_BYTES},
};
use futures_util::StreamExt;
use reqwest::{header::CONTENT_TYPE, Client, ClientBuilder, StatusCode, Url};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    net::lookup_host,
    sync::{Mutex, Semaphore},
    task::JoinSet,
    time::{sleep_until, Instant},
};

const MAX_ROBOTS_BYTES: usize = 64 * 1024;
const MAX_ALLOWED_DOMAINS: usize = 256;
const MAX_CRAWLER_EXECUTION_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_CRAWLER_PROCESSOR_RUNS: usize = 1_024;
const MAX_CRAWLER_PROCESSOR_CONCURRENCY: usize = 4;

#[derive(Debug, Clone)]
pub struct CrawlerConfig {
    /// Exact domains or their subdomains. An empty allowlist is rejected.
    pub allowed_domains: Vec<String>,
    pub user_agent: String,
    pub max_concurrency: usize,
    pub max_pages: usize,
    pub max_depth: usize,
    pub max_page_bytes: usize,
    pub max_total_bytes: usize,
    pub max_links_per_page: usize,
    pub per_domain_delay: Duration,
    pub request_timeout: Duration,
    pub wasm_fuel_per_call: u64,
}

impl Default for CrawlerConfig {
    fn default() -> Self {
        Self {
            allowed_domains: Vec::new(),
            user_agent: "YuKKiOSCrawler/0.1 (+respect robots.txt)".into(),
            max_concurrency: 8,
            max_pages: 100,
            max_depth: 2,
            max_page_bytes: MAX_CRAWLER_INPUT_BYTES,
            max_total_bytes: 64 * 1024 * 1024,
            max_links_per_page: 128,
            per_domain_delay: Duration::from_millis(500),
            request_timeout: Duration::from_secs(15),
            wasm_fuel_per_call: 5_000_000,
        }
    }
}

#[derive(Debug, Error)]
pub enum CrawlerError {
    #[error("invalid crawler configuration: {0}")]
    InvalidConfig(String),
    #[error("seed URL is not permitted: {0}")]
    InvalidSeed(String),
    #[error("DNS resolution failed for {host}: {message}")]
    Dns { host: String, message: String },
    #[error("host {0} resolved to a non-public address; request blocked")]
    NonPublicAddress(String),
    #[error("domain {0} is not in the crawler allowlist")]
    DomainNotAllowed(String),
    #[error("HTTP client construction failed: {0}")]
    HttpClient(String),
    #[error("request failed: {0}")]
    Request(String),
    #[error("robots.txt denied access or could not be safely evaluated")]
    RobotsDenied,
    #[error("per-page byte ceiling exceeded")]
    PageTooLarge,
    #[error("crawl-wide byte budget exceeded")]
    TotalBytesExceeded,
    #[error("WASM extraction failed: {0}")]
    Wasm(#[from] CrawlerWasmError),
}

#[derive(Debug, Clone, Serialize)]
pub struct CrawledPage {
    pub url: String,
    pub depth: usize,
    pub status_code: Option<u16>,
    pub fetched_at_unix_ms: u128,
    pub document_bytes: u64,
    pub sha256: String,
    pub title: String,
    pub links: Vec<String>,
    pub fetch_ms: f64,
    pub extraction_ms: f64,
    pub error: Option<String>,
    /// Present only when the caller explicitly enabled a data processor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution: Option<CrawlerExecutionRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrawlerExecutionRecord {
    pub processor_sha256: String,
    pub input_sha256: String,
    pub output_sha256: Option<String>,
    pub output_bytes: Option<u64>,
    /// Caller-defined sink reference, never an implicit URL or broker address.
    pub output_reference: Option<String>,
    pub execution_ms: f64,
    pub error: Option<String>,
}

/// Application-owned persistence boundary for processor results.
/// Implementations should enforce their own filesystem/database quotas.
pub trait CrawlerExecutionOutputSink: Send + Sync {
    fn store(
        &self,
        input_sha256: &str,
        output_sha256: &str,
        output: &[u8],
    ) -> Result<String, String>;
}

#[derive(Debug, Clone, Serialize)]
pub struct CrawlMetrics {
    pub pages_attempted: usize,
    pub pages_succeeded: usize,
    pub pages_failed: usize,
    pub total_document_bytes: u64,
    pub total_links: u64,
    pub mean_document_bytes: f64,
    pub mean_fetch_ms: f64,
    pub mean_extraction_ms: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrawlReport {
    pub schema_version: u32,
    pub crawler_abi: &'static str,
    pub records: Vec<CrawledPage>,
    pub metrics: CrawlMetrics,
}

#[derive(Clone)]
pub struct Crawler {
    inner: Arc<CrawlerInner>,
}

struct CrawlerInner {
    config: CrawlerConfig,
    allowed_domains: Vec<String>,
    extractor: Arc<WasmHtmlExtractor>,
    clients: Mutex<HashMap<String, CachedClient>>,
    domain_gates: Mutex<HashMap<String, Arc<Mutex<Instant>>>>,
    robots: Mutex<HashMap<String, RobotsPolicy>>,
    page_slots: Arc<Semaphore>,
}

struct CachedClient {
    addresses: Vec<SocketAddr>,
    client: Client,
}

#[derive(Clone, Default)]
struct RobotsPolicy {
    deny_all: bool,
    rules: Vec<RobotsRule>,
}

#[derive(Clone)]
struct RobotsRule {
    allow: bool,
    pattern: String,
}

struct FetchPayload {
    status: u16,
    document_bytes: u64,
    extraction: crate::crawler_wasm::HtmlExtraction,
    sha256: String,
    fetch_ms: f64,
    extraction_ms: f64,
    document: Vec<u8>,
}

impl Crawler {
    pub fn new(config: CrawlerConfig, wasm_plugin: &[u8]) -> Result<Self, CrawlerError> {
        validate_config(&config)?;
        let allowed_domains = config
            .allowed_domains
            .iter()
            .map(|domain| {
                domain
                    .trim()
                    .trim_start_matches('.')
                    .trim_end_matches('.')
                    .to_ascii_lowercase()
            })
            .collect::<Vec<_>>();
        let extractor = WasmHtmlExtractor::from_bytes(
            wasm_plugin,
            config.wasm_fuel_per_call,
            crate::crawler_wasm::MAX_CRAWLER_WASM_MEMORY_BYTES,
        )?;
        Ok(Self {
            inner: Arc::new(CrawlerInner {
                page_slots: Arc::new(Semaphore::new(config.max_concurrency)),
                config,
                allowed_domains,
                extractor: Arc::new(extractor),
                clients: Mutex::new(HashMap::new()),
                domain_gates: Mutex::new(HashMap::new()),
                robots: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// Crawl allowlisted domains without executing the fetched documents.
    pub async fn crawl(&self, seeds: &[String]) -> Result<CrawlReport, CrawlerError> {
        self.crawl_inner(seeds, None, None).await
    }

    /// Crawl and explicitly run a caller-selected processor against each
    /// successfully fetched page's raw HTML bytes. Processor outputs are sent
    /// to the caller-owned sink and are not embedded in the JSON report.
    pub async fn crawl_with_processor(
        &self,
        seeds: &[String],
        processor: CrawlerDataExecutor,
        output_sink: Arc<dyn CrawlerExecutionOutputSink>,
    ) -> Result<CrawlReport, CrawlerError> {
        self.crawl_inner(seeds, Some(Arc::new(processor)), Some(output_sink))
            .await
    }

    async fn crawl_inner(
        &self,
        seeds: &[String],
        processor: Option<Arc<CrawlerDataExecutor>>,
        output_sink: Option<Arc<dyn CrawlerExecutionOutputSink>>,
    ) -> Result<CrawlReport, CrawlerError> {
        if seeds.is_empty() {
            return Err(CrawlerError::InvalidConfig(
                "at least one --seed URL is required".into(),
            ));
        }
        if processor.is_some() != output_sink.is_some() {
            return Err(CrawlerError::InvalidConfig(
                "processor and output sink must be configured together".into(),
            ));
        }

        let mut frontier = VecDeque::new();
        let mut seen = HashSet::new();
        for seed in seeds {
            let url = Url::parse(seed).map_err(|_| CrawlerError::InvalidSeed(seed.clone()))?;
            let normalized = self
                .normalize_url(url)
                .map_err(|_| CrawlerError::InvalidSeed(seed.clone()))?;
            if seen.insert(normalized.as_str().to_string()) {
                frontier.push_back((normalized, 0usize));
            }
        }

        let crawl_byte_budget = Arc::new(AtomicUsize::new(0));
        let execution_output_budget = Arc::new(AtomicUsize::new(0));
        let execution_run_budget = Arc::new(AtomicUsize::new(0));
        let execution_slots = Arc::new(Semaphore::new(MAX_CRAWLER_PROCESSOR_CONCURRENCY));
        let mut tasks = JoinSet::new();
        let mut records = Vec::new();
        while records.len() < self.inner.config.max_pages
            && (!frontier.is_empty() || !tasks.is_empty())
        {
            while tasks.len() < self.inner.config.max_concurrency
                && records.len() + tasks.len() < self.inner.config.max_pages
            {
                let Some((url, depth)) = frontier.pop_front() else {
                    break;
                };
                let crawler = self.clone();
                let crawl_byte_budget = crawl_byte_budget.clone();
                let execution_output_budget = execution_output_budget.clone();
                let execution_run_budget = execution_run_budget.clone();
                let execution_slots = execution_slots.clone();
                let processor = processor.clone();
                let output_sink = output_sink.clone();
                tasks.spawn(async move {
                    let record = crawler
                        .fetch_page(
                            url,
                            depth,
                            crawl_byte_budget,
                            execution_output_budget,
                            execution_run_budget,
                            execution_slots,
                            processor,
                            output_sink,
                        )
                        .await;
                    (depth, record)
                });
            }

            let Some(joined) = tasks.join_next().await else {
                break;
            };
            let (depth, record) = match joined {
                Ok(value) => value,
                Err(_) => continue,
            };
            if depth < self.inner.config.max_depth && record.error.is_none() {
                for link in &record.links {
                    if seen.len() >= self.inner.config.max_pages.saturating_mul(8) {
                        break;
                    }
                    if let Ok(url) = Url::parse(link) {
                        if let Ok(url) = self.normalize_url(url) {
                            if seen.insert(url.as_str().to_string()) {
                                frontier.push_back((url, depth + 1));
                            }
                        }
                    }
                }
            }
            records.push(record);
        }

        let metrics = summarize(&records);
        Ok(CrawlReport {
            schema_version: 1,
            crawler_abi: crate::crawler_wasm::CRAWLER_WASM_ABI,
            records,
            metrics,
        })
    }

    fn normalize_url(&self, mut url: Url) -> Result<Url, CrawlerError> {
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(CrawlerError::InvalidSeed(url.to_string()));
        }
        let host = url
            .host_str()
            .ok_or_else(|| CrawlerError::InvalidSeed(url.to_string()))?;
        if !self.domain_allowed(host) {
            return Err(CrawlerError::DomainNotAllowed(host.to_string()));
        }
        if host.parse::<IpAddr>().is_ok() {
            return Err(CrawlerError::InvalidSeed(
                "IP-literal URLs are not accepted; use an allowlisted DNS name".into(),
            ));
        }
        url.set_fragment(None);
        Ok(url)
    }

    fn domain_allowed(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.inner.allowed_domains.iter().any(|allowed| {
            host == *allowed
                || host
                    .strip_suffix(allowed)
                    .map(|prefix| prefix.ends_with('.'))
                    .unwrap_or(false)
        })
    }

    async fn fetch_page(
        &self,
        url: Url,
        depth: usize,
        crawl_byte_budget: Arc<AtomicUsize>,
        execution_output_budget: Arc<AtomicUsize>,
        execution_run_budget: Arc<AtomicUsize>,
        execution_slots: Arc<Semaphore>,
        processor: Option<Arc<CrawlerDataExecutor>>,
        output_sink: Option<Arc<dyn CrawlerExecutionOutputSink>>,
    ) -> CrawledPage {
        let started = Instant::now();
        let url_text = url.as_str().to_string();
        let fetched_at_unix_ms = now_unix_ms();
        let mut record = CrawledPage {
            url: url_text,
            depth,
            status_code: None,
            fetched_at_unix_ms,
            document_bytes: 0,
            sha256: String::new(),
            title: String::new(),
            links: Vec::new(),
            fetch_ms: 0.0,
            extraction_ms: 0.0,
            error: None,
            execution: None,
        };

        let permit = match self.inner.page_slots.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => {
                record.error = Some("crawler is shutting down".into());
                return record;
            }
        };
        let result = self.fetch_payload(&url, &crawl_byte_budget).await;
        drop(permit);
        record.fetched_at_unix_ms = now_unix_ms();
        record.fetch_ms = started.elapsed().as_secs_f64() * 1000.0;
        match result {
            Ok(payload) => {
                record.status_code = Some(payload.status);
                record.document_bytes = payload.document_bytes;
                record.sha256 = payload.sha256.clone();
                record.title = payload.extraction.title;
                record.links = payload.extraction.links;
                record.fetch_ms = payload.fetch_ms;
                record.extraction_ms = payload.extraction_ms;
                if let (Some(processor), Some(output_sink)) = (processor, output_sink) {
                    record.execution = Some(
                        execute_ingested_page(
                            processor,
                            output_sink,
                            payload.sha256,
                            payload.document,
                            execution_output_budget,
                            execution_run_budget,
                            execution_slots,
                        )
                        .await,
                    );
                }
            }
            Err((status, error)) => {
                record.status_code = status;
                record.error = Some(error);
            }
        }
        record
    }

    async fn fetch_payload(
        &self,
        url: &Url,
        crawl_byte_budget: &AtomicUsize,
    ) -> Result<FetchPayload, (Option<u16>, String)> {
        let host = url
            .host_str()
            .ok_or((None, "missing URL host".into()))?
            .to_string();
        let port = url
            .port_or_known_default()
            .ok_or((None, "unknown URL port".into()))?;
        let client = self
            .client_for(&host, port)
            .await
            .map_err(|error| (None, error.to_string()))?;

        let robots = self
            .robots_policy(url, &client)
            .await
            .map_err(|error| (None, error.to_string()))?;
        if robots.deny_all || !robots.is_allowed(url.path()) {
            return Err((None, CrawlerError::RobotsDenied.to_string()));
        }

        self.throttle_domain(&host).await;
        let fetch_started = Instant::now();
        let response = client
            .get(url.clone())
            .send()
            .await
            .map_err(|error| (None, CrawlerError::Request(error.to_string()).to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err((
                Some(status.as_u16()),
                format!("HTTP status {status}; redirects are not followed"),
            ));
        }
        if let Some(content_type) = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
        {
            let media_type = content_type
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if media_type != "text/html" && media_type != "application/xhtml+xml" {
                return Err((
                    Some(status.as_u16()),
                    format!("unsupported content type: {media_type}"),
                ));
            }
        } else {
            return Err((
                Some(status.as_u16()),
                "missing or invalid Content-Type".into(),
            ));
        }

        if response
            .content_length()
            .map(|length| length as usize > self.inner.config.max_page_bytes)
            .unwrap_or(false)
        {
            return Err((
                Some(status.as_u16()),
                CrawlerError::PageTooLarge.to_string(),
            ));
        }

        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| (Some(status.as_u16()), error.to_string()))?;
            if body.len().saturating_add(chunk.len()) > self.inner.config.max_page_bytes {
                return Err((
                    Some(status.as_u16()),
                    CrawlerError::PageTooLarge.to_string(),
                ));
            }
            reserve_crawl_bytes(
                crawl_byte_budget,
                self.inner.config.max_total_bytes,
                chunk.len(),
            )
            .map_err(|error| (Some(status.as_u16()), error.to_string()))?;
            body.extend_from_slice(&chunk);
        }
        let fetch_ms = fetch_started.elapsed().as_secs_f64() * 1000.0;
        let document_bytes = body.len() as u64;
        let sha256 = hex_digest(&body);
        let extraction_started = Instant::now();
        let extractor = self.inner.extractor.clone();
        let extraction_input = body.clone();
        let extraction = tokio::task::spawn_blocking(move || extractor.extract(&extraction_input))
            .await
            .map_err(|error| (Some(status.as_u16()), error.to_string()))?
            .map_err(|error| (Some(status.as_u16()), error.to_string()))?;
        let extraction_ms = extraction_started.elapsed().as_secs_f64() * 1000.0;

        let mut links = Vec::new();
        let mut unique = HashSet::new();
        for href in extraction
            .links
            .into_iter()
            .take(self.inner.config.max_links_per_page)
        {
            let candidate = match url.join(&href) {
                Ok(candidate) => candidate,
                Err(_) => continue,
            };
            let candidate = match self.normalize_url(candidate) {
                Ok(candidate) => candidate,
                Err(_) => continue,
            };
            if unique.insert(candidate.as_str().to_string()) {
                links.push(candidate.to_string());
            }
        }
        let extraction = crate::crawler_wasm::HtmlExtraction {
            document_bytes: extraction.document_bytes,
            title: extraction.title,
            links,
        };

        Ok(FetchPayload {
            status: status.as_u16(),
            document_bytes,
            extraction,
            sha256,
            fetch_ms,
            extraction_ms,
            document: body,
        })
    }

    async fn client_for(&self, host: &str, port: u16) -> Result<Client, CrawlerError> {
        let lookup = lookup_host(format!("{host}:{port}"))
            .await
            .map_err(|error| CrawlerError::Dns {
                host: host.into(),
                message: error.to_string(),
            })?;
        let mut addresses = lookup.collect::<Vec<_>>();
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
            return Err(CrawlerError::NonPublicAddress(host.into()));
        }

        let key = format!("{host}:{port}");
        let mut cache = self.inner.clients.lock().await;
        if let Some(existing) = cache.get(&key) {
            if existing.addresses == addresses {
                return Ok(existing.client.clone());
            }
        }
        let client = ClientBuilder::new()
            .resolve_to_addrs(host, &addresses)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(self.inner.config.request_timeout)
            .timeout(self.inner.config.request_timeout)
            .user_agent(self.inner.config.user_agent.clone())
            .build()
            .map_err(|error| CrawlerError::HttpClient(error.to_string()))?;
        cache.insert(
            key,
            CachedClient {
                addresses,
                client: client.clone(),
            },
        );
        Ok(client)
    }

    async fn throttle_domain(&self, host: &str) {
        let gate = {
            let mut gates = self.inner.domain_gates.lock().await;
            gates
                .entry(host.to_ascii_lowercase())
                .or_insert_with(|| Arc::new(Mutex::new(Instant::now())))
                .clone()
        };
        let mut next_allowed = gate.lock().await;
        if *next_allowed > Instant::now() {
            sleep_until(*next_allowed).await;
        }
        *next_allowed = Instant::now() + self.inner.config.per_domain_delay;
    }

    async fn robots_policy(
        &self,
        url: &Url,
        client: &Client,
    ) -> Result<RobotsPolicy, CrawlerError> {
        let host = url
            .host_str()
            .ok_or_else(|| CrawlerError::InvalidSeed(url.to_string()))?;
        let key = format!(
            "{}://{}:{}",
            url.scheme(),
            host,
            url.port_or_known_default().unwrap_or(0)
        );
        if let Some(policy) = self.inner.robots.lock().await.get(&key).cloned() {
            return Ok(policy);
        }

        self.throttle_domain(host).await;
        // Concurrent page tasks may have queued behind the same domain gate
        // while the first task fetched robots.txt. Re-check after the gate so
        // only one robots request is sent per origin during this crawl.
        if let Some(policy) = self.inner.robots.lock().await.get(&key).cloned() {
            return Ok(policy);
        }
        let mut robots_url = url.clone();
        robots_url.set_path("/robots.txt");
        robots_url.set_query(None);
        robots_url.set_fragment(None);
        let policy = match client.get(robots_url).send().await {
            Ok(response)
                if response.status() == StatusCode::NOT_FOUND
                    || response.status() == StatusCode::GONE =>
            {
                RobotsPolicy::default()
            }
            Ok(response) if response.status().is_success() => {
                let mut bytes = Vec::new();
                let mut stream = response.bytes_stream();
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk.map_err(|_| CrawlerError::RobotsDenied)?;
                    if bytes.len().saturating_add(chunk.len()) > MAX_ROBOTS_BYTES {
                        return Err(CrawlerError::RobotsDenied);
                    }
                    bytes.extend_from_slice(&chunk);
                }
                parse_robots(
                    &String::from_utf8_lossy(&bytes),
                    &self.inner.config.user_agent,
                )
            }
            _ => return Err(CrawlerError::RobotsDenied),
        };
        self.inner.robots.lock().await.insert(key, policy.clone());
        Ok(policy)
    }
}

impl RobotsPolicy {
    fn is_allowed(&self, path: &str) -> bool {
        if self.deny_all {
            return false;
        }
        let mut best: Option<(usize, bool)> = None;
        for rule in &self.rules {
            if robots_pattern_matches(&rule.pattern, path) {
                let specificity = rule.pattern.trim_end_matches('$').replace('*', "").len();
                if best
                    .map(|(len, allow)| {
                        specificity > len || (specificity == len && !rule.allow && allow)
                    })
                    .unwrap_or(true)
                {
                    best = Some((specificity, rule.allow));
                }
            }
        }
        best.map(|(_, allow)| allow).unwrap_or(true)
    }
}

fn parse_robots(text: &str, user_agent: &str) -> RobotsPolicy {
    let wanted = user_agent
        .split('/')
        .next()
        .unwrap_or(user_agent)
        .to_ascii_lowercase();
    let mut groups: Vec<(Vec<String>, Vec<RobotsRule>)> = Vec::new();
    let mut agents = Vec::new();
    let mut rules = Vec::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "user-agent" {
            if !agents.is_empty() && !rules.is_empty() {
                groups.push((std::mem::take(&mut agents), std::mem::take(&mut rules)));
            }
            agents.push(value.to_ascii_lowercase());
        } else if (name == "allow" || name == "disallow") && !value.is_empty() && !agents.is_empty()
        {
            rules.push(RobotsRule {
                allow: name == "allow",
                pattern: value.to_string(),
            });
        }
    }
    if !agents.is_empty() {
        groups.push((agents, rules));
    }

    let specific: Vec<_> = groups
        .iter()
        .filter(|(agents, _)| {
            agents
                .iter()
                .any(|agent| agent != "*" && wanted.contains(agent))
        })
        .collect();
    let selected = if specific.is_empty() {
        groups
            .iter()
            .filter(|(agents, _)| agents.iter().any(|agent| agent == "*"))
            .collect::<Vec<_>>()
    } else {
        specific
    };
    let selected_rules = selected
        .into_iter()
        .flat_map(|(_, rules)| rules.clone())
        .collect();
    RobotsPolicy {
        deny_all: false,
        rules: selected_rules,
    }
}

fn robots_pattern_matches(pattern: &str, path: &str) -> bool {
    let anchored = pattern.ends_with('$');
    let pattern = pattern.strip_suffix('$').unwrap_or(pattern);
    let parts = pattern.split('*').collect::<Vec<_>>();
    let mut cursor = 0usize;
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        let found = if index == 0 && !pattern.starts_with('*') {
            if path.starts_with(part) {
                Some(0)
            } else {
                None
            }
        } else {
            path.get(cursor..)
                .and_then(|rest| rest.find(part))
                .map(|offset| cursor + offset)
        };
        let Some(found) = found else {
            return false;
        };
        cursor = found + part.len();
    }
    if anchored {
        let last = parts.last().copied().unwrap_or("");
        path.ends_with(last) && cursor <= path.len()
    } else {
        true
    }
}

async fn execute_ingested_page(
    processor: Arc<CrawlerDataExecutor>,
    output_sink: Arc<dyn CrawlerExecutionOutputSink>,
    input_sha256: String,
    document: Vec<u8>,
    output_budget: Arc<AtomicUsize>,
    run_budget: Arc<AtomicUsize>,
    execution_slots: Arc<Semaphore>,
) -> CrawlerExecutionRecord {
    let processor_sha256 = processor.module_sha256().to_string();
    if run_budget
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(1).filter(|next| *next <= MAX_CRAWLER_PROCESSOR_RUNS)
        })
        .is_err()
    {
        return CrawlerExecutionRecord {
            processor_sha256,
            input_sha256,
            output_sha256: None,
            output_bytes: None,
            output_reference: None,
            execution_ms: 0.0,
            error: Some(format!(
                "crawl-wide processor run limit exceeded ({} runs)",
                MAX_CRAWLER_PROCESSOR_RUNS
            )),
        };
    }
    let _permit = match execution_slots.acquire_owned().await {
        Ok(permit) => permit,
        Err(error) => {
            return CrawlerExecutionRecord {
                processor_sha256,
                input_sha256,
                output_sha256: None,
                output_bytes: None,
                output_reference: None,
                execution_ms: 0.0,
                error: Some(format!("processor admission failed: {error}")),
            };
        }
    };
    let started = Instant::now();
    let processor_for_task = processor.clone();
    let processed = tokio::task::spawn_blocking(move || processor_for_task.execute(&document)).await;
    let execution_ms = started.elapsed().as_secs_f64() * 1000.0;

    let output = match processed {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            return CrawlerExecutionRecord {
                processor_sha256,
                input_sha256,
                output_sha256: None,
                output_bytes: None,
                output_reference: None,
                execution_ms,
                error: Some(error.to_string()),
            };
        }
        Err(error) => {
            return CrawlerExecutionRecord {
                processor_sha256,
                input_sha256,
                output_sha256: None,
                output_bytes: None,
                output_reference: None,
                execution_ms,
                error: Some(format!("processor worker failed: {error}")),
            };
        }
    };

    if output_budget
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current
                .checked_add(output.len())
                .filter(|next| *next <= MAX_CRAWLER_EXECUTION_OUTPUT_BYTES)
        })
        .is_err()
    {
        return CrawlerExecutionRecord {
            processor_sha256,
            input_sha256,
            output_sha256: None,
            output_bytes: None,
            output_reference: None,
            execution_ms,
            error: Some(format!(
                "crawl-wide processor output budget exceeded ({} bytes)",
                MAX_CRAWLER_EXECUTION_OUTPUT_BYTES
            )),
        };
    }

    let output_sha256 = hex_digest(&output);
    let sink_for_task = output_sink.clone();
    let input_for_task = input_sha256.clone();
    let output_digest_for_task = output_sha256.clone();
    let stored = tokio::task::spawn_blocking(move || {
        sink_for_task.store(&input_for_task, &output_digest_for_task, &output)
    })
    .await;
    let (output_reference, error) = match stored {
        Ok(Ok(reference)) => (Some(reference), None),
        Ok(Err(error)) => (None, Some(format!("output sink failed: {error}"))),
        Err(error) => (None, Some(format!("output sink worker failed: {error}"))),
    };

    CrawlerExecutionRecord {
        processor_sha256,
        input_sha256,
        output_sha256: Some(output_sha256),
        output_bytes: Some(output.len() as u64),
        output_reference,
        execution_ms,
        error,
    }
}

fn reserve_crawl_bytes(
    budget: &AtomicUsize,
    max_total_bytes: usize,
    bytes: usize,
) -> Result<(), CrawlerError> {
    budget
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current
                .checked_add(bytes)
                .filter(|next| *next <= max_total_bytes)
        })
        .map(|_| ())
        .map_err(|_| CrawlerError::TotalBytesExceeded)
}

fn validate_config(config: &CrawlerConfig) -> Result<(), CrawlerError> {
    if config.allowed_domains.is_empty() || config.allowed_domains.len() > MAX_ALLOWED_DOMAINS {
        return Err(CrawlerError::InvalidConfig(
            "provide 1..=256 allowed domains".into(),
        ));
    }
    if config.allowed_domains.iter().any(|domain| {
        let value = domain.trim().trim_start_matches('.');
        value.is_empty()
            || value.contains('/')
            || value.contains(':')
            || value.contains('*')
            || value.contains(' ')
    }) {
        return Err(CrawlerError::InvalidConfig(
            "allowed domains must be DNS names without schemes, ports or wildcards".into(),
        ));
    }
    if config.user_agent.trim().is_empty() || config.user_agent.len() > 256 {
        return Err(CrawlerError::InvalidConfig(
            "user-agent must be 1..=256 bytes".into(),
        ));
    }
    if !(1..=128).contains(&config.max_concurrency)
        || config.max_pages == 0
        || config.max_pages > 10_000
        || config.max_depth > 16
        || config.max_page_bytes == 0
        || config.max_page_bytes > MAX_CRAWLER_INPUT_BYTES
        || config.max_total_bytes < config.max_page_bytes
        || config.max_total_bytes > 512 * 1024 * 1024
        || config.max_links_per_page == 0
        || config.max_links_per_page > crate::crawler_wasm::MAX_EXTRACTED_LINKS
        || config.per_domain_delay < Duration::from_millis(100)
        || config.request_timeout < Duration::from_secs(1)
        || config.request_timeout > Duration::from_secs(120)
        || config.wasm_fuel_per_call == 0
    {
        return Err(CrawlerError::InvalidConfig(
            "one or more resource limits are outside their safe range".into(),
        ));
    }
    Ok(())
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => is_public_v4(address),
        IpAddr::V6(address) => is_public_v6(address),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (a == 255 && b == 255 && c == 255 && d == 255)
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 240)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_public_v4(mapped);
    }
    let segments = ip.segments();
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (segments[0] & 0xfe00 == 0xfc00)
        || (segments[0] & 0xffc0 == 0xfe80)
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x2001 && segments[1] <= 0x01ff)
        || segments[0] == 0x2002
        || (segments[0] == 0x3fff && (segments[1] & 0xf000) == 0))
}

fn summarize(records: &[CrawledPage]) -> CrawlMetrics {
    let succeeded = records
        .iter()
        .filter(|record| record.error.is_none())
        .collect::<Vec<_>>();
    let pages_succeeded = succeeded.len();
    let total_document_bytes = succeeded.iter().map(|record| record.document_bytes).sum();
    let total_links = succeeded
        .iter()
        .map(|record| record.links.len() as u64)
        .sum();
    let mean = |values: Vec<f64>| {
        if values.is_empty() {
            0.0
        } else {
            values.iter().sum::<f64>() / values.len() as f64
        }
    };
    CrawlMetrics {
        pages_attempted: records.len(),
        pages_succeeded,
        pages_failed: records.len().saturating_sub(pages_succeeded),
        total_document_bytes,
        total_links,
        mean_document_bytes: if pages_succeeded == 0 {
            0.0
        } else {
            total_document_bytes as f64 / pages_succeeded as f64
        },
        mean_fetch_ms: mean(succeeded.iter().map(|record| record.fetch_ms).collect()),
        mean_extraction_ms: mean(
            succeeded
                .iter()
                .map(|record| record.extraction_ms)
                .collect(),
        ),
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut result = String::with_capacity(digest.len() * 2);
    for byte in digest {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn robots_longest_match_and_allow_override() {
        let policy = parse_robots(
            "User-agent: *\nDisallow: /private\nAllow: /private/public\n",
            "YuKKiOSCrawler/0.1",
        );
        assert!(!policy.is_allowed("/private/account"));
        assert!(policy.is_allowed("/private/public/page"));
        assert!(policy.is_allowed("/public"));
    }

    #[test]
    fn robots_wildcards_and_end_anchor_are_supported() {
        let policy = parse_robots("User-agent: *\nDisallow: /*.pdf$\n", "YuKKiOSCrawler/0.1");
        assert!(!policy.is_allowed("/docs/report.pdf"));
        assert!(policy.is_allowed("/docs/report.pdf?download=1"));
    }

    #[test]
    fn private_and_special_addresses_are_rejected() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "169.254.169.254",
            "192.0.2.1",
            "100.64.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "2001:db8::1",
        ] {
            assert!(
                !is_public_ip(ip.parse().unwrap()),
                "{ip} should be rejected"
            );
        }
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn config_rejects_empty_allowlist_and_excessive_limits() {
        assert!(validate_config(&CrawlerConfig::default()).is_err());
        let mut config = CrawlerConfig::default();
        config.allowed_domains.push("example.com".into());
        config.max_concurrency = 129;
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn crawl_byte_budgets_are_independent_between_crawls() {
        let first_crawl = AtomicUsize::new(0);
        let second_crawl = AtomicUsize::new(0);
        assert!(reserve_crawl_bytes(&first_crawl, 10, 8).is_ok());
        assert!(matches!(
            reserve_crawl_bytes(&first_crawl, 10, 3),
            Err(CrawlerError::TotalBytesExceeded)
        ));
        assert!(reserve_crawl_bytes(&second_crawl, 10, 8).is_ok());
        assert_eq!(first_crawl.load(Ordering::Acquire), 8);
        assert_eq!(second_crawl.load(Ordering::Acquire), 8);
    }

    #[test]
    fn summary_uses_only_successful_pages_for_means() {
        let records = vec![
            CrawledPage {
                url: "https://example.com".into(),
                depth: 0,
                status_code: Some(200),
                fetched_at_unix_ms: 1,
                document_bytes: 100,
                sha256: "a".into(),
                title: "A".into(),
                links: vec!["https://example.com/b".into()],
                fetch_ms: 10.0,
                extraction_ms: 2.0,
                error: None,
            },
            CrawledPage {
                url: "https://example.com/b".into(),
                depth: 1,
                status_code: None,
                fetched_at_unix_ms: 2,
                document_bytes: 0,
                sha256: String::new(),
                title: String::new(),
                links: vec![],
                fetch_ms: 0.0,
                extraction_ms: 0.0,
                error: Some("denied".into()),
            },
        ];
        let metrics = summarize(&records);
        assert_eq!(metrics.pages_attempted, 2);
        assert_eq!(metrics.pages_succeeded, 1);
        assert_eq!(metrics.pages_failed, 1);
        assert_eq!(metrics.total_document_bytes, 100);
        assert_eq!(metrics.total_links, 1);
        assert_eq!(metrics.mean_fetch_ms, 10.0);
    }
}
