//! Bounded decoder for untrusted multivariate NDJSON streams.
//!
//! This module only parses numeric observations. It does not execute payloads,
//! fetch URLs, or authorize sources. Callers must apply their own source and
//! tenant admission policy before forwarding observations.

use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};
use thiserror::Error;

pub const OBSERVATION_SCHEMA_VERSION: u16 = 1;
pub const MAX_OBSERVATION_DIMENSIONS: usize = 32;
pub const MAX_OBSERVATION_SOURCE_ID_BYTES: usize = 128;
pub const DEFAULT_MAX_RECORD_BYTES: usize = 16 * 1024;
pub const DEFAULT_MAX_RECORDS_PER_PUSH: usize = 256;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MultivariateObservation {
    pub schema_version: u16,
    pub source_id: String,
    pub sequence: u64,
    pub timestamp_unix_ms: u64,
    /// Missing dimensions remain None; they are never coerced to zero.
    pub values: Vec<Option<f64>>,
}

#[derive(Debug, Error)]
pub enum ObservationDecodeError {
    #[error("record exceeds configured byte limit")]
    RecordTooLarge,
    #[error("push contains too many complete records")]
    TooManyRecords,
    #[error("observation JSON is invalid: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("unsupported observation schema version {0}")]
    UnsupportedVersion(u16),
    #[error("source_id must contain 1..={MAX_OBSERVATION_SOURCE_ID_BYTES} bytes")]
    InvalidSourceId,
    #[error("observation must contain 1..={MAX_OBSERVATION_DIMENSIONS} dimensions")]
    InvalidDimensions,
    #[error("observation contains a non-finite numeric value")]
    NonFiniteValue,
    #[error("decoder has an incomplete record; call finish only at end of stream")]
    IncompleteRecord,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireObservation {
    schema_version: u16,
    source_id: String,
    sequence: u64,
    timestamp_unix_ms: u64,
    values: Vec<Option<f64>>,
}

#[derive(Debug, Clone)]
pub struct ObservationDecoderConfig {
    pub max_record_bytes: usize,
    pub max_records_per_push: usize,
}

impl Default for ObservationDecoderConfig {
    fn default() -> Self {
        Self {
            max_record_bytes: DEFAULT_MAX_RECORD_BYTES,
            max_records_per_push: DEFAULT_MAX_RECORDS_PER_PUSH,
        }
    }
}

/// Incremental NDJSON decoder. The only retained input is one bounded,
/// incomplete line. Completed records are returned to the caller immediately.
pub struct NdjsonObservationDecoder {
    config: ObservationDecoderConfig,
    pending: Vec<u8>,
}

impl NdjsonObservationDecoder {
    pub fn new(config: ObservationDecoderConfig) -> Result<Self, ObservationDecodeError> {
        if config.max_record_bytes == 0 || config.max_records_per_push == 0 {
            return Err(ObservationDecodeError::RecordTooLarge);
        }
        Ok(Self {
            config,
            pending: Vec::new(),
        })
    }

    pub fn push(
        &mut self,
        chunk: &[u8],
    ) -> Result<Vec<MultivariateObservation>, ObservationDecodeError> {
        // Preflight the chunk so a record-count overflow cannot consume earlier
        // records and then return an error with those observations lost.
        if chunk.iter().filter(|byte| **byte == b'\n').count() > self.config.max_records_per_push {
            return Err(ObservationDecodeError::TooManyRecords);
        }
        let mut output = Vec::new();
        let mut start = 0usize;

        for (index, byte) in chunk.iter().enumerate() {
            if *byte != b'\n' {
                continue;
            }
            let segment = &chunk[start..index];
            if self.pending.len().saturating_add(segment.len()) > self.config.max_record_bytes {
                return Err(ObservationDecodeError::RecordTooLarge);
            }
            self.pending.extend_from_slice(segment);
            if self.pending.last() == Some(&b'\r') {
                self.pending.pop();
            }
            if !self.pending.is_empty() {
                if output.len() >= self.config.max_records_per_push {
                    return Err(ObservationDecodeError::TooManyRecords);
                }
                output.push(decode_record(&self.pending)?);
            }
            self.pending.clear();
            start = index + 1;
        }

        let tail = &chunk[start..];
        if self.pending.len().saturating_add(tail.len()) > self.config.max_record_bytes {
            return Err(ObservationDecodeError::RecordTooLarge);
        }
        self.pending.extend_from_slice(tail);
        Ok(output)
    }

    /// Decode the final unterminated line at end-of-stream.
    pub fn finish(&mut self) -> Result<Option<MultivariateObservation>, ObservationDecodeError> {
        if self.pending.is_empty() {
            return Ok(None);
        }
        let record = decode_record(&self.pending)?;
        self.pending.clear();
        Ok(Some(record))
    }

    pub fn pending_bytes(&self) -> usize {
        self.pending.len()
    }
}

fn decode_record(bytes: &[u8]) -> Result<MultivariateObservation, ObservationDecodeError> {
    let wire: WireObservation = serde_json::from_slice(bytes)?;
    if wire.schema_version != OBSERVATION_SCHEMA_VERSION {
        return Err(ObservationDecodeError::UnsupportedVersion(
            wire.schema_version,
        ));
    }
    if wire.source_id.is_empty() || wire.source_id.len() > MAX_OBSERVATION_SOURCE_ID_BYTES {
        return Err(ObservationDecodeError::InvalidSourceId);
    }
    if wire.values.is_empty() || wire.values.len() > MAX_OBSERVATION_DIMENSIONS {
        return Err(ObservationDecodeError::InvalidDimensions);
    }
    if wire.values.iter().flatten().any(|value| !value.is_finite()) {
        return Err(ObservationDecodeError::NonFiniteValue);
    }
    Ok(MultivariateObservation {
        schema_version: wire.schema_version,
        source_id: wire.source_id,
        sequence: wire.sequence,
        timestamp_unix_ms: wire.timestamp_unix_ms,
        values: wire.values,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ObservationDecoderConfig {
        ObservationDecoderConfig {
            max_record_bytes: 256,
            max_records_per_push: 2,
        }
    }

    #[test]
    fn decodes_chunked_records_and_preserves_missing_values() {
        let mut decoder = NdjsonObservationDecoder::new(config()).unwrap();
        let first = br#"{"schema_version":1,"source_id":"sensor-a","sequence":7,"timestamp_unix_ms":1000,"values":[1.5,null,3.0]}"#;
        assert!(decoder.push(&first[..20]).unwrap().is_empty());
        let mut tail = first[20..].to_vec();
        tail.push(b'\n');
        tail.extend_from_slice(br#"{"schema_version":1,"source_id":"sensor-a","sequence":8,"timestamp_unix_ms":1100,"values":[2.5,4.0]}"#);
        let decoded = decoder.push(&tail).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].values, vec![Some(1.5), None, Some(3.0)]);
        let last = decoder.finish().unwrap().unwrap();
        assert_eq!(last.sequence, 8);
        assert_eq!(last.values, vec![Some(2.5), Some(4.0)]);
    }

    #[test]
    fn rejects_oversized_partial_record() {
        let mut decoder = NdjsonObservationDecoder::new(config()).unwrap();
        assert!(matches!(
            decoder.push(&[b'x'; 257]),
            Err(ObservationDecodeError::RecordTooLarge)
        ));
        assert!(decoder.pending_bytes() <= 256);
    }

    #[test]
    fn rejects_unknown_versions_and_dimensions() {
        let mut version_decoder = NdjsonObservationDecoder::new(config()).unwrap();
        let unknown = br#"{"schema_version":2,"source_id":"s","sequence":1,"timestamp_unix_ms":1,"values":[1]}"#;
        assert!(version_decoder.push(unknown).unwrap().is_empty());
        assert!(matches!(
            version_decoder.finish(),
            Err(ObservationDecodeError::UnsupportedVersion(2))
        ));

        // A final NDJSON record may omit its trailing newline. It is validated
        // at end-of-stream by finish(), not during push().
        let mut dimensions_decoder = NdjsonObservationDecoder::new(config()).unwrap();
        let oversized = format!(
            r#"{{"schema_version":1,"source_id":"s","sequence":1,"timestamp_unix_ms":1,"values":[{}]}}"#,
            vec!["1"; 33].join(",")
        );
        assert!(dimensions_decoder
            .push(oversized.as_bytes())
            .unwrap()
            .is_empty());
        assert!(matches!(
            dimensions_decoder.finish(),
            Err(ObservationDecodeError::InvalidDimensions)
        ));
    }
}


pub const MAX_DATA_STREAMS: usize = 128;
pub const MAX_DATA_STREAM_OBSERVATIONS_PER_STREAM: usize = 512;
pub const MAX_DATA_STREAM_OBSERVATIONS_TOTAL: usize = 16_384;
pub const MAX_DATA_STREAM_INGEST_RECORDS: usize = 64;
pub const MAX_DATA_STREAM_INGEST_BYTES: usize = 1024 * 1024;
pub const MAX_DATA_STREAM_READ_RECORDS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DataStreamDescriptor {
    pub source_id: String,
    pub retained_observations: usize,
    pub dimensions: usize,
    pub first_retained_sequence: Option<u64>,
    pub latest_sequence: Option<u64>,
    pub updated_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DataStreamRange {
    pub source_id: String,
    pub first_retained_sequence: Option<u64>,
    pub latest_sequence: Option<u64>,
    pub records: Vec<MultivariateObservation>,
}

#[derive(Debug, Error)]
pub enum ObservationStoreError {
    #[error("observation batch exceeds the configured byte limit")]
    BatchTooLarge,
    #[error("observation batch is empty")]
    EmptyBatch,
    #[error("observation batch contains too many records")]
    TooManyRecords,
    #[error("observation source ID does not match the target data stream")]
    SourceMismatch,
    #[error("observation dimensions changed within a data stream")]
    DimensionsChanged,
    #[error("observation sequence numbers must increase strictly")]
    SequenceNotIncreasing,
    #[error("data stream capacity reached")]
    StreamLimit,
    #[error("data stream was not found")]
    StreamNotFound,
    #[error("data stream read limit must be 1..={MAX_DATA_STREAM_READ_RECORDS}")]
    InvalidReadLimit,
    #[error(transparent)]
    Decode(#[from] ObservationDecodeError),
}

struct StoredObservationStream {
    records: VecDeque<MultivariateObservation>,
    dimensions: usize,
    latest_sequence: u64,
    updated_at_unix_ms: u64,
}

#[derive(Default)]
struct ObservationStoreState {
    streams: HashMap<String, StoredObservationStream>,
    total_records: usize,
}

/// Bounded, in-memory retention for validated multivariate data streams.
/// This is separate from the YKMC media store: data observations do not
/// masquerade as audio/video chunks and are never decoded as media.
#[derive(Clone, Default)]
pub struct ObservationStore {
    state: Arc<Mutex<ObservationStoreState>>,
}

impl ObservationStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate and append one bounded schema-v1 NDJSON batch. All records
    /// are validated before the store is mutated, so malformed batches are
    /// rejected atomically.
    pub fn ingest_ndjson(
        &self,
        source_id: &str,
        bytes: &[u8],
    ) -> Result<DataStreamDescriptor, ObservationStoreError> {
        if bytes.len() > MAX_DATA_STREAM_INGEST_BYTES {
            return Err(ObservationStoreError::BatchTooLarge);
        }
        if source_id.is_empty() || source_id.len() > MAX_OBSERVATION_SOURCE_ID_BYTES {
            return Err(ObservationStoreError::SourceMismatch);
        }

        let mut decoder = NdjsonObservationDecoder::new(ObservationDecoderConfig {
            max_record_bytes: DEFAULT_MAX_RECORD_BYTES,
            max_records_per_push: MAX_DATA_STREAM_INGEST_RECORDS,
        })?;
        let mut records = decoder.push(bytes)?;
        if let Some(last) = decoder.finish()? {
            records.push(last);
        }
        if records.is_empty() {
            return Err(ObservationStoreError::EmptyBatch);
        }
        if records.len() > MAX_DATA_STREAM_INGEST_RECORDS {
            return Err(ObservationStoreError::TooManyRecords);
        }
        if records.iter().any(|record| record.source_id != source_id) {
            return Err(ObservationStoreError::SourceMismatch);
        }
        let dimensions = records[0].values.len();
        if records.iter().any(|record| record.values.len() != dimensions) {
            return Err(ObservationStoreError::DimensionsChanged);
        }
        if records
            .windows(2)
            .any(|pair| pair[0].sequence >= pair[1].sequence)
        {
            return Err(ObservationStoreError::SequenceNotIncreasing);
        }

        let mut state = self
            .state
            .lock()
            .map_err(|_| ObservationStoreError::StreamLimit)?;
        if !state.streams.contains_key(source_id) && state.streams.len() >= MAX_DATA_STREAMS {
            return Err(ObservationStoreError::StreamLimit);
        }
        if let Some(existing) = state.streams.get(source_id) {
            if existing.dimensions != dimensions {
                return Err(ObservationStoreError::DimensionsChanged);
            }
            if records[0].sequence <= existing.latest_sequence {
                return Err(ObservationStoreError::SequenceNotIncreasing);
            }
        }

        for record in records {
            let record_sequence = record.sequence;
            let record_timestamp = record.timestamp_unix_ms;
            let evicted_per_stream = {
                let stream = state
                    .streams
                    .entry(source_id.to_owned())
                    .or_insert_with(|| StoredObservationStream {
                        records: VecDeque::new(),
                        dimensions,
                        latest_sequence: record_sequence,
                        updated_at_unix_ms: record_timestamp,
                    });
                stream.latest_sequence = record_sequence;
                stream.updated_at_unix_ms = record_timestamp;
                stream.records.push_back(record);
                if stream.records.len() > MAX_DATA_STREAM_OBSERVATIONS_PER_STREAM {
                    stream.records.pop_front().is_some()
                } else {
                    false
                }
            };
            state.total_records += 1;
            if evicted_per_stream {
                state.total_records = state.total_records.saturating_sub(1);
            }
            while state.total_records > MAX_DATA_STREAM_OBSERVATIONS_TOTAL {
                let oldest_source = state
                    .streams
                    .iter()
                    .filter_map(|(id, stream)| {
                        stream
                            .records
                            .front()
                            .map(|record| (id.clone(), record.timestamp_unix_ms))
                    })
                    .min_by_key(|(_, timestamp)| *timestamp)
                    .map(|(id, _)| id);
                let Some(oldest_source) = oldest_source else {
                    state.total_records = 0;
                    break;
                };
                let removed = state
                    .streams
                    .get_mut(&oldest_source)
                    .and_then(|stream| stream.records.pop_front())
                    .is_some();
                if removed {
                    state.total_records = state.total_records.saturating_sub(1);
                } else {
                    break;
                }
            }
        }

        let stream = state
            .streams
            .get(source_id)
            .ok_or(ObservationStoreError::StreamNotFound)?;
        Ok(describe_observation_stream(source_id, stream))
    }

    pub fn list(&self) -> Result<Vec<DataStreamDescriptor>, ObservationStoreError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ObservationStoreError::StreamLimit)?;
        let mut streams = state
            .streams
            .iter()
            .map(|(source_id, stream)| describe_observation_stream(source_id, stream))
            .collect::<Vec<_>>();
        streams.sort_by(|left, right| left.source_id.cmp(&right.source_id));
        Ok(streams)
    }

    pub fn read(
        &self,
        source_id: &str,
        from_sequence: u64,
        limit: usize,
    ) -> Result<DataStreamRange, ObservationStoreError> {
        if limit == 0 || limit > MAX_DATA_STREAM_READ_RECORDS {
            return Err(ObservationStoreError::InvalidReadLimit);
        }
        let state = self
            .state
            .lock()
            .map_err(|_| ObservationStoreError::StreamLimit)?;
        let stream = state
            .streams
            .get(source_id)
            .ok_or(ObservationStoreError::StreamNotFound)?;
        let records = stream
            .records
            .iter()
            .filter(|record| record.sequence >= from_sequence)
            .take(limit)
            .cloned()
            .collect();
        Ok(DataStreamRange {
            source_id: source_id.to_owned(),
            first_retained_sequence: stream.records.front().map(|record| record.sequence),
            latest_sequence: Some(stream.latest_sequence),
            records,
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Error)]
pub enum ObservationPublishError {
    #[error("control-plane target URL must be HTTPS, or HTTP on localhost, without credentials, query, or fragment")]
    InvalidTarget,
    #[error("control-plane bearer token must contain 1..=4096 bytes")]
    InvalidToken,
    #[error("observation batch is invalid or exceeds its record/byte limits")]
    InvalidBatch,
    #[error("could not encode observation batch: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("control-plane request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("control-plane rejected observation batch with HTTP {0}")]
    HttpStatus(u16),
}

/// Publish one explicitly selected batch to the authenticated data-stream
/// ingress API. Redirects are disabled so the bearer token cannot be forwarded
/// to another origin. The function never sends page HTML or arbitrary payloads.
#[cfg(not(target_arch = "wasm32"))]
pub async fn publish_observation_batch(
    gateway_base: &str,
    bearer_token: &str,
    source_id: &str,
    records: &[MultivariateObservation],
) -> Result<(), ObservationPublishError> {
    use std::net::IpAddr;
    use std::time::Duration;

    if bearer_token.is_empty() || bearer_token.len() > 4096 {
        return Err(ObservationPublishError::InvalidToken);
    }
    let safe_source = !source_id.is_empty()
        && source_id.len() <= MAX_OBSERVATION_SOURCE_ID_BYTES
        && source_id != "."
        && source_id != ".."
        && source_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !safe_source
        || records.is_empty()
        || records.len() > MAX_DATA_STREAM_INGEST_RECORDS
        || records.iter().any(|record| {
            record.schema_version != OBSERVATION_SCHEMA_VERSION
                || record.source_id != source_id
                || record.values.is_empty()
                || record.values.len() > MAX_OBSERVATION_DIMENSIONS
                || record.values.iter().flatten().any(|value| !value.is_finite())
        })
        || records.windows(2).any(|pair| pair[0].sequence >= pair[1].sequence)
    {
        return Err(ObservationPublishError::InvalidBatch);
    }

    let mut base = reqwest::Url::parse(gateway_base)
        .map_err(|_| ObservationPublishError::InvalidTarget)?;
    let host = base.host_str().ok_or(ObservationPublishError::InvalidTarget)?;
    let local_host = host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|address| address.is_loopback());
    if (base.scheme() != "https" && !(base.scheme() == "http" && local_host))
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return Err(ObservationPublishError::InvalidTarget);
    }

    let mut body = Vec::new();
    for record in records {
        serde_json::to_writer(&mut body, record)?;
        body.push(b'\n');
        if body.len() > MAX_DATA_STREAM_INGEST_BYTES {
            return Err(ObservationPublishError::InvalidBatch);
        }
    }
    let prefix = base.path().trim_end_matches('/');
    base.set_path(&format!(
        "{prefix}/v1/data-streams/{source_id}/observations"
    ));

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build()?;
    let response = client
        .post(base)
        .bearer_auth(bearer_token)
        .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
        .body(body)
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(ObservationPublishError::HttpStatus(
            response.status().as_u16(),
        ));
    }
    Ok(())
}

fn describe_observation_stream(
    source_id: &str,
    stream: &StoredObservationStream,
) -> DataStreamDescriptor {
    DataStreamDescriptor {
        source_id: source_id.to_owned(),
        retained_observations: stream.records.len(),
        dimensions: stream.dimensions,
        first_retained_sequence: stream.records.front().map(|record| record.sequence),
        latest_sequence: Some(stream.latest_sequence),
        updated_at_unix_ms: stream.updated_at_unix_ms,
    }
}
