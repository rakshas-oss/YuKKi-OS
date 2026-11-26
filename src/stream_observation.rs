//! Bounded decoder for untrusted multivariate NDJSON streams.
//!
//! This module only parses numeric observations. It does not execute payloads,
//! fetch URLs, or authorize sources. Callers must apply their own source and
//! tenant admission policy before forwarding observations.

use serde::Deserialize;
use thiserror::Error;

pub const OBSERVATION_SCHEMA_VERSION: u16 = 1;
pub const MAX_OBSERVATION_DIMENSIONS: usize = 32;
pub const MAX_OBSERVATION_SOURCE_ID_BYTES: usize = 128;
pub const DEFAULT_MAX_RECORD_BYTES: usize = 16 * 1024;
pub const DEFAULT_MAX_RECORDS_PER_PUSH: usize = 256;

#[derive(Debug, Clone, PartialEq)]
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
        Ok(Self { config, pending: Vec::new() })
    }

    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<MultivariateObservation>, ObservationDecodeError> {
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
            if self.pending.last() == Some(&b'\\r') {
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
        return Err(ObservationDecodeError::UnsupportedVersion(wire.schema_version));
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
        ObservationDecoderConfig { max_record_bytes: 256, max_records_per_push: 2 }
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
        assert!(matches!(decoder.push(&[b'x'; 257]), Err(ObservationDecodeError::RecordTooLarge)));
        assert!(decoder.pending_bytes() <= 256);
    }

    #[test]
    fn rejects_unknown_versions_and_dimensions() {
        let mut decoder = NdjsonObservationDecoder::new(config()).unwrap();
        let unknown = br#"{"schema_version":2,"source_id":"s","sequence":1,"timestamp_unix_ms":1,"values":[1]}"#;
        assert!(matches!(decoder.push(unknown).unwrap(), _));
        assert!(matches!(decoder.finish(), Err(ObservationDecodeError::UnsupportedVersion(2))));
        let oversized = format!(r#"{{"schema_version":1,"source_id":"s","sequence":1,"timestamp_unix_ms":1,"values":[{}]}}"#, vec!["1"; 33].join(","));
        assert!(matches!(decoder.push(oversized.as_bytes()), Err(ObservationDecodeError::InvalidDimensions)));
    }
}
