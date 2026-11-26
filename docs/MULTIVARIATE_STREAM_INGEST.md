# Bounded multivariate stream ingestion

YuKKi-OS exports `stream_observation::NdjsonObservationDecoder` for
incremental ingestion of untrusted newline-delimited JSON numeric observations.
The decoder is a bounded parsing primitive, not a network client or an
authorization mechanism. Existing crawler source allowlists, DNS/egress
controls, tenant admission and stream backpressure remain in force.

## Version 1 observation record

```json
{"schema_version":1,"source_id":"sensor-a","sequence":42,"timestamp_unix_ms":1730000000000,"values":[12.5,null,0.75]}
```

- `schema_version` must be 1.
- `source_id` is required and limited to 128 UTF-8 bytes.
- `sequence` and `timestamp_unix_ms` are unsigned 64-bit integers.
- `values` contains 1–32 numeric dimensions.
- `null` represents a missing dimension; it is not zero.
- NaN and infinities are rejected by the JSON number parser and finite-value
  validation.
- Unknown fields are rejected to avoid silently accepting contract drift.

## Incremental use

```rust
use yukkios::stream_observation::{
    NdjsonObservationDecoder, ObservationDecoderConfig,
};

let mut decoder = NdjsonObservationDecoder::new(ObservationDecoderConfig::default())?;
for chunk in incoming_chunks {
    let observations = decoder.push(chunk)?;
    // Apply per-source/tenant quotas, then forward bounded batches.
}
if let Some(last) = decoder.finish()? {
    // Process the final line when the stream closes.
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

The decoder retains at most one incomplete line (16 KiB by default), emits at
most 256 complete records per push, and returns completed records to the
caller immediately. Callers should cap incoming chunk sizes and apply bounded
queues/backpressure around the decoder. Parsing does not authorize execution:
records remain data, including when their source is untrusted.

## Aggregation handoff

Normalize observations without dropping source identity, sequence, timestamp,
or missing-value masks. The paired Overhauled library
`Overhauled::multivariate_stats` accepts up to 32 numeric dimensions using a
presence bit mask and performs bounded-memory pairwise covariance/correlation
aggregation. Pair counts must accompany matrix values because missing
dimensions can make sample counts differ by pair.

This parser currently provides the versioned ingestion contract and
incremental decoding API. It does not itself open arbitrary streaming
connections or silently broaden the HTML crawler's network policy.
