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

## Authenticated control-plane data streams

The native stream gateway optionally exposes a bounded observation store
separate from media chunks:

- `GET /v1/data-streams` lists retained descriptors.
- `GET /v1/data-streams/{source_id}/observations?from={sequence}&limit={n}`
  reads 1–128 retained observations.
- `POST /v1/data-streams/{source_id}/observations` accepts schema-v1 NDJSON
  with `application/x-ndjson` or `application/ndjson`, under the existing
  gateway bearer authentication and flood/egress limits.

Ingest batches are limited to 64 records and 1 MiB. The in-memory store is
limited to 128 source streams, 512 retained observations per stream, and
16,384 observations total. Sequence numbers must increase strictly and a
stream's dimension count cannot change. Invalid batches are rejected before
store mutation. This initial store is node-local and not persisted or
replicated through the peer mesh.

The native browser crawler can opt in to publishing metrics by reusing the
node's existing `YUKKI_GATEWAY_TOKEN` and local gateway address. It sends a
nine-dimensional record per completed page, batched in groups of 16:
`[depth, http_status, document_bytes, fetch_ms, extraction_ms, link_count,
title_chars, preview_chars, failed]`. The status dimension is null when a
fetch has no HTTP response. No URL, title, page text, or raw HTML is published.
The browser-WASM dashboard discovers these streams separately from media and
runs each adopted record through its Rust WASM validator.

