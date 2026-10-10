# User How-To: Streaming Binaries and Data

This guide covers the media-chunk, broker, geospatial, and WASM-ingest APIs
provided by YuKKi-OS. See [API.md](API.md) for wire layouts and validation
details.

## Prerequisites: build and start nodes

Build the host node:

```sh
cargo build --release --locked
```

Set a 32-byte pre-shared key as 64 hexadecimal characters. Both the bootstrap
process and every node need the same value:

```sh
export YUKKI_PSK_HEX="$(openssl rand -hex 32)"
```

Start a bootstrap node, then start a node in a separate terminal (export the
same `YUKKI_PSK_HEX` there):

```sh
./target/release/yukki_core_node bootstrap 0.0.0.0:7660
./target/release/yukki_core_node node 127.0.0.1:7660 127.0.0.1:9999
```

The mesh CLI starts the peer nodes; it does not expose the media store as a
network service.

## Stream media and data chunks

`LiveMediaStreams` is a bounded, in-memory store. Open each stream once with a
unique ID and fixed `MediaType`/codec metadata, then ingest chunks in
contiguous sequence order starting at zero. The YKMC v1 format is encoded by
`MediaChunk::encode` and decoded by `MediaChunk::decode`; `ingest_chunk`
decodes and appends an encoded chunk in one call.

```rust,ignore
use yukkios_6_8_0_inet3::{
    LiveMediaStreams, MediaChunk, MediaStreamConfig, MediaStreamMetadata, MediaType,
};

let streams = LiveMediaStreams::new(MediaStreamConfig::default())?;
streams.open_stream(MediaStreamMetadata {
    stream_id: "camera-1".into(),
    media_type: MediaType::Video,
    codec: "h264".into(),
})?;

let chunk = MediaChunk {
    stream_id: "camera-1".into(),
    media_type: MediaType::Video,
    codec: "h264".into(),
    sequence_no: 0,
    timestamp_ms: 0,
    is_keyframe: true,
    payload: encoded_media_bytes,
};
let encoded = chunk.encode()?;
streams.ingest_chunk(&encoded)?;

let first = streams.get_chunk("camera-1", 0)?;
let first = streams.get_range("camera-1", 0, 0)?; // inclusive endpoints
streams.acknowledge_through("camera-1", 0)?; // releases sequence 0
streams.close_stream("camera-1")?;
streams.remove_stream("camera-1")?; // releases remaining retained chunks
```

Ranges have inclusive endpoints and are limited by `max_chunks_per_stream`.
Acknowledgement is also inclusive and only accepts an ingested sequence.
Closing prevents further appends but leaves unacknowledged chunks readable;
removing a stream frees all of its retained chunks.

Default limits are 64 streams, 64 retained chunks per stream, 256 chunks
retained in total, and 256 KiB of payload per chunk. Limits can be lowered
with `MediaStreamConfig`; its maximum chunk size cannot exceed 256 KiB. There
is no automatic eviction. When capacity is full, appends return
`MediaError::Backpressure`; read/consume the retained data and call
`acknowledge_through`, or remove a finished stream, before retrying. Chunks
must use the stream's exact ID, media type, and codec, and their sequence
numbers must be contiguous, without duplicates or gaps.

## Sending chunks and geospatial frames through a broker

The broker adapter carries a `BrokerTask` over raw TCP using a four-byte
big-endian length followed by JSON. Set `YUKKI_BROKER_ENDPOINT` (default
`127.0.0.1:9000`), `YUKKI_BROKER_CONNECT_TIMEOUT_MS` (default 3000),
`YUKKI_BROKER_REQUEST_TIMEOUT_MS` (default 5000),
`YUKKI_BROKER_MAX_FRAME_BYTES` (default 65536), and
`YUKKI_BROKER_TRANSPORT_SECURITY` (`plaintext-boundary` by default, or
`authenticated-proxy`). Timeout values must be in `1..=600000` ms; a task's
`timeout_ms` must be in `1..=300000` ms.

`MediaChunk::to_broker_task` wraps an encoded YKMC chunk in the broker task
JSON. `BrokerClientConfig::from_env` reads the broker environment variables,
and `BrokerClient::submit` sends the task:

```rust,ignore
use yukkios_6_8_0_inet3::{BrokerClient, BrokerClientConfig, MediaChunk};

let task = chunk.to_broker_task("task-1", "camera-1", "broker", 1, 5_000)?;
let client = BrokerClient::with_config(BrokerClientConfig::from_env()?)?;
let result = client.submit(&task).await?;
```

GeoJSON avenues use `ArcGisAvenue::to_broker_task`; NXR1 frames use the
`nxr1::to_broker_task` adapter. Both adapters use the same broker JSON
envelope and `BrokerClient` boundary. An avenue is RFC 7946 GeoJSON, while
NXR1 is a separate binary frame format; neither adapter creates a separate
transport.

The default 64 KiB frame limit applies to the **entire serialized JSON task**,
not just a chunk or frame's raw payload. JSON byte arrays represent each byte
as a decimal number with separators, so the serialized form can be several
times larger than the binary. A 256 KiB media chunk will not fit the default
broker frame limit. Split large binaries into smaller chunks and size them
against the configured frame limit, including the task envelope; raising the
limit is an option only when both broker peers allow it. NXR1's raw payload
limit likewise does not guarantee its complete broker task fits.

## Streaming an arbitrary binary file

There is no dedicated arbitrary-file format or file-transfer service. Treat
the file as opaque payload bytes, split it into chunks no larger than
`MEDIA_MAX_CHUNK_BYTES`, and assign increasing sequence numbers from zero.
`MediaType` itself only has `Audio` and `Video`; it does not inspect the
payload. A codec label such as `application/octet-stream` is valid (non-empty
and at most 64 UTF-8 bytes), provided sender and receiver agree on it.
`MediaChunk` validates metadata and size, but does not transcode or otherwise
interpret the bytes.

```rust,ignore
use std::fs;
use sha2::{Digest, Sha256};
use yukkios_6_8_0_inet3::{MediaChunk, MediaType, MEDIA_MAX_CHUNK_BYTES};

let file = fs::read("input.bin")?;
let sha256 = Sha256::digest(&file); // send/compare this digest out of band
let chunks: Vec<MediaChunk> = file
    .chunks(MEDIA_MAX_CHUNK_BYTES)
    .enumerate()
    .map(|(index, payload)| MediaChunk {
        stream_id: "file-42".into(),
        media_type: MediaType::Video, // required tag; payload remains opaque
        codec: "application/octet-stream".into(),
        sequence_no: index as u64,
        timestamp_ms: index as u64,
        is_keyframe: false,
        payload: payload.to_vec(),
    })
    .collect();

// After receiving, read chunks by sequence number and append their payloads
// in order, then compare Sha256::digest(&reassembled) with `sha256`.
```

For every chunk, verify the stream ID and codec and preserve its sequence
number. Reassemble in sequence order, then compare a SHA-256 digest with a
digest transferred through a separate trusted channel. An empty file produces
no chunks, so communicate its existence/length separately.

## Deploy a WASM binary

The host exposes `wasm_ingest::handle_deploy`, a request handler for
`POST /v1/sandbox/deploy`; it is not an HTTP server. An integrating server
must authenticate the caller before passing the request content type,
`X-YuKKi-Channel-Id` header, body, and its `XpuHandler` to `handle_deploy`.
The body must be a valid WASM module of at most 4 MiB, with the allowed
`env.wasmtime_yield_xpu` import and required exports. The handler validates
the module and smoke-runs it with a small test tensor.

The repository ships no HTTP server or authentication layer. Do not expose
this handler on an unauthenticated endpoint.

## Limitations and security

- `LiveMediaStreams` is in-process memory only; it has no built-in network
  transport or persistence.
- Media payloads are passed through unchanged; there is no transcoding.
- Peer mesh and broker links do not provide built-in TLS. Broker
  `authenticated-proxy` configuration is documentary metadata, not TLS
  enablement.
- These APIs are part of research/demo software, not a production-ready
  streaming service.
