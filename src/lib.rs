//! YuKKi OS v6.9.0 — Library Interface (Inet3 Edition)
//! Exports core modules for testing and external use

pub mod adi_auto_tune;
pub mod arcgis;
pub mod broker_client;
pub mod gpu_adapter;
pub mod media_codec;
pub mod nxr1;
pub mod wasm_ingest;
pub mod wasm_sandbox;

pub use broker_client::{
    BrokerClient, BrokerClientConfig, BrokerClientError, BrokerResult, BrokerTask,
    BrokerTransportSecurity, DEFAULT_BROKER_CONNECT_TIMEOUT, DEFAULT_BROKER_ENDPOINT,
    DEFAULT_BROKER_MAX_FRAME_BYTES, DEFAULT_BROKER_REQUEST_TIMEOUT, MAX_CONFIG_TIMEOUT,
    MAX_TASK_TIMEOUT_MS, MIN_TASK_TIMEOUT_MS,
};

pub use gpu_adapter::{
    decode_brk1_frame, decode_wsm1_message, encode_brk1_frame,
    encode_wsm1_lifecycle_request, encode_wsm1_lifecycle_response,
    encode_wsm1_task_request, encode_wsm1_task_response,
    Brk1Frame, BrokerMessage, BrokerTaskError, BufferAccess, BufferDescriptor, BufferKind,
    CancelTaskRequest, CancelTaskResponse, GpuAdapterConfig, GpuAdapterError, GpuBrokerClient,
    GpuTaskRequest, GpuTaskResponse, GpuTaskStatus, LifecycleClient, LifecycleWireMode,
    ModuleLifecycleManager, ModuleLifecycleState, ModuleVersionHandle, ModuleVersionResources,
    ProtocolHandshakeRequest, ProtocolHandshakeResponse, StateHandoffHook,
    WasmBufferDescriptor, WasmLifecycleAction, WasmLifecycleRequest, WasmLifecycleResponse,
    WasmLifecycleState, WasmLifecycleStatus, WasmTaskRequest, WasmTaskResponse, WasmTaskStatus,
    Wsm1Message, BRK1_MAGIC, BRK1_MSG_REQUEST, BRK1_MSG_RESPONSE, BRK1_PROTOCOL_VERSION,
    CURRENT_PROTOCOL_VERSION, DEFAULT_GPU_BROKER_ENDPOINT, DEFAULT_GPU_CONNECT_TIMEOUT,
    DEFAULT_GPU_MAX_FRAME_BYTES, DEFAULT_GPU_MAX_RETRIES, DEFAULT_GPU_QUIESCE_TIMEOUT,
    DEFAULT_GPU_REQUEST_TIMEOUT, DEFAULT_GPU_RETRY_BACKOFF, SUPPORTED_PROTOCOL_VERSIONS,
    WSM1_MAGIC, WSM1_PROTOCOL_VERSION,
};

pub use nxr1::{
    from_broker_task, to_broker_task, Nxr1Error, Nxr1Frame, GEOSPATIAL_FRAME_KIND, NXR1_HEADER_LEN,
    NXR1_MAGIC, NXR1_MAX_PAYLOAD_BYTES, NXR1_VERSION,
};

pub use arcgis::{
    ArcGisAvenue, ArcGisError, Wgs84Coordinate, ARCGIS_AVENUE_BROKER_KEY, ARCGIS_AVENUE_KIND,
    ARCGIS_AVENUE_MAX_BYTES, ARCGIS_AVENUE_MAX_COORDINATES,
};

pub use media_codec::{
    LiveMediaStreams, MediaChunk, MediaError, MediaStreamConfig, MediaStreamMetadata, MediaType,
    MEDIA_CHUNK_BROKER_KEY, MEDIA_CHUNK_HEADER_LEN, MEDIA_CHUNK_KIND, MEDIA_CHUNK_MAGIC,
    MEDIA_CHUNK_VERSION, MEDIA_MAX_CHUNK_BYTES, MEDIA_MAX_CODEC_BYTES, MEDIA_MAX_STREAM_ID_BYTES,
};

use std::marker::PhantomData;

#[repr(C, packed(8))]
#[derive(Debug, Clone, Copy)]
pub struct SpatiotemporalFrame {
    pub seq_id: u64,
    pub x: f64,
    pub y: f64,
    pub z: f64,
    pub u: f64,
    pub v: f64,
    pub w: f64,
    pub fluidity: f32,
    pub drag: f32,
    pub divergence: f64,
    pub payload: [u8; 16],
}

/// FFI-safe marker for null pointer checks
pub struct FFISafetyMarker {
    _phantom: PhantomData<()>,
}

impl FFISafetyMarker {
    pub fn verify_non_null<T>(ptr: *const T) -> bool {
        !ptr.is_null()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spatiotemporal_frame_layout() {
        assert_eq!(std::mem::size_of::<SpatiotemporalFrame>(), 88);
    }
}
