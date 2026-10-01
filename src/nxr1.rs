//! NXR1 — Neuraxis geospatial frame interoperability codec.
//!
//! This module implements the wire format used to exchange
//! `geospatial.frame.v1` messages with the `overhauled` broker/service. It is
//! a thin, dependency-free binary codec plus an adapter that lets a decoded
//! frame travel over the existing [`crate::broker_client`] JSON transport —
//! YuKKi-OS does not run a second, parallel TCP protocol for this message
//! kind.
//!
//! ## Wire format (NXR1)
//!
//! All multi-byte integers and floats are big-endian. The frame has a fixed
//! 81-byte header followed by an opaque, length-prefixed payload:
//!
//! | Field        | Type        | Bytes |
//! |--------------|-------------|-------|
//! | magic        | `u32`       | 4     |
//! | version      | `u8`        | 1     |
//! | seq_id       | `u64`       | 8     |
//! | x            | `f64`       | 8     |
//! | y            | `f64`       | 8     |
//! | z            | `f64`       | 8     |
//! | u            | `f64`       | 8     |
//! | v            | `f64`       | 8     |
//! | w            | `f64`       | 8     |
//! | fluidity     | `f32`       | 4     |
//! | drag         | `f32`       | 4     |
//! | divergence   | `f64`       | 8     |
//! | payload_len  | `u32`       | 4     |
//! | payload      | `[u8; N]`   | N     |
//!
//! `magic` must equal `0x4E58_5231` (ASCII `"NXR1"`) and `version` must equal
//! `1`. All float fields must be finite (no `NaN`/`±Infinity`). The decoded
//! byte slice must contain exactly `81 + payload_len` bytes — neither
//! truncated nor followed by trailing bytes.
//!
//! ## Broker adapter
//!
//! [`to_broker_task`] and [`from_broker_task`] convert between an
//! [`Nxr1Frame`] and the existing [`crate::broker_client::BrokerTask`]
//! envelope, tagging the request with `kind = "geospatial.frame.v1"` and
//! carrying the encoded NXR1 bytes as a JSON array under the `nxr1` payload
//! key. This reuses the broker's existing 4-byte length-prefixed JSON
//! transport ([`crate::broker_client::BrokerClient`]) rather than inventing a
//! second, conflicting binary transport — see
//! `docs/API.md` for the integration point and
//! `tests/test_nxr1.rs` for end-to-end examples.

use thiserror::Error;

use crate::broker_client::{BrokerClientError, BrokerTask};

/// ASCII `"NXR1"` interpreted as a big-endian `u32`.
pub const NXR1_MAGIC: u32 = 0x4E58_5231;

/// The only wire version currently understood.
pub const NXR1_VERSION: u8 = 1;

/// Size, in bytes, of the fixed NXR1 header (everything before the opaque
/// payload bytes).
pub const NXR1_HEADER_LEN: usize = 4 + 1 + 8 + (8 * 6) + 4 + 4 + 8 + 4;

/// Upper bound on the opaque payload carried inside an NXR1 frame. This
/// mirrors the broker's own frame ceiling
/// ([`crate::broker_client::DEFAULT_BROKER_MAX_FRAME_BYTES`]) so a decoded
/// frame can never be forwarded as a broker task that the broker would
/// itself reject as oversized.
pub const NXR1_MAX_PAYLOAD_BYTES: usize = crate::broker_client::DEFAULT_BROKER_MAX_FRAME_BYTES;

// payload_len is transmitted on the wire as a u32, so the configured max
// must always fit; this is checked at compile time rather than on every
// call to `Nxr1Frame::encode`.
const _NXR1_MAX_PAYLOAD_BYTES_FITS_U32: () = assert!(NXR1_MAX_PAYLOAD_BYTES <= u32::MAX as usize);

/// Message kind used for `geospatial.frame.v1` interoperability traffic.
pub const GEOSPATIAL_FRAME_KIND: &str = "geospatial.frame.v1";

/// JSON payload key used to carry encoded NXR1 bytes inside a
/// [`BrokerTask::payload`].
const BROKER_PAYLOAD_KEY: &str = "nxr1";

/// A decoded NXR1 geospatial frame.
#[derive(Debug, Clone, PartialEq)]
pub struct Nxr1Frame {
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
    pub payload: Vec<u8>,
}

/// Errors produced while encoding or decoding an NXR1 frame, or while
/// adapting it to/from the broker envelope.
#[derive(Debug, Error)]
pub enum Nxr1Error {
    #[error("NXR1 frame is truncated: expected at least {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },
    #[error("NXR1 frame has {actual} trailing byte(s) beyond the expected {expected} bytes")]
    TrailingBytes { expected: usize, actual: usize },
    #[error("invalid NXR1 magic: expected {expected:#010x}, got {found:#010x}")]
    InvalidMagic { expected: u32, found: u32 },
    #[error("unsupported NXR1 version: expected {expected}, got {found}")]
    UnsupportedVersion { expected: u8, found: u8 },
    #[error("NXR1 field '{field}' must be finite, got {value}")]
    NonFiniteValue { field: &'static str, value: f64 },
    #[error("NXR1 payload is {size} bytes, exceeding max {max} bytes")]
    PayloadTooLarge { size: usize, max: usize },
    #[error("broker task kind '{found}' does not match expected '{expected}'")]
    UnexpectedKind { expected: String, found: String },
    #[error("broker task payload is missing the '{0}' field")]
    MissingBrokerPayload(&'static str),
    #[error("broker task payload field '{field}' is malformed: {source}")]
    MalformedBrokerPayload {
        field: &'static str,
        #[source]
        source: serde_json::Error,
    },
}

impl PartialEq for Nxr1Error {
    fn eq(&self, other: &Self) -> bool {
        use Nxr1Error::*;
        match (self, other) {
            (
                Truncated {
                    expected: e1,
                    actual: a1,
                },
                Truncated {
                    expected: e2,
                    actual: a2,
                },
            ) => e1 == e2 && a1 == a2,
            (
                TrailingBytes {
                    expected: e1,
                    actual: a1,
                },
                TrailingBytes {
                    expected: e2,
                    actual: a2,
                },
            ) => e1 == e2 && a1 == a2,
            (
                InvalidMagic {
                    expected: e1,
                    found: f1,
                },
                InvalidMagic {
                    expected: e2,
                    found: f2,
                },
            ) => e1 == e2 && f1 == f2,
            (
                UnsupportedVersion {
                    expected: e1,
                    found: f1,
                },
                UnsupportedVersion {
                    expected: e2,
                    found: f2,
                },
            ) => e1 == e2 && f1 == f2,
            (
                NonFiniteValue {
                    field: f1,
                    value: v1,
                },
                NonFiniteValue {
                    field: f2,
                    value: v2,
                },
            ) => f1 == f2 && (v1.is_nan() && v2.is_nan() || v1 == v2),
            (PayloadTooLarge { size: s1, max: m1 }, PayloadTooLarge { size: s2, max: m2 }) => {
                s1 == s2 && m1 == m2
            }
            (
                UnexpectedKind {
                    expected: e1,
                    found: f1,
                },
                UnexpectedKind {
                    expected: e2,
                    found: f2,
                },
            ) => e1 == e2 && f1 == f2,
            (MissingBrokerPayload(a), MissingBrokerPayload(b)) => a == b,
            (
                MalformedBrokerPayload { field: f1, .. },
                MalformedBrokerPayload { field: f2, .. },
            ) => f1 == f2,
            _ => false,
        }
    }
}

impl From<Nxr1Error> for BrokerClientError {
    fn from(error: Nxr1Error) -> Self {
        BrokerClientError::InvalidRequest(error.to_string())
    }
}

impl Nxr1Frame {
    /// Encode this frame as an NXR1 byte buffer.
    ///
    /// Returns [`Nxr1Error::NonFiniteValue`] if any float field is `NaN` or
    /// infinite, and [`Nxr1Error::PayloadTooLarge`] if the payload exceeds
    /// [`NXR1_MAX_PAYLOAD_BYTES`].
    pub fn encode(&self) -> Result<Vec<u8>, Nxr1Error> {
        check_finite("x", self.x)?;
        check_finite("y", self.y)?;
        check_finite("z", self.z)?;
        check_finite("u", self.u)?;
        check_finite("v", self.v)?;
        check_finite("w", self.w)?;
        check_finite("fluidity", self.fluidity as f64)?;
        check_finite("drag", self.drag as f64)?;
        check_finite("divergence", self.divergence)?;

        if self.payload.len() > NXR1_MAX_PAYLOAD_BYTES {
            return Err(Nxr1Error::PayloadTooLarge {
                size: self.payload.len(),
                max: NXR1_MAX_PAYLOAD_BYTES,
            });
        }
        // Safe: payload.len() <= NXR1_MAX_PAYLOAD_BYTES, which is statically
        // asserted to fit in a u32 (see _NXR1_MAX_PAYLOAD_BYTES_FITS_U32).
        let payload_len = self.payload.len() as u32;

        let mut buf = Vec::with_capacity(NXR1_HEADER_LEN + self.payload.len());
        buf.extend_from_slice(&NXR1_MAGIC.to_be_bytes());
        buf.push(NXR1_VERSION);
        buf.extend_from_slice(&self.seq_id.to_be_bytes());
        buf.extend_from_slice(&self.x.to_be_bytes());
        buf.extend_from_slice(&self.y.to_be_bytes());
        buf.extend_from_slice(&self.z.to_be_bytes());
        buf.extend_from_slice(&self.u.to_be_bytes());
        buf.extend_from_slice(&self.v.to_be_bytes());
        buf.extend_from_slice(&self.w.to_be_bytes());
        buf.extend_from_slice(&self.fluidity.to_be_bytes());
        buf.extend_from_slice(&self.drag.to_be_bytes());
        buf.extend_from_slice(&self.divergence.to_be_bytes());
        buf.extend_from_slice(&payload_len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        Ok(buf)
    }

    /// Decode an NXR1 byte buffer.
    ///
    /// Validates the fixed header length, magic, version, payload length
    /// bound, exact total length (no truncation or trailing bytes), and that
    /// every float field is finite.
    pub fn decode(bytes: &[u8]) -> Result<Self, Nxr1Error> {
        if bytes.len() < NXR1_HEADER_LEN {
            return Err(Nxr1Error::Truncated {
                expected: NXR1_HEADER_LEN,
                actual: bytes.len(),
            });
        }

        let mut cursor = Cursor::new(bytes);

        let magic = cursor.read_u32();
        if magic != NXR1_MAGIC {
            return Err(Nxr1Error::InvalidMagic {
                expected: NXR1_MAGIC,
                found: magic,
            });
        }

        let version = cursor.read_u8();
        if version != NXR1_VERSION {
            return Err(Nxr1Error::UnsupportedVersion {
                expected: NXR1_VERSION,
                found: version,
            });
        }

        let seq_id = cursor.read_u64();
        let x = check_finite("x", cursor.read_f64())?;
        let y = check_finite("y", cursor.read_f64())?;
        let z = check_finite("z", cursor.read_f64())?;
        let u = check_finite("u", cursor.read_f64())?;
        let v = check_finite("v", cursor.read_f64())?;
        let w = check_finite("w", cursor.read_f64())?;
        let fluidity = check_finite("fluidity", cursor.read_f32() as f64)? as f32;
        let drag = check_finite("drag", cursor.read_f32() as f64)? as f32;
        let divergence = check_finite("divergence", cursor.read_f64())?;
        let payload_len = cursor.read_u32() as usize;

        if payload_len > NXR1_MAX_PAYLOAD_BYTES {
            return Err(Nxr1Error::PayloadTooLarge {
                size: payload_len,
                max: NXR1_MAX_PAYLOAD_BYTES,
            });
        }

        let expected_total = NXR1_HEADER_LEN + payload_len;
        if bytes.len() < expected_total {
            return Err(Nxr1Error::Truncated {
                expected: expected_total,
                actual: bytes.len(),
            });
        }
        if bytes.len() > expected_total {
            return Err(Nxr1Error::TrailingBytes {
                expected: expected_total,
                actual: bytes.len(),
            });
        }

        let payload = bytes[NXR1_HEADER_LEN..expected_total].to_vec();

        Ok(Self {
            seq_id,
            x,
            y,
            z,
            u,
            v,
            w,
            fluidity,
            drag,
            divergence,
            payload,
        })
    }
}

fn check_finite(field: &'static str, value: f64) -> Result<f64, Nxr1Error> {
    if value.is_finite() {
        Ok(value)
    } else {
        Err(Nxr1Error::NonFiniteValue { field, value })
    }
}

/// Minimal big-endian reader over a byte slice known to be long enough for
/// the fixed NXR1 header (length is checked by the caller before
/// constructing a `Cursor`).
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Panics if `bytes` is shorter than [`NXR1_HEADER_LEN`]. Callers must
    /// perform that length check themselves (as `Nxr1Frame::decode` does)
    /// before constructing a `Cursor`, since this type only reads the fixed
    /// header and never the variable-length payload.
    fn new(bytes: &'a [u8]) -> Self {
        assert!(
            bytes.len() >= NXR1_HEADER_LEN,
            "Cursor requires at least {NXR1_HEADER_LEN} bytes, got {}",
            bytes.len()
        );
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> &'a [u8] {
        let slice = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        slice
    }

    fn read_u8(&mut self) -> u8 {
        self.take(1)[0]
    }

    fn read_u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take(4).try_into().unwrap())
    }

    fn read_u64(&mut self) -> u64 {
        u64::from_be_bytes(self.take(8).try_into().unwrap())
    }

    fn read_f32(&mut self) -> f32 {
        f32::from_be_bytes(self.take(4).try_into().unwrap())
    }

    fn read_f64(&mut self) -> f64 {
        f64::from_be_bytes(self.take(8).try_into().unwrap())
    }
}

/// Wrap an encoded [`Nxr1Frame`] into a [`BrokerTask`] addressed to
/// `destination`, tagged with [`GEOSPATIAL_FRAME_KIND`].
///
/// This is the integration point referenced in `docs/API.md`: it reuses the
/// existing [`crate::broker_client::BrokerClient`] JSON transport instead of
/// adding a second, parallel binary protocol.
pub fn to_broker_task(
    frame: &Nxr1Frame,
    task_id: impl Into<String>,
    source: impl Into<String>,
    destination: impl Into<String>,
    priority: u8,
    timeout_ms: u32,
) -> Result<BrokerTask, Nxr1Error> {
    let encoded = frame.encode()?;
    Ok(BrokerTask {
        task_id: task_id.into(),
        source: source.into(),
        destination: destination.into(),
        kind: GEOSPATIAL_FRAME_KIND.to_string(),
        priority,
        timeout_ms,
        payload: serde_json::json!({ BROKER_PAYLOAD_KEY: encoded }),
    })
}

/// Extract and decode an [`Nxr1Frame`] carried inside a [`BrokerTask`]
/// produced by [`to_broker_task`] (or a compatible `overhauled` peer).
pub fn from_broker_task(task: &BrokerTask) -> Result<Nxr1Frame, Nxr1Error> {
    if task.kind != GEOSPATIAL_FRAME_KIND {
        return Err(Nxr1Error::UnexpectedKind {
            expected: GEOSPATIAL_FRAME_KIND.to_string(),
            found: task.kind.clone(),
        });
    }
    let raw = task
        .payload
        .get(BROKER_PAYLOAD_KEY)
        .ok_or(Nxr1Error::MissingBrokerPayload(BROKER_PAYLOAD_KEY))?;
    let bytes: Vec<u8> = serde_json::from_value(raw.clone()).map_err(|source| {
        Nxr1Error::MalformedBrokerPayload {
            field: BROKER_PAYLOAD_KEY,
            source,
        }
    })?;
    Nxr1Frame::decode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_frame() -> Nxr1Frame {
        Nxr1Frame {
            seq_id: 42,
            x: 1.5,
            y: -2.25,
            z: 3.0,
            u: 0.125,
            v: -0.5,
            w: 0.0,
            fluidity: 0.9,
            drag: 0.1,
            divergence: -1.0e-3,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        }
    }

    #[test]
    fn round_trips_a_populated_frame() {
        let frame = sample_frame();
        let encoded = frame.encode().expect("encode");
        assert_eq!(encoded.len(), NXR1_HEADER_LEN + frame.payload.len());
        let decoded = Nxr1Frame::decode(&encoded).expect("decode");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn round_trips_an_empty_payload() {
        let mut frame = sample_frame();
        frame.payload.clear();
        let encoded = frame.encode().expect("encode");
        assert_eq!(encoded.len(), NXR1_HEADER_LEN);
        let decoded = Nxr1Frame::decode(&encoded).expect("decode");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn decode_rejects_truncated_header() {
        let encoded = sample_frame().encode().unwrap();
        let truncated = &encoded[..NXR1_HEADER_LEN - 1];
        let err = Nxr1Frame::decode(truncated).unwrap_err();
        assert_eq!(
            err,
            Nxr1Error::Truncated {
                expected: NXR1_HEADER_LEN,
                actual: truncated.len()
            }
        );
    }

    #[test]
    fn decode_rejects_truncated_payload() {
        let encoded = sample_frame().encode().unwrap();
        let truncated = &encoded[..encoded.len() - 1];
        let err = Nxr1Frame::decode(truncated).unwrap_err();
        assert_eq!(
            err,
            Nxr1Error::Truncated {
                expected: encoded.len(),
                actual: truncated.len()
            }
        );
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut encoded = sample_frame().encode().unwrap();
        let expected = encoded.len();
        encoded.push(0x00);
        let err = Nxr1Frame::decode(&encoded).unwrap_err();
        assert_eq!(
            err,
            Nxr1Error::TrailingBytes {
                expected,
                actual: expected + 1
            }
        );
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut encoded = sample_frame().encode().unwrap();
        encoded[0] ^= 0xFF;
        let err = Nxr1Frame::decode(&encoded).unwrap_err();
        assert!(matches!(err, Nxr1Error::InvalidMagic { .. }));
    }

    #[test]
    fn decode_rejects_bad_version() {
        let mut encoded = sample_frame().encode().unwrap();
        encoded[4] = 0xFF;
        let err = Nxr1Frame::decode(&encoded).unwrap_err();
        assert_eq!(
            err,
            Nxr1Error::UnsupportedVersion {
                expected: NXR1_VERSION,
                found: 0xFF
            }
        );
    }

    #[test]
    fn decode_rejects_oversized_declared_payload() {
        let mut encoded = sample_frame().encode().unwrap();
        let len_offset = NXR1_HEADER_LEN - 4;
        let oversized = (NXR1_MAX_PAYLOAD_BYTES as u32) + 1;
        encoded[len_offset..NXR1_HEADER_LEN].copy_from_slice(&oversized.to_be_bytes());
        let err = Nxr1Frame::decode(&encoded).unwrap_err();
        assert_eq!(
            err,
            Nxr1Error::PayloadTooLarge {
                size: oversized as usize,
                max: NXR1_MAX_PAYLOAD_BYTES,
            }
        );
    }

    #[test]
    fn encode_rejects_oversized_payload() {
        let mut frame = sample_frame();
        frame.payload = vec![0u8; NXR1_MAX_PAYLOAD_BYTES + 1];
        let err = frame.encode().unwrap_err();
        assert_eq!(
            err,
            Nxr1Error::PayloadTooLarge {
                size: NXR1_MAX_PAYLOAD_BYTES + 1,
                max: NXR1_MAX_PAYLOAD_BYTES,
            }
        );
    }

    #[test]
    fn encode_rejects_non_finite_values() {
        let mut frame = sample_frame();
        frame.x = f64::NAN;
        let err = frame.encode().unwrap_err();
        assert!(matches!(err, Nxr1Error::NonFiniteValue { field: "x", .. }));

        let mut frame = sample_frame();
        frame.divergence = f64::INFINITY;
        let err = frame.encode().unwrap_err();
        assert!(matches!(
            err,
            Nxr1Error::NonFiniteValue {
                field: "divergence",
                ..
            }
        ));
    }

    #[test]
    fn decode_rejects_non_finite_values() {
        let mut encoded = sample_frame().encode().unwrap();
        // y field starts right after magic(4)+version(1)+seq_id(8)+x(8)
        let y_offset = 4 + 1 + 8 + 8;
        encoded[y_offset..y_offset + 8].copy_from_slice(&f64::NAN.to_be_bytes());
        let err = Nxr1Frame::decode(&encoded).unwrap_err();
        assert!(matches!(err, Nxr1Error::NonFiniteValue { field: "y", .. }));
    }

    #[test]
    fn broker_round_trip_preserves_frame() {
        let frame = sample_frame();
        let task = to_broker_task(&frame, "task-1", "yukki", "overhauled", 5, 1_000)
            .expect("to_broker_task");
        assert_eq!(task.kind, GEOSPATIAL_FRAME_KIND);

        // The task should survive a JSON serialize/deserialize cycle, as it
        // would when sent over the broker's TCP transport.
        let json = serde_json::to_vec(&task).expect("serialize task");
        let roundtripped: BrokerTask = serde_json::from_slice(&json).expect("deserialize task");

        let decoded = from_broker_task(&roundtripped).expect("from_broker_task");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn broker_adapter_rejects_wrong_kind() {
        let frame = sample_frame();
        let mut task = to_broker_task(&frame, "task-1", "yukki", "overhauled", 5, 1_000).unwrap();
        task.kind = "other.kind".to_string();
        let err = from_broker_task(&task).unwrap_err();
        assert!(matches!(err, Nxr1Error::UnexpectedKind { .. }));
    }

    #[test]
    fn broker_adapter_rejects_missing_payload_field() {
        let mut task =
            to_broker_task(&sample_frame(), "task-1", "yukki", "overhauled", 5, 1_000).unwrap();
        task.payload = serde_json::json!({});
        let err = from_broker_task(&task).unwrap_err();
        assert!(matches!(err, Nxr1Error::MissingBrokerPayload(_)));
    }

    #[test]
    fn broker_adapter_rejects_invalid_payload_shape() {
        let mut task =
            to_broker_task(&sample_frame(), "task-1", "yukki", "overhauled", 5, 1_000).unwrap();
        task.payload = serde_json::json!({ "nxr1": "not-an-array" });
        let err = from_broker_task(&task).unwrap_err();
        assert!(matches!(err, Nxr1Error::MalformedBrokerPayload { .. }));
    }
}
