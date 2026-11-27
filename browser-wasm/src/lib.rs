#![cfg_attr(target_arch = "wasm32", no_std)]

//! Small browser-side verifier for YuKKi-OS YKMC v1 media chunks.
//! This crate intentionally has no dependency on the native node, Tokio,
//! Axum, Wasmtime, or a JavaScript binding generator.

/// Bounded geospatial, motion, and spatiotemporal primitives for browser WASM.
pub mod mmo;

pub const YKMC_HEADER_LEN: usize = 31;
pub const MAX_STREAM_ID_BYTES: usize = 128;
pub const MAX_CODEC_BYTES: usize = 64;
pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024;
pub const MAX_FRAME_BYTES: usize =
    YKMC_HEADER_LEN + MAX_STREAM_ID_BYTES + MAX_CODEC_BYTES + MAX_PAYLOAD_BYTES;

pub const MAX_OBSERVATION_DIMENSIONS: usize = 32;
const ERR_OBSERVATION_DIMENSIONS: i32 = -20;
const ERR_OBSERVATION_VALUE: i32 = -21;

const VALID: i32 = 0;
const ERR_TRUNCATED: i32 = -1;
const ERR_MAGIC: i32 = -2;
const ERR_VERSION: i32 = -3;
const ERR_MEDIA_TYPE: i32 = -4;
const ERR_FLAGS: i32 = -5;
const ERR_STREAM_ID_LENGTH: i32 = -6;
const ERR_CODEC_LENGTH: i32 = -7;
const ERR_UTF8: i32 = -8;
const ERR_PAYLOAD_LENGTH: i32 = -9;
const ERR_FRAME_LENGTH: i32 = -10;
const ERR_FRAME_TOO_LARGE: i32 = -11;

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Validate one schema-v1 multivariate observation after its numeric values
/// have been copied into the fixed browser-WASM input buffer. Missing values
/// are represented by bits set in `missing_mask`; all other values must be finite.
pub fn validate_observation_values(values: &[Option<f64>]) -> i32 {
    if values.is_empty() || values.len() > MAX_OBSERVATION_DIMENSIONS {
        return ERR_OBSERVATION_DIMENSIONS;
    }
    if values.iter().flatten().any(|value| !value.is_finite()) {
        return ERR_OBSERVATION_VALUE;
    }
    VALID
}

/// Validate one exact YKMC v1 frame. Returns zero on success and a stable
/// negative status code for malformed input.
pub fn validate_ykmc(bytes: &[u8]) -> i32 {
    if bytes.len() > MAX_FRAME_BYTES {
        return ERR_FRAME_TOO_LARGE;
    }
    if bytes.len() < YKMC_HEADER_LEN {
        return ERR_TRUNCATED;
    }
    if bytes[0..4] != *b"YKMC" {
        return ERR_MAGIC;
    }
    if bytes[4] != 1 {
        return ERR_VERSION;
    }
    if bytes[5] > 1 {
        return ERR_MEDIA_TYPE;
    }
    if bytes[6] & !0x01 != 0 {
        return ERR_FLAGS;
    }

    let stream_id_len = usize::from(read_u16(bytes, 7));
    let codec_len = usize::from(read_u16(bytes, 9));
    let payload_len = read_u32(bytes, 27) as usize;

    if stream_id_len == 0 || stream_id_len > MAX_STREAM_ID_BYTES {
        return ERR_STREAM_ID_LENGTH;
    }
    if codec_len == 0 || codec_len > MAX_CODEC_BYTES {
        return ERR_CODEC_LENGTH;
    }
    if payload_len > MAX_PAYLOAD_BYTES {
        return ERR_PAYLOAD_LENGTH;
    }

    let metadata_end = match YKMC_HEADER_LEN
        .checked_add(stream_id_len)
        .and_then(|value| value.checked_add(codec_len))
    {
        Some(value) => value,
        None => return ERR_FRAME_LENGTH,
    };
    let expected_len = match metadata_end.checked_add(payload_len) {
        Some(value) => value,
        None => return ERR_FRAME_LENGTH,
    };
    if expected_len != bytes.len() {
        return ERR_FRAME_LENGTH;
    }

    let stream_id = &bytes[YKMC_HEADER_LEN..YKMC_HEADER_LEN + stream_id_len];
    let codec = &bytes[YKMC_HEADER_LEN + stream_id_len..metadata_end];
    if core::str::from_utf8(stream_id).is_err() || core::str::from_utf8(codec).is_err() {
        return ERR_UTF8;
    }
    VALID
}

#[cfg(target_arch = "wasm32")]
static mut INPUT_BUFFER: [u8; MAX_FRAME_BYTES] = [0; MAX_FRAME_BYTES];

/// Pointer to the fixed-size input area. The page must write no more than
/// yukki_input_capacity() bytes before calling yukki_validate_ykmc().
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn yukki_input_ptr() -> *mut u8 {
    core::ptr::addr_of_mut!(INPUT_BUFFER).cast::<u8>()
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn yukki_input_capacity() -> u32 {
    MAX_FRAME_BYTES as u32
}

#[cfg(target_arch = "wasm32")]
static mut OBSERVATION_BUFFER: [f64; MAX_OBSERVATION_DIMENSIONS] =
    [0.0; MAX_OBSERVATION_DIMENSIONS];

/// Pointer to the fixed numeric input buffer used by
/// `yukki_validate_observation`.
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn yukki_observation_input_ptr() -> *mut f64 {
    core::ptr::addr_of_mut!(OBSERVATION_BUFFER).cast::<f64>()
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn yukki_observation_input_capacity() -> u32 {
    MAX_OBSERVATION_DIMENSIONS as u32
}

/// Validate a single schema-v1 observation. `sequence` and
/// `timestamp_unix_ms` are exact u64 values supplied by the NDJSON decoder;
/// the data plane retains them unchanged while this function validates the
/// dimensions and finite numeric values in WASM memory.
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn yukki_validate_observation(
    dimensions: u32,
    missing_mask: u32,
    _sequence: u64,
    _timestamp_unix_ms: u64,
) -> i32 {
    let dimensions = dimensions as usize;
    if dimensions == 0 || dimensions > MAX_OBSERVATION_DIMENSIONS {
        return ERR_OBSERVATION_DIMENSIONS;
    }
    let valid_mask = if dimensions == 32 {
        u32::MAX
    } else {
        (1u32 << dimensions) - 1
    };
    if missing_mask & !valid_mask != 0 {
        return ERR_OBSERVATION_DIMENSIONS;
    }
    let ptr = core::ptr::addr_of!(OBSERVATION_BUFFER).cast::<f64>();
    // SAFETY: the caller supplies a dimension count bounded by the fixed buffer.
    let values = unsafe { core::slice::from_raw_parts(ptr, dimensions) };
    if values
        .iter()
        .enumerate()
        .any(|(index, value)| missing_mask & (1u32 << index) == 0 && !value.is_finite())
    {
        return ERR_OBSERVATION_VALUE;
    }
    VALID
}

/// Validate bytes previously copied into the fixed input area.
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn yukki_validate_ykmc(len: u32) -> i32 {
    let len = len as usize;
    if len > MAX_FRAME_BYTES {
        return ERR_FRAME_TOO_LARGE;
    }
    let ptr = core::ptr::addr_of!(INPUT_BUFFER).cast::<u8>();
    // SAFETY: INPUT_BUFFER is fixed and len is bounded by its capacity.
    let input = unsafe { core::slice::from_raw_parts(ptr, len) };
    validate_ykmc(input)
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_frame() -> Vec<u8> {
        let stream_id = b"camera-1";
        let codec = b"h264";
        let payload = [0x01, 0x02, 0x03];
        let mut frame = Vec::new();
        frame.extend_from_slice(b"YKMC");
        frame.push(1);
        frame.push(1);
        frame.push(1);
        frame.extend_from_slice(&(stream_id.len() as u16).to_be_bytes());
        frame.extend_from_slice(&(codec.len() as u16).to_be_bytes());
        frame.extend_from_slice(&7_u64.to_be_bytes());
        frame.extend_from_slice(&1234_u64.to_be_bytes());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(stream_id);
        frame.extend_from_slice(codec);
        frame.extend_from_slice(&payload);
        frame
    }

    #[test]
    fn accepts_a_valid_ykmc_v1_frame() {
        assert_eq!(validate_ykmc(&valid_frame()), VALID);
    }

    #[test]
    fn rejects_short_input_and_trailing_bytes() {
        let mut frame = valid_frame();
        assert_eq!(validate_ykmc(&frame[..YKMC_HEADER_LEN - 1]), ERR_TRUNCATED);
        frame.push(0);
        assert_eq!(validate_ykmc(&frame), ERR_FRAME_LENGTH);
    }

    #[test]
    fn rejects_invalid_magic_version_type_and_flags() {
        let mut frame = valid_frame();
        frame[0] = b'X';
        assert_eq!(validate_ykmc(&frame), ERR_MAGIC);
        frame = valid_frame();
        frame[4] = 2;
        assert_eq!(validate_ykmc(&frame), ERR_VERSION);
        frame = valid_frame();
        frame[5] = 2;
        assert_eq!(validate_ykmc(&frame), ERR_MEDIA_TYPE);
        frame = valid_frame();
        frame[6] = 0x80;
        assert_eq!(validate_ykmc(&frame), ERR_FLAGS);
    }

    #[test]
    fn rejects_invalid_lengths_and_utf8() {
        let mut frame = valid_frame();
        frame[7..9].copy_from_slice(&0_u16.to_be_bytes());
        assert_eq!(validate_ykmc(&frame), ERR_STREAM_ID_LENGTH);

        frame = valid_frame();
        frame[9..11].copy_from_slice(&0_u16.to_be_bytes());
        assert_eq!(validate_ykmc(&frame), ERR_CODEC_LENGTH);

        frame = valid_frame();
        frame[YKMC_HEADER_LEN] = 0xff;
        assert_eq!(validate_ykmc(&frame), ERR_UTF8);

        frame = valid_frame();
        frame[27..31].copy_from_slice(&((MAX_PAYLOAD_BYTES as u32) + 1).to_be_bytes());
        assert_eq!(validate_ykmc(&frame), ERR_PAYLOAD_LENGTH);
    }

    #[test]
    fn validates_schema_v1_data_observations_and_preserves_missing_values() {
        assert_eq!(
            validate_observation_values(&[Some(1.0), None, Some(-2.5)]),
            VALID
        );
        assert_eq!(validate_observation_values(&[]), ERR_OBSERVATION_DIMENSIONS);
        assert_eq!(
            validate_observation_values(&[Some(f64::NAN)]),
            ERR_OBSERVATION_VALUE
        );
        assert_eq!(
            validate_observation_values(&vec![Some(1.0); MAX_OBSERVATION_DIMENSIONS + 1]),
            ERR_OBSERVATION_DIMENSIONS
        );
    }

    #[test]
    fn rejects_frames_above_the_global_bound() {
        let frame = vec![0_u8; MAX_FRAME_BYTES + 1];
        assert_eq!(validate_ykmc(&frame), ERR_FRAME_TOO_LARGE);
    }
}
