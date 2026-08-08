use std::{
    convert::TryInto,
    fmt,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

const ENCRYPTION_MAGIC: &[u8; 4] = b"YKC1";
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

unsafe extern "C" {
    fn crypt_layer_configure(sigma: f64, rho: f64, beta: f64);
    fn crypt_layer_encrypt(input: *const u8, len: usize, nonce: u64, output: *mut u8) -> i32;
    fn crypt_layer_decrypt(input: *const u8, len: usize, nonce: u64, output: *mut u8) -> i32;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoError(&'static str);

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for CryptoError {}

pub fn configure(sigma: f64, rho: f64, beta: f64) {
    unsafe { crypt_layer_configure(sigma, rho, beta) };
}

pub fn encryption_enabled() -> bool {
    std::env::var("YUKKI_ENABLE_ENCRYPTION")
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

pub fn encrypt_payload(payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if !encryption_enabled() {
        return Ok(payload.to_vec());
    }
    encrypt_payload_with_nonce(payload, next_nonce(payload.len()))
}

pub fn decrypt_payload(payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if !payload.starts_with(ENCRYPTION_MAGIC) {
        return Ok(payload.to_vec());
    }

    if payload.len() < ENCRYPTION_MAGIC.len() + std::mem::size_of::<u64>() {
        return Err(CryptoError("encrypted payload header is truncated"));
    }

    let nonce_start = ENCRYPTION_MAGIC.len();
    let nonce_end = nonce_start + std::mem::size_of::<u64>();
    let nonce = u64::from_be_bytes(
        payload[nonce_start..nonce_end]
            .try_into()
            .map_err(|_| CryptoError("invalid encryption nonce"))?,
    );
    crypt(false, nonce, &payload[nonce_end..])
}

fn next_nonce(len: usize) -> u64 {
    let tick = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or_default();
    tick ^ ((len as u64) << 17) ^ NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn encrypt_payload_with_nonce(payload: &[u8], nonce: u64) -> Result<Vec<u8>, CryptoError> {
    let encrypted = crypt(true, nonce, payload)?;
    let mut wrapped =
        Vec::with_capacity(ENCRYPTION_MAGIC.len() + std::mem::size_of::<u64>() + encrypted.len());
    wrapped.extend_from_slice(ENCRYPTION_MAGIC);
    wrapped.extend_from_slice(&nonce.to_be_bytes());
    wrapped.extend_from_slice(&encrypted);
    Ok(wrapped)
}

fn crypt(encrypt: bool, nonce: u64, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut output = vec![0u8; payload.len()];
    if payload.is_empty() {
        return Ok(output);
    }

    let status = unsafe {
        if encrypt {
            crypt_layer_encrypt(payload.as_ptr(), payload.len(), nonce, output.as_mut_ptr())
        } else {
            crypt_layer_decrypt(payload.as_ptr(), payload.len(), nonce, output.as_mut_ptr())
        }
    };

    if status == 0 {
        Ok(output)
    } else {
        Err(CryptoError("cryptographic transform failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::{decrypt_payload, encrypt_payload_with_nonce};

    #[test]
    fn encrypted_payload_round_trips() {
        let payload = br#"{"msg":"interim-crypt"}"#;
        let encrypted = encrypt_payload_with_nonce(payload, 0xACED_BAAD_F00D_1234).unwrap();
        let decrypted = decrypt_payload(&encrypted).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn legacy_payload_passthrough_stays_compatible() {
        let payload = br#"{"msg":"legacy"}"#;
        let decrypted = decrypt_payload(payload).unwrap();
        assert_eq!(decrypted, payload);
    }
}
