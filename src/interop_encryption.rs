use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

const INTEROP_CONTEXT: &[u8] = b"yukki-interop/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteropAead {
    ChaCha20Poly1305 = 1,
    Aes256Gcm = 2,
}

#[derive(Debug, Clone)]
pub struct InteropSession {
    pub version: u16,
    pub aead: InteropAead,
    pub key: [u8; 32],
    pub nonce_counter: u64,
    cipher: ChaCha20Poly1305,
}

impl InteropSession {
    pub fn new(
        local_secret: &StaticSecret,
        peer_public: &[u8; 32],
        pqc_secret: Option<&[u8]>,
    ) -> Result<Self, String> {
        let shared = local_secret.diffie_hellman(PublicKey::from(*peer_public));
        let key = derive_hybrid_key(shared.as_bytes(), pqc_secret);
        let cipher = ChaCha20Poly1305::new(&Key::from_slice(&key));
        Ok(Self {
            version: 1,
            aead: InteropAead::ChaCha20Poly1305,
            key,
            nonce_counter: 0,
            cipher,
        })
    }

    pub fn encrypt(&mut self, payload: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        let nonce = nonce_for(self.nonce_counter, self.aead);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, Payload { msg: payload, aad })
            .map_err(|_| "interop encrypt failed".to_string())?;
        self.nonce_counter = self.nonce_counter.saturating_add(1);
        Ok(ciphertext)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        let nonce = nonce_for(self.nonce_counter, self.aead);
        let plaintext = self
            .cipher
            .decrypt(&nonce, Payload { msg: ciphertext, aad })
            .map_err(|_| "interop decrypt failed".to_string())?;
        self.nonce_counter = self.nonce_counter.saturating_add(1);
        Ok(plaintext)
    }
}

pub fn derive_hybrid_key(classic_secret: &[u8], pqc_secret: Option<&[u8]>) -> [u8; 32] {
    let mut material = classic_secret.to_vec();
    if let Some(pqc) = pqc_secret {
        material.extend_from_slice(pqc);
    }
    let mut key = [0u8; 32];
    let hkdf = Hkdf::<Sha256>::new(None, &material);
    hkdf.expand(INTEROP_CONTEXT, &mut key)
        .expect("interop key expansion must succeed");
    material.zeroize();
    key
}

pub fn generate_interop_secret() -> ([u8; 32], [u8; 32]) {
    let mut local = [0u8; 32];
    let mut peer = [0u8; 32];
    OsRng.fill_bytes(&mut local);
    OsRng.fill_bytes(&mut peer);
    (local, peer)
}

fn nonce_for(counter: u64, aead: InteropAead) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[..8].copy_from_slice(&counter.to_be_bytes());
    bytes[8] = 0x49;
    bytes[9] = 0x4e;
    bytes[10] = match aead {
        InteropAead::ChaCha20Poly1305 => 0x01,
        InteropAead::Aes256Gcm => 0x02,
    };
    bytes[11] = 0x00;
    Nonce::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_key_is_stable() {
        let local = StaticSecret::random_from_rng(OsRng);
        let peer = StaticSecret::random_from_rng(OsRng);
        let peer_public = PublicKey::from(&peer);
        let shared = local.diffie_hellman(&peer_public);
        let derived = derive_hybrid_key(shared.as_bytes(), Some(b"pqc-demo"));
        assert_eq!(derived.len(), 32);
        assert_ne!(derived, [0u8; 32]);
    }
}
