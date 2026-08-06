//! PIN → key derivation (Argon2id) and config sealing (ChaCha20-Poly1305).
//!
//! Parameters follow the Paranoia local vault: 16-byte salt, Argon2id with
//! m=64 MiB / t=3 / p=1, payload laid out as `nonce(12) || ciphertext+tag(16)`.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

const ARGON2_M_COST_KIB: u32 = 65536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

pub fn derive_key(pin: &str, salt: &[u8; SALT_LEN]) -> [u8; KEY_LEN] {
    let params = Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_LEN))
        .expect("static argon2 params are valid");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(pin.as_bytes(), salt, &mut key)
        .expect("argon2 with static params cannot fail");
    key
}

pub fn seal(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .expect("chacha20poly1305 encryption cannot fail");
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// `None` — wrong key or corrupted data.
pub fn open(key: &[u8; KEY_LEN], data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < NONCE_LEN {
        return None;
    }
    let (nonce, ciphertext) = data.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext).ok()
}
