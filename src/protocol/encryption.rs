//! Standalone AES-256-GCM helpers with a random, self-describing (nonce
//! prefixed to ciphertext) framing. These predate the `Noise_NK` handshake
//! (see [`crate::protocol::handshake`]) and connection-scoped
//! [`crate::protocol::message::ConnectionCtx`] that secure `Data` traffic
//! when `ConnectionParams::ENCRYPTED` is set.
//!
//! [`ProtocolMessage::to_bytes`](crate::protocol::message::ProtocolMessage::to_bytes)
//! still uses these directly as its fallback for messages sent *without*
//! `ConnectionParams::ENCRYPTED` (including `Hello`/`HelloAck` themselves): a fresh
//! key is generated per message and carried in the header alongside the
//! ciphertext, which obscures the payload but provides no real
//! confidentiality (see that function's doc comment). They also remain
//! available standalone for callers who want ad hoc, out-of-band AES-GCM
//! encryption with a key they manage themselves.

use std::io;

use aes_gcm::{
    AeadCore, Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng},
};
use rand::Rng;

/// Encrypts `data` under `key` with a fresh random 96-bit nonce, and
/// prefixes that nonce to the returned ciphertext so [`decrypt_with_aes_gcm`]
/// can recover it without a separate channel.
pub fn encrypt_with_aes_gcm(data: &[u8], key: &[u8; 32]) -> io::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    cipher
        .encrypt(&nonce, data)
        .map(|ciphertext| [nonce.to_vec(), ciphertext].concat())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption error: {:?}", e)))
}

/// Reverses [`encrypt_with_aes_gcm`]: splits the leading 12-byte nonce off
/// `data` and decrypts the remainder under `key`.
pub fn decrypt_with_aes_gcm(data: &[u8], key: &[u8; 32]) -> io::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());

    // Ensure the data is at least the size of a nonce
    if data.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Data too short to contain a valid nonce",
        ));
    }

    // Split the data into nonce and ciphertext
    let (nonce_bytes, ciphertext) = data.split_at(12); // Nonce is 12 bytes for AES-GCM
    let nonce = Nonce::from_slice(nonce_bytes); // Create nonce from the extracted bytes

    // Decrypt the ciphertext
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption error: {:?}", e)))
}

/// Fills `buffer` with cryptographically random bytes (e.g. for a 32-byte
/// key to use with [`encrypt_with_aes_gcm`]).
pub fn generate_key(buffer: &mut [u8]) {
    let mut rng = rand::thread_rng(); // Create a random number generator
    for byte in buffer.iter_mut() {
        *byte = rng.r#gen(); // Fill each byte with random data
    }
}
