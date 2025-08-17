use std::io;

use aes_gcm::{
    aead::{Aead, OsRng, Payload},
    AeadCore, Aes256Gcm, KeyInit, Nonce,
};
use rand::Rng;

pub fn encrypt_with_aes_gcm(data: &[u8], key: &[u8; 32]) -> io::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    cipher
        .encrypt(&nonce, data)
        .map(|ciphertext| [nonce.to_vec(), ciphertext].concat())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption error: {:?}", e)))
}

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

pub fn generate_key(buffer: &mut [u8]) {
    let mut rng = rand::thread_rng(); // Create a random number generator
    for byte in buffer.iter_mut() {
        *byte = rng.r#gen(); // Fill each byte with random data
    }
}

// New: explicit-nonce encrypt that does NOT prefix nonce to the ciphertext
pub fn encrypt_with_aes_gcm_session(
    data: &[u8],
    session_key: &[u8; 32],
    nonce_96: &[u8; 12],
    aad: &[u8],               // e.g., seq_no or (session_id||seq_no)
) -> io::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(session_key.into());
    let nonce = Nonce::from_slice(nonce_96); // 96-bit nonce
    cipher
        .encrypt(nonce, Payload { msg: data, aad })
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption error: {:?}", e)))
}

// New: explicit-nonce decrypt to match the above
pub fn decrypt_with_aes_gcm_session(
    ciphertext: &[u8],
    session_key: &[u8; 32],
    nonce_96: &[u8; 12],
    aad: &[u8],
) -> io::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(session_key.into());
    let nonce = Nonce::from_slice(nonce_96);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption error: {:?}", e)))
}