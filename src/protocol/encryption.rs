use std::io;

use aes_gcm::{
    aead::{Aead, OsRng},
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
        *byte = rng.gen(); // Fill each byte with random data
    }
}
