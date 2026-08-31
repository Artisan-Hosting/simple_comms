//! SHA-256 integrity check applied to a payload when [`crate::protocol::flags::ConnectionParams::SIGNATURE`]
//! is set, ahead of encryption (see the transform order in
//! [`crate::protocol::message::ProtocolMessage::to_bytes`]).

use sha2::{Digest, Sha256};

/// Appends a 32-byte SHA-256 digest of `data` to `data` itself, in place,
/// and returns the combined buffer. Pair with [`verify_checksum`] on the
/// receiving end.
pub fn generate_checksum(data: &mut Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data.clone());
    let mut checksum: Vec<u8> = hasher.finalize().to_vec();
    data.append(&mut checksum);
    data.to_vec()
}

/// Splits the trailing 32-byte SHA-256 digest off `data_with_checksum`,
/// recomputes it over the remaining bytes, and returns just the original
/// data if it matches.
///
/// # Panics
/// Panics if `data_with_checksum` is shorter than 32 bytes, or if the
/// recomputed digest doesn't match the trailing one.
pub fn verify_checksum(data_with_checksum: Vec<u8>) -> Vec<u8> {
    // Check that the data has at least a SHA-256 checksum length appended
    if data_with_checksum.len() < 32 {
        panic!("checksum data too small")
    }

    // Separate the data and the appended checksum
    let data_len = data_with_checksum.len() - 32;
    let (data, checksum) = data_with_checksum.split_at(data_len);

    // Generate the checksum for the data portion
    let mut hasher = Sha256::new();
    hasher.update(data);
    let calculated_checksum = hasher.finalize().to_vec();

    // Compare the calculated checksum with the provided checksum
    if checksum == calculated_checksum.as_slice() {
        data.to_vec() // Return original data if checksum is valid
    } else {
        panic!("checksum invalid")
    }
}
