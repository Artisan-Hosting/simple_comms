use sha2::{Digest, Sha256};


pub fn generate_checksum(data: &mut Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data.clone());
    let mut checksum: Vec<u8> = hasher.finalize().to_vec();
    data.append(&mut checksum);
    data.to_vec()
}

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