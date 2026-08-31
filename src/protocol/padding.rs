//! Generic block-padding helpers, parameterized over a padding scheme.
//! `simple_comms` currently ships a PKCS#7 scheme ([`pkcs7_padding`]/
//! [`pkcs7_validation`]) and a fixed-byte scheme ([`x_padding`]/
//! [`x_trim_validation`]); neither is wired into
//! [`crate::protocol::message::ProtocolMessage::to_bytes`] today (it's
//! commented out there as a documented extension point for length-hiding).

/// Pads `data` out to a multiple of `block_size` using `padding_fn` to
/// generate the padding bytes given how many are needed.
///
/// # Panics
/// Panics if `block_size` is 0 or greater than 255 (padding schemes here
/// encode the padding length in a single byte).
pub fn add_padding_with_scheme<F>(data: &[u8], block_size: usize, padding_fn: F) -> Vec<u8>
where
    F: Fn(usize) -> Vec<u8>,
{
    if !(1..=255).contains(&block_size) {
        panic!("Block size must be between 1 and 255 inclusive");
    }
    let padding_len = block_size - (data.len() % block_size);
    let mut padded_data = data.to_vec();
    padded_data.extend(padding_fn(padding_len));
    padded_data
}

/// Reverses [`add_padding_with_scheme`]: uses `validate_fn` to determine how
/// many trailing bytes are padding, and strips them off.
///
/// Returns `Err` if `padded_data` is empty, if `validate_fn` rejects it, or
/// if the reported padding length is larger than `block_size` or the data
/// itself.
pub fn remove_padding_with_scheme<F>(
    padded_data: &[u8],
    block_size: usize,
    validate_fn: F,
) -> Result<Vec<u8>, String>
where
    F: Fn(&[u8]) -> Result<usize, String>,
{
    if padded_data.is_empty() {
        return Err("Data is empty, no padding to remove".to_string());
    }

    let padding_len = validate_fn(&padded_data)?;

    if padding_len > block_size || padding_len > padded_data.len() {
        return Err("Invalid padding length".to_string());
    }

    let actual_data_len = padded_data.len() - padding_len;

    Ok(padded_data[..actual_data_len].to_vec())
}

/// PKCS#7: pad with `padding_len` bytes, each holding the value `padding_len`.
pub fn pkcs7_padding(padding_len: usize) -> Vec<u8> {
    vec![padding_len as u8; padding_len]
}

/// PKCS#7: read the padding length from the last byte, then confirm every
/// padding byte agrees with it.
pub fn pkcs7_validation(padded: &[u8]) -> Result<usize, String> {
    let padding_len = *padded.last().unwrap() as usize;
    if padding_len == 0 || padding_len > padded.len() {
        return Err("Invalid padding length".to_string());
    }

    if !padded[padded.len() - padding_len..]
        .iter()
        .all(|&byte| byte as usize == padding_len)
    {
        return Err("Invalid padding bytes".to_string());
    }

    Ok(padding_len)
}

/// A simpler fixed-byte scheme: pad with `padding_len` bytes of `0x08`.
pub fn x_padding(padding_len: usize) -> Vec<u8> {
    vec![8; padding_len]
}

/// Counts trailing `0x08` bytes to determine the padding length. Unlike
/// [`pkcs7_validation`], this can't distinguish real trailing `0x08` data
/// bytes from padding -- only use it with data that can't end in `0x08`.
pub fn x_trim_validation(padded: &[u8]) -> Result<usize, String> {
    let padding_len = padded.iter().rev().take_while(|&&byte| byte == 8).count();
    Ok(padding_len)
}
