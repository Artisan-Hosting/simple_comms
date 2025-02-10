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

pub fn pkcs7_padding(padding_len: usize) -> Vec<u8> {
    vec![padding_len as u8; padding_len]
}

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

pub fn x_padding(padding_len: usize) -> Vec<u8> {
    vec![8; padding_len]
}

pub fn x_trim_validation(padded: &[u8]) -> Result<usize, String> {
    let padding_len = padded.iter().rev().take_while(|&&byte| byte == 8).count();
    Ok(padding_len)
}
