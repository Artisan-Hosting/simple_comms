use std::io::{self, Read};

use tokio::io::AsyncReadExt;

// Read helpers
pub fn read_with_std_io<R: Read>(reader: &mut R, buffer: &mut [u8]) -> io::Result<()> {
    reader.read_exact(buffer)?;
    Ok(())
}

pub async fn read_with_tokio_io<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
) -> io::Result<()> {
    reader.read_to_end(buffer).await?;
    Ok(())
}

pub async fn read_until<T>(stream: &mut T, delimiter: Vec<u8>) -> io::Result<Vec<u8>>
where
    T: AsyncReadExt + Unpin,
{
    let mut result_buffer: Vec<u8> = Vec::new();
    let delimiter_len = delimiter.len();

    loop {
        // Buffer for reading a single byte at a time
        let mut byte = [0u8];

        // Read one byte
        let bytes_read = stream.read(&mut byte).await?;
        if bytes_read == 0 {
            // End of stream reached without finding the delimiter
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Delimiter not found",
            ));
        }

        // Append the byte to the result buffer
        result_buffer.push(byte[0]);

        // Check if the end of result_buffer matches the delimiter
        if result_buffer.len() >= delimiter_len
            && result_buffer[result_buffer.len() - delimiter_len..] == delimiter[..]
        {
            // Found the delimiter; return the buffer up to (and including) it
            return Ok(result_buffer);
        }
    }
}
