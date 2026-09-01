//! Low-level byte-reading helpers used while parsing a
//! [`crate::protocol::header::ProtocolHeader`] and while framing messages
//! off the wire.

use std::io::{self, Read};

use tokio::io::AsyncReadExt;

use crate::protocol::header::EOL;

/// Fills `buffer` exactly from `reader`, synchronously. Used by
/// [`crate::protocol::message::ProtocolMessage::from_bytes`] to walk a
/// fixed-size header a field at a time via a [`std::io::Cursor`].
// Read helpers
pub fn read_with_std_io<R: Read>(reader: &mut R, buffer: &mut [u8]) -> io::Result<()> {
    reader.read_exact(buffer)?;
    Ok(())
}

/// Reads `reader` to completion into `buffer`. Unlike [`read_until`], this
/// has no delimiter -- it only returns once the stream is closed.
pub async fn read_with_tokio_io<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
) -> io::Result<()> {
    reader.read_to_end(buffer).await?;
    Ok(())
}

/// Reads one byte at a time from `stream` until the trailing bytes match
/// `delimiter` (in practice always [`EOL`]), then returns everything read
/// *excluding* the delimiter itself.
///
/// This is how message framing works end-to-end: every sent message ends
/// with exactly one `EOL`, and every caller reads with this function to find
/// that boundary. Returns `UnexpectedEof` if the stream closes first.
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
            result_buffer.truncate(result_buffer.len() - EOL.len());
            return Ok(result_buffer);
        }
    }
}

/// Cancellation-safe counterpart to [`read_until`]: identical
/// delimiter-scanning, but progress is kept in the caller-owned `buf`
/// rather than this function's own local state. [`read_until`] is *not*
/// safe to use as a `tokio::select!` branch -- if the future is dropped
/// mid-scan (because a different branch became ready first), the bytes
/// it's already consumed from `stream` but not yet returned are gone,
/// silently desynchronizing the framing for every message after it. Here,
/// since `buf` lives in the caller (e.g. a `tokio::select!` loop's state,
/// declared outside the `loop` -- see [`crate::network::driver`]) rather
/// than in this future's own stack frame, a cancelled call leaves the
/// bytes it already read safely in `buf` for the next call to resume
/// from exactly where it left off. `buf` should start empty (or however a
/// previously-cancelled call left it) and is cleared on a successful
/// return -- the frame is returned separately, not left in `buf`.
pub async fn read_until_buffered<T>(
    stream: &mut T,
    delimiter: &[u8],
    buf: &mut Vec<u8>,
) -> io::Result<Vec<u8>>
where
    T: AsyncReadExt + Unpin,
{
    let delimiter_len = delimiter.len();

    loop {
        if buf.len() >= delimiter_len && buf[buf.len() - delimiter_len..] == *delimiter {
            let frame_len = buf.len() - delimiter_len;
            let frame = buf[..frame_len].to_vec();
            buf.clear();
            return Ok(frame);
        }

        let mut byte = [0u8];
        let bytes_read = stream.read(&mut byte).await?;
        if bytes_read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Delimiter not found",
            ));
        }
        buf.push(byte[0]);
    }
}
