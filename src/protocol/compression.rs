//! Gzip payload compression, applied when [`crate::protocol::flags::ConnectionParams::COMPRESSED`]
//! is set (see the transform order in
//! [`crate::protocol::message::ProtocolMessage::to_bytes`]).

use std::io::{self, Read, Write};
use flate2::{bufread::GzDecoder, write::GzEncoder, Compression};

/// Gzip-compresses `data` at the default compression level.
pub fn compress_data(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder
        .finish()
        .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("Compression error: {}", err)))
}

/// Reverses [`compress_data`].
pub fn decompress_data(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut decompressed_data = Vec::new();
    decoder.read_to_end(&mut decompressed_data)?;
    Ok(decompressed_data)
}
