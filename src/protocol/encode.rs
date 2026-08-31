//! Hex text-encoding of a payload, applied when [`crate::protocol::flags::ConnectionParams::ENCODED`]
//! is set (see the transform order in
//! [`crate::protocol::message::ProtocolMessage::to_bytes`]). Mainly useful
//! for transports that can't safely carry arbitrary binary.

use dusa_collection_utils::core::errors::ErrorArrayItem;

/// Hex-encodes `data` into its ASCII representation.
pub fn encode_data(data: &[u8]) -> Vec<u8> {
    // Encode the data into a hex string and convert it into bytes
    hex::encode(data).into_bytes()
}

/// Reverses [`encode_data`]. Fails if `data` isn't valid UTF-8 or isn't a
/// valid hex string.
pub fn decode_data(data: &[u8]) -> Result<Vec<u8>, ErrorArrayItem> {
    // Convert the input bytes to a string
    let hex_string = String::from_utf8(data.to_vec()).map_err(|err| ErrorArrayItem::from(err))?;
    // Decode the hex string back into bytes
    hex::decode(hex_string).map_err(|err| ErrorArrayItem::from(err))
}
