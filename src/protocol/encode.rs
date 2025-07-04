use dusa_collection_utils::core::errors::ErrorArrayItem;

pub fn encode_data(data: &[u8]) -> Vec<u8> {
    // Encode the data into a hex string and convert it into bytes
    hex::encode(data).into_bytes()
}

pub fn decode_data(data: &[u8]) -> Result<Vec<u8>, ErrorArrayItem> {
    // Convert the input bytes to a string
    let hex_string = String::from_utf8(data.to_vec()).map_err(|err| ErrorArrayItem::from(err))?;
    // Decode the hex string back into bytes
    hex::decode(hex_string).map_err(|err| ErrorArrayItem::from(err))
}
