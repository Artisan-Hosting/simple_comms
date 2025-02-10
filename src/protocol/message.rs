use std::io::{self, Cursor};

use crate::{
    network::utils::{get_header_version, get_local_ip},
    protocol::{
        checksum::{generate_checksum, verify_checksum},
        compression::{compress_data, decompress_data},
        encode::{decode_data, encode_data},
        encryption::{decrypt_with_aes_gcm, encrypt_with_aes_gcm, generate_key},
        flags::Flags,
        header::HEADER_LENGTH,
        io_helpers::read_with_std_io,
        padding::{
            add_padding_with_scheme, pkcs7_padding, pkcs7_validation, remove_padding_with_scheme,
        },
        status::ProtocolStatus,
    },
    RELEASEINFO,
};

use super::{
    header::{ProtocolHeader, EOL},
    reserved::Reserved,
};
use dusa_collection_utils::logger::LogLevel;
use dusa_collection_utils::{log, version::Version};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ProtocolMessage<T> {
    pub header: ProtocolHeader,
    pub payload: T,
}

impl<T> ProtocolMessage<T>
where
    T: Serialize + for<'a> Deserialize<'a> + std::fmt::Debug + Clone,
{
    // Create a new protocol message
    pub fn new(flags: Flags, payload: T) -> io::Result<Self> {
        let origin_address: [u8; 4] = get_local_ip().octets();

        // This is to be removed when reserved has been
        // assigned
        let reserved = Reserved::NONE;

        let header = ProtocolHeader {
            version: get_header_version(),
            flags: flags.bits(),
            payload_length: 0, // Will be set in to_bytes
            reserved: reserved.bits(),
            status: ProtocolStatus::OK.bits(), // Set initial status
            origin_address,
            encryption_key: [0u8; 32],
        };

        Ok(Self { header, payload })
    }

    // Standardized order of processing flags: Compression -> Encoding -> Encryption
    fn ordered_flags() -> Vec<Flags> {
        vec![
            Flags::ENCRYPTED,
            Flags::COMPRESSED,
            Flags::ENCODED,
            Flags::SIGNATURE,
        ]
    }

    pub async fn to_bytes(&mut self) -> io::Result<Vec<u8>> {
        log!(LogLevel::Trace, "Starting to_bytes conversion.");

        // Serialize and process payload
        let payload_bytes_unpadded = bincode::serialize(&self.payload)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;

        let mut payload_bytes: Vec<u8> =
            add_padding_with_scheme(&payload_bytes_unpadded, 16, pkcs7_padding);

        // Generate a random key for AES-GCM encryption
        let mut encryption_key: [u8; 32] = [0u8; 32];
        generate_key(&mut encryption_key);

        let flags = Flags::from_bits_truncate(self.header.flags);
        for flag in Self::ordered_flags() {
            if flags.contains(flag.clone()) {
                payload_bytes = match flag {
                    Flags::ENCRYPTED => encrypt_with_aes_gcm(&payload_bytes, &encryption_key)?,
                    Flags::COMPRESSED => compress_data(&payload_bytes)?,
                    Flags::ENCODED => encode_data(&payload_bytes),
                    Flags::SIGNATURE => generate_checksum(&mut payload_bytes),
                    _ => payload_bytes,
                };
            }
        }

        // Set payload length after transformations
        self.header.payload_length = payload_bytes.len() as u64;

        // Manually serialize the header fields into a fixed-size buffer
        let mut header_bytes: Vec<u8> = Vec::with_capacity(HEADER_LENGTH);
        header_bytes.extend(&self.header.version.to_be_bytes());
        header_bytes.extend(&self.header.flags.to_be_bytes());
        header_bytes.extend(&self.header.payload_length.to_be_bytes());
        header_bytes.extend(&self.header.reserved.to_be_bytes());
        header_bytes.extend(&self.header.status.to_be_bytes()); // Updated
        header_bytes.extend(&self.header.origin_address);
        if flags.contains(Flags::ENCRYPTED) {
            header_bytes.extend(&encryption_key); // Append the encryption key
        } else {
            header_bytes.extend([0u8; 32]); // appened 0's to satify the key legnth
        }
        // log!(LogLevel::Debug, "Generated header \n{}", self.header);

        // Combine header and payload
        let mut buffer = Vec::with_capacity(HEADER_LENGTH + payload_bytes.len());
        buffer.extend(header_bytes);
        buffer.extend(payload_bytes);

        Ok(buffer)
    }

    pub async fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        log!(LogLevel::Trace, "Starting from_bytes conversion.");

        if bytes.len() < HEADER_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Byte array too short to contain valid header",
            ));
        }

        // remove eof

        let header_bytes: &[u8] = &bytes[..HEADER_LENGTH];
        let payload_bytes: &[u8] = &bytes[HEADER_LENGTH..];

        // Manually deserialize the header fields
        let mut cursor = Cursor::new(header_bytes);

        let mut version_bytes: [u8; 2] = [0u8; 2];
        read_with_std_io(&mut cursor, &mut version_bytes)?;
        let version = u16::from_be_bytes(version_bytes);

        // Check and reject version data
        let incomming_version = Version::decode(version);
        let current_version = Version::new(env!("CARGO_PKG_VERSION"), RELEASEINFO);
        if !current_version.compare_versions(&incomming_version) {
            log!(
                LogLevel::Warn,
                "Message dropped, Outdated version. Required: {}, Recieved: {}",
                current_version,
                incomming_version
            );
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Out of date message recieved",
            ));
        }

        let mut flags_bytes: [u8; 1] = [0u8; 1];
        read_with_std_io(&mut cursor, &mut flags_bytes)?;
        let flags = u8::from_be_bytes(flags_bytes);

        let mut payload_length_bytes: [u8; 8] = [0u8; 8];
        read_with_std_io(&mut cursor, &mut payload_length_bytes)?;
        let payload_length = u64::from_be_bytes(payload_length_bytes);

        let mut reserved_bytes: [u8; 1] = [0u8; 1];
        read_with_std_io(&mut cursor, &mut reserved_bytes)?;
        let reserved = u8::from_be_bytes(reserved_bytes);

        let mut status_byte: [u8; 1] = [0u8; 1];
        // cursor.clone().read_exact(&mut status_byte)?;
        read_with_std_io(&mut cursor, &mut status_byte)?;
        let status_bits: u8 = u8::from_be_bytes(status_byte);
        let status: ProtocolStatus = ProtocolStatus::from_bits_truncate(status_bits);

        let mut origin_address: [u8; 4] = [0u8; 4];
        read_with_std_io(&mut cursor, &mut origin_address)?;

        let mut encryption_key = [0u8; 32];
        read_with_std_io(&mut cursor, &mut encryption_key)?;

        let header: ProtocolHeader = ProtocolHeader {
            version,
            flags,
            payload_length,
            reserved,
            status: status.bits(),
            origin_address,
            encryption_key,
        };
        log!(LogLevel::Debug, "Recieved header \n{}", header);

        let mut payload = payload_bytes.to_vec();

        let flags = Flags::from_bits_truncate(header.flags);
        for flag in Self::ordered_flags().iter().rev().cloned() {
            if flags.contains(flag) {
                payload = match flag {
                    Flags::SIGNATURE => verify_checksum(payload),
                    Flags::ENCODED => decode_data(&payload).unwrap(),
                    Flags::COMPRESSED => decompress_data(&payload)?,
                    Flags::ENCRYPTED => decrypt_with_aes_gcm(&payload, &encryption_key)?,
                    _ => payload,
                };
            }
        }

        // Deserialize and process payload
        payload = match remove_padding_with_scheme(&payload, 16, pkcs7_validation) {
            Ok(payload) => payload,
            Err(e) => {
                log!(LogLevel::Debug, "Failed to de-pad data: {}", e);
                payload_bytes.to_vec()
            }
        };

        let payload: T = bincode::deserialize(&payload).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Payload error from bytes: {}", err),
            )
        })?;

        Ok(Self { header, payload })
    }

    pub async fn get_payload(&self) -> T {
        return self.payload.clone();
    }

    pub async fn get_header(&self) -> ProtocolHeader {
        return self.header.clone();
    }

    /// returns a sendable Vec<u8> with the EOL appended
    pub async fn format(self) -> Result<Vec<u8>, io::Error> {
        let mut message: ProtocolMessage<T> = self;
        let mut message_bytes: Vec<u8> = message.to_bytes().await?;
        message_bytes.extend_from_slice(EOL);
        return Ok(message_bytes);
    }
}
