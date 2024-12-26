use colored::Colorize;
use dusa_collection_utils::stringy::Stringy;
use dusa_collection_utils::version::Version;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;

use crate::protocol::flags::Flags;
use crate::protocol::status::ProtocolStatus;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProtocolHeader {
    pub version: u16,
    pub flags: u8,
    pub payload_length: u64,
    pub reserved: u8,
    pub status: u8,
    pub origin_address: [u8; 4],
    pub encryption_key: [u8; 32],
}

impl fmt::Display for ProtocolHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let version: Version = Version::decode(self.version);

        let origin_addr: Stringy = match self.get_origin_ip() == IpAddr::V4([0, 0, 0, 0].into()) {
            true => Stringy::from("Internal"),
            false => Stringy::from(self.get_origin_ip().to_string()),
        };

        write!(
            f,
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            format!("Library Version:  {}", version).bold().green(),
            format!(
                "Flags:            {:#010b} ({})",
                self.flags,
                Flags::from_bits_truncate(self.flags)
            )
            .bold()
            .blue(),
            format!(
                "Payload Key:      {}",
                if self.encryption_key == [0u8; 32] {
                    "No Key Set".to_string()
                } else {
                    format!("{}", hex::encode(self.encryption_key))
                }
            )
            .bold()
            .purple(),
            format!("Payload Length:   {}", self.payload_length)
                .bold()
                .purple(),
            format!("Reserved:         {:#010b}", self.reserved)
                .bold()
                .yellow(),
            format!(
                "Status:           {:#010b} ({})",
                self.status,
                ProtocolStatus::from_bits_truncate(self.status)
            )
            .bold()
            .red(),
            format!("Origin Address:   {}", origin_addr).bold().cyan(),
        )
    }
}

impl ProtocolHeader {
    pub fn get_origin_ip(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(self.origin_address)
    }
}

// HEADER LEGNTH DATA. 
// IF THIS IS WRONG data will be offset or err not enough data for a message

const HEADER_VERSION_LEN: usize = 2; // u16
const HEADER_FLAGS_LEN: usize = 1; // u8
const HEADER_PAYLOAD_LENGTH_LEN: usize = 8; // u64
const HEADER_RESERVED_LEN: usize = 1; // u8
const HEADER_STATUS_LEN: usize = 1; // u8 for ProtocolStatus
const HEADER_ORIGIN_ADDRESS_LEN: usize = 4; // [u8; 4] for IPv4 address
const HEADER_ENCRYPTION_KEY_LEN: usize = 32; // [u8; 32] for the 256 bit key

// Calculate the fixed header length
pub const HEADER_LENGTH: usize = HEADER_VERSION_LEN
    + HEADER_FLAGS_LEN
    + HEADER_PAYLOAD_LENGTH_LEN
    + HEADER_RESERVED_LEN
    + HEADER_STATUS_LEN
    + HEADER_ORIGIN_ADDRESS_LEN
    + HEADER_ENCRYPTION_KEY_LEN;

pub const EOL: &str = "-EOL-";