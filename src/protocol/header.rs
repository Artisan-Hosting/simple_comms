use colored::Colorize;
use dusa_collection_utils::core::types::stringy::Stringy;
use dusa_collection_utils::core::version::Version;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;

use crate::protocol::flags::Flags;
use crate::protocol::status::ProtocolStatus;

#[repr(C)]
pub struct RecordMeta {
    pub session_id: [u8; 16],
    pub seq_no: u64,
    pub nonce: [u8; 12],
}


pub fn meta_to_bytes(m: &RecordMeta) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&m.session_id);
    out[8..16].copy_from_slice(&m.seq_no.to_be_bytes());
    out[16..28].copy_from_slice(&m.nonce);
    out[28..32].copy_from_slice(&m.pad);
    out
}

pub fn meta_from_bytes(b: &[u8; 32]) -> RecordMeta {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&b[16..28]);
    let mut pad = [0u8; 4];
    pad.copy_from_slice(&b[28..32]);
    RecordMeta {
        session_id: u64::from_be_bytes(b[0..8].try_into().unwrap()),
        seq_no: u64::from_be_bytes(b[8..16].try_into().unwrap()),
        nonce,
        pad,
    }
}


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

    pub fn get_meta(&self) -> RecordMeta {
        let mut sid = [0u8; 16];
        sid.copy_from_slice(&self.encryption_key[0..16]);
        let mut seq = [0u8; 8];
        seq.copy_from_slice(&self.encryption_key[16..24]);
        let mut nn: [u8; 12] = [0u8; 12];
        nn.copy_from_slice(&self.encryption_key[24..32]);
        RecordMeta {
            session_id: sid,
            seq_no: u64::from_be_bytes(seq),
            nonce: nn,
        }
    }

    pub fn set_meta(&mut self, m: &RecordMeta) {
        self.encryption_key[0..16].copy_from_slice(&m.session_id);
        self.encryption_key[16..24].copy_from_slice(&m.seq_no.to_be_bytes());
        self.encryption_key[24..32].copy_from_slice(&m.nonce);
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
// TODO: Rename this to a meta related name? 
const HEADER_ENCRYPTION_KEY_LEN: usize = 32; // [u8; 32] for the 256 bit key 

//  +-------------------- 32 bytes ---------------------+
//  |  session_id (16)  |  seq_no (8)  |  nonce (8)    |
//  +--------------------------------------------------+

// Calculate the fixed header length
pub const HEADER_LENGTH: usize = HEADER_VERSION_LEN
    + HEADER_FLAGS_LEN
    + HEADER_PAYLOAD_LENGTH_LEN
    + HEADER_RESERVED_LEN
    + HEADER_STATUS_LEN
    + HEADER_ORIGIN_ADDRESS_LEN
    + HEADER_ENCRYPTION_KEY_LEN;

pub const EOL: &[u8] = b"-EOL-";
