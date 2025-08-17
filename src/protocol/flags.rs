use std::fmt;

use colored::Colorize;

bitflags::bitflags! {
    #[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
    pub struct Flags: u8 {
        const NONE       = 0b0000_0000;
        const COMPRESSED = 0b0000_0001;
        const ENCRYPTED  = 0b0000_0010;
        const ENCODED    = 0b0000_0100;
        const SIGNATURE  = 0b0000_1000;
        const OPTIMIZED  = 0b0000_1111; //
        const READY      = 0b0001_0000; // peer finished handshake
        const RESUMED    = 0b0010_0000; // connection resume in effect
        // Add other flags as needed
    }
}

impl Flags {
    pub fn expect(&self, val: Flags) -> bool {
        // Checks if `self` contains exactly the same flags as `val`
        *self == val
    }
}

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut flags = vec![];
        if self.contains(Flags::COMPRESSED) {
            flags.push("Compressed".cyan().to_string());
        }
        if self.contains(Flags::ENCRYPTED) {
            flags.push("Encrypted".magenta().to_string());
        }
        if self.contains(Flags::ENCODED) {
            flags.push("Encoded".blue().to_string());
        }
        if self.contains(Flags::SIGNATURE) {
            flags.push("Signed".yellow().to_string());
        }
        if self.contains(Flags::OPTIMIZED) {
            flags.push("SECURE".bright_green().bold().to_string());
        }
        if self.contains(Flags::READY) {
            flags.push("READY".bright_green().bold().to_string());
        }
        if self.contains(Flags::RESUMED) {
            flags.push("RESUME".bright_blue().bold().to_string());
        }
        write!(f, "{}", flags.join(", "))
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MsgType {
    Hello = 0x01,
    HelloAck = 0x02,
    Open = 0x03,
    OpenAck = 0x04,
    Data = 0x05,
    Heartbeat = 0x06,
    Close = 0x07,
    Error = 0x08,
    Rekey = 0x09,
    /// Used for unknown/unsupported values.
    Unknown = 0xff,
}

impl From<u8> for MsgType {
    fn from(b: u8) -> Self {
        match b {
            0x01 => MsgType::Hello,
            0x02 => MsgType::HelloAck,
            0x03 => MsgType::Open,
            0x04 => MsgType::OpenAck,
            0x05 => MsgType::Data,
            0x06 => MsgType::Heartbeat,
            0x07 => MsgType::Close,
            0x08 => MsgType::Error,
            0x09 => MsgType::Rekey,
            _ => MsgType::Unknown,
        }
    }
}
impl From<MsgType> for u8 {
    fn from(t: MsgType) -> u8 {
        t as u8
    }
}
