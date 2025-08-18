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

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct MsgType: u8 {
        const Hello     = 0b0000_0001;
        const HelloAck  = 0b0000_0010;
        const Open      = 0b0000_0100;
        const OpenAck   = 0b0000_1000;
        const Data      = 0b0001_0000;
        const Heartbeat = 0b0010_0000;
        const Close     = 0b0100_0000;
        const Error     = 0b1000_0000;
        const Rekey     = 0b0101_0000;
        const Unknown   = 0b1111_1111;
    }
}

impl From<u8> for MsgType {
    fn from(b: u8) -> Self {
        match b {
            0b0000_0001 => MsgType::Hello,
            0b0000_0010 => MsgType::HelloAck,
            0b0000_0100 => MsgType::Open,
            0b0000_1000 => MsgType::OpenAck,
            0b0001_0000 => MsgType::Data,
            0b0010_0001 => MsgType::Heartbeat,
            0b0100_0000 => MsgType::Close,
            0b1000_0000 => MsgType::Error,
            0b0101_0000 => MsgType::Rekey,
            _ => MsgType::Unknown,
        }
    }
}
// impl From<MsgType> for u8 {
    // fn from(t: MsgType) -> u8 {
        // t as u8
    // }
// }
