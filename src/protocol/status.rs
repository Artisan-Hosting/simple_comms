use std::fmt;

use colored::Color;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ProtocolStatus: u8 {
        // Status Flags
        const OK        = 0b0000_0001;
        const ERROR     = 0b0000_0010;
        const WAITING   = 0b0000_0100;

        // Error Flags
        const MALFORMED = 0b0001_0000; // The message fit what we were expecting but was trash
        const REFUSED   = 0b0010_0000; // Don't retry
        const RESERVED  = 0b0100_0000; // Reciver needs to parse reserved field
        const VERSION   = 0b1000_0000; // The version communicated is the problem

        // Invalid Version Flags

        /// Way out of date. The connection
        const OUTOFBAND = Self::ERROR.bits() | Self::REFUSED.bits() | Self::VERSION.bits();

        /// Not the current version but we can support you.
        const NOTINBAND = Self::OK.bits() | Self::VERSION.bits();

        // Sidegrade

        /// A request to change the flags the message was send with based on the reserved field
        const SIDEGRADE = Self::WAITING.bits() | Self::MALFORMED.bits() | Self::RESERVED.bits();

        // Time codes

        /// We connected to the client and started data and the they gohsted us
        const TIMEDOUT = Self::ERROR.bits() | Self::WAITING.bits();

        /// For uses like discovery where the target maynot exist
        const GAVEUP   = Self::OK.bits() | Self::WAITING.bits();

        /// Using the reserved field. tells client within X seconds I'll send the response to your query
        const WAITSEC  = Self::OK.bits() | Self::WAITING.bits() | Self::RESERVED.bits();
    }
}

impl ProtocolStatus {
    pub fn has_flag(&self, flag: ProtocolStatus) -> bool {
        self.contains(flag)
    }

    pub fn is_error(&self) -> bool {
        self.contains(ProtocolStatus::ERROR)
    }

    pub fn is_ok(&self) -> bool {
        self.contains(ProtocolStatus::OK)
    }

    pub fn is_waiting(&self) -> bool {
        self.contains(ProtocolStatus::WAITING)
    }

    pub fn get_status_color(&self) -> Color {
        match *self {
            ProtocolStatus::OK => Color::Green,
            ProtocolStatus::ERROR => Color::Red,
            ProtocolStatus::WAITING => Color::Yellow,
            ProtocolStatus::SIDEGRADE => Color::BrightMagenta,
            _ => Color::White,
        }
    }
}

impl fmt::Display for ProtocolStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let description = match *self {
            ProtocolStatus::OK => "OK",
            ProtocolStatus::ERROR => "Error",
            ProtocolStatus::WAITING => "Waiting",
            ProtocolStatus::SIDEGRADE => "SideGrade",
            _ => "Unknown",
        };
        write!(f, "{}", description)
    }
}
