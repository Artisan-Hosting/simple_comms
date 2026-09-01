//! Outcome flags carried in a response header's `status` byte -- distinct
//! from [`crate::protocol::flags::ConnectionParams`] (payload/connection
//! transforms) and [`crate::protocol::flags::MsgType`] (what kind of
//! message this is). `ProtocolStatus` composes several base flags into
//! higher-level outcomes (`SIDEGRADE`, `OUTOFBAND`, ...) that
//! [`crate::network::send_receive`] branches on.

use std::fmt;

use colored::{Color, Colorize};
use dusa_collection_utils::core::errors::{ErrorArrayItem, Errors};

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ProtocolStatus: u8 {
        // Status Flags
        const OK        = 0b0000_0001;
        const ERROR     = 0b0000_0010;
        const WAITING   = 0b0000_0100;
        /// Peer finished the `Hello`/`HelloAck` handshake. Relocated here
        /// from `ConnectionParams` (where it was never actually checked
        /// anywhere) since it describes connection/negotiation outcome,
        /// not a payload transform. Still unimplemented -- reserved for
        /// when handshake-state signaling is actually built.
        const READY     = 0b0000_1000;

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

        /// A request to change the connection params the message was sent
        /// with, based on the `reserved` field. See
        /// [`crate::network::send_receive::send_sidegrade`].
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
    /// Whether every bit of `flag` (including composite flags like
    /// `SIDEGRADE`) is set.
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

    /// Convert this status into an [`ErrorArrayItem`] describing the
    /// failure it represents, using this status's [`Display`](fmt::Display)
    /// output as the message. Callers are expected to have already decided
    /// this status indicates failure (e.g. via [`Self::is_error`],
    /// [`Self::has_flag`]) before calling this -- it doesn't itself check.
    pub fn to_error_item(&self) -> ErrorArrayItem {
        let kind = if self.contains(ProtocolStatus::VERSION) {
            Errors::Protocol
        } else if self.contains(ProtocolStatus::TIMEDOUT) {
            Errors::ConnectionTimedOut
        } else {
            Errors::Protocol
        };
        ErrorArrayItem::new(kind, self.to_string())
    }

    /// A terminal color for logging/CLI display.
    pub fn get_status_color(&self) -> Color {
        if self.contains(ProtocolStatus::SIDEGRADE) {
            Color::BrightMagenta
        } else if self.contains(ProtocolStatus::ERROR) {
            Color::Red
        } else if self.contains(ProtocolStatus::WAITING) {
            Color::Yellow
        } else if self.contains(ProtocolStatus::OK) {
            Color::Green
        } else {
            Color::White
        }
    }
}

impl fmt::Display for ProtocolStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Composable, like ConnectionParams's Display -- a single status
        // byte can carry several bits at once (e.g. SIDEGRADE is WAITING |
        // MALFORMED | RESERVED, and READY can co-occur with OK).
        let mut parts = vec![];
        if self.contains(ProtocolStatus::SIDEGRADE) {
            parts.push("SideGrade".bright_magenta().to_string());
        } else {
            if self.contains(ProtocolStatus::OK) {
                parts.push("OK".green().to_string());
            }
            if self.contains(ProtocolStatus::ERROR) {
                parts.push("Error".red().to_string());
            }
            if self.contains(ProtocolStatus::WAITING) {
                parts.push("Waiting".yellow().to_string());
            }
            if self.contains(ProtocolStatus::MALFORMED) {
                parts.push("Malformed".red().to_string());
            }
            if self.contains(ProtocolStatus::REFUSED) {
                parts.push("Refused".red().to_string());
            }
            if self.contains(ProtocolStatus::VERSION) {
                parts.push("VersionMismatch".red().to_string());
            }
        }
        if self.contains(ProtocolStatus::READY) {
            parts.push("READY".bright_green().bold().to_string());
        }
        if parts.is_empty() {
            parts.push("Unknown".to_string());
        }
        write!(f, "{}", parts.join(", "))
    }
}
