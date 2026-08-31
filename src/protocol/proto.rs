//! Which transport a message is being sent over. A handful of framing
//! details (e.g. origin address, flushing behavior) differ between the two.

use std::fmt;

use colored::{ColoredString, Colorize};

/// The underlying transport for a connection.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
pub enum Proto {
    /// A TCP socket -- `origin_address` is populated with the local host's
    /// IP (see [`crate::network::utils::get_local_ip`]).
    TCP,
    /// A Unix domain socket -- `origin_address` is left zeroed, since a
    /// local IP is meaningless.
    UNIX,
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let protocol: ColoredString = "PROTOCOL".bold().blue();
        match &self {
            Proto::TCP => write!(f, "{}: {}", protocol, "TCP".green().bold()),
            Proto::UNIX => write!(f, "{}: {}", protocol, "UNIX".green().bold()),
        }
    }
}
