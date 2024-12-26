use std::fmt;

use colored::{ColoredString, Colorize};

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
pub enum Proto {
    TCP,
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