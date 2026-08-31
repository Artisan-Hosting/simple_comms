//! Small helpers for stamping messages with version/origin metadata and for
//! discovering this host's own IP addresses.

use std::net::{IpAddr, Ipv4Addr};

use dusa_collection_utils::core::{errors::ErrorArrayItem, types::stringy::Stringy, version::Version};
use get_if_addrs::{IfAddr, get_if_addrs};

use crate::RELEASEINFO;

/// This crate's own version, tagged with [`crate::RELEASEINFO`]. Compared
/// against an incoming message's header version in
/// [`crate::network::send_receive::send_message`] to detect protocol drift.
pub fn comms_version() -> Version {
    let version = env!("CARGO_PKG_VERSION");
    let mut parts = version.split('.');

    let major = parts.next().unwrap_or("0");
    let minor = parts.next().unwrap_or("0");
    let patch = parts.next().unwrap_or("0");

    Version {
        number: Stringy::from(format!("{}.{}.{}", major, minor, patch)),
        code: RELEASEINFO,
    }
}

/// [`comms_version`], encoded into the `u16` that goes in
/// [`crate::protocol::header::ProtocolHeader::version`].
pub fn get_header_version() -> u16 {
    let lib_version = comms_version();
    lib_version.encode()
}

/// The first non-loopback IPv4 address on any local interface, or
/// `127.0.0.1` if none is found. Used to stamp `origin_address` on outgoing
/// TCP messages.
pub fn get_local_ip() -> Ipv4Addr {
    let if_addrs = match get_if_addrs() {
        Ok(addrs) => addrs,
        Err(_) => return Ipv4Addr::LOCALHOST, // Return loopback address if interface fetching fails
    };
    
    for iface in if_addrs {
        if let IfAddr::V4(v4_addr) = iface.addr {
            if !v4_addr.ip.is_loopback() { // Filter out loopback addresses
                return v4_addr.ip;
            }
        }
    }
    
    Ipv4Addr::LOCALHOST // Return loopback address if no suitable non-loopback address is found
}

/// This host's public IP, as seen by an external service. Not used
/// internally by the protocol -- provided for callers building
/// discovery/registration on top of it.
pub async fn get_external_ip() -> Result<IpAddr, ErrorArrayItem> {
    let url = "https://api.ipify.org"; // Alternatively, use "https://ifconfig.me"
    let response = reqwest::get(url).await?.text().await?;

    // Attempt to parse the response into an IpAddr
    match response.trim().parse::<IpAddr>() {
        Ok(ip) => Ok(ip),
        Err(err) => Err(ErrorArrayItem::from(err)),
    }
}