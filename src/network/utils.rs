use std::net::{IpAddr, Ipv4Addr};

use dusa_collection_utils::{errors::ErrorArrayItem, types::stringy::Stringy, version::Version};
use get_if_addrs::{IfAddr, get_if_addrs};

use crate::RELEASEINFO;

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

pub fn get_header_version() -> u16 {
    let lib_version = comms_version();
    lib_version.encode()
}

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

pub async fn get_external_ip() -> Result<IpAddr, ErrorArrayItem> {
    let url = "https://api.ipify.org"; // Alternatively, use "https://ifconfig.me"
    let response = reqwest::get(url).await?.text().await?;

    // Attempt to parse the response into an IpAddr
    match response.trim().parse::<IpAddr>() {
        Ok(ip) => Ok(ip),
        Err(err) => Err(ErrorArrayItem::from(err)),
    }
}