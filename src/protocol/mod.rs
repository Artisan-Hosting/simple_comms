//! The `simple_comms` wire protocol: message framing, the fixed header
//! format, flags/message types, the `Noise_NK` handshake, and the payload
//! transforms (compression, encoding, checksums, padding, encryption)
//! applied when serializing a [`message::ProtocolMessage`].
//!
//! See `docs/PROTOCOL.md` for the byte-level wire format and
//! `docs/HANDSHAKE.md` for how a connection is established and secured.

pub mod checksum;
pub mod compression;
pub mod encode;
pub mod encryption;
pub mod flags;
pub mod handshake;
pub mod header;
pub mod io_helpers;
pub mod message;
pub mod padding;
pub mod heartbeat;
pub mod proto;
pub mod reserved;
pub mod status;
