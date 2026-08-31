//! `simple_comms` is Artisan Hosting's wire protocol for authenticated,
//! encrypted communication between two peers over TCP or a Unix domain
//! socket.
//!
//! A connection is secured with a `Noise_NK` handshake (see
//! [`protocol::handshake`]), after which every message is framed by
//! [`protocol::message::ProtocolMessage`] and encrypted with the resulting
//! transport cipher. See `docs/QUICKSTART.md` for a fast-path tour with
//! examples, `docs/PROTOCOL.md` for the byte-level wire format, and
//! `docs/HANDSHAKE.md` for the connection lifecycle (`Hello` -> `HelloAck`
//! -> `Open` -> `OpenAck` -> `Data`, plus `Rekey`).
//!
//! - [`protocol`] is the wire format itself: the fixed header, flags and
//!   message types, the Noise handshake, and the payload transforms
//!   (compression, hex-encoding, checksums, padding) applied before
//!   encryption.
//! - [`network`] is the async glue that drives the protocol over a `tokio`
//!   stream: establishing a connection and sending/receiving messages on it.

use dusa_collection_utils::core::version::VersionCode;

pub mod protocol;
pub mod network;

/// The release channel this build identifies itself as. Encoded into every
/// outgoing message's header version (see
/// [`network::utils::comms_version`]) so peers can detect protocol drift.
pub const RELEASEINFO: VersionCode = VersionCode::Production;
