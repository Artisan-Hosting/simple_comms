//! The fixed-size [`ProtocolHeader`] every message starts with, and the
//! [`RecordMeta`] overlay carried inside its `encryption_key` field. See
//! `docs/PROTOCOL.md` for the full byte-level layout.

use colored::Colorize;
use dusa_collection_utils::core::types::stringy::Stringy;
use dusa_collection_utils::core::version::Version;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;

use crate::protocol::flags::{ConnectionParams, MsgType};
use crate::protocol::status::ProtocolStatus;

/// Metadata that overlays the `encryption_key` field in the header
/// whenever `ConnectionParams::ENCRYPTED` is set (see
/// [`ProtocolHeader::encryption_key`] for the other case).
///
/// The layout (all in network byte order) is:
/// `session_id[16] || seq_no[4]`, followed by 12 reserved/zeroed bytes.
///
/// `session_id` is a *logical* multiplexing tag assigned via `Open`/`OpenAck`
/// (or the connection id, for unmultiplexed traffic) -- it does not identify
/// a cryptographic key. The actual transport encryption is a single
/// `Noise_NK` session per physical connection (see
/// [`crate::protocol::handshake`] and [`crate::protocol::message::ConnectionCtx`]),
/// which tracks its own send/receive nonce counters internally, so there is
/// nothing nonce-related left to transmit here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordMeta {
    /// Logical multiplexing tag. Both sides share the same value for a given
    /// logical session/channel.
    pub session_id: [u8; 16],
    /// Monotonic sequence number used for ordering/diagnostics.
    pub seq_no: u32,
}


/// The fixed [`HEADER_LENGTH`]-byte header that prefixes every message on
/// the wire, followed by the (possibly transformed/encrypted) payload and
/// then the [`EOL`] delimiter.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProtocolHeader {
    /// This build's [`crate::network::utils::comms_version`], encoded via
    /// [`Version::encode`]. Checked against the peer's version on receipt.
    pub version: u16,
    /// Raw bits of a [`ConnectionParams`] value; read/write via
    /// [`ProtocolHeader::flags`]/[`ProtocolHeader::set_flags`].
    pub flags: u8,
    /// Length in bytes of the payload that follows this header (after any
    /// compression/encoding/encryption has already been applied to it).
    pub payload_length: u64,
    /// Raw bits of a [`MsgType`] value; read/write via
    /// [`ProtocolHeader::msg_type`]/[`ProtocolHeader::set_msg_type`].
    pub msg_type: u8,
    /// Genuinely free for future use -- e.g. a `SIDEGRADE` response's
    /// requested [`ConnectionParams`] (see
    /// [`crate::network::send_receive::send_sidegrade`]). Not read or
    /// written by anything else in this crate.
    pub reserved: u8,
    /// Raw bits of a [`ProtocolStatus`] value; read/write via
    /// [`ProtocolHeader::status`]/[`ProtocolHeader::set_status`].
    pub status: u8,
    /// The sender's local IPv4 address for TCP, or all-zero for a Unix
    /// socket (see [`crate::protocol::proto::Proto`]).
    pub origin_address: [u8; 4],
    /// Dual-purpose, depending on `flags`:
    /// - `ConnectionParams::ENCRYPTED` set: the [`RecordMeta`] overlay
    ///   (session routing + sequence number). The actual transport
    ///   encryption key lives in the connection's
    ///   [`crate::protocol::message::ConnectionCtx`], established
    ///   out-of-band by the `Noise_NK` handshake -- never transmitted in
    ///   the header in this case.
    /// - `ConnectionParams::ENCRYPTED` unset: a literal, freshly-generated
    ///   AES-256 key that decrypts *this message's own payload*. Sent in
    ///   the clear alongside the ciphertext it protects -- this is an
    ///   obfuscation-only fallback (see `ProtocolMessage::to_bytes`), not a
    ///   confidentiality guarantee.
    pub encryption_key: [u8; 32],
}

impl fmt::Display for ProtocolHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let version: Version = Version::decode(self.version);

        let origin_addr: Stringy = match self.get_origin_ip() == IpAddr::V4([0, 0, 0, 0].into()) {
            true => Stringy::from("Internal"),
            false => Stringy::from(self.get_origin_ip().to_string()),
        };

        write!(
            f,
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            format!("Library Version:  {}", version).bold().green(),
            format!(
                "Flags:            {:#010b} ({})",
                self.flags,
                self.flags()
            )
            .bold()
            .blue(),
            format!(
                "Type:            ({:?})",
                self.msg_type(),
            )
            .bold()
            .blue(),
            format!(
                "Payload Key:      {}",
                if self.encryption_key == [0u8; 32] {
                    "No Key Set".to_string()
                } else {
                    format!("{}", hex::encode(self.encryption_key))
                }
            )
            .bold()
            .purple(),
            format!("Payload Length:   {}", self.payload_length)
                .bold()
                .purple(),
            format!(
                "Status:           {:#010b} ({})",
                self.status,
                self.status()
            )
            .bold()
            .red(),
            format!("Origin Address:   {}", origin_addr).bold().cyan(),
        )
    }
}

impl ProtocolHeader {
    /// Decodes `origin_address` back into an [`std::net::Ipv4Addr`].
    pub fn get_origin_ip(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(self.origin_address)
    }

    /// Extract the [`RecordMeta`] overlay from `encryption_key`.
    pub fn meta(&self) -> RecordMeta {
        let mut sid = [0u8; 16];
        sid.copy_from_slice(&self.encryption_key[0..16]);
        let mut seq = [0u8; 4];
        seq.copy_from_slice(&self.encryption_key[16..20]);
        RecordMeta {
            session_id: sid,
            seq_no: u32::from_be_bytes(seq),
        }
    }

    /// Write the [`RecordMeta`] overlay into `encryption_key`. Bytes 20..32
    /// are reserved and left zeroed.
    pub fn set_meta(&mut self, m: &RecordMeta) {
        self.encryption_key[0..16].copy_from_slice(&m.session_id);
        self.encryption_key[16..20].copy_from_slice(&m.seq_no.to_be_bytes());
        self.encryption_key[20..32].fill(0);
    }

    /// Read the `msg_type` field as a [`MsgType`].
    pub fn msg_type(&self) -> MsgType {
        MsgType::from(self.msg_type)
    }

    /// Set the `msg_type` field to the provided [`MsgType`].
    pub fn set_msg_type(&mut self, t: MsgType) {
        self.msg_type = t.bits();
    }

    /// Read the `flags` field as a [`ConnectionParams`].
    pub fn flags(&self) -> ConnectionParams {
        ConnectionParams::from_bits_truncate(self.flags)
    }

    /// Set the `flags` field to the provided [`ConnectionParams`].
    pub fn set_flags(&mut self, params: ConnectionParams) {
        self.flags = params.bits();
    }

    /// Read the `status` field as a [`ProtocolStatus`].
    pub fn status(&self) -> ProtocolStatus {
        ProtocolStatus::from_bits_truncate(self.status)
    }

    /// Set the `status` field to the provided [`ProtocolStatus`].
    pub fn set_status(&mut self, status: ProtocolStatus) {
        self.status = status.bits();
    }
}

// HEADER LEGNTH DATA.
// IF THIS IS WRONG data will be offset or err not enough data for a message

const HEADER_VERSION_LEN: usize = 2; // u16
const HEADER_FLAGS_LEN: usize = 1; // u8
const HEADER_PAYLOAD_LENGTH_LEN: usize = 8; // u64
const HEADER_MSG_TYPE_LEN: usize = 1; // u8
const HEADER_RESERVED_LEN: usize = 1; // u8, genuinely free
const HEADER_STATUS_LEN: usize = 1; // u8 for ProtocolStatus
const HEADER_ORIGIN_ADDRESS_LEN: usize = 4; // [u8; 4] for IPv4 address
const HEADER_ENCRYPTION_KEY_LEN: usize = 32; // [u8; 32], dual-purpose -- see ProtocolHeader::encryption_key

//  +------------------------ 32 bytes -----------------------+
//  |  session_id (16)  |  seq_no (4)  |  reserved (12)        |
//  +-----------------------------------------------------------+

/// Total byte length of a serialized [`ProtocolHeader`] -- the number of
/// bytes [`crate::protocol::message::ProtocolMessage::from_bytes`] consumes
/// before it starts reading the payload.
// Calculate the fixed header length
pub const HEADER_LENGTH: usize = HEADER_VERSION_LEN
    + HEADER_FLAGS_LEN
    + HEADER_PAYLOAD_LENGTH_LEN
    + HEADER_MSG_TYPE_LEN
    + HEADER_RESERVED_LEN
    + HEADER_STATUS_LEN
    + HEADER_ORIGIN_ADDRESS_LEN
    + HEADER_ENCRYPTION_KEY_LEN;

/// End-of-message delimiter. Every serialized message is followed by
/// exactly one copy of this; see [`crate::protocol::io_helpers::read_until`].
pub const EOL: &[u8] = b"-EOL-";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_meta_roundtrip() {
        let meta = RecordMeta {
            session_id: [0xAA; 16],
            seq_no: 42,
        };

        let mut header = ProtocolHeader {
            version: 2,
            flags: 0,
            payload_length: 0,
            msg_type: 0,
            reserved: 0,
            status: 0,
            origin_address: [0; 4],
            encryption_key: [0u8; 32],
        };

        header.set_meta(&meta);
        let parsed = header.meta();
        assert_eq!(parsed, meta);
    }

    #[test]
    fn msg_type_and_reserved_are_independent() {
        let mut header = ProtocolHeader {
            version: 2,
            flags: 0,
            payload_length: 0,
            msg_type: 0,
            reserved: 0,
            status: 0,
            origin_address: [0; 4],
            encryption_key: [0u8; 32],
        };

        header.set_msg_type(MsgType::Data);
        header.reserved = ConnectionParams::COMPRESSED.bits();

        assert_eq!(header.msg_type(), MsgType::Data);
        assert_eq!(header.reserved, ConnectionParams::COMPRESSED.bits());
    }

    #[test]
    fn flags_and_status_accessors_roundtrip() {
        let mut header = ProtocolHeader {
            version: 2,
            flags: 0,
            payload_length: 0,
            msg_type: 0,
            reserved: 0,
            status: 0,
            origin_address: [0; 4],
            encryption_key: [0u8; 32],
        };

        header.set_flags(ConnectionParams::ENCRYPTED | ConnectionParams::COMPRESSED);
        header.set_status(ProtocolStatus::OK);

        assert_eq!(
            header.flags(),
            ConnectionParams::ENCRYPTED | ConnectionParams::COMPRESSED
        );
        assert_eq!(header.status(), ProtocolStatus::OK);
    }
}
