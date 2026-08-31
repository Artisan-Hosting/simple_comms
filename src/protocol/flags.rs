//! The parameters a connection communicates with ([`ConnectionParams`]) and
//! the single discrete kind of message being sent ([`MsgType`]). Both live
//! in the fixed header (see [`crate::protocol::header::ProtocolHeader`]) --
//! `ConnectionParams` in the `flags` byte, `MsgType` (packed via
//! [`MsgType::bits`]) in the dedicated `msg_type` byte. See
//! `docs/PROTOCOL.md` for the full header layout.

use std::fmt;

use colored::Colorize;

bitflags::bitflags! {
    /// The parameters a connection communicates with, applied (when
    /// serializing) in the fixed order
    /// [`crate::protocol::message::ProtocolMessage::to_bytes`] applies
    /// them: compress -> hex-encode -> checksum -> encrypt. Unlike
    /// [`MsgType`], these are genuine bitflags -- a message can be e.g.
    /// both `COMPRESSED` and `ENCRYPTED` at once.
    ///
    /// These are connection-level, not fire-and-forget per-message
    /// choices: a connection is established with a baseline set of params
    /// (see [`crate::protocol::message::ConnectionCtx::params`]), and
    /// `docs/HANDSHAKE.md` describes how a `SIDEGRADE` response
    /// renegotiates them mid-connection when `INSECURE` permits it.
    #[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
    pub struct ConnectionParams: u8 {
        const NONE       = 0b0000_0000;
        /// Payload is gzip-compressed; see [`crate::protocol::compression`].
        const COMPRESSED = 0b0000_0001;
        /// Payload is encrypted with the connection's `Noise_NK` transport
        /// cipher. Requires a [`crate::protocol::message::ConnectionCtx`] to
        /// be passed to `to_bytes`/`from_bytes`; see `docs/HANDSHAKE.md`.
        ///
        /// When this is *not* set, the payload isn't sent as plaintext
        /// either -- `to_bytes` falls back to a fresh, single-message
        /// AES-GCM key carried in the header instead (no real
        /// confidentiality, since the key travels alongside the
        /// ciphertext it protects, but nothing ever goes out fully in the
        /// clear). See the fallback branch in `ProtocolMessage::to_bytes`.
        const ENCRYPTED  = 0b0000_0010;
        /// Payload is hex-encoded; see [`crate::protocol::encode`].
        const ENCODED    = 0b0000_0100;
        /// A trailing SHA-256 checksum covers the payload; see
        /// [`crate::protocol::checksum`].
        const SIGNATURE  = 0b0000_1000;
        const OPTIMIZED  = 0b0000_1111; //
        /// Declared by the initiator on the `Hello` message: whether this
        /// connection permits mid-connection param renegotiation via a
        /// `SIDEGRADE` response. Carried into
        /// [`crate::protocol::message::ConnectionCtx::insecure`] by both
        /// peers once the handshake completes; see `docs/HANDSHAKE.md`.
        const INSECURE   = 0b0001_0000;
        // Add other flags as needed
    }
}

impl ConnectionParams {
    /// Whether `self` is *exactly* `val` -- not merely a superset. A
    /// stricter check than [`bitflags::Flags::contains`].
    pub fn expect(&self, val: ConnectionParams) -> bool {
        // Checks if `self` contains exactly the same flags as `val`
        *self == val
    }
}

impl fmt::Display for ConnectionParams {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut flags = vec![];
        if self.contains(ConnectionParams::COMPRESSED) {
            flags.push("Compressed".cyan().to_string());
        }
        if self.contains(ConnectionParams::ENCRYPTED) {
            flags.push("Encrypted".magenta().to_string());
        }
        if self.contains(ConnectionParams::ENCODED) {
            flags.push("Encoded".blue().to_string());
        }
        if self.contains(ConnectionParams::SIGNATURE) {
            flags.push("Signed".yellow().to_string());
        }
        if self.contains(ConnectionParams::OPTIMIZED) {
            flags.push("SECURE".bright_green().bold().to_string());
        }
        if self.contains(ConnectionParams::INSECURE) {
            flags.push("INSECURE".bright_red().bold().to_string());
        }
        write!(f, "{}", flags.join(", "))
    }
}

/// A message's type is a single discrete value (a message is never
/// simultaneously `Hello` and `Data`), so this is a plain enum rather than
/// bitflags -- there is no room for a 9th one-hot bit in a u8 anyway.
///
/// See `docs/HANDSHAKE.md` for the full connection lifecycle these values
/// walk through: `Hello`/`HelloAck` secure the connection, `Open`/`OpenAck`
/// negotiate a logical, multiplexed session on top of it, `Data` carries
/// application payloads, and `Rekey` re-runs the handshake to rotate keys.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MsgType {
    /// Initiator -> responder: first message of the `Noise_NK` handshake.
    /// Sent without `ConnectionParams::ENCRYPTED` (there's no connection
    /// cipher yet -- this is what establishes one), but still
    /// fallback-wrapped like any other non-`ENCRYPTED` message; see
    /// [`crate::protocol::handshake::perform_handshake_initiator`].
    Hello = 0,
    /// Responder -> initiator: completes the `Noise_NK` handshake. Same
    /// `ENCRYPTED`-unset, fallback-wrapped treatment as `Hello`; see
    /// [`crate::protocol::handshake::perform_handshake_responder`].
    HelloAck = 1,
    /// Request to open a logical, multiplexed session on an already-secured
    /// connection. Payload is
    /// [`crate::protocol::message::SessionRequest`].
    Open = 2,
    /// Acknowledges an `Open` request. Payload is
    /// [`crate::protocol::message::SessionAck`].
    OpenAck = 3,
    /// An application payload on an established (and optionally
    /// logically-sessioned) connection.
    Data = 4,
    /// Keepalive/liveness probe; see [`crate::protocol::heartbeat`].
    Heartbeat = 5,
    /// Graceful connection teardown.
    Close = 6,
    /// Carries a [`crate::protocol::status::ProtocolStatus`] error rather
    /// than a normal payload.
    Error = 7,
    /// Signals that the sender is about to re-run the `Noise_NK` handshake
    /// to rotate keys; see
    /// [`crate::protocol::handshake::rekey_initiator`].
    Rekey = 8,
    /// Any byte that doesn't map to a known variant.
    Unknown = 255,
}

impl From<u8> for MsgType {
    fn from(b: u8) -> Self {
        match b {
            0 => MsgType::Hello,
            1 => MsgType::HelloAck,
            2 => MsgType::Open,
            3 => MsgType::OpenAck,
            4 => MsgType::Data,
            5 => MsgType::Heartbeat,
            6 => MsgType::Close,
            7 => MsgType::Error,
            8 => MsgType::Rekey,
            _ => MsgType::Unknown,
        }
    }
}

impl From<MsgType> for u8 {
    fn from(t: MsgType) -> u8 {
        t as u8
    }
}

impl MsgType {
    /// The raw byte stored in [`crate::protocol::header::ProtocolHeader::msg_type`].
    pub fn bits(self) -> u8 {
        self.into()
    }
}

#[cfg(test)]
mod msg_type_tests {
    use super::MsgType;

    #[test]
    fn msg_type_bits_roundtrip() {
        let variants = [
            MsgType::Hello,
            MsgType::HelloAck,
            MsgType::Open,
            MsgType::OpenAck,
            MsgType::Data,
            MsgType::Heartbeat,
            MsgType::Close,
            MsgType::Error,
            MsgType::Rekey,
        ];
        for v in variants {
            assert_eq!(MsgType::from(v.bits()), v);
        }
        assert_eq!(MsgType::from(254u8), MsgType::Unknown);
    }
}
