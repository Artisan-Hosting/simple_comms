//! [`ProtocolMessage`], the framed unit every send/receive call in
//! [`crate::network::send_receive`] operates on, plus the connection
//! ([`ConnectionCtx`]) and logical-session ([`SessionRequest`]/
//! [`SessionAck`]) types it depends on. See `docs/PROTOCOL.md` for the wire
//! layout and `docs/HANDSHAKE.md` for how a `ConnectionCtx` comes to exist.

use std::io::{self, Cursor};

use crate::{
    RELEASEINFO,
    network::utils::{get_header_version, get_local_ip},
    protocol::{
        checksum::{generate_checksum, verify_checksum},
        compression::{compress_data, decompress_data},
        encode::{decode_data, encode_data},
        encryption::{decrypt_with_aes_gcm, encrypt_with_aes_gcm, generate_key},
        flags::{ConnectionParams, MsgType},
        header::{EOL, HEADER_LENGTH, ProtocolHeader, RecordMeta},
        io_helpers::{read_until, read_with_std_io},
        padding::{
             pkcs7_validation, remove_padding_with_scheme,
        },
        proto::Proto,
        status::ProtocolStatus,
    },
};

use dusa_collection_utils::core::logger::LogLevel;
use dusa_collection_utils::{core::version::Version, log};
use serde::{Deserialize, Serialize};
use snow::TransportState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Cryptographic context for one physical connection, established once via
/// the `Noise_NK` handshake (see [`crate::protocol::handshake`]). A single
/// `TransportState` secures every message sent over the connection in both
/// directions; `session_id` in [`RecordMeta`] is a logical multiplexing tag
/// for `Open`/`OpenAck`-negotiated channels layered on top, not a separate
/// crypto boundary.
pub struct ConnectionCtx {
    /// The `Noise_NK` transport cipher, split into independent send/receive
    /// directions internally. Returned by
    /// [`crate::protocol::handshake::perform_handshake_initiator`]/
    /// [`crate::protocol::handshake::perform_handshake_responder`].
    pub noise: TransportState,
    /// Derived from the handshake transcript
    /// ([`snow::HandshakeState::get_handshake_hash`]); identical on both
    /// peers, and used as the default [`RecordMeta::session_id`] for
    /// traffic that isn't tagged with a specific logical session via
    /// [`ProtocolMessage::with_logical_session`].
    pub conn_id: [u8; 16],
    /// Diagnostic-only sequence counter stamped into [`RecordMeta::seq_no`].
    /// Not consulted for security -- the Noise cipher tracks its own
    /// internal nonce counters independently.
    pub next_seq: u32,
    /// The [`ConnectionParams`] baseline this connection was established
    /// with (declared by the initiator on `Hello`, adopted as-is by the
    /// responder). Used by [`crate::network::send_receive::receive_message`]
    /// to detect when a peer sends a message with different params than
    /// expected, and by a successful `SIDEGRADE` renegotiation to record
    /// the new agreed baseline. See `docs/HANDSHAKE.md`.
    pub params: ConnectionParams,
    /// Whether this connection permits mid-connection param renegotiation
    /// via `SIDEGRADE` -- `params.contains(ConnectionParams::INSECURE)`,
    /// cached here for cheap access.
    pub insecure: bool,
}

impl std::fmt::Debug for ConnectionCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionCtx")
            .field("conn_id", &hex::encode(self.conn_id))
            .field("next_seq", &self.next_seq)
            .field("params", &self.params)
            .field("insecure", &self.insecure)
            .finish()
    }
}

/// Payload of a [`MsgType::Open`] message: a request to open a logical,
/// multiplexed session on top of an already-secured connection. Sent
/// encrypted, using the connection's [`ConnectionCtx`]. See
/// `docs/HANDSHAKE.md`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionRequest {
    /// Application-defined name of the service being requested.
    pub service: String,
    /// Application-defined identifier for this particular session/channel.
    pub id: String,
    /// Application-defined port to associate with the session (e.g. the
    /// port a proxied service should be forwarded to).
    pub port: u32,
}

/// Payload of a [`MsgType::OpenAck`] message: acknowledges a
/// [`SessionRequest`]. The responder is expected to assign a
/// [`RecordMeta::session_id`] for this logical session out of band (e.g. via
/// [`ProtocolMessage::with_logical_session`] on the reply) -- this type only
/// carries the port confirmation.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionAck {
    pub port: u32,
}

/// A single framed protocol message: [`ProtocolHeader`] followed by a
/// payload of type `T`. Construct with [`ProtocolMessage::new`], then
/// serialize with [`ProtocolMessage::to_bytes`] (or parse with
/// [`ProtocolMessage::from_bytes`]), or use [`ProtocolMessage::write_to`]/
/// [`ProtocolMessage::read_from`] to go directly to/from a stream.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProtocolMessage<T> {
    pub header: ProtocolHeader,
    pub payload: T,

    /// Which logical (`Open`/`OpenAck`-negotiated) channel this message
    /// belongs to. Only meaningful when `ConnectionParams::ENCRYPTED` is
    /// set -- `None` stamps the connection id instead, the default for
    /// unmultiplexed traffic. Ignored entirely on the fallback
    /// (non-`ENCRYPTED`) path, where `encryption_key` carries a
    /// single-message key instead of a `RecordMeta` overlay.
    #[serde(skip)]
    logical_session_id: Option<[u8; 16]>,
}

impl<T> ProtocolMessage<T>
where
    T: Serialize + for<'a> Deserialize<'a> + std::fmt::Debug + Clone,
{
    /// Create a new protocol message with the provided flags and type.
    pub fn new(flags: ConnectionParams, msg_type: MsgType, payload: T) -> io::Result<Self> {
        let origin_address: [u8; 4] = get_local_ip().octets();
        let header = ProtocolHeader {
            version: get_header_version(),
            flags: flags.bits(),
            payload_length: 0,
            msg_type: msg_type.bits(),
            reserved: 0,
            status: ProtocolStatus::RESERVED.bits(),
            origin_address,
            encryption_key: [0u8; 32],
        };

        Ok(Self {
            header,
            payload,
            logical_session_id: None,
        })
    }

    /// Tag this message with a logical session id (assigned via
    /// `Open`/`OpenAck`) rather than defaulting to the connection id.
    pub fn with_logical_session(mut self, session_id: [u8; 16]) -> Self {
        self.logical_session_id = Some(session_id);
        self
    }

    /// This message's [`ConnectionParams`], read out of the header's
    /// `flags` byte.
    pub fn flags(&self) -> ConnectionParams {
        self.header.flags()
    }

    /// This message's [`ProtocolStatus`], read out of the header's
    /// `status` byte.
    pub fn status(&self) -> ProtocolStatus {
        self.header.status()
    }

    /// Shorthand for `self.flags().contains(ConnectionParams::ENCRYPTED)`.
    pub fn is_encrypted(&self) -> bool {
        self.flags().contains(ConnectionParams::ENCRYPTED)
    }

    /// Serialize the message into bytes ready for transport.
    ///
    /// When `ConnectionParams::ENCRYPTED` is set, `conn` must be provided
    /// -- it holds the `Noise_NK` transport cipher established by the
    /// handshake (see [`crate::protocol::handshake`]). Otherwise `conn` is
    /// unused: the payload is still never sent as raw plaintext, but falls
    /// back to a fresh single-message AES-GCM key carried in the header
    /// (see the comment in the implementation) rather than the
    /// connection's negotiated session key.
    pub fn to_bytes(&mut self, conn: Option<&mut ConnectionCtx>) -> io::Result<Vec<u8>> {
        log!(LogLevel::Trace, "Starting to_bytes conversion.");

        // 1) Serialize payload
        let payload_plain = bincode::serialize(&self.payload)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;

        // === Recommended transform order ===
        let flags = self.header.flags();
        let mut payload = payload_plain.clone();

        if flags.contains(ConnectionParams::COMPRESSED) {
            payload = compress_data(&payload)?;
        }
        if flags.contains(ConnectionParams::ENCODED) {
            payload = encode_data(&payload);
        }
        // If you use padding for length-hiding, do it AFTER compress/encode:
        // payload = add_padding_with_scheme(&payload, 16, pkcs7_padding);

        if flags.contains(ConnectionParams::SIGNATURE) {
            // If this is a plaintext checksum, it should cover the state right before encryption.
            payload = generate_checksum(&mut payload);
        }

        // 2) Encryption
        let header_bytes;
        if flags.contains(ConnectionParams::ENCRYPTED) {
            let ctx = conn.ok_or_else(|| {
                io::Error::new(io::ErrorKind::Other, "missing connection context")
            })?;

            let seq_no = ctx.next_seq;
            ctx.next_seq = ctx.next_seq.wrapping_add(1);

            let meta = RecordMeta {
                session_id: self.logical_session_id.unwrap_or(ctx.conn_id),
                seq_no,
            };
            self.header.set_meta(&meta);

            // The Noise transport cipher tracks its own send/receive nonce
            // counters; we only need to hand it the plaintext.
            let mut ciphertext = vec![0u8; payload.len() + 16];
            let len = ctx.noise.write_message(&payload, &mut ciphertext).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("noise encrypt error: {e:?}"))
            })?;
            ciphertext.truncate(len);

            self.header.payload_length = ciphertext.len() as u64;
            header_bytes = Self::serialize_header(&self.header);
            payload = ciphertext;
        } else {
            // No Noise session requested for this message -- skip session
            // establishment entirely (this is also the path Hello/HelloAck
            // themselves take) and fall back to the scheme used before
            // per-connection sessions existed: a fresh, single-message
            // AES-256-GCM key, generated per message and carried in the
            // header's `encryption_key` field right alongside the
            // ciphertext it protects.
            //
            // This is NOT confidential -- the key travels in the clear in
            // the same message, so anyone who can read the header can
            // decrypt the payload. Its only purpose is to guarantee nothing
            // ever goes out as raw, directly-readable plaintext. Prefer
            // `ConnectionParams::ENCRYPTED` with a `ConnectionCtx` whenever
            // one is available.
            let mut key = [0u8; 32];
            generate_key(&mut key);
            self.header.encryption_key = key;

            let ciphertext = encrypt_with_aes_gcm(&payload, &key)?;
            self.header.payload_length = ciphertext.len() as u64;
            header_bytes = Self::serialize_header(&self.header);
            payload = ciphertext;
        }

        // 3) Frame (delimiter is appended by the caller)
        let mut buffer = Vec::with_capacity(HEADER_LENGTH + payload.len());
        buffer.extend_from_slice(&header_bytes);
        buffer.extend_from_slice(&payload);
        Ok(buffer)
    }

    /// Deserialize a message from raw bytes. `conn` must be provided when
    /// the `ENCRYPTED` flag is set, for decryption; otherwise the
    /// single-message key is read directly out of the header (see
    /// [`Self::to_bytes`]).
    pub fn from_bytes(bytes: &[u8], conn: Option<&mut ConnectionCtx>) -> io::Result<Self> {
        log!(LogLevel::Trace, "Starting from_bytes conversion.");

        if bytes.len() < HEADER_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Byte array too short to contain valid header",
            ));
        }

        let header_bytes = &bytes[..HEADER_LENGTH];
        let payload_bytes = &bytes[HEADER_LENGTH..];

        // deserialize header
        let mut cursor = Cursor::new(header_bytes);
        let mut version_bytes = [0u8; 2];
        read_with_std_io(&mut cursor, &mut version_bytes)?;
        let version = u16::from_be_bytes(version_bytes);

        // version check
        let incoming_version = Version::decode(version);
        let current_version = Version::new(env!("CARGO_PKG_VERSION"), RELEASEINFO);
        if !current_version.compare_versions(&incoming_version) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Out of date message recieved",
            ));
        }

        let mut b = [0u8; 1];
        read_with_std_io(&mut cursor, &mut b)?;
        let flags = b[0];

        let mut len_bytes = [0u8; 8];
        read_with_std_io(&mut cursor, &mut len_bytes)?;
        let payload_length = u64::from_be_bytes(len_bytes);

        read_with_std_io(&mut cursor, &mut b)?;
        let msg_type = b[0];

        read_with_std_io(&mut cursor, &mut b)?;
        let reserved = b[0];

        read_with_std_io(&mut cursor, &mut b)?;
        let status = b[0];

        let mut origin_address = [0u8; 4];
        read_with_std_io(&mut cursor, &mut origin_address)?;

        let mut encryption_key = [0u8; 32];
        read_with_std_io(&mut cursor, &mut encryption_key)?;

        let header: ProtocolHeader = ProtocolHeader {
            version,
            flags,
            payload_length,
            msg_type,
            reserved,
            status,
            origin_address,
            encryption_key,
        };

        let mut payload = payload_bytes.to_vec();
        let flags = header.flags();

        // decrypt if necessary
        if flags.contains(ConnectionParams::ENCRYPTED) {
            let ctx = conn.ok_or_else(|| {
                io::Error::new(io::ErrorKind::Other, "missing connection context")
            })?;

            let mut plain = vec![0u8; payload.len()];
            let len = ctx.noise.read_message(&payload, &mut plain).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("noise decrypt error: {e:?}"))
            })?;
            plain.truncate(len);
            payload = plain;
        } else {
            // Fallback path -- see the matching branch in to_bytes. The key
            // was carried in the clear in the header, right alongside the
            // ciphertext it protects.
            payload = decrypt_with_aes_gcm(&payload, &header.encryption_key)?;
        }

        // Reverse order transforms
        if flags.contains(ConnectionParams::SIGNATURE) {
            payload = verify_checksum(payload);
        }
        if flags.contains(ConnectionParams::ENCODED) {
            payload = decode_data(&payload).unwrap();
        }
        if flags.contains(ConnectionParams::COMPRESSED) {
            payload = decompress_data(&payload)?;
        }

        payload = match remove_padding_with_scheme(&payload, 16, pkcs7_validation) {
            Ok(p) => p,
            Err(_) => payload,
        };

        let payload: T = bincode::deserialize(&payload)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;

        Ok(Self {
            header,
            payload,
            logical_session_id: None,
        })
    }

    /// [`Self::to_bytes`], with the [`EOL`] frame delimiter appended --
    /// ready to write directly to a stream.
    pub async fn format(mut self, conn: Option<&mut ConnectionCtx>) -> io::Result<Vec<u8>> {
        let mut bytes = self.to_bytes(conn)?;
        bytes.extend_from_slice(EOL);
        Ok(bytes)
    }

    /// Serializes this message (see [`Self::format`]) and writes it
    /// directly to `stream`, flushing when `proto` is [`Proto::TCP`]
    /// (flushing is skipped for [`Proto::UNIX`], matching
    /// [`crate::network::send_receive::send_data`]'s behavior).
    pub async fn write_to<STREAM>(
        self,
        stream: &mut STREAM,
        proto: Proto,
        conn: Option<&mut ConnectionCtx>,
    ) -> io::Result<()>
    where
        STREAM: AsyncWriteExt + Unpin,
    {
        let bytes = self.format(conn).await?;
        stream.write_all(&bytes).await?;
        if proto == Proto::TCP {
            stream.flush().await?;
        }
        Ok(())
    }

    /// Reads one framed message off `stream` (via
    /// [`crate::protocol::io_helpers::read_until`]) and parses it (see
    /// [`Self::from_bytes`]).
    pub async fn read_from<STREAM>(
        stream: &mut STREAM,
        conn: Option<&mut ConnectionCtx>,
    ) -> io::Result<Self>
    where
        STREAM: AsyncReadExt + Unpin,
    {
        let buffer = read_until(stream, EOL.to_vec()).await?;
        Self::from_bytes(&buffer, conn)
    }

    /// Packs a [`ProtocolHeader`]'s fields into their fixed-width,
    /// big-endian wire representation (see `docs/PROTOCOL.md`).
    fn serialize_header(h: &ProtocolHeader) -> Vec<u8> {
        let mut header_bytes: Vec<u8> = Vec::with_capacity(HEADER_LENGTH);
        header_bytes.extend(&h.version.to_be_bytes());
        header_bytes.extend(&h.flags.to_be_bytes());
        header_bytes.extend(&h.payload_length.to_be_bytes());
        header_bytes.extend(&h.msg_type.to_be_bytes());
        header_bytes.extend(&h.reserved.to_be_bytes());
        header_bytes.extend(&h.status.to_be_bytes());
        header_bytes.extend(&h.origin_address);
        header_bytes.extend(&h.encryption_key);
        header_bytes
    }

    /// This message's [`MsgType`], read out of the header's `msg_type` byte.
    pub fn msg_type(&self) -> MsgType {
        self.header.msg_type()
    }

    pub fn set_msg_type(&mut self, t: MsgType) {
        self.header.set_msg_type(t);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::handshake::{
        NoiseIdentity, perform_handshake_initiator, perform_handshake_responder,
    };

    #[test]
    fn msg_type_roundtrip() {
        let msg: ProtocolMessage<()> =
            ProtocolMessage::new(ConnectionParams::empty(), MsgType::Heartbeat, ()).unwrap();
        assert_eq!(msg.msg_type(), MsgType::Heartbeat);
    }

    /// Without `ConnectionParams::ENCRYPTED`, no `ConnectionCtx` is needed
    /// at all -- the message still round-trips, and the payload never
    /// appears as a readable substring of the bytes actually sent on the
    /// wire.
    #[test]
    fn unencrypted_messages_fall_back_to_a_single_message_key() {
        let plaintext = b"do not leak this".to_vec();
        let mut msg =
            ProtocolMessage::new(ConnectionParams::NONE, MsgType::Data, plaintext.clone()).unwrap();
        let bytes = msg.to_bytes(None).unwrap();

        // The fallback key travels in the header, and the payload is
        // AES-GCM ciphertext under it -- never the raw bytes.
        assert_ne!(msg.header.encryption_key, [0u8; 32]);
        assert!(
            bytes.windows(plaintext.len()).all(|w| w != plaintext.as_slice()),
            "plaintext must not appear verbatim in the serialized message"
        );

        let parsed: ProtocolMessage<Vec<u8>> =
            ProtocolMessage::from_bytes(&bytes, None).unwrap();
        assert_eq!(parsed.payload, plaintext);
    }

    fn test_conn_ctx(noise: TransportState, conn_id: [u8; 16]) -> ConnectionCtx {
        ConnectionCtx {
            noise,
            conn_id,
            next_seq: 0,
            params: ConnectionParams::ENCRYPTED,
            insecure: false,
        }
    }

    /// Full Hello -> HelloAck -> Open -> OpenAck -> Data flow: establishes a
    /// real `Noise_NK` connection over an in-memory duplex stream, then
    /// exercises the encrypted message path on top of it.
    #[tokio::test]
    async fn encrypt_decrypt_roundtrip() {
        let identity = NoiseIdentity::generate().unwrap();
        let remote_pub = identity.public_key();
        let (mut client_stream, mut server_stream) = tokio::io::duplex(8192);

        let params = ConnectionParams::ENCRYPTED;
        // tokio::join! co-polls both sides on this same task -- avoids the
        // cross-task scheduling race that tokio::spawn can hit if one side
        // errors/finishes before the other has been polled (see the same
        // note in handshake.rs's tests).
        let (initiator_result, responder_result) = tokio::join!(
            perform_handshake_initiator(&mut client_stream, &remote_pub, params),
            perform_handshake_responder(&mut server_stream, &identity),
        );
        let (client_transport, client_conn_id, client_params) = initiator_result.unwrap();
        let (server_transport, server_conn_id, server_params) = responder_result.unwrap();
        assert_eq!(client_conn_id, server_conn_id);
        assert_eq!(client_params, server_params);

        let mut client_ctx = test_conn_ctx(client_transport, client_conn_id);
        client_ctx.params = client_params;
        let mut server_ctx = test_conn_ctx(server_transport, server_conn_id);
        server_ctx.params = server_params;

        // Open a logical session on top of the now-secured connection.
        let request = SessionRequest {
            service: "echo".into(),
            id: "test-channel".into(),
            port: 9000,
        };
        let mut open_msg =
            ProtocolMessage::new(ConnectionParams::ENCRYPTED, MsgType::Open, request.clone()).unwrap();
        let open_bytes = open_msg.to_bytes(Some(&mut client_ctx)).unwrap();
        let parsed_open: ProtocolMessage<SessionRequest> =
            ProtocolMessage::from_bytes(&open_bytes, Some(&mut server_ctx)).unwrap();
        assert_eq!(parsed_open.payload.id, request.id);
        assert_eq!(parsed_open.msg_type(), MsgType::Open);

        // Server assigns a logical session id and acknowledges.
        let session_id = server_ctx.conn_id;
        let ack = SessionAck { port: request.port };
        let mut ack_msg = ProtocolMessage::new(ConnectionParams::ENCRYPTED, MsgType::OpenAck, ack)
            .unwrap()
            .with_logical_session(session_id);
        let ack_bytes = ack_msg.to_bytes(Some(&mut server_ctx)).unwrap();
        let parsed_ack: ProtocolMessage<SessionAck> =
            ProtocolMessage::from_bytes(&ack_bytes, Some(&mut client_ctx)).unwrap();
        assert_eq!(parsed_ack.payload.port, request.port);

        // Data flows on the negotiated logical session.
        let mut data_msg =
            ProtocolMessage::new(ConnectionParams::ENCRYPTED, MsgType::Data, b"hello".to_vec())
                .unwrap()
                .with_logical_session(session_id);
        let data_bytes = data_msg.to_bytes(Some(&mut client_ctx)).unwrap();
        let parsed_data: ProtocolMessage<Vec<u8>> =
            ProtocolMessage::from_bytes(&data_bytes, Some(&mut server_ctx)).unwrap();
        assert_eq!(parsed_data.payload, b"hello".to_vec());
        assert_eq!(parsed_data.msg_type(), MsgType::Data);
        assert_eq!(parsed_data.header.meta().session_id, session_id);
        assert!(parsed_data.is_encrypted());
    }
}
