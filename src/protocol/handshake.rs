//! The `Noise_NK` handshake that secures a `simple_comms` connection, plus
//! `Rekey` support for rotating keys mid-connection. See `docs/HANDSHAKE.md`
//! for the full connection lifecycle and rationale; this module is the
//! implementation of just the `Hello`/`HelloAck` exchange described there.

use std::io;

use snow::{Builder, Keypair, TransportState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::protocol::{
    flags::{ConnectionParams, MsgType},
    message::{ConnectionCtx, ProtocolMessage},
    proto::Proto,
};

/// `Noise_NK_25519_AESGCM_SHA256`: the initiator has no static key of its
/// own, and authenticates the responder using a static key it already knows
/// out-of-band. A single round trip (`Hello` / `HelloAck`) is enough to
/// establish a secure channel.
const NOISE_PARAMS: &str = "Noise_NK_25519_AESGCM_SHA256";

fn noise_error(err: snow::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("noise error: {err:?}"))
}

/// The responder's long-term static identity. The initiator must know the
/// public half of this out-of-band before it can connect.
pub struct NoiseIdentity {
    keypair: Keypair,
}

impl NoiseIdentity {
    /// Generate a fresh static identity keypair.
    pub fn generate() -> io::Result<Self> {
        let keypair = Builder::new(NOISE_PARAMS.parse().map_err(noise_error)?)
            .generate_keypair()
            .map_err(noise_error)?;
        Ok(Self { keypair })
    }

    /// Build an identity from an already-generated keypair (e.g. one loaded
    /// from config/storage rather than freshly generated).
    pub fn from_keypair(private: [u8; 32], public: [u8; 32]) -> Self {
        Self {
            keypair: Keypair {
                private: private.to_vec(),
                public: public.to_vec(),
            },
        }
    }

    /// The 32-byte private half. Callers persisting a responder's identity
    /// across restarts should store this (and reconstruct via
    /// [`Self::from_keypair`]) rather than calling [`Self::generate`] anew
    /// each time -- a new identity invalidates every initiator's pinned
    /// `remote_static_pubkey`.
    pub fn private_key(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.keypair.private);
        out
    }

    /// The 32-byte public half. This is what initiators must be given
    /// out-of-band (config, DNS, a pinned constant, ...) as
    /// `remote_static_pubkey` before they can connect.
    pub fn public_key(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.keypair.public);
        out
    }
}

/// Serializes `payload` as a [`ProtocolMessage`] of the given type without
/// `ConnectionParams::ENCRYPTED` (so `to_bytes` falls back to its
/// single-message key wrapping rather than raw plaintext or the
/// not-yet-established connection cipher -- this frame's own `flags` is
/// always `ConnectionParams::NONE`) and writes it to `stream`. Used only
/// for the handshake's own `Hello`/`HelloAck`/`Rekey`-signal frames --
/// everything after the handshake goes through the normal
/// [`ProtocolMessage::write_to`]/[`crate::network::send_receive`] path.
///
/// `declared_params` is *not* this message's own `flags` (which must stay
/// `NONE` -- see above) -- it's carried in the header's free `reserved`
/// byte instead, purely as data for the peer to read. `Hello` uses this to
/// declare the connection's intended baseline; `HelloAck` doesn't need it
/// (pass `ConnectionParams::NONE`).
async fn write_frame<STREAM>(
    stream: &mut STREAM,
    msg_type: MsgType,
    payload: Vec<u8>,
    declared_params: ConnectionParams,
) -> io::Result<()>
where
    STREAM: AsyncWriteExt + Unpin,
{
    let mut msg: ProtocolMessage<Vec<u8>> =
        ProtocolMessage::new(ConnectionParams::NONE, msg_type, payload)?;
    msg.header.reserved = declared_params.bits();
    // Proto doesn't matter for the handshake's own framing (no Unix-socket
    // flush quirks apply to the small, one-shot Hello/HelloAck exchange);
    // TCP always flushes.
    msg.write_to(stream, Proto::TCP, None).await
}

/// Reads one framed, non-`ENCRYPTED` message from `stream` (see
/// [`write_frame`]) and returns its raw payload plus whatever
/// [`ConnectionParams`] the sender declared in the free `reserved` byte,
/// erroring if its [`MsgType`] doesn't match `expect`. Counterpart to
/// [`write_frame`].
async fn read_frame<STREAM>(
    stream: &mut STREAM,
    expect: MsgType,
) -> io::Result<(Vec<u8>, ConnectionParams)>
where
    STREAM: AsyncReadExt + Unpin,
{
    let msg: ProtocolMessage<Vec<u8>> = ProtocolMessage::read_from(stream, None).await?;
    if msg.msg_type() != expect {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected {expect:?} during handshake, got {:?}", msg.msg_type()),
        ));
    }
    let declared_params = ConnectionParams::from_bits_truncate(msg.header.reserved);
    Ok((msg.payload, declared_params))
}

/// Run the initiator side of the `Noise_NK` handshake: send `Hello`
/// (declaring `params` as this connection's baseline -- see
/// `docs/HANDSHAKE.md`), receive `HelloAck`, and return the resulting
/// transport cipher, a connection id derived from the handshake transcript,
/// and the (unchanged) `params` for convenience when building a
/// [`ConnectionCtx`].
pub async fn perform_handshake_initiator<STREAM>(
    stream: &mut STREAM,
    remote_static_pubkey: &[u8; 32],
    params: ConnectionParams,
) -> io::Result<(TransportState, [u8; 16], ConnectionParams)>
where
    STREAM: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut initiator = Builder::new(NOISE_PARAMS.parse().map_err(noise_error)?)
        .remote_public_key(remote_static_pubkey)
        .map_err(noise_error)?
        .build_initiator()
        .map_err(noise_error)?;

    let mut buf = vec![0u8; 65535];
    let len = initiator.write_message(&[], &mut buf).map_err(noise_error)?;
    write_frame(stream, MsgType::Hello, buf[..len].to_vec(), params).await?;

    let (ack_payload, _ack_flags) = read_frame(stream, MsgType::HelloAck).await?;
    let mut scratch = vec![0u8; 65535];
    initiator
        .read_message(&ack_payload, &mut scratch)
        .map_err(noise_error)?;

    let conn_id = conn_id_from_handshake(&initiator);
    let transport = initiator.into_transport_mode().map_err(noise_error)?;
    Ok((transport, conn_id, params))
}

/// Run the responder side of the `Noise_NK` handshake: receive `Hello`
/// (adopting whatever [`ConnectionParams`] baseline it declares -- see
/// `docs/HANDSHAKE.md`), send `HelloAck`, and return the resulting
/// transport cipher, a connection id derived from the handshake transcript,
/// and the baseline read off `Hello`.
pub async fn perform_handshake_responder<STREAM>(
    stream: &mut STREAM,
    identity: &NoiseIdentity,
) -> io::Result<(TransportState, [u8; 16], ConnectionParams)>
where
    STREAM: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut responder = Builder::new(NOISE_PARAMS.parse().map_err(noise_error)?)
        .local_private_key(&identity.keypair.private)
        .map_err(noise_error)?
        .build_responder()
        .map_err(noise_error)?;

    let (hello_payload, hello_params) = read_frame(stream, MsgType::Hello).await?;
    let mut scratch = vec![0u8; 65535];
    responder
        .read_message(&hello_payload, &mut scratch)
        .map_err(noise_error)?;

    let mut buf = vec![0u8; 65535];
    let len = responder.write_message(&[], &mut buf).map_err(noise_error)?;
    write_frame(stream, MsgType::HelloAck, buf[..len].to_vec(), ConnectionParams::NONE).await?;

    let conn_id = conn_id_from_handshake(&responder);
    let transport = responder.into_transport_mode().map_err(noise_error)?;
    Ok((transport, conn_id, hello_params))
}

pub(crate) fn ctx_from_handshake_result(
    noise: TransportState,
    conn_id: [u8; 16],
    params: ConnectionParams,
) -> ConnectionCtx {
    ConnectionCtx {
        noise,
        conn_id,
        next_seq: 0,
        params,
        insecure: params.contains(ConnectionParams::INSECURE),
    }
}

/// Re-key an existing connection: signal the peer via an encrypted `Rekey`
/// message (consuming a sequence number from the *old* context), then
/// re-run the `Noise_NK` handshake -- carrying `old`'s [`ConnectionParams`]
/// baseline through unchanged, so it persists across the rekey without
/// needing to be re-declared -- and return a fresh `ConnectionCtx`. Call
/// this proactively (e.g. after N messages or T time) -- no separate rekey
/// sub-protocol is needed, since redoing the handshake is cheap.
pub async fn rekey_initiator<STREAM>(
    stream: &mut STREAM,
    old: &mut ConnectionCtx,
    remote_static_pubkey: &[u8; 32],
) -> io::Result<ConnectionCtx>
where
    STREAM: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let signal: ProtocolMessage<()> =
        ProtocolMessage::new(ConnectionParams::ENCRYPTED, MsgType::Rekey, ())?;
    signal.write_to(stream, Proto::TCP, Some(old)).await?;

    let (noise, conn_id, params) =
        perform_handshake_initiator(stream, remote_static_pubkey, old.params).await?;
    Ok(ctx_from_handshake_result(noise, conn_id, params))
}

/// Responder-side counterpart to [`rekey_initiator`]. The caller's receive
/// loop must first read and decrypt the incoming `MsgType::Rekey` message
/// with the *old* `ConnectionCtx` (the same way any other encrypted message
/// is handled) before calling this to process the `Hello` that follows it.
pub async fn rekey_responder<STREAM>(
    stream: &mut STREAM,
    identity: &NoiseIdentity,
) -> io::Result<ConnectionCtx>
where
    STREAM: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let (noise, conn_id, params) = perform_handshake_responder(stream, identity).await?;
    Ok(ctx_from_handshake_result(noise, conn_id, params))
}

/// Derives a connection id from the first 16 bytes of the handshake's
/// transcript hash. Both peers compute an identical value once the
/// handshake completes, without any extra exchange.
fn conn_id_from_handshake(state: &snow::HandshakeState) -> [u8; 16] {
    let hash = state.get_handshake_hash();
    let mut conn_id = [0u8; 16];
    conn_id.copy_from_slice(&hash[..16]);
    conn_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::io_helpers::read_until;
    use crate::protocol::header::EOL;

    #[tokio::test]
    async fn handshake_agrees_on_connection_id() {
        let identity = NoiseIdentity::generate().unwrap();
        let remote_pub = identity.public_key();

        let (mut client, mut server) = tokio::io::duplex(4096);

        // tokio::join! co-polls both sides of the handshake on this same
        // task, so there's no cross-task scheduling race to worry about
        // (unlike tokio::spawn, which can leave one side's stream half
        // dropped mid-handshake if the other side errors first).
        let (initiator_result, responder_result) = tokio::join!(
            perform_handshake_initiator(&mut client, &remote_pub, ConnectionParams::INSECURE),
            perform_handshake_responder(&mut server, &identity),
        );
        let (initiator_transport, initiator_conn_id, initiator_params) = initiator_result.unwrap();
        let (_responder_transport, responder_conn_id, responder_params) = responder_result.unwrap();

        assert_eq!(initiator_conn_id, responder_conn_id);
        assert_eq!(initiator_params, responder_params);
        assert!(responder_params.contains(ConnectionParams::INSECURE));
        assert!(initiator_transport.is_initiator());
    }

    #[tokio::test]
    async fn rekey_produces_a_fresh_connection() {
        let identity = NoiseIdentity::generate().unwrap();
        let remote_pub = identity.public_key();
        let (mut client, mut server) = tokio::io::duplex(4096);

        let client_fut = async {
            let (noise, conn_id, params) =
                perform_handshake_initiator(&mut client, &remote_pub, ConnectionParams::ENCRYPTED)
                    .await
                    .unwrap();
            let mut client_ctx = ctx_from_handshake_result(noise, conn_id, params);
            let old_conn_id = client_ctx.conn_id;
            let new_ctx = rekey_initiator(&mut client, &mut client_ctx, &remote_pub)
                .await
                .unwrap();
            (old_conn_id, new_ctx)
        };

        let server_fut = async {
            let (noise, conn_id, params) = perform_handshake_responder(&mut server, &identity)
                .await
                .unwrap();
            let mut server_ctx = ctx_from_handshake_result(noise, conn_id, params);
            let old_conn_id = server_ctx.conn_id;

            // Consume the encrypted Rekey signal with the old context, then
            // process the fresh Hello that follows it.
            let mut buffer = read_until(&mut server, EOL.to_vec()).await.unwrap();
            if let Some(pos) = buffer.windows(EOL.len()).rposition(|w| w == EOL) {
                buffer.truncate(pos);
            }
            let signal: ProtocolMessage<()> =
                ProtocolMessage::from_bytes(&buffer, Some(&mut server_ctx)).unwrap();
            assert_eq!(signal.msg_type(), MsgType::Rekey);

            let new_ctx = rekey_responder(&mut server, &identity).await.unwrap();
            (old_conn_id, new_ctx)
        };

        // tokio::join! co-polls both sides on this same task -- see the note
        // in `handshake_agrees_on_connection_id` above.
        let ((old_client_conn_id, new_client_ctx), (old_server_conn_id, mut new_server_ctx)) =
            tokio::join!(client_fut, server_fut);

        assert_eq!(old_client_conn_id, old_server_conn_id);
        assert_ne!(new_client_ctx.conn_id, old_client_conn_id);
        assert_eq!(new_client_ctx.conn_id, new_server_ctx.conn_id);
        assert_eq!(new_client_ctx.params, ConnectionParams::ENCRYPTED);

        // The new context actually works for encrypted traffic.
        let mut client_ctx = new_client_ctx;
        let mut data_msg =
            ProtocolMessage::new(ConnectionParams::ENCRYPTED, MsgType::Data, b"post-rekey".to_vec())
                .unwrap();
        let bytes = data_msg.to_bytes(Some(&mut client_ctx)).unwrap();
        let parsed: ProtocolMessage<Vec<u8>> =
            ProtocolMessage::from_bytes(&bytes, Some(&mut new_server_ctx)).unwrap();
        assert_eq!(parsed.payload, b"post-rekey".to_vec());
    }
}
