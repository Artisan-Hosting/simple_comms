//! Establishing a `Noise_NK`-secured connection (`establish_connection_initiator`/
//! `establish_connection_responder`) and sending/receiving framed
//! messages on it (`send_message`/`receive_message`), including
//! responder-side `SIDEGRADE` param renegotiation (`send_sidegrade`,
//! `receive_message_with_required_params`). See `docs/HANDSHAKE.md` for the
//! connection lifecycle these functions implement.


use dusa_collection_utils::core::logger::LogLevel;
use dusa_collection_utils::{log, core::version::Version};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

use crate::network::utils::{comms_version, get_local_ip};
use crate::protocol::{
    flags::{ConnectionParams, MsgType},
    handshake::{NoiseIdentity, ctx_from_handshake_result, perform_handshake_initiator, perform_handshake_responder},
    message::{ConnectionCtx, ProtocolMessage},
    proto::Proto,
    status::ProtocolStatus,
};

/// Run the initiator side of the `Noise_NK` handshake (`Hello`/`HelloAck`)
/// over an already-connected stream, declaring `params` as this
/// connection's baseline (see `docs/HANDSHAKE.md`) and establishing the
/// connection-wide transport cipher that `send_message`/`receive_message`
/// need for any `ConnectionParams::ENCRYPTED` traffic.
pub async fn establish_connection_initiator<STREAM>(
    stream: &mut STREAM,
    remote_static_pubkey: &[u8; 32],
    params: ConnectionParams,
) -> io::Result<ConnectionCtx>
where
    STREAM: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let (noise, conn_id, params) =
        perform_handshake_initiator(stream, remote_static_pubkey, params).await?;
    Ok(ctx_from_handshake_result(noise, conn_id, params))
}

/// Run the responder side of the `Noise_NK` handshake, using `identity` as
/// this side's long-term static key and adopting whatever
/// [`ConnectionParams`] baseline the initiator declares on `Hello`.
pub async fn establish_connection_responder<STREAM>(
    stream: &mut STREAM,
    identity: &NoiseIdentity,
) -> io::Result<ConnectionCtx>
where
    STREAM: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let (noise, conn_id, params) = perform_handshake_responder(stream, identity).await?;
    Ok(ctx_from_handshake_result(noise, conn_id, params))
}

/// Sends `data` as a `Data` message and waits for a single response.
///
/// Pass `conn` (from [`establish_connection_initiator`]/
/// [`establish_connection_responder`]) whenever `flags` includes
/// `ConnectionParams::ENCRYPTED`. Omitting it (`None`) doesn't send the
/// payload as plaintext -- `ProtocolMessage::to_bytes` still falls back to
/// a single-message key -- it's just not backed by the connection's
/// negotiated Noise session, so only do this pre-handshake or when that
/// weaker guarantee is acceptable.
///
/// If the peer's response carries `ProtocolStatus::SIDEGRADE`, this retries
/// the send once with the params the peer's `reserved` byte requested.
/// Whether that retry is attempted is no longer a parameter here -- it's
/// read from `conn.insecure` (declared once, at handshake time; see
/// `docs/HANDSHAKE.md`), defaulting to `false` (no retry) when `conn` is
/// `None`.
pub async fn send_message<STREAM, DATA, RESPONSE>(
    mut stream: &mut STREAM,
    flags: ConnectionParams,
    data: DATA,
    proto: Proto,
    mut conn: Option<&mut ConnectionCtx>,
) -> Result<Result<ProtocolMessage<RESPONSE>, ProtocolStatus>, io::Error>
where
    STREAM: AsyncReadExt + AsyncWriteExt + Unpin,
    DATA: serde::de::DeserializeOwned + std::fmt::Debug + serde::Serialize + Clone + Unpin,
    RESPONSE: serde::de::DeserializeOwned + std::fmt::Debug + serde::Serialize + Clone + Unpin,
{
    let insecure = conn.as_ref().map(|c| c.insecure).unwrap_or(false);

    let mut message: ProtocolMessage<DATA> =
        ProtocolMessage::new(flags, MsgType::Data, data.clone())?;

    match proto {
        Proto::TCP => message.header.origin_address = get_local_ip().octets(),
        Proto::UNIX => message.header.origin_address = [0, 0, 0, 0],
    };

    log!(LogLevel::Trace, "message serialized for sending");

    message
        .write_to(&mut stream, proto, conn.as_deref_mut())
        .await?;
    log!(LogLevel::Trace, "Message sent over {proto}");

    match ProtocolMessage::<RESPONSE>::read_from(&mut stream, conn.as_deref_mut()).await {
        Ok(response) => {
            let response_status: ProtocolStatus = response.status();
            let response_params: ConnectionParams =
                ConnectionParams::from_bits_truncate(response.header.reserved);
            let response_version: Version = Version::decode(response.header.version);

            let in_band = Version::compare_versions(&comms_version(), &response_version);

            if !insecure && !in_band {
                return Ok(Err(ProtocolStatus::NOTINBAND));
            }

            if response_status.has_flag(ProtocolStatus::SIDEGRADE) {
                log!(LogLevel::Debug, "SideGrade requested");
                if insecure {
                    return Box::pin(send_message::<STREAM, DATA, RESPONSE>(
                        stream,
                        response_params,
                        data,
                        proto,
                        conn,
                    ))
                    .await;
                } else {
                    log!(LogLevel::Info, "Sidegrade not allowed dropping connections");
                    stream.shutdown().await?;
                    return Ok(Err(ProtocolStatus::REFUSED));
                }
            }
            log!(LogLevel::Trace, "Received response: {:?}", response);
            Ok(Ok(response))
        }
        Err(err) => Err(err),
    }
}

/// Core of [`receive_message`]/[`receive_message_with_required_params`]:
/// reads one message, and if `required` is `Some(want)` and the message's
/// params don't already satisfy `want`, logs the mismatch and -- when
/// `force` is set, or `conn.insecure` is true -- transparently sends a
/// `SIDEGRADE` requesting `want`, reads a single retry, and (on success)
/// records `want` as the connection's new baseline.
async fn receive_message_impl<STREAM, RESPONSE>(
    stream: &mut STREAM,
    auto_reply: bool,
    proto: Proto,
    mut conn: Option<&mut ConnectionCtx>,
    required: Option<ConnectionParams>,
    force: bool,
) -> io::Result<ProtocolMessage<RESPONSE>>
where
    STREAM: AsyncReadExt + AsyncWriteExt + Unpin,
    RESPONSE: serde::de::DeserializeOwned + std::fmt::Debug + serde::Serialize + Clone,
{
    let message: ProtocolMessage<RESPONSE> =
        match ProtocolMessage::read_from(stream, conn.as_deref_mut()).await {
            Ok(message) => message,
            Err(err) => {
                log!(LogLevel::Error, "Deserialization error: {}", err);
                // Best-effort -- don't let a failed ack write mask the
                // original read/parse error.
                let _ = send_empty_err(stream, proto).await;
                return Err(err);
            }
        };

    if proto == Proto::TCP {
        stream.flush().await?;
    }

    log!(LogLevel::Debug, "Received message: {:?}", message);

    if let Some(want) = required {
        if !message.flags().contains(want) {
            log!(
                LogLevel::Warn,
                "peer used unexpected connection params: expected {:?}, got {:?}",
                want,
                message.flags()
            );

            let should_negotiate = force || conn.as_ref().map(|c| c.insecure).unwrap_or(false);
            if should_negotiate {
                send_sidegrade(stream, proto, want).await?;
                let retried: ProtocolMessage<RESPONSE> =
                    ProtocolMessage::read_from(stream, conn.as_deref_mut()).await?;

                if !retried.flags().contains(want) {
                    log!(
                        LogLevel::Warn,
                        "peer's SIDEGRADE retry still didn't satisfy required params: expected {:?}, got {:?}",
                        want,
                        retried.flags()
                    );
                } else if let Some(ctx) = conn.as_deref_mut() {
                    ctx.params = want;
                }

                if auto_reply {
                    send_empty_ok(stream, proto).await?;
                }
                return Ok(retried);
            }
        }
    }

    if auto_reply {
        send_empty_ok(stream, proto).await?;
    }
    Ok(message)
}

/// Reads one framed message off `stream` and parses it. Pass `conn` for any
/// connection where `ConnectionParams::ENCRYPTED` traffic is expected (see
/// [`send_message`]). If `auto_reply` is set, an empty acknowledgement is
/// sent back automatically on success (or an error acknowledgement on parse
/// failure).
///
/// **Transparent `SIDEGRADE`**: if `conn` is provided, an incoming message
/// whose params don't match `conn.params` (the connection's established
/// baseline) is logged, and -- only when `conn.insecure` is true --
/// automatically renegotiated via `SIDEGRADE` before returning. See
/// [`receive_message_with_required_params`] for the manual/explicit
/// counterpart, and `docs/HANDSHAKE.md` for the full picture.
pub async fn receive_message<STREAM, RESPONSE>(
    stream: &mut STREAM,
    auto_reply: bool,
    proto: Proto,
    mut conn: Option<&mut ConnectionCtx>,
) -> io::Result<ProtocolMessage<RESPONSE>>
where
    STREAM: AsyncReadExt + AsyncWriteExt + Unpin,
    RESPONSE: serde::de::DeserializeOwned + std::fmt::Debug + serde::Serialize + Clone,
{
    let required = conn.as_deref().map(|c| c.params);
    receive_message_impl(stream, auto_reply, proto, conn.as_deref_mut(), required, false).await
}

/// Manual counterpart to [`receive_message`]'s transparent negotiation:
/// explicitly demand `required` params for this exchange, regardless of
/// the connection's current baseline or its `insecure` bit -- an explicit
/// ask always attempts the `SIDEGRADE` renegotiation. Useful for the
/// "connection started with minimal params, now upgrade for sensitive
/// work" case. On success, `conn.params` is updated to `required` so later
/// calls default to it. Check the returned message's
/// [`ProtocolMessage::flags`] to confirm what was actually negotiated.
pub async fn receive_message_with_required_params<STREAM, RESPONSE>(
    stream: &mut STREAM,
    auto_reply: bool,
    proto: Proto,
    conn: Option<&mut ConnectionCtx>,
    required: ConnectionParams,
) -> io::Result<ProtocolMessage<RESPONSE>>
where
    STREAM: AsyncReadExt + AsyncWriteExt + Unpin,
    RESPONSE: serde::de::DeserializeOwned + std::fmt::Debug + serde::Serialize + Clone,
{
    receive_message_impl(stream, auto_reply, proto, conn, Some(required), true).await
}

// * Sending and recieving helpers

/// Sends a bare message with `status = ProtocolStatus::SIDEGRADE` and
/// `desired` packed into the header's free `reserved` byte, requesting the
/// peer resend with those params. Sent without `ConnectionParams::ENCRYPTED`
/// (so it goes out via the single-message fallback key, like any other
/// control message -- see `ProtocolMessage::to_bytes`). See
/// `docs/HANDSHAKE.md`.
pub async fn send_sidegrade<S>(stream: &mut S, proto: Proto, desired: ConnectionParams) -> io::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    let mut message: ProtocolMessage<()> =
        ProtocolMessage::new(ConnectionParams::NONE, MsgType::Data, ())?;
    message.header.status = ProtocolStatus::SIDEGRADE.bits();
    message.header.reserved = desired.bits();
    message.write_to(stream, proto, None).await
}

/// Sends a bare `ProtocolStatus::ERROR` acknowledgement.
pub async fn send_empty_err<S>(stream: &mut S, proto: Proto) -> Result<(), io::Error>
where
    S: AsyncWriteExt + Unpin,
{
    let mut message: ProtocolMessage<()> = ProtocolMessage::new(ConnectionParams::NONE, MsgType::Data, ())?;
    message.header.status = ProtocolStatus::ERROR.bits();
    message.write_to(stream, proto, None).await
}

/// Sends a bare `ProtocolStatus::OK` acknowledgement.
pub async fn send_empty_ok<S>(stream: &mut S, proto: Proto) -> Result<(), io::Error>
where
    S: AsyncWriteExt + Unpin,
{
    let mut message: ProtocolMessage<()> = ProtocolMessage::new(ConnectionParams::NONE, MsgType::Data, ())?;
    message.header.status = ProtocolStatus::OK.bits();
    message.write_to(stream, proto, None).await
}

/// Writes `data` to `stream` and flushes (TCP only -- a Unix socket doesn't
/// need an explicit flush). Retained for callers building their own frames;
/// [`ProtocolMessage::write_to`] is the preferred entry point for sending
/// an actual [`ProtocolMessage`].
pub async fn send_data<S>(stream: &mut S, data: Vec<u8>, proto: Proto) -> Result<(), io::Error>
where
    S: AsyncWriteExt + Unpin,
{
    stream.write_all(&data).await?;

    if proto == Proto::TCP {
        stream.flush().await?
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::handshake::NoiseIdentity;

    /// Establishes a real `Noise_NK` connection over an in-memory duplex
    /// stream, declaring `params` as the baseline, and returns both stream
    /// halves plus both sides' resulting `ConnectionCtx`.
    async fn establish_pair(
        params: ConnectionParams,
    ) -> (
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        ConnectionCtx,
        ConnectionCtx,
    ) {
        let identity = NoiseIdentity::generate().unwrap();
        let remote_pub = identity.public_key();
        let (mut client, mut server) = tokio::io::duplex(8192);

        let (client_ctx, server_ctx) = tokio::join!(
            establish_connection_initiator(&mut client, &remote_pub, params),
            establish_connection_responder(&mut server, &identity),
        );
        (client, server, client_ctx.unwrap(), server_ctx.unwrap())
    }

    /// Transparent path: a message sent with params that don't match the
    /// connection's established baseline, on an `insecure` connection, is
    /// automatically renegotiated via `SIDEGRADE` -- the caller of
    /// `receive_message` just sees the successfully-negotiated message.
    #[tokio::test]
    async fn transparent_sidegrade_when_insecure() {
        let (mut client, mut server, mut client_ctx, mut server_ctx) =
            establish_pair(ConnectionParams::ENCRYPTED | ConnectionParams::INSECURE).await;
        assert!(client_ctx.insecure);
        assert!(server_ctx.insecure);

        let client_fut = send_message::<_, Vec<u8>, ()>(
            &mut client,
            ConnectionParams::NONE, // deliberately wrong -- doesn't match the established baseline
            b"hello".to_vec(),
            Proto::TCP,
            Some(&mut client_ctx),
        );
        let server_fut =
            receive_message::<_, Vec<u8>>(&mut server, true, Proto::TCP, Some(&mut server_ctx));

        let (client_result, server_result) = tokio::join!(client_fut, server_fut);

        let received = server_result.unwrap();
        assert_eq!(received.payload, b"hello".to_vec());
        assert!(received.flags().contains(server_ctx.params));

        let response = client_result.unwrap().unwrap();
        assert!(response.status().is_ok());
    }

    /// Same mismatch, but the connection was *not* declared `insecure`:
    /// the message is delivered as-is, with no forced renegotiation.
    #[tokio::test]
    async fn no_sidegrade_when_not_insecure() {
        let (mut client, mut server, mut client_ctx, mut server_ctx) =
            establish_pair(ConnectionParams::ENCRYPTED).await;
        assert!(!client_ctx.insecure);
        assert!(!server_ctx.insecure);

        let client_fut = send_message::<_, Vec<u8>, ()>(
            &mut client,
            ConnectionParams::NONE,
            b"hello".to_vec(),
            Proto::TCP,
            Some(&mut client_ctx),
        );
        let server_fut =
            receive_message::<_, Vec<u8>>(&mut server, true, Proto::TCP, Some(&mut server_ctx));

        let (client_result, server_result) = tokio::join!(client_fut, server_fut);

        let received = server_result.unwrap();
        assert_eq!(received.flags(), ConnectionParams::NONE);
        assert_ne!(received.flags(), server_ctx.params);

        let response = client_result.unwrap().unwrap();
        assert!(response.status().is_ok());
    }

    /// Manual path: a connection established with a minimal baseline can
    /// be explicitly upgraded for one exchange via
    /// `receive_message_with_required_params`, regardless of the `insecure`
    /// bit -- and the connection's baseline is updated afterward.
    #[tokio::test]
    async fn manual_required_params_upgrades_the_baseline() {
        let (mut client, mut server, mut client_ctx, mut server_ctx) =
            establish_pair(ConnectionParams::INSECURE).await;

        let client_fut = send_message::<_, Vec<u8>, ()>(
            &mut client,
            ConnectionParams::INSECURE, // matches the (minimal) established baseline
            b"sensitive".to_vec(),
            Proto::TCP,
            Some(&mut client_ctx),
        );
        let server_fut = receive_message_with_required_params::<_, Vec<u8>>(
            &mut server,
            true,
            Proto::TCP,
            Some(&mut server_ctx),
            ConnectionParams::ENCRYPTED | ConnectionParams::INSECURE,
        );

        let (client_result, server_result) = tokio::join!(client_fut, server_fut);

        let received = server_result.unwrap();
        assert_eq!(received.payload, b"sensitive".to_vec());
        assert!(received.flags().contains(ConnectionParams::ENCRYPTED));
        assert_eq!(
            server_ctx.params,
            ConnectionParams::ENCRYPTED | ConnectionParams::INSECURE
        );

        let response = client_result.unwrap().unwrap();
        assert!(response.status().is_ok());
    }
}
