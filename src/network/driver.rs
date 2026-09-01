//! A background task that drives a `simple_comms` connection full-duplex:
//! independent, concurrent send and receive on one already-`Noise_NK`-secured
//! connection, automatic `MsgType::Heartbeat` liveness, and both
//! self-initiated and peer-initiated `MsgType::Rekey` handled inline. See
//! `docs/HANDSHAKE.md` for the wider connection lifecycle this sits on top
//! of, and [`crate::network::send_receive`] for the simpler
//! request/response API this complements (a connection that doesn't need a
//! live duplex session -- a one-shot exchange, or the pre-driver handshake
//! itself -- can keep using that instead).
//!
//! Unlike [`crate::network::send_receive`]'s helpers, [`ConnectionDriver`]
//! owns the connection exclusively for its lifetime: it splits the
//! underlying stream into independent read/write halves and runs a single
//! background task that `select!`s across them, an outbound queue, a rekey
//! control channel, and a heartbeat timer. Because that one task is the
//! *only* thing that ever touches the connection's [`ConnectionCtx`] or
//! stream halves, no lock is needed around them -- every operation
//! (including an in-progress rekey) is naturally serialized, so nothing can
//! race a send against a rekey, and no signal can be missed.

use std::time::{Duration, Instant};

use dusa_collection_utils::core::errors::{ErrorArrayItem, Errors};
use dusa_collection_utils::core::logger::LogLevel;
use dusa_collection_utils::log;
use tokio::io::{self, AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use crate::protocol::{
    flags::MsgType,
    handshake::{NoiseIdentity, rekey_initiator_rw, rekey_responder_rw},
    heartbeat::{Heartbeat, HeartbeatState},
    message::{ConnectionCtx, ProtocolMessage, SessionAck, SessionRequest, read_message_raw_buffered},
    proto::Proto,
};

/// One of the message kinds a [`ConnectionDriver`] surfaces to the
/// application via [`ConnectionHandle::recv`]. `Heartbeat`/`Rekey`/`Close`/
/// `Hello`/`HelloAck` never reach here -- they're handled internally by the
/// driver loop.
#[derive(Debug)]
pub enum DriverMessage<APP> {
    /// An application `Data` message.
    Data(ProtocolMessage<APP>),
    /// A logical-session `Open` request; see `docs/HANDSHAKE.md`. Routing
    /// this to the right application handler (by
    /// `ProtocolMessage::header::meta().session_id` or otherwise) is left
    /// to the caller, same as the rest of `Open`/`OpenAck` bookkeeping.
    Open(ProtocolMessage<SessionRequest>),
    /// An `OpenAck` confirmation.
    OpenAck(ProtocolMessage<SessionAck>),
}

/// Tuning knobs for [`ConnectionDriver::spawn`].
#[derive(Debug, Clone, Copy)]
pub struct DriverConfig {
    /// How often to send `MsgType::Heartbeat`, and the unit
    /// [`Heartbeat::state`] judges peer liveness against (`Suspect` at 3
    /// missed intervals, `Timeout` -- connection torn down -- at 5).
    pub heartbeat_interval: Duration,
    /// Bound on the outbound [`ConnectionHandle::send`] queue.
    pub outbound_buffer: usize,
    /// Bound on the inbound [`ConnectionHandle::recv`] queue.
    pub inbound_buffer: usize,
}

impl Default for DriverConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: Duration::from_secs(15),
            outbound_buffer: 64,
            inbound_buffer: 64,
        }
    }
}

/// Which side of the original `Noise_NK` handshake this connection played
/// (see `docs/HANDSHAKE.md`). A rekey re-runs `Hello`/`HelloAck` with the
/// same asymmetry as the original handshake -- only the side that knows the
/// peer's static key can *ask* for one (`rekey_initiator_rw`); only the
/// side with a static identity can *answer* one (`rekey_responder_rw`) --
/// so the driver needs to know which role it's playing to handle both
/// self-initiated ([`ConnectionHandle::rekey`]) and peer-initiated (an
/// incoming `MsgType::Rekey` frame) rekeys correctly.
pub enum ConnectionRole {
    /// This side ran [`crate::network::send_receive::establish_connection_initiator`].
    /// Only this role can call [`ConnectionHandle::rekey`].
    Initiator { remote_static_pubkey: [u8; 32] },
    /// This side ran [`crate::network::send_receive::establish_connection_responder`].
    /// Only this role reacts to a peer-initiated `MsgType::Rekey`.
    Responder { identity: NoiseIdentity },
}

enum Control {
    Rekey(oneshot::Sender<Result<(), ErrorArrayItem>>),
    Shutdown,
}

/// Handle to a connection being driven full-duplex by a background task
/// spawned via [`ConnectionDriver::spawn`]. Dropping this without calling
/// [`Self::shutdown`] still stops the driver (its outbound/control channels
/// close), just without a way to observe how it stopped.
pub struct ConnectionHandle<APP> {
    outbound_tx: mpsc::Sender<ProtocolMessage<APP>>,
    inbound_rx: mpsc::Receiver<DriverMessage<APP>>,
    control_tx: mpsc::Sender<Control>,
    task: JoinHandle<io::Result<()>>,
}

impl<APP> ConnectionHandle<APP>
where
    APP: serde::de::DeserializeOwned
        + serde::Serialize
        + std::fmt::Debug
        + Clone
        + Unpin
        + Send
        + 'static,
{
    /// Enqueue `msg` for sending. Doesn't wait for a reply -- this is the
    /// full-duplex push path, not [`crate::network::send_receive::send_message`]'s
    /// request/response one, so a peer can receive any number of these
    /// without needing to reply to each. `msg`'s `ConnectionParams` (set
    /// via [`ProtocolMessage::new`], typically `conn.params`) travel with
    /// it as normal.
    pub async fn send(&self, msg: ProtocolMessage<APP>) -> Result<(), ErrorArrayItem> {
        self.outbound_tx
            .send(msg)
            .await
            .map_err(|_| ErrorArrayItem::new(Errors::ConnectionError, "driver task has stopped"))
    }

    /// Wait for the next dispatched `Data`/`Open`/`OpenAck` message.
    /// Returns `None` once the driver has stopped (peer sent `Close`, a
    /// heartbeat timeout, or a fatal I/O error) -- see [`Self::shutdown`]
    /// to retrieve the reason.
    pub async fn recv(&mut self) -> Option<DriverMessage<APP>> {
        self.inbound_rx.recv().await
    }

    /// Rotate this connection's transport key (`docs/HANDSHAKE.md`'s
    /// `Rekey`), as the connection's original Noise initiator. Waits for
    /// the driver's in-loop rekey to actually complete before returning.
    /// Only valid when this connection was established via
    /// [`crate::network::send_receive::establish_connection_initiator`]
    /// (see [`ConnectionRole`]) -- called on the responder side, this
    /// returns `Err`.
    pub async fn rekey(&self) -> Result<(), ErrorArrayItem> {
        let (ack, done) = oneshot::channel();
        self.control_tx
            .send(Control::Rekey(ack))
            .await
            .map_err(|_| ErrorArrayItem::new(Errors::ConnectionError, "driver task has stopped"))?;
        done.await
            .map_err(|_| ErrorArrayItem::new(Errors::ConnectionError, "driver task has stopped"))?
    }

    /// Whether the driver task has already stopped.
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// Signal the driver to stop and wait for it to actually do so,
    /// returning whatever error it stopped with -- a heartbeat timeout or a
    /// fatal I/O error -- if it stopped abnormally.
    pub async fn shutdown(mut self) -> io::Result<()> {
        let _ = self.control_tx.send(Control::Shutdown).await;
        self.inbound_rx.close();
        match self.task.await {
            Ok(result) => result,
            Err(join_err) => Err(io::Error::other(join_err.to_string())),
        }
    }
}

/// Spawns and drives a connection full-duplex. See the module docs.
pub struct ConnectionDriver;

impl ConnectionDriver {
    /// Split `stream` and spawn the background task that drives it. `ctx`
    /// must already be an established connection (from
    /// [`crate::network::send_receive::establish_connection_initiator`] or
    /// [`crate::network::send_receive::establish_connection_responder`]) --
    /// the driver doesn't perform the initial handshake itself, only
    /// `Rekey`; `role` must match how `ctx` was established (see
    /// [`ConnectionRole`]).
    pub fn spawn<S, APP>(
        stream: S,
        ctx: ConnectionCtx,
        role: ConnectionRole,
        proto: Proto,
        config: DriverConfig,
    ) -> ConnectionHandle<APP>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        APP: serde::de::DeserializeOwned
            + serde::Serialize
            + std::fmt::Debug
            + Clone
            + Unpin
            + Send
            + 'static,
    {
        let (read_half, write_half) = tokio::io::split(stream);
        let (outbound_tx, outbound_rx) = mpsc::channel(config.outbound_buffer);
        let (inbound_tx, inbound_rx) = mpsc::channel(config.inbound_buffer);
        let (control_tx, control_rx) = mpsc::channel(4);

        let task = tokio::spawn(driver_loop::<S, APP>(
            read_half,
            write_half,
            ctx,
            role,
            proto,
            config,
            DriverChannels { outbound_rx, inbound_tx, control_rx },
        ));

        ConnectionHandle {
            outbound_tx,
            inbound_rx,
            control_tx,
            task,
        }
    }
}

/// The channel endpoints [`driver_loop`] owns, bundled into one parameter
/// to stay under a sane argument count.
struct DriverChannels<APP> {
    outbound_rx: mpsc::Receiver<ProtocolMessage<APP>>,
    inbound_tx: mpsc::Sender<DriverMessage<APP>>,
    control_rx: mpsc::Receiver<Control>,
}

async fn driver_loop<S, APP>(
    mut read_half: ReadHalf<S>,
    mut write_half: WriteHalf<S>,
    mut ctx: ConnectionCtx,
    role: ConnectionRole,
    proto: Proto,
    config: DriverConfig,
    channels: DriverChannels<APP>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    APP: serde::de::DeserializeOwned
        + serde::Serialize
        + std::fmt::Debug
        + Clone
        + Unpin
        + Send
        + 'static,
{
    let DriverChannels { mut outbound_rx, inbound_tx, mut control_rx } = channels;

    let mut heartbeat = Heartbeat::new(config.heartbeat_interval, Instant::now());
    let mut ticker = tokio::time::interval(config.heartbeat_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    // Owned here (not inside the read future) so a cancelled read -- this
    // branch losing the select! race to another one -- doesn't lose bytes
    // already consumed from `read_half`; see `read_message_raw_buffered`.
    let mut frame_buf: Vec<u8> = Vec::new();

    loop {
        tokio::select! {
            read_result = read_message_raw_buffered(&mut read_half, Some(&mut ctx), &mut frame_buf) => {
                let (header, payload) = match read_result {
                    Ok(v) => v,
                    Err(err) => {
                        log!(LogLevel::Error, "driver read error: {err}");
                        return Err(err);
                    }
                };

                match header.msg_type() {
                    MsgType::Heartbeat => {
                        heartbeat.mark_recv(Instant::now());
                    }
                    MsgType::Data => {
                        let msg: ProtocolMessage<APP> = ProtocolMessage::finish(header, &payload)?;
                        if inbound_tx.send(DriverMessage::Data(msg)).await.is_err() {
                            return Ok(());
                        }
                    }
                    MsgType::Open => {
                        let msg: ProtocolMessage<SessionRequest> =
                            ProtocolMessage::finish(header, &payload)?;
                        if inbound_tx.send(DriverMessage::Open(msg)).await.is_err() {
                            return Ok(());
                        }
                    }
                    MsgType::OpenAck => {
                        let msg: ProtocolMessage<SessionAck> =
                            ProtocolMessage::finish(header, &payload)?;
                        if inbound_tx.send(DriverMessage::OpenAck(msg)).await.is_err() {
                            return Ok(());
                        }
                    }
                    MsgType::Rekey => match &role {
                        ConnectionRole::Responder { identity } => {
                            match rekey_responder_rw(&mut read_half, &mut write_half, identity).await {
                                Ok(new_ctx) => {
                                    ctx = new_ctx;
                                    heartbeat.mark_recv(Instant::now());
                                    log!(LogLevel::Info, "rekeyed (peer-initiated)");
                                }
                                Err(err) => {
                                    log!(LogLevel::Error, "peer-initiated rekey failed: {err}");
                                    return Err(err);
                                }
                            }
                        }
                        ConnectionRole::Initiator { .. } => {
                            log!(
                                LogLevel::Warn,
                                "ignoring unexpected Rekey signal from peer -- this side is the Noise initiator"
                            );
                        }
                    },
                    MsgType::Close => {
                        log!(LogLevel::Info, "peer closed the connection");
                        return Ok(());
                    }
                    other => {
                        log!(LogLevel::Warn, "driver ignoring unexpected message type: {other:?}");
                    }
                }
            }

            outbound = outbound_rx.recv() => {
                let Some(msg) = outbound else {
                    // The handle (and every clone of `outbound_tx`) was
                    // dropped without an explicit `shutdown()` -- stop.
                    return Ok(());
                };
                if let Err(err) = msg.write_to(&mut write_half, proto, Some(&mut ctx)).await {
                    log!(LogLevel::Error, "driver write error: {err}");
                    return Err(err);
                }
            }

            ctrl = control_rx.recv() => {
                match ctrl {
                    Some(Control::Shutdown) | None => return Ok(()),
                    Some(Control::Rekey(ack)) => {
                        let result = match &role {
                            ConnectionRole::Initiator { remote_static_pubkey } => {
                                rekey_initiator_rw(&mut read_half, &mut write_half, &mut ctx, remote_static_pubkey)
                                    .await
                                    .map(|new_ctx| {
                                        ctx = new_ctx;
                                        heartbeat.mark_sent(Instant::now());
                                        log!(LogLevel::Info, "rekeyed (self-initiated)");
                                    })
                                    .map_err(|err| ErrorArrayItem::new(Errors::Network, err.to_string()))
                            }
                            ConnectionRole::Responder { .. } => Err(ErrorArrayItem::new(
                                Errors::Unauthorized,
                                "only the connection's original Noise initiator can self-initiate a rekey",
                            )),
                        };
                        let _ = ack.send(result);
                    }
                }
            }

            _ = ticker.tick() => {
                if heartbeat.should_send(Instant::now()) {
                    let hb: ProtocolMessage<()> = ProtocolMessage::new(ctx.params, MsgType::Heartbeat, ())?;
                    if let Err(err) = hb.write_to(&mut write_half, proto, Some(&mut ctx)).await {
                        log!(LogLevel::Error, "driver heartbeat write error: {err}");
                        return Err(err);
                    }
                    heartbeat.mark_sent(Instant::now());
                }

                if heartbeat.state(Instant::now()) == HeartbeatState::Timeout {
                    log!(LogLevel::Error, "peer heartbeat timeout -- tearing down connection");
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "peer heartbeat timeout"));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::send_receive::{establish_connection_initiator, establish_connection_responder};
    use crate::protocol::flags::ConnectionParams;

    /// Two drivers, each spawned as a real background task (`tokio::spawn`,
    /// not `tokio::join!`, since this is specifically testing task
    /// concurrency): the client pushes several `Data` messages back-to-back
    /// with no reply in between, and the server independently pushes one
    /// back, unprompted -- proving sends aren't coupled to a request/reply
    /// pairing in either direction on the same connection.
    #[tokio::test]
    async fn full_duplex_push_without_reply() {
        let identity = NoiseIdentity::generate().unwrap();
        let remote_pub = identity.public_key();
        let (mut client_stream, mut server_stream) = tokio::io::duplex(8192);

        let (client_ctx, server_ctx) = tokio::join!(
            establish_connection_initiator(&mut client_stream, &remote_pub, ConnectionParams::ENCRYPTED),
            establish_connection_responder(&mut server_stream, &identity),
        );
        let client_ctx = client_ctx.unwrap();
        let server_ctx = server_ctx.unwrap();

        let config = DriverConfig::default();
        let mut client: ConnectionHandle<Vec<u8>> = ConnectionDriver::spawn(
            client_stream,
            client_ctx,
            ConnectionRole::Initiator { remote_static_pubkey: remote_pub },
            Proto::TCP,
            config,
        );
        let mut server: ConnectionHandle<Vec<u8>> = ConnectionDriver::spawn(
            server_stream,
            server_ctx,
            ConnectionRole::Responder { identity },
            Proto::TCP,
            config,
        );

        for seq in 0..3u8 {
            client
                .send(ProtocolMessage::new(ConnectionParams::ENCRYPTED, MsgType::Data, vec![seq]).unwrap())
                .await
                .unwrap();
        }

        for seq in 0..3u8 {
            match server.recv().await.unwrap() {
                DriverMessage::Data(msg) => assert_eq!(msg.payload, vec![seq]),
                other => panic!("unexpected message: {other:?}"),
            }
        }

        // The other half of "full duplex": the server can push back,
        // unprompted, on the same connection.
        server
            .send(ProtocolMessage::new(ConnectionParams::ENCRYPTED, MsgType::Data, b"pong".to_vec()).unwrap())
            .await
            .unwrap();
        match client.recv().await.unwrap() {
            DriverMessage::Data(msg) => assert_eq!(msg.payload, b"pong".to_vec()),
            other => panic!("unexpected message: {other:?}"),
        }

        let _ = client.shutdown().await;
        let _ = server.shutdown().await;
    }

    /// If the peer goes silent (connection stays open, but nothing arrives
    /// -- as opposed to an EOF/closed socket) for 5 heartbeat intervals,
    /// [`Heartbeat::state`] reports `Timeout` and the driver tears itself
    /// down, ending `recv()` and surfacing the reason via `shutdown()`.
    #[tokio::test(start_paused = true)]
    async fn heartbeat_timeout_tears_down_driver() {
        let identity = NoiseIdentity::generate().unwrap();
        let remote_pub = identity.public_key();
        let (mut client_stream, mut server_stream) = tokio::io::duplex(8192);

        let (client_ctx, server_ctx) = tokio::join!(
            establish_connection_initiator(&mut client_stream, &remote_pub, ConnectionParams::ENCRYPTED),
            establish_connection_responder(&mut server_stream, &identity),
        );
        let client_ctx = client_ctx.unwrap();
        let _server_ctx = server_ctx.unwrap();
        // Keep the server's half alive (an open, merely silent connection)
        // without ever reading or writing on it -- if it were dropped
        // instead, the client would see EOF and error out on that, rather
        // than actually exercising the heartbeat timeout path.
        let _server_stream = server_stream;

        let config = DriverConfig {
            heartbeat_interval: Duration::from_millis(50),
            ..Default::default()
        };
        let mut client: ConnectionHandle<Vec<u8>> = ConnectionDriver::spawn(
            client_stream,
            client_ctx,
            ConnectionRole::Initiator { remote_static_pubkey: remote_pub },
            Proto::TCP,
            config,
        );

        // 5+ missed intervals -> Timeout (see Heartbeat::state).
        tokio::time::advance(config.heartbeat_interval * 6).await;

        assert!(client.recv().await.is_none());
        assert!(client.shutdown().await.is_err());
    }

    /// A self-initiated rekey mid-stream doesn't lose or misdecrypt
    /// messages sent shortly before or after it -- the driver loop
    /// serializes the rekey against the outbound queue, so every send
    /// (whichever side of the rekey it lands on) is written under whatever
    /// cipher epoch is current at that point, and the peer -- reading the
    /// same ordered stream -- decrypts each one the same way.
    #[tokio::test]
    async fn rekey_while_sending_preserves_message_order() {
        let identity = NoiseIdentity::generate().unwrap();
        let remote_pub = identity.public_key();
        let (mut client_stream, mut server_stream) = tokio::io::duplex(8192);

        let (client_ctx, server_ctx) = tokio::join!(
            establish_connection_initiator(&mut client_stream, &remote_pub, ConnectionParams::ENCRYPTED),
            establish_connection_responder(&mut server_stream, &identity),
        );
        let client_ctx = client_ctx.unwrap();
        let server_ctx = server_ctx.unwrap();

        let config = DriverConfig::default();
        let client: ConnectionHandle<Vec<u8>> = ConnectionDriver::spawn(
            client_stream,
            client_ctx,
            ConnectionRole::Initiator { remote_static_pubkey: remote_pub },
            Proto::TCP,
            config,
        );
        let mut server: ConnectionHandle<Vec<u8>> = ConnectionDriver::spawn(
            server_stream,
            server_ctx,
            ConnectionRole::Responder { identity },
            Proto::TCP,
            config,
        );

        for seq in 0..5u8 {
            client
                .send(ProtocolMessage::new(ConnectionParams::ENCRYPTED, MsgType::Data, vec![seq]).unwrap())
                .await
                .unwrap();
        }

        client.rekey().await.unwrap();

        for seq in 5..10u8 {
            client
                .send(ProtocolMessage::new(ConnectionParams::ENCRYPTED, MsgType::Data, vec![seq]).unwrap())
                .await
                .unwrap();
        }

        for seq in 0..10u8 {
            match server.recv().await.unwrap() {
                DriverMessage::Data(msg) => assert_eq!(msg.payload, vec![seq]),
                other => panic!("unexpected message: {other:?}"),
            }
        }

        // A responder can't self-initiate a rekey (see ConnectionRole).
        assert!(server.rekey().await.is_err());

        let _ = client.shutdown().await;
        let _ = server.shutdown().await;
    }
}
