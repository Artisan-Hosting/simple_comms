# Quick start

A minimal, practical tour of `simple_comms`: the basic shapes, establishing
a connection, and sending/receiving messages on it. For the full wire
format see [`PROTOCOL.md`](./PROTOCOL.md); for the handshake/session
lifecycle in depth see [`HANDSHAKE.md`](./HANDSHAKE.md).

```toml
[dependencies]
simple_comms = { path = "." } # or the published version
tokio = { version = "1", features = ["full"] }
```

## The basic shapes

- [`ConnectionParams`](../src/protocol/flags.rs) -- what a message/connection
  is doing: `COMPRESSED`, `ENCRYPTED`, `ENCODED`, `SIGNATURE`, `INSECURE`.
  Combine with `|`, e.g. `ConnectionParams::ENCRYPTED | ConnectionParams::COMPRESSED`.
- [`MsgType`](../src/protocol/flags.rs) -- what kind of message this is
  (`Data` is what you'll use almost everywhere; `Hello`/`HelloAck`/`Rekey`
  are handled for you by the handshake functions below).
- [`Proto`](../src/protocol/proto.rs) -- `Proto::TCP` or `Proto::UNIX`,
  passed to most functions so they know whether to flush after writes.
- [`ProtocolMessage<T>`](../src/protocol/message.rs) -- a header plus a
  payload of your own type `T` (anything `Serialize + Deserialize + Debug +
  Clone`). You'll mostly interact with it as the return value of
  `receive_message`, not construct it directly.
- [`ConnectionCtx`](../src/protocol/message.rs) -- the result of a
  handshake: the Noise transport cipher, connection id, and the
  `ConnectionParams` baseline this connection was established with. You
  hold one of these per connection and pass `Some(&mut ctx)` to every call
  that needs it.

## Establishing a connection

Every connection starts with a `Noise_NK` handshake: the *responder* (the
side accepting connections) has a long-term identity keypair, and the
*initiator* (the side connecting out) must already know that identity's
public key.

**Responder** (e.g. behind a `TcpListener`):

```rust
use std::sync::Arc;
use simple_comms::network::send_receive::establish_connection_responder;
use simple_comms::protocol::handshake::NoiseIdentity;

// Generate once, persist identity.private_key() across restarts (see
// HANDSHAKE.md), and hand identity.public_key() to clients out-of-band.
let identity = Arc::new(NoiseIdentity::generate()?);

let listener = tokio::net::TcpListener::bind("0.0.0.0:7000").await?;
loop {
    let (mut stream, _addr) = listener.accept().await?;
    let identity = Arc::clone(&identity);
    tokio::spawn(async move {
        let mut conn = establish_connection_responder(&mut stream, &identity).await?;
        // ... handle the connection, see below ...
        Ok::<_, std::io::Error>(())
    });
}
```

**Initiator**:

```rust
use simple_comms::network::send_receive::establish_connection_initiator;
use simple_comms::protocol::flags::ConnectionParams;

let remote_pubkey: [u8; 32] = /* known out-of-band */ todo!();
let mut stream = tokio::net::TcpStream::connect("127.0.0.1:7000").await?;

let mut conn = establish_connection_initiator(
    &mut stream,
    &remote_pubkey,
    ConnectionParams::ENCRYPTED, // the baseline this connection will use
).await?;
```

Pass `ConnectionParams::INSECURE` too (`ConnectionParams::ENCRYPTED |
ConnectionParams::INSECURE`) if you want this connection to allow
`SIDEGRADE` param renegotiation later -- see
[`HANDSHAKE.md`](./HANDSHAKE.md#connection-params-insecure-and-sidegrade).

## Sending and receiving

Once you have a `ConnectionCtx`, define a payload type and use
`send_message`/`receive_message`:

```rust
use serde::{Deserialize, Serialize};
use simple_comms::network::send_receive::{receive_message, send_message};
use simple_comms::protocol::{flags::ConnectionParams, proto::Proto};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Ping {
    seq: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Pong {
    seq: u32,
}
```

**Initiator side** -- send a request and wait for a response:

```rust
let outcome = send_message::<_, Ping, Pong>(
    &mut stream,
    ConnectionParams::ENCRYPTED,
    Ping { seq: 1 },
    Proto::TCP,
    Some(&mut conn),
)
.await?;

match outcome {
    Ok(response) => println!("got pong: {:?}", response.payload),
    Err(status) => eprintln!("request refused/failed: {status}"),
}
```

**Responder side** -- receive a request and reply. `receive_message` only
reads and parses; you reply yourself (typically with another message of
your own, or via `send_message` again if you want request/response in the
other direction). For a simple ack-style reply, [`send_receive`](../src/network/send_receive.rs)
also exposes `send_empty_ok`/`send_empty_err` for bare acknowledgements:

```rust
use simple_comms::network::send_receive::receive_message;
use simple_comms::protocol::{flags::MsgType, message::ProtocolMessage};

loop {
    let request = receive_message::<_, Ping>(
        &mut stream,
        false, // auto_reply -- see note below
        Proto::TCP,
        Some(&mut conn),
    )
    .await?;

    println!("got ping: {:?}", request.payload);

    // Reply with a real Pong payload of our own, encrypted the same way.
    let reply = ProtocolMessage::new(
        ConnectionParams::ENCRYPTED,
        MsgType::Data,
        Pong { seq: request.payload.seq },
    )?;
    reply.write_to(&mut stream, Proto::TCP, Some(&mut conn)).await?;
}
```

`auto_reply: true` on `receive_message` sends a bare `OK`/`ERROR`
acknowledgement automatically (useful for fire-and-forget messages); pass
`false` when you're going to send your own meaningful reply instead, as
above.

## Logical sessions (`Open`/`OpenAck`)

One connection can multiplex several independent logical sessions --
useful once you have more than one kind of traffic sharing a connection.
See [`HANDSHAKE.md`](./HANDSHAKE.md#open--openack-logical-multiplexed-sessions)
for the full picture; in short:

```rust
use simple_comms::protocol::{
    flags::MsgType,
    message::{ProtocolMessage, SessionRequest, SessionAck},
};

// Initiator requests a session:
let open = ProtocolMessage::new(
    ConnectionParams::ENCRYPTED,
    MsgType::Open,
    SessionRequest { service: "echo".into(), id: "session-1".into(), port: 9000 },
)?;
open.write_to(&mut stream, Proto::TCP, Some(&mut conn)).await?;

// Responder reads it, assigns a session id (e.g. hash of `id`, or its own
// choice), and acknowledges, tagging the reply with that session id:
let opened: ProtocolMessage<SessionRequest> =
    ProtocolMessage::read_from(&mut stream, Some(&mut conn)).await?;
let session_id: [u8; 16] = /* your own assignment */ todo!();
let ack = ProtocolMessage::new(ConnectionParams::ENCRYPTED, MsgType::OpenAck, SessionAck { port: 9000 })?
    .with_logical_session(session_id);
ack.write_to(&mut stream, Proto::TCP, Some(&mut conn)).await?;

// Subsequent Data messages for this session are tagged the same way:
let data = ProtocolMessage::new(ConnectionParams::ENCRYPTED, MsgType::Data, b"payload".to_vec())?
    .with_logical_session(session_id);
```

The session table itself (mapping `service`/`id` -> assigned `session_id`,
and dispatching incoming `Data` by tag) is application bookkeeping, not
something the library manages for you.

## Rotating keys (`Rekey`)

Either side can proactively rotate the connection's key material without
reconnecting:

```rust
use simple_comms::protocol::handshake::rekey_initiator;

// old `conn` gets replaced with a fresh one carrying the same
// ConnectionParams baseline and insecure setting.
conn = rekey_initiator(&mut stream, &mut conn, &remote_pubkey).await?;
```

The responder side needs to notice an incoming `MsgType::Rekey` (decrypted
with the *old* context) and call
[`rekey_responder`](../src/protocol/handshake.rs) in response -- see
[`HANDSHAKE.md`](./HANDSHAKE.md#rekey-rotating-keys-mid-connection) for the
full sequence.

## What's next

- [`PROTOCOL.md`](./PROTOCOL.md) -- exact header layout and byte-level framing.
- [`HANDSHAKE.md`](./HANDSHAKE.md) -- the full connection lifecycle,
  including `SIDEGRADE` param renegotiation (`receive_message_with_required_params`
  for explicit "start minimal, upgrade later" flows) and what's not
  implemented yet.
