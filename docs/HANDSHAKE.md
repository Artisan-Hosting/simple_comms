# Connection lifecycle: handshake, sessions, rekey

This document describes how a `simple_comms` connection gets secured and how
traffic flows on it. For the exact bytes on the wire, see
[`PROTOCOL.md`](./PROTOCOL.md).

## Why `Noise_NK`

`simple_comms` secures every connection with the [Noise Protocol
Framework](https://noiseprotocol.org/), specifically the `NK` handshake
pattern, via the [`snow`](https://docs.rs/snow) crate:

```
Noise_NK(rs):
  <- s
  ...
  -> e, es
  <- e, ee
```

- **`N`** -- the *initiator* has no static key of its own. It doesn't need
  one: `simple_comms` doesn't require client identity/authentication at the
  transport layer (an application built on top of it is free to add its own,
  e.g. inside the first `Data` message on a session).
- **`K`** -- the *responder*'s static key is already **k**nown to the
  initiator, out-of-band, before the connection starts (config, DNS, a
  pinned constant, ...). This is what authenticates the responder -- an
  initiator that doesn't already have the right public key can't complete a
  handshake with an impostor.

This gives every connection forward secrecy (each handshake generates fresh
ephemeral keys) and responder authentication, in a single round trip, using
a well-specified and independently-audited protocol rather than a
hand-rolled key exchange.

The concrete parameter string used is `Noise_NK_25519_AESGCM_SHA256`:
Curve25519 for the DH, AES-256-GCM for the AEAD, SHA-256 for the hash.

## `Hello` / `HelloAck`: securing the connection

Exactly one Noise handshake happens per physical connection (not per
logical session -- see below). It maps directly onto the two Noise `NK`
messages:

```
initiator                                responder
    |                                        |
    |  Hello (ConnectionParams::ENCRYPTED    |
    |  unset -- wrapped in the fallback key  |
    |  instead, see PROTOCOL.md; declares    |
    |  the connection's ConnectionParams     |
    |  baseline in the header's `reserved`   |
    |  byte, see below)                      |
    |  -- Noise message 1: -> e, es -------->|
    |                                        |
    |  HelloAck (same fallback wrapping)     |
    |<-- Noise message 2: <- e, ee ----------|
    |                                        |
    |  [both sides: into_transport_mode()]   |
    |                                        |
    |  connection is now secured             |
```

Note that "`ConnectionParams::ENCRYPTED` unset" doesn't mean these two
messages go out as raw plaintext: `ProtocolMessage::to_bytes` still wraps
every message without `ConnectionParams::ENCRYPTED` in a fallback,
single-message AES-GCM key (see
[`PROTOCOL.md`](./PROTOCOL.md#the-encryption_key-field-recordmeta-overlay-or-a-fallback-key))
so nothing ever leaves the wire fully readable -- it's just that `Hello`
can't use the *connection's* Noise cipher, since it's the very message that
establishes it.

`Hello`'s own `flags` byte therefore always stays `ConnectionParams::NONE`
-- it can't simultaneously mean "how this message itself is wrapped" and
"the baseline this connection should use going forward" without a chicken-
and-egg problem. Instead, the initiator packs the intended baseline (see
[**Connection params, `INSECURE`, and `SIDEGRADE`**](#connection-params-insecure-and-sidegrade)
below) into the header's free `reserved` byte, purely as data for the
responder to read -- not as an instruction for encoding `Hello` itself.

Implementation: [`handshake::perform_handshake_initiator`](../src/protocol/handshake.rs)
/ [`handshake::perform_handshake_responder`](../src/protocol/handshake.rs).
Both sides end up with a `snow::TransportState` -- a single object that
handles encryption in both directions, tracking its own send/receive nonce
counters internally, so there's no nonce material to transmit on the wire
at all (contrast this with the discarded earlier design, where a
hand-rolled `nonce_salt` was meant to be derived via HKDF and mixed into an
explicit per-record nonce; using `snow`'s transport mode makes that
unnecessary).

Both sides also derive a **connection id** (`conn_id`) as the first 16 bytes
of the handshake transcript hash (`get_handshake_hash()`). Since both sides
compute it from the same transcript, it's identical on both ends with no
extra exchange, and serves as the default
[`RecordMeta::session_id`](./PROTOCOL.md#the-encryption_key-field-recordmeta-overlay-or-a-fallback-key)
for connections that don't use logical session multiplexing.

The result of a successful handshake is a
[`ConnectionCtx`](../src/protocol/message.rs) `{ noise, conn_id, next_seq,
params, insecure }`. `noise`/`conn_id`/`next_seq` are what every subsequent
`to_bytes`/`from_bytes` call needs when `ConnectionParams::ENCRYPTED` is
set; `params`/`insecure` are covered next.

### Setting up a responder identity

A responder needs a static keypair before it can accept connections:

```rust
let identity = NoiseIdentity::generate()?;
// Distribute identity.public_key() to initiators out-of-band --
// e.g. bake it into client config, publish it via DNS, etc.
```

Persist `identity.private_key()` across restarts (via
`NoiseIdentity::from_keypair`) rather than regenerating it each time --
every initiator that already has the old public key pinned won't be able to
complete a handshake against a new one.

## Connection params, `INSECURE`, and `SIDEGRADE`

Every connection is established with a **baseline** [`ConnectionParams`](../src/protocol/flags.rs)
value -- the initiator declares it on `Hello` (in the `reserved` byte, as
described above); the responder adopts it as-is. Both sides end up with
identical `ConnectionCtx::params`, with no separate exchange needed.

```rust
let ctx = establish_connection_initiator(
    &mut stream,
    &remote_static_pubkey,
    ConnectionParams::ENCRYPTED | ConnectionParams::INSECURE,
).await?;
```

`ConnectionParams::INSECURE` is one of the bits that can be part of that
baseline: it declares whether this connection permits its params to be
renegotiated mid-connection via a `SIDEGRADE` response. `ConnectionCtx::insecure`
caches `params.contains(INSECURE)` for cheap access. This is a
connection-wide property -- both peers read the *same* declaration off
`Hello`, so `client_ctx.insecure` and `server_ctx.insecure` always agree.

### `SIDEGRADE`: renegotiating params mid-connection

A `SIDEGRADE` response (`status = ProtocolStatus::SIDEGRADE`, requested
params packed into the `reserved` byte -- see
[`send_receive::send_sidegrade`](../src/network/send_receive.rs)) asks the
sender of a message to resend it with different `ConnectionParams`. Two
paths trigger it:

**Transparent** -- [`receive_message`](../src/network/send_receive.rs)
compares an incoming message's params against `conn.params` (the
connection's established baseline). If they don't match:
- The mismatch is always logged, regardless of what happens next.
- If `conn.insecure` is `true`: `receive_message` automatically replies
  with `SIDEGRADE` requesting the baseline, reads one retry, and returns
  it -- transparent to the caller, who just sees the successfully
  negotiated message. The sender's own [`send_message`](../src/network/send_receive.rs)
  call (still waiting for a response to its original send) receives the
  `SIDEGRADE` status and -- since it independently reads the *same*
  `conn.insecure` off its own `ConnectionCtx` -- automatically resends with
  the requested params. No consumer code is needed to wire this up; it
  works as long as both sides pass a `conn` with `insecure` declared.
- If `conn.insecure` is `false`: no forced renegotiation. The message is
  delivered as received.

**Manual** -- [`receive_message_with_required_params`](../src/network/send_receive.rs)
lets a caller explicitly demand different params for one exchange,
*regardless* of `conn.insecure` or the current baseline (an explicit ask
always attempts the negotiation). This is the "connection started
minimal/insecure, now upgrade for sensitive work" case:

```rust
// Established with just ConnectionParams::INSECURE; now require ENCRYPTED
// for this one exchange.
let msg = receive_message_with_required_params::<_, MyPayload>(
    &mut stream,
    true, // auto_reply
    proto,
    Some(&mut conn),
    ConnectionParams::ENCRYPTED | ConnectionParams::INSECURE,
).await?;
```

Note this still relies on the *sender's* `send_message` call reading
`conn.insecure == true` to actually retry -- a connection whose `Hello`
never declared `INSECURE` can't be upgraded this way, by design (the
initiator's original declaration is what authorizes renegotiation at all).

On a successful negotiation (either path), `conn.params` is updated to the
newly-agreed value, so later calls on the same connection default to it.

## `Open` / `OpenAck`: logical, multiplexed sessions

A single Noise-secured physical connection can carry **multiple
independent logical sessions**, the same way SSH multiplexes channels over
one encrypted transport, or HTTP/2 multiplexes streams over one TLS
connection. There is only ever one `Noise_NK` handshake (and one
`TransportState`) per physical connection -- `Open`/`OpenAck` doesn't
negotiate new key material, it just tags subsequent `Data` messages so they
can be routed to the right logical handler.

```
initiator                                responder
    |                                        |
    |  Open { service, id, port } (enc.)     |
    |--------------------------------------->|
    |                                        |  assigns a session_id
    |  OpenAck { port } (enc., tagged)       |  for this {service, id}
    |<---------------------------------------|
    |                                        |
    |  Data (enc., tagged with session_id)   |
    |<--------------------------------------->|
```

- **`Open`** carries a [`SessionRequest`](../src/protocol/message.rs)
  `{ service, id, port }` -- application-defined fields naming what's being
  requested.
- **`OpenAck`** carries a [`SessionAck`](../src/protocol/message.rs)
  `{ port }` confirming it, and is tagged (via
  `ProtocolMessage::with_logical_session`) with the `session_id` the
  responder assigned for this session.
- Subsequent `Data` messages for that logical session are tagged the same
  way, so a reader can dispatch them by `header.meta().session_id`.

**Not yet implemented:** the actual session table (mapping `service`/`id` ->
assigned `session_id`/`port`, and dispatching incoming `Data` by that tag)
is application-level bookkeeping, not something the library does for you --
`send_receive.rs` and `message.rs` provide the pieces (`Open`/`OpenAck`
message types, `with_logical_session`, `RecordMeta.session_id`) but not a
connection-manager abstraction on top of them.

## `Data`

Ordinary application traffic. Typically sent with `ConnectionParams::ENCRYPTED`,
optionally combined with `COMPRESSED`/`ENCODED`/`SIGNATURE` (see
`PROTOCOL.md` for the transform order). Tag with
`ProtocolMessage::with_logical_session(session_id)` when it belongs to a
specific `Open`/`OpenAck`-negotiated session; omit it to default to the
connection id (fine for connections that don't multiplex).

## `Rekey`: rotating keys mid-connection

Either side can proactively rotate the transport key without tearing down
the connection, by re-running the `Hello`/`HelloAck` handshake in place:

```
initiator                                responder
    |                                        |
    |  Rekey (enc., using the OLD cipher)    |
    |--------------------------------------->|  decrypts with old ConnectionCtx,
    |                                        |  sees MsgType::Rekey
    |  Hello (fresh ephemeral, fallback-     |
    |  wrapped like any other Hello)         |
    |--------------------------------------->|
    |  HelloAck (same)                       |
    |<---------------------------------------|
    |                                        |
    |  [both sides swap in a fresh           |
    |   ConnectionCtx / TransportState]      |
```

Implementation: [`handshake::rekey_initiator`](../src/protocol/handshake.rs)
/ [`handshake::rekey_responder`](../src/protocol/handshake.rs). There's no
separate rekey sub-protocol beyond the `Rekey` signal frame -- redoing the
Noise handshake is cheap, so that's reused wholesale rather than inventing
a bespoke key-rotation scheme. A responder's receive loop is expected to
check for an incoming `MsgType::Rekey` and dispatch to `rekey_responder`
after decrypting the signal frame with the *old* context.

`simple_comms` doesn't currently decide *when* to rekey (message count,
elapsed time, ...) -- that policy is left to the caller.

## `Close` / `Error`

`Close` signals a graceful teardown; `Error` carries a `ProtocolStatus`
value describing what went wrong rather than a normal payload. Neither has
handshake-specific logic beyond normal message framing.

## What's explicitly out of scope today

- **0-RTT session resumption** (e.g. via a Noise PSK pattern like
  `NKpsk0`). A `ConnectionParams::RESUMED` bit briefly existed as an
  unimplemented placeholder for this and was removed rather than kept
  around unused; a fresh `Hello`/`HelloAck` handshake is always required
  today. Re-add whatever's actually needed if/when this gets built.
- **`ProtocolStatus::READY`** ("peer finished handshake") is defined
  (relocated here from `ConnectionParams`, where it was never checked) but
  still not read or set by anything.
- **Heartbeats** ([`heartbeat.rs`](../src/protocol/heartbeat.rs)) track
  liveness state locally but aren't wired into `send_receive.rs` -- nothing
  currently sends or reacts to `MsgType::Heartbeat` automatically.
- **Session-table bookkeeping** for `Open`/`OpenAck` (see above) is left to
  the application.
