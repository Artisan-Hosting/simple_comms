# `simple_comms` wire protocol

This document describes the byte-level format of a `simple_comms` message.
For how a connection gets established and secured in the first place, see
[`HANDSHAKE.md`](./HANDSHAKE.md).

## Framing

Every message on the wire has the same shape:

```
+----------------------+-------------------------+-----+
|  header (50 bytes)   |  payload (variable)      | EOL |
+----------------------+-------------------------+-----+
```

- **header** -- a fixed-size, big-endian [`ProtocolHeader`](../src/protocol/header.rs)
  (see below).
- **payload** -- the message body, after whatever transforms `flags` say
  were applied (compression, hex-encoding, checksum, encryption).
- **EOL** -- the literal bytes `-EOL-`. Readers scan byte-by-byte for this
  delimiter ([`io_helpers::read_until`](../src/protocol/io_helpers.rs)) to
  find the end of a message; a message never contains `EOL` as a substring
  of its own bytes, so there is exactly one copy of it per message.

There is no length-prefixed outer envelope -- the header's own
`payload_length` field tells a reader how many payload bytes to expect
*after* parsing the header, but framing between messages on a stream is done
purely by scanning for `EOL`.

## Header layout (50 bytes, all integers big-endian)

| Field            | Size | Description |
|------------------|------|-------------|
| `version`        | 2    | This build's protocol version, encoded via `Version::encode`. Checked against the peer's version on receipt; a mismatch that's out of band fails the message. |
| `flags`          | 1    | Bitflags -- see [`ConnectionParams`](../src/protocol/flags.rs). |
| `payload_length` | 8    | Length in bytes of the payload that follows (post-transform, i.e. the length actually on the wire). |
| `msg_type`       | 1    | See [`MsgType`](../src/protocol/flags.rs). |
| `reserved`       | 1    | Genuinely free for future use. Repurposed contextually by `SIDEGRADE` responses to carry the requested [`ConnectionParams`] (see below) -- not tied to any single fixed meaning. |
| `status`         | 1    | Bitflags -- see [`ProtocolStatus`](../src/protocol/status.rs). Only meaningful on responses. |
| `origin_address` | 4    | Sender's local IPv4 address for TCP, or all-zero for a Unix socket. |
| `encryption_key` | 32   | Dual-purpose depending on `flags` -- either the [`RecordMeta`](../src/protocol/header.rs) overlay, or a literal fallback key. See below. |

2 + 1 + 8 + 1 + 1 + 1 + 4 + 32 = **50 bytes** total (see `HEADER_LENGTH` in
`header.rs`). `msg_type` and `reserved` used to be a single overloaded byte
(the header's `reserved` field, which had been repurposed to always hold
`MsgType` bits) -- they were split into two dedicated bytes so `msg_type`
and "genuinely free for other purposes" no longer collide. `ProtocolHeader`
also exposes `.flags()`/`.set_flags()`, `.status()`/`.set_status()`, and
`.msg_type()`/`.set_msg_type()` accessors for reading/writing each typed
value from its raw byte, rather than requiring callers to
`from_bits_truncate` manually.

### `ConnectionParams` vs. `MsgType` vs. `ProtocolStatus`

These three bitflag types live in different header bytes and answer three
different questions:

- **[`ConnectionParams`](../src/protocol/flags.rs)** (`flags` byte) -- the
  parameters a connection communicates with: `COMPRESSED`, `ENCRYPTED`,
  `ENCODED`, `SIGNATURE`, `INSECURE`. These are connection-level, not just
  one-off per-message choices -- a connection is established with a
  baseline set of them (see `docs/HANDSHAKE.md`), renegotiable
  mid-connection via `SIDEGRADE`. Several can be set at once.
- **[`MsgType`](../src/protocol/flags.rs)** (`msg_type` byte) -- what
  *kind* of message this is: `Hello`, `HelloAck`, `Open`, `OpenAck`, `Data`,
  `Heartbeat`, `Close`, `Error`, `Rekey`. Exactly one applies per message,
  which is why it's a plain enum rather than bitflags (see the note in
  `flags.rs` about why an earlier attempt to make this a `bitflags!` type
  didn't fit in a `u8`).
- **[`ProtocolStatus`](../src/protocol/status.rs)** (`status` byte) -- the
  outcome of a request, set on *responses*: `OK`, `ERROR`, `WAITING`,
  `READY` (peer finished the handshake -- defined, not yet implemented),
  plus composite values like `SIDEGRADE` (peer wants you to resend with
  different connection params) and `NOTINBAND` (protocol version mismatch,
  but still supported).

### The `encryption_key` field: `RecordMeta` overlay, or a fallback key

The 32-byte `encryption_key` field's meaning depends on whether
`ConnectionParams::ENCRYPTED` is set on the same message:

**`ENCRYPTED` set** -- overlaid with a [`RecordMeta`](../src/protocol/header.rs)
structure:

```
+------------------------ 32 bytes -----------------------+
|  session_id (16)  |  seq_no (4)  |  reserved (12)        |
+-----------------------------------------------------------+
```

- **`session_id`** -- a *logical* multiplexing tag, not a cryptographic
  identifier. It ties a message to a specific `Open`/`OpenAck`-negotiated
  session on a connection (or to the connection itself, for unmultiplexed
  traffic). See `HANDSHAKE.md` for why the actual encryption key never
  appears on the wire at all in this case.
- **`seq_no`** -- a diagnostic/ordering counter. It is *not* consulted for
  replay protection -- the `Noise_NK` transport cipher tracks its own
  send/receive nonce counters internally, independent of this field.
- **12 reserved bytes**, currently always zeroed.

**`ENCRYPTED` unset** -- holds a literal, freshly-generated AES-256 key,
used to encrypt *this message's own payload* (see the next section).
Despite living in a field named `encryption_key`, this really is a raw key
here, sent in the clear right alongside the ciphertext it decrypts -- the
whole point is to never send a message's payload as directly-readable
plaintext, not to provide real confidentiality (an observer who can read
the header can trivially also read this key). Prefer
`ConnectionParams::ENCRYPTED` with a real `Noise_NK`-negotiated session
whenever one is available.

## Payload transform order

The payload always goes through this fixed order (see
`ProtocolMessage::to_bytes`):

1. `bincode::serialize` the payload
2. If `COMPRESSED`: gzip ([`compression::compress_data`](../src/protocol/compression.rs))
3. If `ENCODED`: hex-encode ([`encode::encode_data`](../src/protocol/encode.rs))
4. If `SIGNATURE`: append a SHA-256 checksum ([`checksum::generate_checksum`](../src/protocol/checksum.rs))
5. Always encrypted, one of two ways:
   - If `ENCRYPTED`: with the connection's `Noise_NK` transport cipher (see
     `HANDSHAKE.md`).
   - Otherwise: with a fresh single-message AES-GCM key carried in
     `encryption_key` (see above) -- including for the `Hello`/`HelloAck`
     handshake messages themselves, which necessarily can't use the
     `Noise_NK` cipher since they're what establishes it.

`from_bytes` reverses these in the opposite order on receipt.

## Message types (`MsgType`)

| Value | Name | Direction | Payload | Notes |
|-------|------|-----------|---------|-------|
| 0 | `Hello` | initiator -> responder | opaque Noise handshake bytes | `ENCRYPTED` unset (can't be, since this is what establishes the cipher) -- wrapped in the single-message fallback key instead. Declares the connection's intended `ConnectionParams` baseline in the header's `reserved` byte (not `flags` -- see `docs/HANDSHAKE.md`). First message of the handshake. |
| 1 | `HelloAck` | responder -> initiator | opaque Noise handshake bytes | Same fallback wrapping as `Hello`. Completes the handshake. |
| 2 | `Open` | either | [`SessionRequest`](../src/protocol/message.rs) `{ service, id, port }` | `ENCRYPTED`. Requests a logical, multiplexed session. |
| 3 | `OpenAck` | either | [`SessionAck`](../src/protocol/message.rs) `{ port }` | `ENCRYPTED`. Acknowledges an `Open`. |
| 4 | `Data` | either | application-defined | `ENCRYPTED` typically set once a connection is established. The normal traffic type. Also used, with `status = SIDEGRADE`, as the `SIDEGRADE` control message itself (see `docs/HANDSHAKE.md`). |
| 5 | `Heartbeat` | either | -- | Liveness probe; see [`heartbeat`](../src/protocol/heartbeat.rs). Not yet wired into the send/receive path. |
| 6 | `Close` | either | -- | Graceful teardown. |
| 7 | `Error` | either | -- | Carries a `ProtocolStatus` error rather than a normal payload. |
| 8 | `Rekey` | either | -- (signal only) | Announces that a fresh `Hello`/`HelloAck` is about to follow, to rotate keys. |
| 255 | `Unknown` | -- | -- | Any byte that doesn't map to a known variant. |

See [`HANDSHAKE.md`](./HANDSHAKE.md) for how these fit together into a
connection's lifecycle.
