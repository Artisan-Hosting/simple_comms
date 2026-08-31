# simple_comms

Artisan Hosting's wire protocol for authenticated, encrypted communication
between two peers over TCP or a Unix domain socket.

A connection is secured with a `Noise_NK` handshake, after which every
message is framed and encrypted with the resulting transport cipher.
Optional per-message compression, hex-encoding, and checksums are also
available, layered on top.

## Documentation

- [`docs/QUICKSTART.md`](./docs/QUICKSTART.md) -- the fast path: basic
  shapes, establishing a connection, and sending/receiving messages, with
  runnable-shaped examples.
- [`docs/PROTOCOL.md`](./docs/PROTOCOL.md) -- the byte-level wire format:
  header layout, connection params, message types.
- [`docs/HANDSHAKE.md`](./docs/HANDSHAKE.md) -- the connection lifecycle in
  depth: how the `Noise_NK` handshake secures a connection, connection
  params/`INSECURE`/`SIDEGRADE` renegotiation, how logical sessions are
  multiplexed on top of it (`Open`/`OpenAck`), and how keys are rotated
  mid-connection (`Rekey`).

Rustdoc comments throughout `src/` cross-reference both documents; run
`cargo doc --open` for the full generated API reference.

## Layout

- `src/protocol/` -- the wire format itself: the fixed header, flags and
  message types, the Noise handshake, and the payload transforms
  (compression, hex-encoding, checksums, padding) applied before
  encryption.
- `src/network/` -- async helpers that drive the protocol over a `tokio`
  stream: establishing a connection and sending/receiving messages on it.
