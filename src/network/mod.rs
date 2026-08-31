//! Async helpers that drive the [`crate::protocol`] wire format over a
//! `tokio` stream (TCP or Unix socket): establishing a `Noise_NK`-secured
//! connection and sending/receiving framed [`crate::protocol::message::ProtocolMessage`]s
//! on it.

pub mod send_receive;
pub mod utils;
