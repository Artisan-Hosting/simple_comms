use std::fmt::Display;

use dusa_collection_utils::{log, version::Version};
use dusa_collection_utils::log::LogLevel;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

use crate::network::utils::{comms_version, get_local_ip};
use crate::protocol::{flags::Flags, header::EOL, io_helpers::read_until, message::ProtocolMessage, proto::Proto, status::ProtocolStatus};


pub async fn send_message<STREAM, DATA, RESPONSE>(
    mut stream: &mut STREAM,
    flags: Flags,
    data: DATA,
    proto: Proto,
    insecure: bool,
) -> Result<Result<ProtocolMessage<RESPONSE>, ProtocolStatus>, io::Error>
where
    STREAM: AsyncReadExt + AsyncWriteExt + Unpin,
    DATA: serde::de::DeserializeOwned + std::fmt::Debug + serde::Serialize + Clone + Unpin,
    RESPONSE: serde::de::DeserializeOwned + std::fmt::Debug + serde::Serialize + Clone + Unpin,
{
    let mut message: ProtocolMessage<DATA> = ProtocolMessage::new(flags, data.clone())?;

    match proto {
        Proto::TCP => message.header.origin_address = get_local_ip().octets(),
        Proto::UNIX => message.header.origin_address = [0, 0, 0, 0],
    };

    // Ensure that we send a header with empty reserved field
    // message.header.reserved = Flags::NONE.bits();

    // Creating message bytes and appending eol
    let mut serialized_message: Vec<u8> = message.to_bytes().await?;
    serialized_message.extend(EOL.as_bytes());

    log!(LogLevel::Trace, "message serialized for sending");

    // sending the data
    match proto {
        Proto::TCP => {
            send_data(stream, serialized_message, Proto::TCP).await?;
            log!(LogLevel::Trace, "Message sent over tcp");
        }
        Proto::UNIX => {
            send_data(stream, serialized_message, Proto::UNIX).await?;
            log!(LogLevel::Trace, "Message sent over unix socket")
        }
    }

    // Sleep a second for unix socket issues
    // tokio::time::sleep(Duration::from_micros(500)).await;
    match read_until(&mut stream, EOL.as_bytes().to_vec()).await {
        Ok(response_buffer) => {
            if response_buffer.is_empty() {
                log!(LogLevel::Error, "Received empty response data");
                stream.shutdown().await?;
                return Ok(Err(ProtocolStatus::MALFORMED));
            }

            let response: ProtocolMessage<RESPONSE> =
                ProtocolMessage::from_bytes(&response_buffer).await?;

            let response_status: ProtocolStatus =
                ProtocolStatus::from_bits_truncate(response.header.status);

            let response_reserved: Flags = Flags::from_bits_truncate(response.header.reserved);

            let response_version: Version = Version::decode(response.header.version);

            let in_band = Version::compare_versions(&comms_version(), &response_version);

            if !insecure {
                if !in_band {
                    return Ok(Err(ProtocolStatus::NOTINBAND));
                }
            }

            if response_status.has_flag(ProtocolStatus::SIDEGRADE) {
                log!(LogLevel::Debug, "SideGrade requested");
                match insecure {
                    true => {
                        return match proto {
                            Proto::TCP => {
                                Box::pin(send_message::<STREAM, DATA, RESPONSE>(
                                    stream,
                                    response_reserved,
                                    data,
                                    proto,
                                    insecure,
                                ))
                                .await
                            }
                            Proto::UNIX => {
                                Box::pin(send_message::<STREAM, DATA, RESPONSE>(
                                    stream,
                                    response_reserved,
                                    data,
                                    proto,
                                    insecure,
                                ))
                                .await
                            }
                        };
                    }
                    false => {
                        log!(LogLevel::Info, "Sidegrade not allowed dropping connections");
                        stream.shutdown().await?;
                        return Ok(Err(ProtocolStatus::REFUSED));
                    }
                }
            }
            log!(LogLevel::Trace, "Received response: {:?}", response);
            return Ok(Ok(response));
        }
        Err(err) => return Err(err),
    }
}

pub async fn receive_message<STREAM, RESPONSE>(
    stream: &mut STREAM,
    auto_reply: bool,
    proto: Proto,
) -> io::Result<ProtocolMessage<RESPONSE>>
where
    STREAM: AsyncReadExt + AsyncWriteExt + Unpin,
    RESPONSE: serde::de::DeserializeOwned + std::fmt::Debug + serde::Serialize + Clone + Display,
{
    let mut buffer: Vec<u8> = read_until(stream, EOL.as_bytes().to_vec()).await?;

    if proto == Proto::TCP {
        stream.flush().await?;
    }

    if let Some(pos) = buffer
        .windows(EOL.len())
        .rposition(|window| window == EOL.as_bytes())
    {
        buffer.truncate(pos);
    }

    match ProtocolMessage::<RESPONSE>::from_bytes(&buffer).await {
        Ok(message) => {
            log!(LogLevel::Debug, "Received message: {:?}", message);

            match auto_reply {
                true => {
                    send_empty_ok(stream, proto).await?;
                    return Ok(message);
                }
                false => return Ok(message),
            }
        }
        Err(err) => {
            log!(LogLevel::Error, "Deserialization error: {}", err);
            send_empty_err(stream, proto).await?;
            return Err(io::Error::new(io::ErrorKind::InvalidData, err));
        }
    }
}

// * Sending and recieving helpers
pub async fn create_response(status: ProtocolStatus) -> Result<Vec<u8>, io::Error> {
    let mut message: ProtocolMessage<()> = ProtocolMessage::new(Flags::NONE, ())?;
    message.header.status = status.bits();
    let mut message_bytes = message.to_bytes().await?;
    message_bytes.extend_from_slice(EOL.as_bytes());
    return Ok(message_bytes);
}

pub async fn send_empty_err<S>(stream: &mut S, proto: Proto) -> Result<(), io::Error>
where
    S: AsyncWriteExt + Unpin,
{
    let response: Vec<u8> = create_response(ProtocolStatus::ERROR).await?;
    send_data(stream, response, proto).await
}

pub async fn send_empty_ok<S>(stream: &mut S, proto: Proto) -> Result<(), io::Error>
where
    S: AsyncWriteExt + Unpin,
{
    let response: Vec<u8> = create_response(ProtocolStatus::OK).await?;
    send_data(stream, response, proto).await
}

pub async fn send_data<S>(stream: &mut S, data: Vec<u8>, proto: Proto) -> Result<(), io::Error>
where
    S: AsyncWriteExt + Unpin,
{
    if let Err(err) = stream.write_all(&data).await {
        return Err(err);
    }

    if proto == Proto::TCP {
        stream.flush().await?
    }

    Ok(())
}