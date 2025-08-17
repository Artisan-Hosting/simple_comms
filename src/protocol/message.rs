use std::io::{self, Cursor};

use crate::{
    RELEASEINFO,
    network::utils::{get_header_version, get_local_ip},
    protocol::{
        checksum::{generate_checksum, verify_checksum},
        compression::{compress_data, decompress_data},
        encode::{decode_data, encode_data},
        encryption::{
            decrypt_with_aes_gcm_session, encrypt_with_aes_gcm_session,
        },
        flags::{Flags, MsgType},
        header::{ProtocolHeader, RecordMeta, HEADER_LENGTH, EOL},
        io_helpers::read_with_std_io,
        padding::{
            add_padding_with_scheme, pkcs7_padding, pkcs7_validation, remove_padding_with_scheme,
        },
        status::ProtocolStatus,
    },
};

use dusa_collection_utils::core::logger::LogLevel;
use dusa_collection_utils::{core::version::Version, log};
use rand::Rng;
use serde::{Deserialize, Serialize};

/// Minimal session context required for encrypting/decrypting records.
#[derive(Clone, Copy, Debug)]
pub struct SessionCtx {
    pub session_id: [u8; 16],
    pub key: [u8; 32],
    pub next_seq: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProtocolMessage<T> {
    pub header: ProtocolHeader,
    pub payload: T,

    #[serde(skip)]
    session: Option<SessionCtx>,
}

impl<T> ProtocolMessage<T>
where
    T: Serialize + for<'a> Deserialize<'a> + std::fmt::Debug + Clone,
{
    /// Create a new protocol message with the provided flags and type.
    pub fn new(flags: Flags, msg_type: MsgType, payload: T) -> io::Result<Self> {
        let origin_address: [u8; 4] = get_local_ip().octets();
        let mut header = ProtocolHeader {
            version: get_header_version(),
            flags: flags.bits(),
            payload_length: 0,
            reserved: 0,
            status: ProtocolStatus::OK.bits(),
            origin_address,
            encryption_key: [0u8; 32],
        };
        header.set_msg_type(msg_type);

        Ok(Self {
            header,
            payload,
            session: None,
        })
    }

    /// Attach session information used for encryption/decryption.
    pub fn with_session(mut self, session: SessionCtx) -> Self {
        self.session = Some(session);
        self
    }

    /// Serialize the message into bytes ready for transport.
    pub async fn to_bytes(&mut self) -> io::Result<Vec<u8>> {
        log!(LogLevel::Trace, "Starting to_bytes conversion.");

        // Serialize payload
        let payload_bytes_unpadded = bincode::serialize(&self.payload)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        let mut payload_bytes =
            add_padding_with_scheme(&payload_bytes_unpadded, 16, pkcs7_padding);

        let flags = Flags::from_bits_truncate(self.header.flags);

        // Pre-encryption transforms
        if flags.contains(Flags::COMPRESSED) {
            payload_bytes = compress_data(&payload_bytes)?;
        }
        if flags.contains(Flags::ENCODED) {
            payload_bytes = encode_data(&payload_bytes);
        }
        if flags.contains(Flags::SIGNATURE) {
            payload_bytes = generate_checksum(&mut payload_bytes);
        }

        // Encryption
        let header_bytes;
        if flags.contains(Flags::ENCRYPTED) {
            let sess = self.session.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::Other, "missing session context")
            })?;

            // derive per-record metadata
            let seq_no = sess.next_seq;
            sess.next_seq = sess.next_seq.wrapping_add(1);
            let nonce = rand::thread_rng().r#gen::<u64>();
            let meta = RecordMeta {
                session_id: sess.session_id,
                seq_no,
                nonce,
            };
            self.header.set_meta(&meta);

            // ciphertext length includes 16 byte tag
            self.header.payload_length = (payload_bytes.len() + 16) as u64;

            // serialize header now for AAD
            header_bytes = Self::serialize_header(&self.header);

            // build 96-bit nonce from 64-bit value (pad with zeros)
            let mut nonce96 = [0u8; 12];
            nonce96[..8].copy_from_slice(&nonce.to_be_bytes());

            payload_bytes = encrypt_with_aes_gcm_session(
                &payload_bytes,
                &sess.key,
                &nonce96,
                &header_bytes,
            )?;
        } else {
            self.header.payload_length = payload_bytes.len() as u64;
            self.header.encryption_key = [0u8; 32];
            header_bytes = Self::serialize_header(&self.header);
        }

        let mut buffer = Vec::with_capacity(HEADER_LENGTH + payload_bytes.len());
        buffer.extend_from_slice(&header_bytes);
        buffer.extend_from_slice(&payload_bytes);
        Ok(buffer)
    }

    /// Deserialize a message from raw bytes.  When the `ENCRYPTED` flag is set,
    /// a `SessionCtx` must be provided for decryption.
    pub async fn from_bytes(bytes: &[u8], session: Option<SessionCtx>) -> io::Result<Self> {
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
        let reserved = b[0];

        read_with_std_io(&mut cursor, &mut b)?;
        let status = b[0];

        let mut origin_address = [0u8; 4];
        read_with_std_io(&mut cursor, &mut origin_address)?;

        let mut encryption_key = [0u8; 32];
        read_with_std_io(&mut cursor, &mut encryption_key)?;

        let header = ProtocolHeader {
            version,
            flags,
            payload_length,
            reserved,
            status,
            origin_address,
            encryption_key,
        };

        let mut payload = payload_bytes.to_vec();
        let flags = Flags::from_bits_truncate(header.flags);

        // decrypt if necessary
        if flags.contains(Flags::ENCRYPTED) {
            let sess = session.ok_or_else(|| {
                io::Error::new(io::ErrorKind::Other, "missing session context")
            })?;

            let meta = header.meta();
            if meta.session_id != sess.session_id {
                return Err(io::Error::new(io::ErrorKind::Other, "session mismatch"));
            }

            let mut nonce96 = [0u8; 12];
            nonce96[..8].copy_from_slice(&meta.nonce.to_be_bytes());

            payload = decrypt_with_aes_gcm_session(
                &payload,
                &sess.key,
                &nonce96,
                header_bytes,
            )?;
        }

        // Reverse order transforms
        if flags.contains(Flags::SIGNATURE) {
            payload = verify_checksum(payload);
        }
        if flags.contains(Flags::ENCODED) {
            payload = decode_data(&payload).unwrap();
        }
        if flags.contains(Flags::COMPRESSED) {
            payload = decompress_data(&payload)?;
        }

        payload = match remove_padding_with_scheme(&payload, 16, pkcs7_validation) {
            Ok(p) => p,
            Err(_) => payload,
        };

        let payload: T = bincode::deserialize(&payload).map_err(|err| {
            io::Error::new(io::ErrorKind::InvalidData, err.to_string())
        })?;

        let mut msg = Self {
            header,
            payload,
            session: None,
        };
        if let Some(sess) = session {
            msg.session = Some(sess);
        }
        Ok(msg)
    }

    /// returns a sendable Vec<u8> with the EOL appended
    pub async fn format(mut self) -> io::Result<Vec<u8>> {
        let mut bytes = self.to_bytes().await?;
        bytes.extend_from_slice(EOL);
        Ok(bytes)
    }

    fn serialize_header(h: &ProtocolHeader) -> Vec<u8> {
        let mut header_bytes: Vec<u8> = Vec::with_capacity(HEADER_LENGTH);
        header_bytes.extend(&h.version.to_be_bytes());
        header_bytes.extend(&h.flags.to_be_bytes());
        header_bytes.extend(&h.payload_length.to_be_bytes());
        header_bytes.extend(&h.reserved.to_be_bytes());
        header_bytes.extend(&h.status.to_be_bytes());
        header_bytes.extend(&h.origin_address);
        header_bytes.extend(&h.encryption_key);
        header_bytes
    }

    /// Convenience accessors for message type
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
    use rand::RngCore;

    fn rand_array<const N: usize>() -> [u8; N] {
        let mut arr = [0u8; N];
        rand::thread_rng().fill_bytes(&mut arr);
        arr
    }

    #[test]
    fn msg_type_roundtrip() {
        let msg: ProtocolMessage<()> =
            ProtocolMessage::new(Flags::empty(), MsgType::Heartbeat, ()).unwrap();
        assert_eq!(msg.msg_type(), MsgType::Heartbeat);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let session = SessionCtx {
            session_id: rand_array(),
            key: rand_array(),
            next_seq: 1,
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut msg = ProtocolMessage::new(Flags::ENCRYPTED, MsgType::Data, b"hello".to_vec())
                .unwrap()
                .with_session(session);
            let bytes = msg.to_bytes().await.unwrap();

            let parsed: ProtocolMessage<Vec<u8>> =
                ProtocolMessage::from_bytes(&bytes, Some(session))
                    .await
                    .unwrap();
            assert_eq!(parsed.payload, b"hello".to_vec());
            assert_eq!(parsed.msg_type(), MsgType::Data);
        });
    }
}

