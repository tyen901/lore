// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;

use crate::ProtocolError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicObjectKeyScheme {
    HashHex,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicObjectReadConfig {
    pub base_url: String,
    pub key_scheme: PublicObjectKeyScheme,
}

impl PublicObjectReadConfig {
    pub fn new_hash_hex(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            key_scheme: PublicObjectKeyScheme::HashHex,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum ImmutablePayloadReadMode {
    #[default]
    ServerStream,
    PublicHttp(PublicObjectReadConfig),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageSessionStart {
    pub session_id: u32,
    pub immutable_payload_read: ImmutablePayloadReadMode,
}

impl StorageSessionStart {
    pub fn server_stream(session_id: u32) -> Self {
        Self {
            session_id,
            immutable_payload_read: ImmutablePayloadReadMode::ServerStream,
        }
    }

    pub fn public_http_hash_hex(session_id: u32, base_url: impl Into<String>) -> Self {
        Self {
            session_id,
            immutable_payload_read: ImmutablePayloadReadMode::PublicHttp(
                PublicObjectReadConfig::new_hash_hex(base_url),
            ),
        }
    }

    pub fn encode_quic_v4(&self) -> Bytes {
        let mut out = BytesMut::new();
        out.extend_from_slice(&self.session_id.to_le_bytes());
        match &self.immutable_payload_read {
            ImmutablePayloadReadMode::ServerStream => {
                out.put_u8(0);
                out.put_u8(0);
                out.extend_from_slice(&0u16.to_le_bytes());
            }
            ImmutablePayloadReadMode::PublicHttp(config) => {
                out.put_u8(1);
                out.put_u8(match config.key_scheme {
                    PublicObjectKeyScheme::HashHex => 0,
                });
                let base = config.base_url.as_bytes();
                let len = u16::try_from(base.len()).unwrap_or(u16::MAX);
                out.extend_from_slice(&len.to_le_bytes());
                out.extend_from_slice(&base[..usize::from(len)]);
            }
        }
        out.freeze()
    }

    pub fn decode_quic_v4(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() == 4 {
            return Ok(Self::server_stream(u32::from_le_bytes(
                bytes.try_into().unwrap(),
            )));
        }
        if bytes.len() < 8 {
            return Err(ProtocolError::internal(format!(
                "session_start: expected at least 8-byte capability response, got {} bytes",
                bytes.len()
            )));
        }
        let session_id = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let mode = bytes[4];
        let key_scheme = bytes[5];
        let base_len = u16::from_le_bytes(bytes[6..8].try_into().unwrap()) as usize;
        if bytes.len() != 8 + base_len {
            return Err(ProtocolError::internal(format!(
                "session_start: public read base URL length mismatch: declared {base_len}, response {} bytes",
                bytes.len()
            )));
        }
        let immutable_payload_read = match mode {
            0 => ImmutablePayloadReadMode::ServerStream,
            1 => {
                if key_scheme != 0 {
                    return Err(ProtocolError::internal(format!(
                        "session_start: unsupported public object key scheme {key_scheme}"
                    )));
                }
                let base_url = String::from_utf8(bytes[8..].to_vec()).map_err(|error| {
                    ProtocolError::internal_with_context(
                        error,
                        "session_start: invalid public read base URL encoding",
                    )
                })?;
                ImmutablePayloadReadMode::PublicHttp(PublicObjectReadConfig::new_hash_hex(base_url))
            }
            other => {
                return Err(ProtocolError::internal(format!(
                    "session_start: unsupported immutable payload read mode {other}"
                )));
            }
        };
        Ok(Self {
            session_id,
            immutable_payload_read,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_legacy_four_byte_session_start_as_server_stream() {
        let decoded = StorageSessionStart::decode_quic_v4(&7u32.to_le_bytes()).unwrap();
        assert_eq!(decoded, StorageSessionStart::server_stream(7));
    }

    #[test]
    fn encodes_public_http_capability() {
        let start = StorageSessionStart::public_http_hash_hex(9, "https://objects.example.com/");
        let decoded = StorageSessionStart::decode_quic_v4(&start.encode_quic_v4()).unwrap();
        assert_eq!(
            decoded,
            StorageSessionStart::public_http_hash_hex(9, "https://objects.example.com")
        );
    }
}
