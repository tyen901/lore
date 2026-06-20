// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use bytes::{BufMut, Bytes, BytesMut};

use crate::ProtocolError;

/// Appended to AuthorizeStart after the declared auth token.
///
/// Existing servers ignore this tail because AuthorizeStart parsing consumes
/// exactly the declared auth token length. New servers must only send the
/// extended public-read session_start response when this capability is present.
pub const AUTHORIZE_PUBLIC_READ_RESPONSE_CAPABILITY: u8 = 1;

pub const PUBLIC_READ_BASE_URL_MAX_LEN: usize = u16::MAX as usize;

const MODE_PUBLIC_HTTP_HASH_HEX: u8 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageSessionStart {
    pub session_id: u32,
    pub public_read_base_url: Option<String>,
}

impl StorageSessionStart {
    pub fn server_stream(session_id: u32) -> Self {
        Self {
            session_id,
            public_read_base_url: None,
        }
    }

    pub fn public_http_hash_hex(session_id: u32, base_url: impl Into<String>) -> Self {
        Self {
            session_id,
            public_read_base_url: Some(base_url.into().trim_end_matches('/').to_owned()),
        }
    }

    pub fn encode_quic_v4(&self) -> Result<Bytes, ProtocolError> {
        let Some(base_url) = self.public_read_base_url.as_deref() else {
            return Ok(Bytes::copy_from_slice(&self.session_id.to_le_bytes()));
        };

        let base = base_url.as_bytes();
        let len = u16::try_from(base.len()).map_err(|_| {
            ProtocolError::internal(format!(
                "session_start: public read base URL length {} exceeds u16 wire limit",
                base.len()
            ))
        })?;

        let mut out = BytesMut::with_capacity(8 + base.len());
        out.put_slice(&self.session_id.to_le_bytes());
        out.put_u8(MODE_PUBLIC_HTTP_HASH_HEX);
        out.put_u8(0);
        out.put_slice(&len.to_le_bytes());
        out.put_slice(base);
        Ok(out.freeze())
    }

    pub fn decode_quic_v4(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() == 4 {
            return Ok(Self::server_stream(u32::from_le_bytes(
                bytes.try_into().unwrap(),
            )));
        }

        if bytes.len() < 8 {
            return Err(ProtocolError::internal(format!(
                "session_start: expected 4-byte legacy response or 8-byte extended response, got {} bytes",
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

        match mode {
            MODE_PUBLIC_HTTP_HASH_HEX => {
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

                if base_url.is_empty() {
                    return Err(ProtocolError::internal(
                        "session_start: public read base URL must not be empty",
                    ));
                }

                Ok(Self::public_http_hash_hex(session_id, base_url))
            }
            other => Err(ProtocolError::internal(format!(
                "session_start: unsupported immutable payload read mode {other}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_stream_encodes_legacy_four_byte_session_id() {
        assert_eq!(
            StorageSessionStart::server_stream(7)
                .encode_quic_v4()
                .unwrap()
                .as_ref(),
            &7u32.to_le_bytes()
        );
    }

    #[test]
    fn decodes_legacy_four_byte_session_start_as_server_stream() {
        let decoded = StorageSessionStart::decode_quic_v4(&7u32.to_le_bytes()).unwrap();
        assert_eq!(decoded, StorageSessionStart::server_stream(7));
    }

    #[test]
    fn encodes_public_http_hash_hex_capability() {
        let start = StorageSessionStart::public_http_hash_hex(9, "https://objects.example.com/");
        let decoded =
            StorageSessionStart::decode_quic_v4(&start.encode_quic_v4().unwrap()).unwrap();

        assert_eq!(
            decoded,
            StorageSessionStart::public_http_hash_hex(9, "https://objects.example.com")
        );
    }

    #[test]
    fn rejects_overlong_public_http_capability() {
        let start = StorageSessionStart::public_http_hash_hex(
            9,
            format!(
                "https://objects.example.com/{}",
                "a".repeat(u16::MAX as usize)
            ),
        );

        assert!(start.encode_quic_v4().is_err());
    }
}
