// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use bytes::Bytes;
use lore_revision::lore::RepositoryId;
use lore_transport::AUTHORIZE_PUBLIC_READ_RESPONSE_CAPABILITY;

use crate::protocol::storage::messages::MessageParseError;

const ACTION_START: u8 = 0;
const ACTION_STOP: u8 = 1;

// Minimum payload size for Authorize start:
// action(1) + repo_id(16) + corr_len(1) + auth_token_len(2) = 20
const AUTHORIZE_START_MIN_PAYLOAD: usize = 20;

#[derive(Clone, Debug, PartialEq)]
pub struct AuthorizeStart {
    pub repository: RepositoryId,
    pub correlation_id: String,
    pub auth_token: Vec<u8>,
    pub public_read_response_supported: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AuthorizeStop {
    pub session_id: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AuthorizeAction {
    Start(AuthorizeStart),
    Stop(AuthorizeStop),
}

impl AuthorizeStart {
    pub fn parse(bytes: Bytes) -> Result<Self, MessageParseError> {
        if bytes.len() < AUTHORIZE_START_MIN_PAYLOAD {
            return Err(MessageParseError::InvalidFieldLength);
        }

        if bytes[0] != ACTION_START {
            return Err(MessageParseError::ParseFailure("invalid action byte"));
        }

        let repository: RepositoryId = bytes.slice(1..17).into();
        let corr_len = bytes[17] as usize;
        let corr_end = 18 + corr_len;

        if bytes.len() < corr_end + 2 {
            return Err(MessageParseError::InvalidFieldLength);
        }

        let token_len = u16::from_le_bytes([bytes[corr_end], bytes[corr_end + 1]]) as usize;
        let token_start = corr_end + 2;

        if bytes.len() < token_start + token_len {
            return Err(MessageParseError::InvalidFieldLength);
        }

        // Allocate strings only after all length validations pass
        let correlation_id = if corr_len > 0 {
            String::from_utf8(bytes.slice(18..corr_end).to_vec()).map_err(|err| {
                tracing::debug!("Invalid UTF-8 in correlation_id: {err}");
                MessageParseError::ParseFailure("correlation_id is not valid UTF-8")
            })?
        } else {
            String::new()
        };

        let auth_token = bytes.slice(token_start..token_start + token_len).to_vec();
        let tail = bytes.slice(token_start + token_len..);
        let public_read_response_supported = tail
            .iter()
            .any(|byte| *byte == AUTHORIZE_PUBLIC_READ_RESPONSE_CAPABILITY);

        Ok(Self {
            repository,
            correlation_id,
            auth_token,
            public_read_response_supported,
        })
    }
}

impl AuthorizeStop {
    pub fn parse(session_id: u32, bytes: Bytes) -> Result<Self, MessageParseError> {
        if bytes.len() != 1 {
            return Err(MessageParseError::InvalidFieldLength);
        }
        if bytes[0] != ACTION_STOP {
            return Err(MessageParseError::ParseFailure("invalid action byte"));
        }
        if session_id == 0 {
            return Err(MessageParseError::ParseFailure(
                "session_id must be non-zero for stop",
            ));
        }
        Ok(Self { session_id })
    }
}

/// Parse an Authorize command payload, determining start vs stop from the action byte.
pub fn parse_authorize(
    session_id: u32,
    bytes: Bytes,
) -> Result<AuthorizeAction, MessageParseError> {
    if bytes.is_empty() {
        return Err(MessageParseError::InvalidFieldLength);
    }
    match bytes[0] {
        ACTION_START => {
            if session_id != 0 {
                return Err(MessageParseError::ParseFailure(
                    "session_id must be 0 for authorize start",
                ));
            }
            Ok(AuthorizeAction::Start(AuthorizeStart::parse(bytes)?))
        }
        ACTION_STOP => Ok(AuthorizeAction::Stop(AuthorizeStop::parse(
            session_id, bytes,
        )?)),
        _ => Err(MessageParseError::ParseFailure("unrecognized action byte")),
    }
}

#[cfg(test)]
mod tests {
    use rand::random;
    use zerocopy::IntoBytes;

    use super::*;

    fn build_start_payload(repo: RepositoryId, corr: &str, token: &[u8]) -> Bytes {
        let mut buf = Vec::new();
        buf.push(ACTION_START);
        buf.extend_from_slice(repo.as_bytes());
        buf.push(corr.len() as u8);
        buf.extend_from_slice(corr.as_bytes());
        buf.extend_from_slice(&(token.len() as u16).to_le_bytes());
        buf.extend_from_slice(token);
        Bytes::from(buf)
    }

    #[test]
    fn parse_start_valid() {
        let repo = random::<RepositoryId>();
        let payload = build_start_payload(repo, "my-corr", b"my-token");
        let result = AuthorizeStart::parse(payload).unwrap();
        assert_eq!(result.repository, repo);
        assert_eq!(result.correlation_id, "my-corr");
        assert_eq!(result.auth_token, b"my-token");
        assert!(!result.public_read_response_supported);
    }

    #[test]
    fn parse_start_public_read_response_capability() {
        let repo = random::<RepositoryId>();
        let mut payload = build_start_payload(repo, "my-corr", b"my-token").to_vec();
        payload.push(AUTHORIZE_PUBLIC_READ_RESPONSE_CAPABILITY);

        let result = AuthorizeStart::parse(Bytes::from(payload)).unwrap();

        assert!(result.public_read_response_supported);
    }

    #[test]
    fn parse_start_empty_correlation() {
        let repo = random::<RepositoryId>();
        let payload = build_start_payload(repo, "", b"tok");
        let result = AuthorizeStart::parse(payload).unwrap();
        assert_eq!(result.correlation_id, "");
    }

    #[test]
    fn parse_start_empty_token() {
        let repo = random::<RepositoryId>();
        let payload = build_start_payload(repo, "corr", b"");
        let result = AuthorizeStart::parse(payload).unwrap();
        assert!(result.auth_token.is_empty());
    }

    #[test]
    fn parse_start_too_short() {
        let payload = Bytes::from(vec![0u8; 19]);
        assert_eq!(
            AuthorizeStart::parse(payload),
            Err(MessageParseError::InvalidFieldLength)
        );
    }

    #[test]
    fn parse_start_bad_action() {
        let mut buf = vec![0u8; 20];
        buf[0] = 99; // bad action
        assert!(AuthorizeStart::parse(Bytes::from(buf)).is_err());
    }

    #[test]
    fn parse_start_invalid_utf8_correlation() {
        let repo = random::<RepositoryId>();
        let mut buf = Vec::new();
        buf.push(ACTION_START);
        buf.extend_from_slice(repo.as_bytes());
        buf.push(2); // corr_len = 2
        buf.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
        buf.extend_from_slice(&0u16.to_le_bytes()); // token_len = 0
        let result = AuthorizeStart::parse(Bytes::from(buf));
        assert!(result.is_err());
    }

    #[test]
    fn parse_start_corr_len_exceeds_payload() {
        let repo = random::<RepositoryId>();
        let mut buf = Vec::new();
        buf.push(ACTION_START);
        buf.extend_from_slice(repo.as_bytes());
        buf.push(200); // corr_len = 200 but only a few bytes follow
        buf.extend_from_slice(b"short");
        let result = AuthorizeStart::parse(Bytes::from(buf));
        assert_eq!(result, Err(MessageParseError::InvalidFieldLength));
    }

    #[test]
    fn parse_start_token_len_exceeds_payload() {
        let repo = random::<RepositoryId>();
        let mut buf = Vec::new();
        buf.push(ACTION_START);
        buf.extend_from_slice(repo.as_bytes());
        buf.push(1); // corr_len = 1
        buf.push(b'c');
        buf.extend_from_slice(&100u16.to_le_bytes()); // token_len = 100 but no bytes follow
        let result = AuthorizeStart::parse(Bytes::from(buf));
        assert_eq!(result, Err(MessageParseError::InvalidFieldLength));
    }

    #[test]
    fn parse_stop_valid() {
        let payload = Bytes::from(vec![ACTION_STOP]);
        let result = AuthorizeStop::parse(42, payload).unwrap();
        assert_eq!(result.session_id, 42);
    }

    #[test]
    fn parse_stop_session_id_zero() {
        let payload = Bytes::from(vec![ACTION_STOP]);
        assert!(AuthorizeStop::parse(0, payload).is_err());
    }

    #[test]
    fn parse_stop_wrong_size() {
        let payload = Bytes::from(vec![ACTION_STOP, 0]);
        assert_eq!(
            AuthorizeStop::parse(1, payload),
            Err(MessageParseError::InvalidFieldLength)
        );
    }

    #[test]
    fn parse_stop_bad_action() {
        let payload = Bytes::from(vec![99]);
        assert!(AuthorizeStop::parse(1, payload).is_err());
    }

    #[test]
    fn parse_authorize_start() {
        let repo = random::<RepositoryId>();
        let payload = build_start_payload(repo, "corr", b"tok");
        match parse_authorize(0, payload).unwrap() {
            AuthorizeAction::Start(s) => {
                assert_eq!(s.repository, repo);
                assert_eq!(s.correlation_id, "corr");
            }
            AuthorizeAction::Stop(_) => panic!("expected Start"),
        }
    }

    #[test]
    fn parse_authorize_stop() {
        let payload = Bytes::from(vec![ACTION_STOP]);
        match parse_authorize(7, payload).unwrap() {
            AuthorizeAction::Stop(s) => assert_eq!(s.session_id, 7),
            AuthorizeAction::Start(_) => panic!("expected Stop"),
        }
    }

    #[test]
    fn parse_authorize_start_nonzero_session_id() {
        let repo = random::<RepositoryId>();
        let payload = build_start_payload(repo, "corr", b"tok");
        assert!(parse_authorize(5, payload).is_err());
    }

    #[test]
    fn parse_authorize_empty_payload() {
        assert_eq!(
            parse_authorize(0, Bytes::new()),
            Err(MessageParseError::InvalidFieldLength)
        );
    }
}
