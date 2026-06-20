// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use crate::Hash;
use crate::StorageError;

pub const PUBLIC_READ_BASE_URL_MAX_LEN: usize = u16::MAX as usize;

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PublicObjectReadConfig {
    pub base_url: String,
}

impl PublicObjectReadConfig {
    pub fn try_new(base_url: impl AsRef<str>) -> Result<Self, StorageError> {
        Ok(Self {
            base_url: validate_public_base_url(base_url.as_ref())?,
        })
    }

    pub fn url_for_hash(&self, hash: Hash) -> String {
        format!("{}/{}", self.base_url, hash)
    }
}

pub fn validate_public_base_url(base_url: &str) -> Result<String, StorageError> {
    let normalized = base_url.trim().trim_end_matches('/').to_owned();

    if normalized.is_empty() {
        return Err(StorageError::internal(
            "public_read_base_url must not be empty",
        ));
    }

    if normalized.len() > PUBLIC_READ_BASE_URL_MAX_LEN {
        return Err(StorageError::internal(format!(
            "public_read_base_url length {} exceeds QUIC capability limit {}",
            normalized.len(),
            PUBLIC_READ_BASE_URL_MAX_LEN
        )));
    }

    let parsed = url::Url::parse(&normalized).map_err(|err| {
        StorageError::internal_with_context(err, "public_read_base_url must be an absolute URL")
    })?;

    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            return Err(StorageError::internal(format!(
                "public_read_base_url must use http or https, got {other}"
            )));
        }
    }

    if !parsed.has_host() {
        return Err(StorageError::internal(
            "public_read_base_url must include a host",
        ));
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(StorageError::internal(
            "public_read_base_url must not include credentials",
        ));
    }

    if parsed.query().is_some() {
        return Err(StorageError::internal(
            "public_read_base_url must not include a query string",
        ));
    }

    if parsed.fragment().is_some() {
        return Err(StorageError::internal(
            "public_read_base_url must not include a fragment",
        ));
    }

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_for_hash_uses_normalized_base_and_hash_hex() {
        let hash = Hash::from([0xabu8; 32]);
        let config = PublicObjectReadConfig::try_new("https://objects.example.com///").unwrap();

        assert_eq!(
            config.url_for_hash(hash),
            "https://objects.example.com/abababababababababababababababababababababababababababababababab"
        );
    }

    #[test]
    fn rejects_invalid_public_read_base_urls() {
        for base_url in [
            "",
            "not-a-url",
            "/relative/path",
            "file:///tmp/lore",
            "https://objects.example.com?x=1",
            "https://objects.example.com#frag",
            "https://user:pass@objects.example.com",
        ] {
            assert!(
                PublicObjectReadConfig::try_new(base_url).is_err(),
                "base URL should be rejected: {base_url:?}"
            );
        }
    }

    #[test]
    fn rejects_too_long_public_read_base_url() {
        let base_url = format!(
            "https://objects.example.com/{}",
            "a".repeat(u16::MAX as usize)
        );

        assert!(PublicObjectReadConfig::try_new(base_url).is_err());
    }
}
