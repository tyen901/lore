// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use bytes::Bytes;
use bytes::BytesMut;
use reqwest::StatusCode;
use tokio::sync::Semaphore;

use crate::Address;
use crate::Fragment;
use crate::Hash;
use crate::STORE_RETRY_ATTEMPTS;
use crate::StorageError;
use crate::errors::SlowDown;

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

static PUBLIC_HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
static PUBLIC_HTTP_GET_LIMITER: OnceLock<Arc<Semaphore>> = OnceLock::new();

fn public_http_client() -> reqwest::Client {
    PUBLIC_HTTP_CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(120))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("public HTTP client configuration is valid")
        })
        .clone()
}

fn public_http_limiter() -> Arc<Semaphore> {
    PUBLIC_HTTP_GET_LIMITER
        .get_or_init(|| Arc::new(Semaphore::new(32)))
        .clone()
}

enum PublicHttpFetchError {
    Retry(StorageError),
    Fail(StorageError),
}

pub(crate) async fn fetch_public_hash_payload(
    base_url: &str,
    hash: Hash,
    fragment: Fragment,
) -> Result<Bytes, StorageError> {
    let config = PublicObjectReadConfig::try_new(base_url)?;
    let url = config.url_for_hash(hash);
    let mut retry = crate::retry(50, 10_000, *STORE_RETRY_ATTEMPTS.get_or_init(|| 60));

    loop {
        match fetch_public_hash_payload_once(&url, hash, fragment).await {
            Ok(payload) => return Ok(payload),
            Err(PublicHttpFetchError::Retry(err)) => {
                if !retry.wait().await {
                    return Err(err);
                }
            }
            Err(PublicHttpFetchError::Fail(err)) => return Err(err),
        }
    }
}

async fn fetch_public_hash_payload_once(
    url: &str,
    hash: Hash,
    fragment: Fragment,
) -> Result<Bytes, PublicHttpFetchError> {
    let limiter = public_http_limiter();
    let _permit = limiter.acquire().await.map_err(|err| {
        PublicHttpFetchError::Fail(StorageError::internal_with_context(
            err,
            "public HTTP GET permit",
        ))
    })?;

    let response = public_http_client().get(url).send().await;

    match response {
        Ok(response) if response.status() == StatusCode::OK => {
            read_verified_public_body(response, hash, fragment)
                .await
                .map_err(PublicHttpFetchError::Fail)
        }

        Ok(response) if response.status() == StatusCode::NOT_FOUND => {
            Err(PublicHttpFetchError::Fail(StorageError::from(
                crate::errors::AddressNotFound::from(Address::zero_context_hash(hash)),
            )))
        }

        Ok(response)
            if response.status() == StatusCode::TOO_MANY_REQUESTS
                || response.status().is_server_error() =>
        {
            Err(PublicHttpFetchError::Retry(StorageError::from(SlowDown)))
        }

        Ok(response) => Err(PublicHttpFetchError::Fail(StorageError::internal(format!(
            "public immutable payload GET {url} failed with HTTP {}",
            response.status()
        )))),

        Err(err) => Err(PublicHttpFetchError::Retry(
            StorageError::internal_with_context(err, "public immutable payload GET failed"),
        )),
    }
}

async fn read_verified_public_body(
    mut response: reqwest::Response,
    hash: Hash,
    fragment: Fragment,
) -> Result<Bytes, StorageError> {
    let expected = fragment.size_payload as usize;

    if expected > crate::FRAGMENT_SIZE_THRESHOLD {
        return Err(StorageError::from(crate::errors::Oversized {
            context: format!(
                "public immutable payload size {expected} exceeds FRAGMENT_SIZE_THRESHOLD {}",
                crate::FRAGMENT_SIZE_THRESHOLD
            ),
        }));
    }

    if let Some(len) = response.content_length() {
        if len != fragment.size_payload as u64 {
            return Err(StorageError::internal(format!(
                "public immutable payload size mismatch for {hash}: expected {}, got {len}",
                fragment.size_payload
            )));
        }

        if len as usize > crate::FRAGMENT_SIZE_THRESHOLD {
            return Err(StorageError::from(crate::errors::Oversized {
                context: format!(
                    "public immutable payload size {len} exceeds FRAGMENT_SIZE_THRESHOLD {}",
                    crate::FRAGMENT_SIZE_THRESHOLD
                ),
            }));
        }
    }

    let mut bytes = BytesMut::with_capacity(expected);

    while let Some(chunk) = response.chunk().await.map_err(|err| {
        StorageError::internal_with_context(err, "public immutable payload body read failed")
    })? {
        if bytes.len() + chunk.len() > crate::FRAGMENT_SIZE_THRESHOLD {
            return Err(StorageError::from(crate::errors::Oversized {
                context: format!(
                    "public immutable payload body exceeds FRAGMENT_SIZE_THRESHOLD {}",
                    crate::FRAGMENT_SIZE_THRESHOLD
                ),
            }));
        }

        bytes.extend_from_slice(&chunk);
    }

    let bytes = bytes.freeze();

    if bytes.len() != expected {
        return Err(StorageError::internal(format!(
            "public immutable payload size mismatch for {hash}: expected {expected}, got {}",
            bytes.len()
        )));
    }

    let loaded_hash = crate::hash::hash_fragment(fragment, bytes.as_ref())
        .map_err(|err| StorageError::internal_with_context(err, "public payload hash"))?;

    if loaded_hash != hash {
        return Err(StorageError::internal(format!(
            "public immutable payload hash mismatch for {hash}: got {loaded_hash}"
        )));
    }

    Ok(bytes)
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
