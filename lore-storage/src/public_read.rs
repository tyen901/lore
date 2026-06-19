// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use crate::Hash;

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PublicObjectReadConfig {
    pub base_url: String,
}

impl PublicObjectReadConfig {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: normalize_public_base_url(base_url.into()),
        }
    }

    pub fn url_for_hash(&self, hash: Hash) -> String {
        format!("{}/{}", self.base_url, hash)
    }
}

pub fn normalize_public_base_url(base_url: String) -> String {
    base_url.trim_end_matches('/').to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_for_hash_uses_normalized_base_and_hash_hex() {
        let hash = Hash::from([0xabu8; 32]);
        let config = PublicObjectReadConfig::new("https://objects.example.com///");
        assert_eq!(
            config.url_for_hash(hash),
            "https://objects.example.com/abababababababababababababababababababababababababababababababab"
        );
    }
}
