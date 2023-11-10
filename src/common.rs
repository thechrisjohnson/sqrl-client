//! Common code used by both SQRL clients and servers

use crate::error::SqrlError;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use std::fmt;
use url::Url;
use x25519_dalek::PublicKey;

/// The general protocl for SQRL urls
pub const SQRL_PROTOCOL: &str = "sqrl";

/// Parses a SQRL url and breaks it into its parts
#[derive(Debug, PartialEq)]
pub struct SqrlUrl {
    url: Url,
}

impl SqrlUrl {
    /// Parse a SQRL url string and convert it into the object
    pub fn parse(url: &str) -> Result<Self, SqrlError> {
        let parsed = Url::parse(url)?;
        if parsed.scheme() != SQRL_PROTOCOL {
            return Err(SqrlError::new(format!(
                "Invalid sqrl url, incorrect protocol: {}",
                url
            )));
        }
        if parsed.domain().is_none() {
            return Err(SqrlError::new(format!(
                "Invalid sqrl url, missing domain: {}",
                url
            )));
        }

        Ok(SqrlUrl { url: parsed })
    }

    /// Get the auth domain used for calculating identities
    pub fn get_auth_domain(&self) -> String {
        format!("{}{}", self.get_domain(), self.get_path())
    }

    fn get_domain(&self) -> String {
        self.url.domain().unwrap().to_lowercase()
    }

    fn get_path(&self) -> String {
        let path = self.url.path().strip_suffix('/').unwrap_or(self.url.path());
        path.to_owned()
    }
}

impl fmt::Display for SqrlUrl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.url)
    }
}

/// THe keys needed to unlock a SQRL identity
pub struct IdentityUnlockKeys {
    /// The server unlock key (aka the public portion of a Diffie-Helman key)
    pub server_unlock_key: PublicKey,
    /// The verify unlock key (aka the public portion of a signing keypair)
    pub verify_unlock_key: VerifyingKey,
}

impl IdentityUnlockKeys {
    /// Create an identity unlock key pair from existing keys
    pub fn new(server_unlock_key: PublicKey, verify_unlock_key: VerifyingKey) -> Self {
        IdentityUnlockKeys {
            server_unlock_key,
            verify_unlock_key,
        }
    }
}

pub(crate) fn vec_to_u8_32(vector: &Vec<u8>) -> Result<[u8; 32], SqrlError> {
    let mut result = [0; 32];
    if vector.len() != 32 {
        return Err(SqrlError::new(format!(
            "Error converting vec<u8> to [u8; 32]: Expected 32 bytes, but found {}",
            vector.len()
        )));
    }

    result[..32].copy_from_slice(&vector[..32]);
    Ok(result)
}

pub(crate) fn vec_to_u8_64(vector: &Vec<u8>) -> Result<[u8; 64], SqrlError> {
    let mut result = [0; 64];
    if vector.len() != 64 {
        return Err(SqrlError::new(format!(
            "Error converting vec<u8> to [u8; 64]: Expected 64 bytes, but found {}",
            vector.len()
        )));
    }

    result[..64].copy_from_slice(&vector[..64]);
    Ok(result)
}

pub(crate) fn en_hash(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let mut output: [u8; 32] = [0; 32];
    for _ in 0..16 {
        let hash_result: [u8; 32] = hasher.finalize().into();
        hasher = Sha256::new();
        hasher.update(hash_result);
        xor(&mut output, &hash_result);
    }

    output
}

pub(crate) fn xor(output: &mut [u8], other: &[u8]) {
    for i in 0..output.len() {
        output[i] ^= other[i];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqrl_url_parse() {
        let url = SqrlUrl::parse("sqrl://example.com?nut=8675309").unwrap();
        assert_eq!(url.get_auth_domain(), "example.com");
    }

    #[test]
    fn sqrl_url_parse_auth_domain_casing() {
        let url = SqrlUrl::parse("sqrl://ExAmpLe.coM?nut=8675309").unwrap();
        assert_eq!(url.get_auth_domain(), "example.com");
    }

    #[test]
    fn sqrl_url_parse_auth_domain_trailing_forward_slash() {
        let url = SqrlUrl::parse("sqrl://example.com/?nut=8675309").unwrap();
        assert_eq!(url.get_auth_domain(), "example.com");
    }

    #[test]
    fn sqrl_url_parse_auth_domain_port() {
        let url = SqrlUrl::parse("sqrl://example.com:1234?nut=8675309").unwrap();
        assert_eq!(url.get_auth_domain(), "example.com");
    }

    #[test]
    fn sqrl_url_parse_auth_domain_password() {
        let url = SqrlUrl::parse("sqrl://jonny:secret@example.com?nut=8675309").unwrap();
        assert_eq!(url.get_auth_domain(), "example.com");
    }

    #[test]
    fn sqrl_url_parse_auth_domain_path() {
        let url = SqrlUrl::parse("sqrl://example.com/jimbo/?nut=8675309").unwrap();
        assert_eq!(url.get_auth_domain(), "example.com/jimbo");
    }

    #[test]
    fn sqrl_url_parse_auth_domain_path_case() {
        let url = SqrlUrl::parse("sqrl://example.com/JIMBO?nut=8675309").unwrap();
        assert_eq!(url.get_auth_domain(), "example.com/JIMBO");
    }
}
