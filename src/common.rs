use crate::error::SqrlError;
use ed25519_dalek::PublicKey;
use std::fmt;
use url::Url;

pub const SQRL_PROTOCOL: &str = "sqrl";

#[derive(Debug, PartialEq)]
pub struct SqrlUrl {
    url: Url,
}

impl SqrlUrl {
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

pub struct IdentityUnlockKeys {
    pub server_unlock_key: x25519_dalek::PublicKey,
    pub verify_unlock_key: PublicKey,
}

impl IdentityUnlockKeys {
    pub fn new(server_unlock_key: x25519_dalek::PublicKey, verify_unlock_key: PublicKey) -> Self {
        IdentityUnlockKeys {
            server_unlock_key,
            verify_unlock_key,
        }
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
