//! A common error used by SQRL clients and servers

use scrypt::errors::{InvalidOutputLen, InvalidParams};
use std::{fmt, num::ParseIntError, string::FromUtf8Error};

/// An error that can occur in the SQRL library
pub struct SqrlError {
    error_message: String,
}

impl SqrlError {
    /// Create a new SqrlError with the string as error message
    pub fn new(error: String) -> Self {
        SqrlError {
            error_message: error,
        }
    }
}

impl std::error::Error for SqrlError {}

impl From<std::io::Error> for SqrlError {
    fn from(error: std::io::Error) -> Self {
        SqrlError::new(error.to_string())
    }
}

impl From<std::array::TryFromSliceError> for SqrlError {
    fn from(error: std::array::TryFromSliceError) -> Self {
        SqrlError::new(error.to_string())
    }
}

impl From<url::ParseError> for SqrlError {
    fn from(error: url::ParseError) -> Self {
        SqrlError::new(error.to_string())
    }
}

impl From<base64::DecodeError> for SqrlError {
    fn from(error: base64::DecodeError) -> Self {
        SqrlError::new(error.to_string())
    }
}

impl From<FromUtf8Error> for SqrlError {
    fn from(error: FromUtf8Error) -> Self {
        SqrlError::new(error.to_string())
    }
}

impl From<InvalidParams> for SqrlError {
    fn from(value: InvalidParams) -> Self {
        SqrlError::new(value.to_string())
    }
}

impl From<InvalidOutputLen> for SqrlError {
    fn from(value: InvalidOutputLen) -> Self {
        SqrlError::new(value.to_string())
    }
}

impl From<aes_gcm::Error> for SqrlError {
    fn from(value: aes_gcm::Error) -> Self {
        SqrlError::new(value.to_string())
    }
}

impl From<hmac::digest::InvalidLength> for SqrlError {
    fn from(value: hmac::digest::InvalidLength) -> Self {
        SqrlError::new(value.to_string())
    }
}

impl From<ed25519_dalek::ed25519::Error> for SqrlError {
    fn from(value: ed25519_dalek::ed25519::Error) -> Self {
        SqrlError::new(value.to_string())
    }
}

impl From<ParseIntError> for SqrlError {
    fn from(value: ParseIntError) -> Self {
        SqrlError::new(value.to_string())
    }
}

impl From<sqrl_protocol::error::SqrlError> for SqrlError {
    fn from(value: sqrl_protocol::error::SqrlError) -> Self {
        SqrlError::new(value.to_string())
    }
}

impl fmt::Display for SqrlError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.error_message)
    }
}

impl fmt::Debug for SqrlError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.error_message)
    }
}
