use std::{fmt, string::FromUtf8Error};

pub struct SqrlError {
    error_message: String,
}

impl SqrlError {
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

impl fmt::Display for SqrlError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.error_message)
    }
}

impl fmt::Debug for SqrlError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {}",
            self.error_message,
            // Temp fix until https://github.com/rust-lang/rust-clippy/issues/2768 is fixed
            concat!("{{ file: ", file!(), ", line: ", line!(), " }}")
        )
    }
}
