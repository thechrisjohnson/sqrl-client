use std::fmt;

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

impl fmt::Display for SqrlError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.error_message)
    }
}

impl fmt::Debug for SqrlError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{ file: {}, line: {} }}", file!(), line!())
    }
}
