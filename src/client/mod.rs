mod identity;

use self::identity::IdentityInformation;
use error::SqrlError;

pub struct SqrlClient {
    identity_information: IdentityInformation,
}

pub struct Nut {}

impl SqrlClient {
    pub fn new() -> Self {
        // TODO: Make this a public config
        SqrlClient {
            identity_information: IdentityInformation::new(),
        }
    }

    pub fn from_file(file_name: &str) -> Result<Self, SqrlError> {
        Ok(SqrlClient {
            identity_information: IdentityInformation::from_file(file_name)?,
        })
    }

    pub fn to_file(&self, file_name: &str) -> Result<(), SqrlError> {
        self.identity_information.to_file(file_name)
    }

    pub fn from_base64(input: &str) -> Result<Self, SqrlError> {
        Ok(SqrlClient {
            identity_information: IdentityInformation::from_base64(input)?,
        })
    }

    pub fn to_base64(&self) -> Result<String, SqrlError> {
        self.identity_information.to_base64()
    }

    pub fn from_textual_identity_format(input: &str) -> Result<Self, SqrlError> {
        Ok(SqrlClient {
            identity_information: IdentityInformation::from_textual_identity_format(input)?,
        })
    }

    pub fn to_textual_identity_format(&self) -> Result<String, SqrlError> {
        self.identity_information.to_textual_identity_format()
    }
}
