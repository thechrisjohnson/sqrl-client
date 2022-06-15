use super::identity_key::IdentityKey;
use super::readable_vector::ReadableVector;
use super::scrypt_config::ScryptConfig;
use super::writable_datablock::WritableDataBlock;
use super::DataType;
use crate::error::SqrlError;
use std::collections::VecDeque;
use std::convert::TryInto;
use std::io::Write;

#[derive(Debug, PartialEq)]
pub(crate) struct IdentityUnlock {
    scrypt_config: ScryptConfig,
    identity_unlock_key: IdentityKey,
    verification_data: [u8; 16],
}

impl IdentityUnlock {
    pub fn new() -> Self {
        IdentityUnlock {
            scrypt_config: ScryptConfig::new(),
            identity_unlock_key: IdentityKey::Plaintext([0; 32]),
            verification_data: [0; 16],
        }
    }
}

impl WritableDataBlock for IdentityUnlock {
    fn get_type(&self) -> DataType {
        DataType::RescueCode
    }

    fn len(&self) -> u16 {
        73
    }

    fn from_binary(binary: &mut VecDeque<u8>) -> Result<Self, SqrlError> {
        Ok(IdentityUnlock {
            scrypt_config: ScryptConfig::from_binary(binary)?,
            identity_unlock_key: IdentityKey::from_binary(binary)?,
            verification_data: binary.next_sub_array(16)?.as_slice().try_into()?,
        })
    }

    fn to_binary_inner(&self, output: &mut Vec<u8>) -> Result<(), SqrlError> {
        self.scrypt_config.to_binary(output)?;
        self.identity_unlock_key.to_binary(output)?;
        output.write(&self.verification_data)?;
        Ok(())
    }
}
