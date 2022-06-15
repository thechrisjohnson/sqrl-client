use super::readable_vector::ReadableVector;
use crate::error::SqrlError;
use std::{collections::VecDeque, convert::TryInto, io::Write};

#[derive(Debug, PartialEq)]
pub(crate) enum IdentityKey {
    Encrypted([u8; 32]),
    Plaintext([u8; 32]),
}

impl IdentityKey {
    pub(crate) fn from_binary(binary: &mut VecDeque<u8>) -> Result<Self, SqrlError> {
        Ok(IdentityKey::Encrypted(
            binary.next_sub_array(32)?.as_slice().try_into()?,
        ))
    }

    pub(crate) fn to_binary(&self, output: &mut Vec<u8>) -> Result<(), SqrlError> {
        match self {
            IdentityKey::Encrypted(data) => {
                output.write(data)?;
            }
            IdentityKey::Plaintext(_) => {
                return Err(SqrlError::new(
                    "Cannot safe unencrypted identity key!".to_owned(),
                ))
            }
        };

        Ok(())
    }
}
