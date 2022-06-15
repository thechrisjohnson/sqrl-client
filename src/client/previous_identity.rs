use super::{
    identity_key::IdentityKey, readable_vector::ReadableVector,
    writable_datablock::WritableDataBlock, DataType,
};
use crate::error::SqrlError;
use byteorder::{LittleEndian, WriteBytesExt};
use std::{collections::VecDeque, convert::TryInto};

#[derive(Debug, PartialEq)]
pub(crate) struct PreviousIdentityData {
    pub(crate) edition: u16,
    pub(crate) previous_identity_unlock_keys: Vec<IdentityKey>,
    pub(crate) verification_data: [u8; 16],
}

impl WritableDataBlock for PreviousIdentityData {
    fn get_type(&self) -> DataType {
        DataType::PreviousIdentity
    }

    fn len(&self) -> u16 {
        if self.edition > 0 {
            22 + (self.edition * 32)
        } else {
            0
        }
    }

    fn from_binary(binary: &mut VecDeque<u8>) -> Result<Self, SqrlError> {
        let edition = binary.next_u16()?;

        let mut previous_identity_unlock_keys = Vec::new();
        for _ in 0..edition {
            previous_identity_unlock_keys.push(IdentityKey::from_binary(binary)?);
        }

        let verification_data = binary.next_sub_array(16)?.as_slice().try_into()?;

        Ok(PreviousIdentityData {
            edition: edition,
            previous_identity_unlock_keys: previous_identity_unlock_keys,
            verification_data: verification_data,
        })
    }

    fn to_binary_inner(&self, output: &mut Vec<u8>) -> Result<(), SqrlError> {
        if self.edition == 0 {
            return Ok(());
        }

        output.write_u16::<LittleEndian>(self.edition)?;
        for key in &self.previous_identity_unlock_keys {
            key.to_binary(output)?;
        }

        Ok(())
    }
}
