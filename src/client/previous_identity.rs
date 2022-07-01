use super::{readable_vector::ReadableVector, writable_datablock::WritableDataBlock, DataType};
use crate::error::SqrlError;
use byteorder::{LittleEndian, WriteBytesExt};
use std::io::Write;
use std::{collections::VecDeque, convert::TryInto};

#[derive(Debug, PartialEq)]
pub(crate) struct PreviousIdentityData {
    edition: u16,
    pub(crate) previous_identity_unlock_keys: Vec<[u8; 32]>,
    pub(crate) verification_data: [u8; 16],
}

impl PreviousIdentityData {
    pub(crate) fn  new() -> Self {
        PreviousIdentityData { edition: 0, previous_identity_unlock_keys: Vec::new(), verification_data: [0; 16] }
    }

    pub(crate) fn add_previous_identity(&mut self, key: [u8; 32]) -> () {
        self.edition += 1;
        self.previous_identity_unlock_keys.push(key)
    }
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
            previous_identity_unlock_keys.push(binary.next_sub_array(32)?.as_slice().try_into()?);
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
            output.write(key);
        }
        output.write(&self.verification_data)?;

        Ok(())
    }
}
