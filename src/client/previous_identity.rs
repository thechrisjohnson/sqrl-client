use super::{readable_vector::ReadableVector, writable_datablock::WritableDataBlock, DataType};
use crate::common::EMPTY_NONCE;
use crate::error::SqrlError;
use byteorder::{LittleEndian, WriteBytesExt};
use crypto::aead::{AeadDecryptor, AeadEncryptor};
use crypto::aes::KeySize;
use crypto::aes_gcm::AesGcm;
use std::io::Write;
use std::{collections::VecDeque, convert::TryInto};

#[derive(Debug, PartialEq)]
pub(crate) struct PreviousIdentityData {
    edition: u16,
    pub(crate) previous_identity_unlock_keys: Vec<[u8; 32]>,
    pub(crate) verification_data: [u8; 16],
}

impl PreviousIdentityData {
    pub(crate) fn new() -> Self {
        PreviousIdentityData {
            edition: 0,
            previous_identity_unlock_keys: Vec::new(),
            verification_data: [0; 16],
        }
    }

    pub(crate) fn add_previous_identity(
        &mut self,
        identity_master_key: &[u8],
        key: [u8; 32],
    ) -> Result<(), SqrlError> {
        // First decrypt the existing data
        let mut unencrypted_keys: VecDeque<[u8; 32]>;
        if self.edition > 0 {
            unencrypted_keys = self.decrypt_previous_identities(identity_master_key)?;
        } else {
            unencrypted_keys = VecDeque::new()
        }

        // Add the new key
        if self.edition < 4 {
            self.edition += 1;
            unencrypted_keys.push_back(key);
        } else {
            unencrypted_keys.pop_front();
            unencrypted_keys.push_back(key);
        }

        let mut aes = AesGcm::new(
            KeySize::KeySize256,
            &identity_master_key,
            &EMPTY_NONCE,
            self.aad()?.as_slice(),
        );

        let mut encrypted_data = vec![0; (self.edition * 32).into()];
        aes.encrypt(
            &unencrypted_keys.into_iter().flatten().collect::<Vec<u8>>(),
            &mut encrypted_data,
            &mut self.verification_data,
        );

        let mut result = Vec::new();
        let mut iter = encrypted_data.into_iter();
        for _ in 0..self.edition {
            let mut key: [u8; 32] = [0; 32];
            for i in 0..32 {
                key[i] = iter.next().unwrap();
            }
            result.push(key);
        }
        self.previous_identity_unlock_keys = result;

        Ok(())
    }

    fn decrypt_previous_identities(
        &self,
        identity_master_key: &[u8],
    ) -> Result<VecDeque<[u8; 32]>, SqrlError> {
        let mut encrypted_data = Vec::new();
        for key in self.previous_identity_unlock_keys.iter() {
            for byte in key {
                encrypted_data.push(*byte);
            }
        }

        let mut aes = AesGcm::new(
            KeySize::KeySize256,
            identity_master_key,
            &EMPTY_NONCE,
            self.aad()?.as_slice(),
        );

        let mut unencrypted_data = vec![0; (self.edition * 32).into()];
        if aes.decrypt(
            &encrypted_data,
            &mut unencrypted_data,
            &self.verification_data,
        ) {
            let mut result = VecDeque::new();
            let mut iter = unencrypted_data.into_iter();
            for _ in 0..self.edition {
                let mut key: [u8; 32] = [0; 32];
                for i in 0..32 {
                    key[i] = iter.next().unwrap();
                }
                result.push_back(key);
            }

            return Ok(result);
        } else {
            return Err(SqrlError::new(
                "Decryption failed. Check the identity master key!".to_owned(),
            ));
        }
    }

    fn aad(&self) -> Result<Vec<u8>, SqrlError> {
        let mut result = Vec::<u8>::new();
        result.write_u16::<LittleEndian>(self.len())?;
        self.get_type().to_binary(&mut result)?;
        result.write_u16::<LittleEndian>(self.edition)?;
        Ok(result)
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
            output.write(key)?;
        }
        output.write(&self.verification_data)?;

        Ok(())
    }
}
