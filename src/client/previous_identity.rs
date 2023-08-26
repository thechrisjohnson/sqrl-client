use super::EMPTY_NONCE;
use super::{
    readable_vector::ReadableVector, writable_datablock::WritableDataBlock, DataType, IdentityKey,
};
use crate::error::SqrlError;
use aes_gcm::aead::{AeadMut, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use byteorder::{LittleEndian, WriteBytesExt};
use client::AesVerificationData;
use std::io::Write;
use std::{collections::VecDeque, convert::TryInto};

const MAX_NUM_KEYS: u16 = 4;

#[derive(Debug, PartialEq)]
pub(crate) struct PreviousIdentityData {
    edition: u16,
    pub(crate) previous_identity_unlock_keys: VecDeque<IdentityKey>,
    pub(crate) verification_data: AesVerificationData,
}

impl PreviousIdentityData {
    pub(crate) fn new() -> Self {
        PreviousIdentityData {
            edition: 0,
            previous_identity_unlock_keys: VecDeque::new(),
            verification_data: [0; 16],
        }
    }

    pub(crate) fn add_previous_identity(
        &mut self,
        identity_master_key: &[u8],
        key: IdentityKey,
    ) -> Result<(), SqrlError> {
        // First decrypt the existing data
        let mut unencrypted_keys: VecDeque<IdentityKey>;
        if self.edition > 0 {
            unencrypted_keys = self.decrypt_previous_identities(identity_master_key)?;
        } else {
            unencrypted_keys = VecDeque::new()
        }

        // Add the new key
        if self.edition >= MAX_NUM_KEYS {
            unencrypted_keys.pop_back();
        }
        unencrypted_keys.push_front(key);

        self.encrypt_previous_identities(unencrypted_keys, identity_master_key)
    }

    pub(crate) fn rekey_previous_identities(
        &mut self,
        current_identity_master_key: &[u8],
        new_identity_master_key: &[u8],
        current_identity_unlock_key: Option<IdentityKey>,
    ) -> Result<(), SqrlError> {
        let mut unencrypted_keys = self.decrypt_previous_identities(current_identity_master_key)?;

        if let Some(key) = current_identity_unlock_key {
            if unencrypted_keys.len() >= MAX_NUM_KEYS.into() {
                unencrypted_keys.pop_back();
            }
            unencrypted_keys.push_front(key);
        }

        self.encrypt_previous_identities(unencrypted_keys, new_identity_master_key)
    }

    pub(crate) fn get_previous_identity(
        &self,
        identity_master_key: &[u8],
        index: usize,
    ) -> Result<Option<IdentityKey>, SqrlError> {
        let keys = self.decrypt_previous_identities(identity_master_key)?;
        if index < keys.len() {
            Ok(Some(keys[index]))
        } else {
            Ok(None)
        }
    }

    fn decrypt_previous_identities(
        &self,
        identity_master_key: &[u8],
    ) -> Result<VecDeque<IdentityKey>, SqrlError> {
        // Append the various previous identities and the verification data
        let mut encrypted_data = Vec::new();
        for key in self.previous_identity_unlock_keys.iter() {
            for byte in key {
                encrypted_data.push(*byte);
            }
        }

        for byte in self.verification_data {
            encrypted_data.push(byte);
        }

        let mut aes = Aes256Gcm::new(identity_master_key.into());
        let payload = Payload {
            msg: &encrypted_data,
            aad: &self.aad()?,
        };

        let unencrypted_data = aes.decrypt(&EMPTY_NONCE.into(), payload)?;
        let mut result = VecDeque::new();
        let mut iter = unencrypted_data.into_iter();
        for _ in 0..self.edition {
            let mut key: IdentityKey = [0; 32];
            for i in &mut key {
                *i = iter.next().unwrap();
            }
            result.push_back(key);
        }

        Ok(result)
    }

    fn encrypt_previous_identities(
        &mut self,
        unencrypted_keys: VecDeque<IdentityKey>,
        identity_master_key: &[u8],
    ) -> Result<(), SqrlError> {
        let num_keys: u16 = match unencrypted_keys.len().try_into() {
            Ok(p) => p,
            Err(_) => return Err(SqrlError::new("Too many previous keys".to_owned())),
        };

        let mut aes = Aes256Gcm::new(identity_master_key.into());
        let payload = Payload {
            msg: &unencrypted_keys.into_iter().flatten().collect::<Vec<u8>>(),
            aad: &self.aad()?,
        };

        let encrypted_data = aes.encrypt(&EMPTY_NONCE.into(), payload)?;

        let mut result = VecDeque::new();
        let mut iter = encrypted_data.into_iter();
        for _ in 0..self.edition {
            let mut key: IdentityKey = [0; 32];
            for i in &mut key {
                *i = iter.next().unwrap();
            }
            result.push_back(key);
        }

        self.edition = num_keys;
        self.previous_identity_unlock_keys = result;

        Ok(())
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

        let mut previous_identity_unlock_keys = VecDeque::new();
        for _ in 0..edition {
            previous_identity_unlock_keys
                .push_back(binary.next_sub_array(32)?.as_slice().try_into()?);
        }

        let verification_data = binary.next_sub_array(16)?.as_slice().try_into()?;

        Ok(PreviousIdentityData {
            edition,
            previous_identity_unlock_keys,
            verification_data,
        })
    }

    fn to_binary_inner(&self, output: &mut Vec<u8>) -> Result<(), SqrlError> {
        if self.edition == 0 {
            return Ok(());
        }

        output.write_u16::<LittleEndian>(self.edition)?;
        for key in &self.previous_identity_unlock_keys {
            output.write_all(key)?;
        }
        output.write_all(&self.verification_data)?;

        Ok(())
    }
}
