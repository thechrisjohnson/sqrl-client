use super::{
    identity_key::IdentityKey, readable_vector::ReadableVector, scrypt_config::ScryptConfig,
    writable_datablock::WritableDataBlock, DataType,
};
use crate::{common::en_scrypt, error::SqrlError};
use byteorder::{LittleEndian, WriteBytesExt};
use crypto::{
    aead::{AeadDecryptor, AeadEncryptor},
    aes::KeySize,
    aes_gcm::AesGcm,
};
use rand::{prelude::StdRng, RngCore, SeedableRng};
use std::{collections::VecDeque, convert::TryInto, io::Write};

#[derive(Debug, PartialEq)]
pub(crate) struct UserConfiguration {
    aes_gcm_iv: [u8; 12],
    scrypt_config: ScryptConfig,
    option_flags: u16,
    hint_length: u8,
    pw_verify_sec: u8,
    idle_timeout_min: u16,
    pub(crate) identity_master_key: IdentityKey,
    identity_lock_key: IdentityKey,
    verification_data: [u8; 16],
}

impl UserConfiguration {
    pub fn new() -> Self {
        let mut random = StdRng::from_entropy();
        let mut aes_gcm_iv: [u8; 12] = [0; 12];
        random.fill_bytes(&mut aes_gcm_iv);
        UserConfiguration {
            aes_gcm_iv: aes_gcm_iv,
            scrypt_config: ScryptConfig::new(),
            option_flags: 0,
            hint_length: 0,
            pw_verify_sec: 5,
            idle_timeout_min: 0,
            identity_master_key: IdentityKey::Plaintext([0; 32]),
            identity_lock_key: IdentityKey::Plaintext([0; 32]),
            verification_data: [0; 16],
        }
    }

    pub fn aad(&self) -> [u8; 45] {
        // TODO: Do this better
        let mut result: [u8; 45] = [0; 45];
        const SIZE: u16 = 125;
        const BLOCK_TYPE: u16 = 1;
        const UNENCRYPTED_SIZE: u16 = 45;
        for i in 0..45 {
            if i < 2 {
                result[i] = SIZE.to_le_bytes()[i]
            } else if i >= 2 && i < 4 {
                result[i] = BLOCK_TYPE.to_le_bytes()[i - 2]
            } else if i >= 4 && i < 6 {
                result[i] = UNENCRYPTED_SIZE.to_le_bytes()[i - 4]
            } else if i >= 6 && i < 18 {
                result[i] = self.aes_gcm_iv[i - 6];
            } else if i >= 18 && i < 34 {
                result[i] = self.scrypt_config.random_salt[i - 18];
            } else if i == 34 {
                result[i] = self.scrypt_config.log_n_factor
            } else if i >= 35 && i < 39 {
                result[i] = self.scrypt_config.iteration_factor.unwrap().to_le_bytes()[i - 35];
            } else if i >= 39 && i < 41 {
                result[i] = self.option_flags.to_le_bytes()[i - 39];
            } else if i == 41 {
                result[i] = self.hint_length;
            } else if i == 42 {
                result[i] = self.pw_verify_sec;
            } else if i >= 43 {
                result[i] = self.idle_timeout_min.to_le_bytes()[i - 43];
            }
        }
        result
    }

    pub fn unencrypt_identity_master_key(&mut self, password: &str) -> Result<(), SqrlError> {
        match self.identity_master_key {
            IdentityKey::Encrypted(data) => {
                let mut encrypted_data: [u8; 64] = [0; 64];
                let key_two = match self.identity_lock_key {
                    IdentityKey::Encrypted(x) => x,
                    IdentityKey::Plaintext(x) => x,
                };
                for i in 0..64 {
                    if i < 32 {
                        encrypted_data[i] = data[i];
                    } else {
                        encrypted_data[i] = key_two[i - 32];
                    }
                }
                let mut unencrypted_data: [u8; 64] = [0; 64];
                let key = en_scrypt(
                    password.as_bytes(),
                    &mut self.scrypt_config,
                    self.pw_verify_sec,
                );
                let mut aes = AesGcm::new(KeySize::KeySize256, &key, &self.aes_gcm_iv, &self.aad());
                if aes.decrypt(
                    &encrypted_data,
                    &mut unencrypted_data,
                    &self.verification_data,
                ) {
                    // self.identity_master_key = IdentityKey::Plaintext(unencrypted_data[..32]);
                } else {
                    return Err(SqrlError::new(
                        "Decryption failed. Check your password!".to_owned(),
                    ));
                }
            }
            _ => (),
        };

        Ok(())
    }

    pub fn encrypt_identity_master_key(&mut self, password: &str) -> Result<(), SqrlError> {
        match self.identity_master_key {
            IdentityKey::Plaintext(data) => {
                let mut random = StdRng::from_entropy();
                let mut encrypted_data: [u8; 32] = [0; 32];

                let key = en_scrypt(
                    password.as_bytes(),
                    &mut self.scrypt_config,
                    self.pw_verify_sec,
                );
                random.fill_bytes(&mut self.aes_gcm_iv);
                let mut aes = AesGcm::new(KeySize::KeySize256, &key, &self.aes_gcm_iv, &self.aad());
                aes.encrypt(&data, &mut encrypted_data, &mut self.verification_data);
                self.identity_master_key = IdentityKey::Encrypted(encrypted_data);
            }
            _ => (),
        }

        Ok(())
    }
}

impl WritableDataBlock for UserConfiguration {
    fn get_type(&self) -> DataType {
        DataType::UserAccess
    }

    fn len(&self) -> u16 {
        125
    }

    fn from_binary(binary: &mut VecDeque<u8>) -> Result<Self, SqrlError> {
        // TODO: Do I need to worry about plaintext length?
        binary.skip(2);

        let aes_gcm_iv = binary.next_sub_array(12)?.as_slice().try_into()?;
        let scrypt_config = ScryptConfig::from_binary(binary)?;
        let option_flags = binary.next_u16()?;
        let hint_length = binary
            .pop_front()
            .ok_or(SqrlError::new("Invalid binary data".to_owned()))?;
        let pw_verify_sec = binary
            .pop_front()
            .ok_or(SqrlError::new("Invalid binary data".to_owned()))?;
        let idle_timeout_min = binary.next_u16()?;
        let identity_master_key = IdentityKey::from_binary(binary)?;
        let identity_lock_key = IdentityKey::from_binary(binary)?;
        let verification_data = binary.next_sub_array(16)?.as_slice().try_into()?;

        Ok(UserConfiguration {
            aes_gcm_iv: aes_gcm_iv,
            scrypt_config: scrypt_config,
            option_flags: option_flags,
            hint_length: hint_length,
            pw_verify_sec: pw_verify_sec,
            idle_timeout_min: idle_timeout_min,
            identity_master_key: identity_master_key,
            identity_lock_key: identity_lock_key,
            verification_data: verification_data,
        })
    }

    fn to_binary_inner(&self, output: &mut Vec<u8>) -> Result<(), SqrlError> {
        output.write_u16::<LittleEndian>(45)?;
        output.write(&self.aes_gcm_iv)?;
        self.scrypt_config.to_binary(output)?;
        output.write_u16::<LittleEndian>(self.option_flags)?;
        output.push(self.hint_length);
        output.push(self.pw_verify_sec);
        output.write_u16::<LittleEndian>(self.idle_timeout_min)?;
        self.identity_master_key.to_binary(output)?;
        self.identity_lock_key.to_binary(output)?;
        output.write(&self.verification_data)?;

        Ok(())
    }
}
