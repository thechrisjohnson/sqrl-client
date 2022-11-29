use super::{
    readable_vector::ReadableVector,
    scrypt::{en_scrypt, mut_en_scrypt, Scrypt},
    writable_datablock::WritableDataBlock,
    DataType,
};
use crate::error::SqrlError;
use byteorder::{LittleEndian, WriteBytesExt};
use crypto::{
    aead::{AeadDecryptor, AeadEncryptor},
    aes::KeySize,
    aes_gcm::AesGcm,
};
use rand::{prelude::StdRng, RngCore, SeedableRng};
use std::{collections::VecDeque, convert::TryInto, io::Write};

#[derive(Debug, PartialEq)]
pub(crate) struct IdentityInformation {
    aes_gcm_iv: [u8; 12],
    scrypt_config: Scrypt,
    option_flags: u16,
    hint_length: u8,
    pw_verify_sec: u8,
    idle_timeout_min: u16,
    identity_master_key: [u8; 32],
    identity_lock_key: [u8; 32],
    verification_data: [u8; 16],
}

impl IdentityInformation {
    pub fn new(
        password: &str,
        identity_master_key: [u8; 32],
        identity_lock_key: [u8; 32],
    ) -> Result<Self, SqrlError> {
        let mut config = IdentityInformation {
            aes_gcm_iv: [0; 12],
            scrypt_config: Scrypt::new(),
            option_flags: 0,
            hint_length: 0,
            pw_verify_sec: 5,
            idle_timeout_min: 0,
            identity_master_key: identity_master_key,
            identity_lock_key: [0; 32],
            verification_data: [0; 16],
        };
        config.update_keys(password, identity_master_key, identity_lock_key)?;

        Ok(config)
    }

    fn aad(&self) -> Result<Vec<u8>, SqrlError> {
        let mut result = Vec::<u8>::new();
        result.write_u16::<LittleEndian>(self.len())?;
        self.get_type().to_binary(&mut result)?;
        result.write_u16::<LittleEndian>(45)?;
        result.write(&self.aes_gcm_iv)?;
        self.scrypt_config.to_binary(&mut result)?;
        result.write_u16::<LittleEndian>(self.option_flags)?;
        result.push(self.hint_length);
        result.push(self.pw_verify_sec);
        result.write_u16::<LittleEndian>(self.idle_timeout_min)?;
        Ok(result)
    }

    pub(crate) fn decrypt_identity_master_key(
        &self,
        password: &str,
    ) -> Result<[u8; 32], SqrlError> {
        let mut user_identity_key = [0; 32];
        let decrypted_data = self.decrypt(password)?;
        for n in 0..32 {
            user_identity_key[n] = decrypted_data[n];
        }

        Ok(user_identity_key)
    }

    pub(crate) fn decrypt_identity_lock_key(&self, password: &str) -> Result<[u8; 32], SqrlError> {
        let mut user_unlock_key = [0; 32];
        let decrypted_data = self.decrypt(password)?;
        for n in 0..32 {
            user_unlock_key[n] = decrypted_data[32 + n];
        }

        Ok(user_unlock_key)
    }

    pub(crate) fn verify(&self, password: &str) -> Result<(), SqrlError> {
        self.decrypt(password)?;
        Ok(())
    }

    pub(crate) fn update_keys(
        &mut self,
        password: &str,
        identity_master_key: [u8; 32],
        identity_lock_key: [u8; 32],
    ) -> Result<(), SqrlError> {
        let mut random = StdRng::from_entropy();
        let mut encrypted_data: [u8; 64] = [0; 64];
        let mut to_encrypt = Vec::new();
        to_encrypt.write(&identity_master_key)?;
        to_encrypt.write(&identity_lock_key)?;

        let key = mut_en_scrypt(
            password.as_bytes(),
            &mut self.scrypt_config,
            self.pw_verify_sec,
        );

        random.fill_bytes(&mut self.aes_gcm_iv);
        let mut aes = AesGcm::new(
            KeySize::KeySize256,
            &key,
            &self.aes_gcm_iv,
            self.aad()?.as_slice(),
        );

        aes.encrypt(
            &to_encrypt,
            &mut encrypted_data,
            &mut self.verification_data,
        );

        for i in 0..64 {
            if i < 32 {
                self.identity_master_key[i] = encrypted_data[i];
            } else {
                self.identity_lock_key[i - 32] = encrypted_data[i];
            }
        }

        Ok(())
    }

    fn decrypt(&self, password: &str) -> Result<[u8; 64], SqrlError> {
        let mut encrypted_data: [u8; 64] = [0; 64];
        for i in 0..64 {
            if i < 32 {
                encrypted_data[i] = self.identity_master_key[i];
            } else {
                encrypted_data[i] = self.identity_lock_key[i - 32];
            }
        }
        let mut unencrypted_data: [u8; 64] = [0; 64];
        let key = en_scrypt(password.as_bytes(), &self.scrypt_config)?;
        let mut aes = AesGcm::new(
            KeySize::KeySize256,
            &key,
            &self.aes_gcm_iv,
            self.aad()?.as_slice(),
        );
        if aes.decrypt(
            &encrypted_data,
            &mut unencrypted_data,
            &self.verification_data,
        ) {
            Ok(unencrypted_data)
        } else {
            return Err(SqrlError::new(
                "Decryption failed. Check your password!".to_owned(),
            ));
        }
    }
}

impl WritableDataBlock for IdentityInformation {
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
        let scrypt_config = Scrypt::from_binary(binary)?;
        let option_flags = binary.next_u16()?;
        let hint_length = binary
            .pop_front()
            .ok_or(SqrlError::new("Invalid binary data".to_owned()))?;
        let pw_verify_sec = binary
            .pop_front()
            .ok_or(SqrlError::new("Invalid binary data".to_owned()))?;
        let idle_timeout_min = binary.next_u16()?;
        let identity_master_key = binary.next_sub_array(32)?.as_slice().try_into()?;
        let identity_lock_key = binary.next_sub_array(32)?.as_slice().try_into()?;
        let verification_data = binary.next_sub_array(16)?.as_slice().try_into()?;

        Ok(IdentityInformation {
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
        output.write(&self.identity_master_key)?;
        output.write(&self.identity_lock_key)?;
        output.write(&self.verification_data)?;

        Ok(())
    }
}
