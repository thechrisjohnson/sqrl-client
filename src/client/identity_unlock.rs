use super::readable_vector::ReadableVector;
use super::scrypt_config::ScryptConfig;
use super::writable_datablock::WritableDataBlock;
use super::DataType;
use crate::common::{
    decode_rescue_code, en_scrypt, generate_rescue_code, mut_en_scrypt, EMPTY_NONCE,
};
use crate::error::SqrlError;
use byteorder::{LittleEndian, WriteBytesExt};
use crypto::aead::{AeadDecryptor, AeadEncryptor};
use crypto::aes::KeySize;
use crypto::aes_gcm::AesGcm;
use std::collections::VecDeque;
use std::convert::TryInto;
use std::io::Write;

const RESCUE_CODE_SCRYPT_TIME: u8 = 5;

#[derive(Debug, PartialEq)]
pub(crate) struct IdentityUnlock {
    scrypt_config: ScryptConfig,
    identity_unlock_key: [u8; 32],
    verification_data: [u8; 16],
}

impl IdentityUnlock {
    pub(crate) fn new(identity_unlock_key: [u8; 32]) -> Result<(Self, String), SqrlError> {
        let mut identity_unlock = IdentityUnlock {
            scrypt_config: ScryptConfig::new(),
            identity_unlock_key: [0; 32],
            verification_data: [0; 16],
        };

        let (rescue_code, _) = identity_unlock.update_unlock_key("", identity_unlock_key)?;

        Ok((identity_unlock, rescue_code))
    }

    pub(crate) fn update_unlock_key(
        &mut self,
        previous_rescue_code: &str,
        identity_unlock_key: [u8; 32],
    ) -> Result<(String, [u8; 32]), SqrlError> {
        let mut previous_identity_key = [0; 32];
        if self.identity_unlock_key != previous_identity_key {
            previous_identity_key = self.decrypt_identity_unlock_key(previous_rescue_code)?;
        }

        let mut encrypted_data: [u8; 32] = [0; 32];
        let rescue_code = generate_rescue_code();

        let key = mut_en_scrypt(
            &rescue_code.as_bytes(),
            &mut self.scrypt_config,
            RESCUE_CODE_SCRYPT_TIME,
        );
        let mut aes = AesGcm::new(
            KeySize::KeySize256,
            &key,
            &EMPTY_NONCE,
            self.aad()?.as_slice(),
        );

        aes.encrypt(
            &identity_unlock_key,
            &mut encrypted_data,
            &mut self.verification_data,
        );

        self.identity_unlock_key = encrypted_data;

        Ok((rescue_code, previous_identity_key))
    }

    pub(crate) fn decrypt_identity_unlock_key(
        &self,
        rescue_code: &str,
    ) -> Result<[u8; 32], SqrlError> {
        let mut unencrypted_data: [u8; 32] = [0; 32];
        let decoded_rescue_key = decode_rescue_code(rescue_code);
        println!("Scrypt config: {:?}", &self.scrypt_config);
        let key = en_scrypt(&decoded_rescue_key.as_bytes(), &self.scrypt_config)?;
        print!("Key: ");
        for b in &key {
            print!("{:#02X}, ", b);
        }
        println!("");

        let mut aes = AesGcm::new(
            KeySize::KeySize256,
            &key,
            &EMPTY_NONCE,
            self.aad()?.as_slice(),
        );
        if aes.decrypt(
            &self.identity_unlock_key,
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

    fn aad(&self) -> Result<Vec<u8>, SqrlError> {
        let mut result = Vec::<u8>::new();
        result.write_u16::<LittleEndian>(self.len())?;
        self.get_type().to_binary(&mut result)?;
        self.scrypt_config.to_binary(&mut result)?;
        Ok(result)
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
            identity_unlock_key: binary.next_sub_array(32)?.as_slice().try_into()?,
            verification_data: binary.next_sub_array(16)?.as_slice().try_into()?,
        })
    }

    fn to_binary_inner(&self, output: &mut Vec<u8>) -> Result<(), SqrlError> {
        self.scrypt_config.to_binary(output)?;
        output.write(&self.identity_unlock_key)?;
        output.write(&self.verification_data)?;
        Ok(())
    }
}
