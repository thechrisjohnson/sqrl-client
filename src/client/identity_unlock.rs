use super::common::EMPTY_NONCE;
use super::readable_vector::ReadableVector;
use super::scrypt::{en_scrypt, mut_en_scrypt, Scrypt};
use super::writable_datablock::WritableDataBlock;
use super::{AesVerificationData, DataType, IdentityKey};
use crate::error::SqrlError;
use byteorder::{LittleEndian, WriteBytesExt};
use crypto::aead::{AeadDecryptor, AeadEncryptor};
use crypto::aes::KeySize;
use crypto::aes_gcm::AesGcm;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use rand::prelude::StdRng;
use rand::{RngCore, SeedableRng};
use std::collections::VecDeque;
use std::convert::TryInto;
use std::io::Write;

const RESCUE_CODE_SCRYPT_TIME: u8 = 5;
const RESCUE_CODE_ALPHABET: [char; 10] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];

#[derive(Debug, PartialEq)]
pub(crate) struct IdentityUnlockData {
    scrypt_config: Scrypt,
    identity_unlock_key: [u8; 32],
    verification_data: AesVerificationData,
}

impl IdentityUnlockData {
    pub(crate) fn new(identity_unlock_key: [u8; 32]) -> Result<(Self, String), SqrlError> {
        let mut identity_unlock = IdentityUnlockData {
            scrypt_config: Scrypt::new(),
            identity_unlock_key: [0; 32],
            verification_data: [0; 16],
        };

        let (rescue_code, _) = identity_unlock.update_unlock_key("", identity_unlock_key)?;

        Ok((identity_unlock, rescue_code))
    }

    pub(crate) fn update_unlock_key(
        &mut self,
        previous_rescue_code: &str,
        identity_unlock_key: IdentityKey,
    ) -> Result<(String, IdentityKey), SqrlError> {
        let mut previous_identity_key = [0; 32];
        if self.identity_unlock_key != previous_identity_key {
            previous_identity_key = self.decrypt_identity_unlock_key(previous_rescue_code)?;
        }

        let mut encrypted_data: [u8; 32] = [0; 32];
        let rescue_code = generate_rescue_code();
        let decoded_rescue_code = decode_rescue_code(&rescue_code);

        let key = mut_en_scrypt(
            &decoded_rescue_code.as_bytes(),
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
    ) -> Result<IdentityKey, SqrlError> {
        let mut unencrypted_data: [u8; 32] = [0; 32];
        let decoded_rescue_key = decode_rescue_code(rescue_code);
        let key = en_scrypt(&decoded_rescue_key.as_bytes(), &self.scrypt_config)?;

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
                "Decryption failed. Check your rescue code!".to_owned(),
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

impl WritableDataBlock for IdentityUnlockData {
    fn get_type(&self) -> DataType {
        DataType::RescueCode
    }

    fn len(&self) -> u16 {
        73
    }

    fn from_binary(binary: &mut VecDeque<u8>) -> Result<Self, SqrlError> {
        Ok(IdentityUnlockData {
            scrypt_config: Scrypt::from_binary(binary)?,
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

// Generate a random rescue code for use in encrypting data
fn generate_rescue_code() -> String {
    let mut random = StdRng::from_entropy();
    let mut rescue_code_data: [u8; 32] = [0; 32];
    random.fill_bytes(&mut rescue_code_data);

    let mut num = BigUint::from_bytes_be(&rescue_code_data);
    let mut rescue_code = String::new();
    let mut count = 0;
    for _ in 0..24 {
        let remainder = &num % 10u8;
        num /= 10u8;
        let character = RESCUE_CODE_ALPHABET[remainder.to_usize().unwrap()];
        rescue_code.push(character);

        // Every four characters add a hyphen
        count += 1;
        if count == 4 {
            count = 0;
            rescue_code.push('-');
        }
    }

    rescue_code
}

// Remove the hyphens from the rescue code
fn decode_rescue_code(rescue_code: &str) -> String {
    let mut result = String::new();
    for c in rescue_code.chars() {
        if c == '-' {
            continue;
        }
        result.push(c);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_unlock_with_rescue_code() {
        let mut random = StdRng::from_entropy();
        let mut identity_unlock_key: [u8; 32] = [0; 32];
        random.fill_bytes(&mut identity_unlock_key);

        let (unlock_data, rescue_code) = IdentityUnlockData::new(identity_unlock_key).unwrap();
        let decrypted_key = unlock_data
            .decrypt_identity_unlock_key(&rescue_code)
            .unwrap();

        assert_eq!(
            decrypted_key, identity_unlock_key,
            "Identity unlock keys do not match!"
        );
    }
}
