use crate::{
    readable_vector::ReadableVector,
    scrypt_config::{en_scrypt, mut_en_scrypt, ScryptConfig},
    writable_datablock::WritableDataBlock,
    AesVerificationData, DataType, IdentityKey, Result, EMPTY_NONCE,
};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit,
};
use byteorder::{LittleEndian, WriteBytesExt};
use ed25519_dalek::SigningKey;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use rand::{prelude::StdRng, RngCore, SeedableRng};
use std::{collections::VecDeque, convert::TryInto, io::Write};
use x25519_dalek::{PublicKey, StaticSecret};

const RESCUE_CODE_SCRYPT_TIME: u8 = 5;
const RESCUE_CODE_ALPHABET: [char; 10] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct IdentityUnlockData {
    scrypt_config: ScryptConfig,
    identity_unlock_key: [u8; 32],
    verification_data: AesVerificationData,
}

impl IdentityUnlockData {
    pub(crate) fn new(identity_unlock_key: IdentityKey) -> Result<(Self, String)> {
        let mut identity_unlock = IdentityUnlockData {
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
        identity_unlock_key: IdentityKey,
    ) -> Result<(String, IdentityKey)> {
        let mut previous_identity_key = [0; 32];
        if self.identity_unlock_key != previous_identity_key {
            previous_identity_key = self.decrypt_identity_unlock_key(previous_rescue_code)?;
        }

        let rescue_code = generate_rescue_code();
        let decoded_rescue_code = decode_rescue_code(&rescue_code);

        let key = mut_en_scrypt(
            decoded_rescue_code.as_bytes(),
            &mut self.scrypt_config,
            RESCUE_CODE_SCRYPT_TIME,
        )?;

        let aes = Aes256Gcm::new(&key.into());
        let payload = Payload {
            msg: &identity_unlock_key,
            aad: &self.aad()?,
        };

        let encrypted_data = aes.encrypt(&EMPTY_NONCE.into(), payload)?;
        for (i, x) in encrypted_data.iter().enumerate() {
            if i < 32 {
                self.identity_unlock_key[i] = *x;
            } else {
                self.verification_data[i - 32] = *x;
            }
        }

        Ok((rescue_code, previous_identity_key))
    }

    pub(crate) fn decrypt_identity_unlock_key(&self, rescue_code: &str) -> Result<IdentityKey> {
        let mut unencrypted_data: [u8; 32] = [0; 32];
        let decoded_rescue_key = decode_rescue_code(rescue_code);
        let key = en_scrypt(decoded_rescue_key.as_bytes(), &self.scrypt_config)?;

        let mut encrypted_data: Vec<u8> = Vec::new();
        for byte in self.identity_unlock_key {
            encrypted_data.push(byte);
        }
        for byte in self.verification_data {
            encrypted_data.push(byte);
        }

        let aes = Aes256Gcm::new(&key.into());
        let payload = Payload {
            msg: &encrypted_data,
            aad: &self.aad()?,
        };

        for (i, x) in aes
            .decrypt(&EMPTY_NONCE.into(), payload)?
            .iter()
            .enumerate()
        {
            unencrypted_data[i] = *x;
        }

        Ok(unencrypted_data)
    }

    pub(crate) fn generate_unlock_request_signing_key(
        &self,
        rescue_code: &str,
        server_unlock_key: [u8; 32],
    ) -> Result<SigningKey> {
        // Decrypt the identity unlock key and convert it to a DHKA secret key
        let unlock_key = self.decrypt_identity_unlock_key(rescue_code)?;
        let secret_key = StaticSecret::from(unlock_key);

        // Do the key exchange and make it the secret key
        let shared_secret = secret_key.diffie_hellman(&PublicKey::from(server_unlock_key));
        Ok(SigningKey::from_bytes(shared_secret.as_bytes()))
    }

    fn aad(&self) -> Result<Vec<u8>> {
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

    fn from_binary(binary: &mut VecDeque<u8>) -> Result<Self> {
        Ok(IdentityUnlockData {
            scrypt_config: ScryptConfig::from_binary(binary)?,
            identity_unlock_key: binary.next_sub_array(32)?.as_slice().try_into()?,
            verification_data: binary.next_sub_array(16)?.as_slice().try_into()?,
        })
    }

    fn to_binary_inner(&self, output: &mut Vec<u8>) -> Result<()> {
        self.scrypt_config.to_binary(output)?;
        output.write_all(&self.identity_unlock_key)?;
        output.write_all(&self.verification_data)?;
        Ok(())
    }
}

// Generate a random rescue code for use in encrypting data
fn generate_rescue_code() -> String {
    let mut random = StdRng::from_os_rng();
    let mut rescue_code_data: [u8; 32] = [0; 32];
    random.fill_bytes(&mut rescue_code_data);

    let mut num = BigUint::from_bytes_be(&rescue_code_data);
    let mut rescue_code = String::new();
    let mut count = 0;
    for i in 0..24 {
        let remainder = &num % 10u8;
        num /= 10u8;
        let character = RESCUE_CODE_ALPHABET[remainder.to_usize().unwrap()];
        rescue_code.push(character);

        // Every four characters add a hyphen (except for the last time)
        count += 1;
        if count == 4 && i != 23 {
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
        let mut random = StdRng::from_os_rng();
        let mut identity_unlock_key: IdentityKey = [0; 32];
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
