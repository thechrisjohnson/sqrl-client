use crate::{
    common::en_hash,
    config_options_to_u16,
    error::SqrlError,
    readable_vector::ReadableVector,
    scrypt_config::{en_scrypt, mut_en_scrypt, ScryptConfig},
    writable_datablock::WritableDataBlock,
    AesVerificationData, ConfigOptions, DataType, IdentityKey, IdentityUnlockKeys, Result,
};
use aes_gcm::{
    aead::{AeadMut, OsRng, Payload},
    Aes256Gcm, KeyInit,
};
use byteorder::{LittleEndian, WriteBytesExt};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{prelude::StdRng, RngCore, SeedableRng};
use std::{collections::VecDeque, convert::TryInto, io::Write};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct IdentityInformation {
    aes_gcm_iv: [u8; 12],
    scrypt_config: ScryptConfig,
    option_flags: Vec<ConfigOptions>,
    hint_length: u8,
    pw_verify_sec: u8,
    idle_timeout_min: u16,
    identity_master_key: IdentityKey,
    identity_lock_key: IdentityKey,
    verification_data: AesVerificationData,
}

impl IdentityInformation {
    pub(crate) fn new(
        password: &str,
        identity_master_key: [u8; 32],
        identity_lock_key: [u8; 32],
    ) -> Result<Self> {
        let mut config = IdentityInformation {
            aes_gcm_iv: [0; 12],
            scrypt_config: ScryptConfig::new(),
            option_flags: Vec::new(),
            hint_length: 0,
            pw_verify_sec: 5,
            idle_timeout_min: 0,
            identity_master_key,
            identity_lock_key: [0; 32],
            verification_data: [0; 16],
        };
        config.update_keys(password, identity_master_key, identity_lock_key)?;

        Ok(config)
    }

    pub(crate) fn from_identity_unlock_key(
        password: &str,
        identity_unlock_key: [u8; 32],
    ) -> Result<Self> {
        // From the identity unlock key, generate the identity lock key and identity master key
        // NOTE: The identity_lock_key is the "public key" for an ECDHKA ED25519 where the private key is the identity unlock key
        let identity_master_key = en_hash(&identity_unlock_key);
        let secret_key = StaticSecret::from(identity_unlock_key);
        let public_key = PublicKey::from(&secret_key);
        let identity_lock_key = public_key.to_bytes();

        Self::new(password, identity_master_key, identity_lock_key)
    }

    fn aad(&self) -> Result<Vec<u8>> {
        let mut result = Vec::<u8>::new();
        result.write_u16::<LittleEndian>(self.len())?;
        self.get_type().to_binary(&mut result)?;
        result.write_u16::<LittleEndian>(45)?;
        result.write_all(&self.aes_gcm_iv)?;
        self.scrypt_config.to_binary(&mut result)?;
        result.write_u16::<LittleEndian>(config_options_to_u16(&self.option_flags))?;
        result.push(self.hint_length);
        result.push(self.pw_verify_sec);
        result.write_u16::<LittleEndian>(self.idle_timeout_min)?;
        Ok(result)
    }

    pub(crate) fn decrypt_identity_master_key(&self, password: &str) -> Result<IdentityKey> {
        let decrypted_data = self.decrypt(password)?;
        Ok(decrypted_data.identity_master_key)
    }

    pub(crate) fn decrypt_identity_lock_key(&self, password: &str) -> Result<PublicKey> {
        let decrypted_data = self.decrypt(password)?;
        Ok(PublicKey::from(decrypted_data.identity_lock_key))
    }

    pub(crate) fn verify(&self, password: &str) -> Result<()> {
        self.decrypt(password)?;
        Ok(())
    }

    pub(crate) fn update_keys(
        &mut self,
        password: &str,
        identity_master_key: [u8; 32],
        identity_lock_key: [u8; 32],
    ) -> Result<()> {
        let mut random = StdRng::from_os_rng();
        let mut to_encrypt = Vec::new();
        to_encrypt.write_all(&identity_master_key)?;
        to_encrypt.write_all(&identity_lock_key)?;

        let key = mut_en_scrypt(
            password.as_bytes(),
            &mut self.scrypt_config,
            self.pw_verify_sec,
        )?;

        random.fill_bytes(&mut self.aes_gcm_iv);
        let mut aes = Aes256Gcm::new(&key.into());
        let payload = Payload {
            msg: &to_encrypt,
            aad: &self.aad()?,
        };
        let encrypted_data = aes.encrypt(&self.aes_gcm_iv.into(), payload)?;

        for (i, item) in encrypted_data.iter().enumerate() {
            if i < 32 {
                self.identity_master_key[i] = *item;
            } else if i < 64 {
                self.identity_lock_key[i - 32] = *item;
            } else {
                self.verification_data[i - 64] = *item;
            }
        }

        Ok(())
    }

    pub(crate) fn generate_server_unlock_and_verify_unlock_keys(
        &self,
        password: &str,
    ) -> Result<IdentityUnlockKeys> {
        // Get the identity lock key so we confirm the password first
        let identity_lock_key = self.decrypt_identity_lock_key(password)?;

        // Generate the random secret key and the server unlock key (the matching public key)
        let random_key = EphemeralSecret::random_from_rng(OsRng);
        let server_unlock_key = PublicKey::from(&random_key);

        // Diffie-Hellman the random key with the identity lock key
        // Take that shared secret key and use it to generate an ed25519 key pair
        let shared_secret = random_key.diffie_hellman(&identity_lock_key);
        let secret_key = SigningKey::from_bytes(shared_secret.as_bytes());
        let verify_unlock_key = VerifyingKey::from(&secret_key);

        Ok(IdentityUnlockKeys::new(
            server_unlock_key,
            verify_unlock_key,
        ))
    }

    pub(crate) fn change_password(
        &mut self,
        current_password: &str,
        new_password: &str,
    ) -> Result<()> {
        let decrypted_data = self.decrypt(current_password)?;
        self.update_keys(
            new_password,
            decrypted_data.identity_master_key,
            decrypted_data.identity_lock_key,
        )
    }

    pub(crate) fn update_setings(
        &mut self,
        password: &str,
        option_flags: Option<Vec<ConfigOptions>>,
        hint_length: Option<u8>,
        pw_verify_sec: Option<u8>,
        idle_timeout_min: Option<u16>,
    ) -> Result<()> {
        let decryted = self.decrypt(password)?;

        if let Some(options) = option_flags {
            self.option_flags = options;
        }
        if let Some(hint) = hint_length {
            self.hint_length = hint;
        }
        if let Some(verify) = pw_verify_sec {
            self.pw_verify_sec = verify;
        }
        if let Some(idle) = idle_timeout_min {
            self.idle_timeout_min = idle;
        }

        self.update_keys(
            password,
            decryted.identity_master_key,
            decryted.identity_lock_key,
        )
    }

    fn decrypt(&self, password: &str) -> Result<EncryptedKeyPair> {
        let mut encrypted_data: Vec<u8> = Vec::new();
        for byte in self.identity_master_key {
            encrypted_data.push(byte);
        }
        for byte in self.identity_lock_key {
            encrypted_data.push(byte);
        }
        for byte in self.verification_data {
            encrypted_data.push(byte);
        }

        let key = en_scrypt(password.as_bytes(), &self.scrypt_config)?;
        let mut aes = Aes256Gcm::new(&key.into());
        let payload = Payload {
            msg: &encrypted_data,
            aad: &self.aad()?,
        };

        let mut decrypted_data: [u8; 64] = [0; 64];
        for (i, x) in aes
            .decrypt(&self.aes_gcm_iv.into(), payload)?
            .iter()
            .enumerate()
        {
            decrypted_data[i] = *x;
        }

        let mut identity_master_key = [0; 32];
        let mut identity_lock_key = [0; 32];
        identity_master_key[..32].copy_from_slice(&decrypted_data[..32]);
        identity_lock_key[..32].copy_from_slice(&decrypted_data[32..64]);

        Ok(EncryptedKeyPair {
            identity_master_key,
            identity_lock_key,
        })
    }
}

impl WritableDataBlock for IdentityInformation {
    fn get_type(&self) -> DataType {
        DataType::UserAccess
    }

    fn len(&self) -> u16 {
        125
    }

    fn from_binary(binary: &mut VecDeque<u8>) -> Result<Self> {
        // Skip over the plaintext length
        binary.skip(2);

        let aes_gcm_iv = binary.next_sub_array(12)?.as_slice().try_into()?;
        let scrypt_config = ScryptConfig::from_binary(binary)?;
        let option_flags = ConfigOptions::from_u16(binary.next_u16()?);
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
            aes_gcm_iv,
            scrypt_config,
            option_flags,
            hint_length,
            pw_verify_sec,
            idle_timeout_min,
            identity_master_key,
            identity_lock_key,
            verification_data,
        })
    }

    fn to_binary_inner(&self, output: &mut Vec<u8>) -> Result<()> {
        output.write_u16::<LittleEndian>(45)?;
        output.write_all(&self.aes_gcm_iv)?;
        self.scrypt_config.to_binary(output)?;

        output.write_u16::<LittleEndian>(config_options_to_u16(&self.option_flags))?;
        output.push(self.hint_length);
        output.push(self.pw_verify_sec);
        output.write_u16::<LittleEndian>(self.idle_timeout_min)?;
        output.write_all(&self.identity_master_key)?;
        output.write_all(&self.identity_lock_key)?;
        output.write_all(&self.verification_data)?;

        Ok(())
    }
}

#[derive(Debug, PartialEq)]
struct EncryptedKeyPair {
    identity_master_key: [u8; 32],
    identity_lock_key: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PASSWORD: &str = "password";

    #[test]
    fn decrypt_identity_lock_key_matches() {
        let mut identity_lock_key = [0; 32];
        let mut random = StdRng::from_os_rng();
        random.fill_bytes(&mut identity_lock_key);

        let identity_information =
            IdentityInformation::new(TEST_PASSWORD, [0; 32], identity_lock_key).unwrap();
        let decrypted = identity_information
            .decrypt_identity_lock_key(TEST_PASSWORD)
            .unwrap();
        assert_eq!(decrypted.as_bytes(), &identity_lock_key);
    }

    #[test]
    fn decrypt_identity_master_key_matches() {
        let mut identity_master_key = [0; 32];
        let mut random = StdRng::from_os_rng();
        random.fill_bytes(&mut identity_master_key);

        let identity_information =
            IdentityInformation::new(TEST_PASSWORD, identity_master_key, [0; 32]).unwrap();
        let decrypted = identity_information
            .decrypt_identity_master_key(TEST_PASSWORD)
            .unwrap();
        assert_eq!(decrypted, identity_master_key)
    }

    #[test]
    fn update_keys_updates_keys() {
        let mut identity_master_key = [0; 32];
        let mut identity_lock_key = [0; 32];
        let mut random = StdRng::from_os_rng();
        random.fill_bytes(&mut identity_master_key);
        random.fill_bytes(&mut identity_lock_key);

        let mut identity_information =
            IdentityInformation::new(TEST_PASSWORD, [0; 32], [0; 32]).unwrap();
        assert_eq!(
            identity_information
                .decrypt_identity_master_key(TEST_PASSWORD)
                .unwrap(),
            [0; 32]
        );
        assert_eq!(
            identity_information
                .decrypt_identity_lock_key(TEST_PASSWORD)
                .unwrap(),
            PublicKey::from([0; 32])
        );

        identity_information
            .update_keys(TEST_PASSWORD, identity_master_key, identity_lock_key)
            .unwrap();
        assert_eq!(
            identity_information
                .decrypt_identity_master_key(TEST_PASSWORD)
                .unwrap(),
            identity_master_key
        );
        assert_eq!(
            identity_information
                .decrypt_identity_lock_key(TEST_PASSWORD)
                .unwrap()
                .as_bytes(),
            &identity_lock_key
        );
    }

    #[test]
    fn reset_password_works() {
        let mut identity_master_key = [0; 32];
        let mut identity_lock_key = [0; 32];
        let mut random = StdRng::from_os_rng();
        random.fill_bytes(&mut identity_master_key);
        random.fill_bytes(&mut identity_lock_key);

        let mut identity_information =
            IdentityInformation::new(TEST_PASSWORD, identity_master_key, identity_lock_key)
                .unwrap();
        let decryted = identity_information.decrypt(TEST_PASSWORD).unwrap();

        identity_information
            .change_password(TEST_PASSWORD, "password2")
            .unwrap();
        let decryted2 = identity_information.decrypt("password2").unwrap();
        assert_eq!(decryted, decryted2);
    }
}
