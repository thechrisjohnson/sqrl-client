use byteorder::{LittleEndian, WriteBytesExt};
use crypto::aead::{AeadDecryptor, AeadEncryptor};
use crypto::aes::KeySize;
use crypto::aes_gcm::AesGcm;
use crypto::digest::Digest;
use crypto::ed25519::{keypair, signature};
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::scrypt::{scrypt, ScryptParams};
use crypto::sha2::Sha256;
use error::SqrlError;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::collections::VecDeque;
use std::convert::TryInto;
use std::fs::File;
use std::io::prelude::*;
use std::str;
use std::time::Instant;
use url::{Host, Url};

// The configuration options for the SqrlClient
pub const CHECK_FOR_UPDATES: u16 = 0x0001;
pub const UPDATE_ANONYMOUSLY: u16 = 0x0002;
pub const SQRL_ONLY_LOGIN: u16 = 0x0004;
pub const NO_SQRL_BYPASS: u16 = 0x0008;
pub const WARN_MITM: u16 = 0x0010;
pub const CLEAR_DATA_ON_SUSPEND: u16 = 0x0020;
pub const CLEAR_DATA_ON_USER_SWITCH: u16 = 0x0040;
pub const CLEAR_DATA_ON_IDLE: u16 = 0x0080;
pub const WARN_NON_CPS: u16 = 0x0100;

const FILE_HEADER: &str = "sqrldata";
const SCRYPT_DEFAULT_LOG_N: u8 = 9;
const SCRYPT_DEFAULT_R: u32 = 256;
const SCRYPT_DEFAULT_P: u32 = 1;
const TEXT_IDENTITY_ALPHABET: &str = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz";

trait SqrlStorage
where
    Self: Sized,
{
    fn from_file(file_path: &str) -> Result<Self, SqrlError>;
    fn to_file(&self, file_path: &str) -> Result<(), SqrlError>;
    fn from_base64(input: &str) -> Result<Self, SqrlError>;
    fn to_base64(&self) -> Result<String, SqrlError>;
    fn from_textual_identity_format(input: &str) -> Result<Self, SqrlError>;
    fn to_textual_identity_format(&self) -> Result<String, SqrlError>;
}

trait SqrlSigning {}

// List of features needed in the client:
// + Load data from binary format
// + Load data from text based format
// + Load data from base64url encoded format
// - Sign request based on website and nut (and alternative identity information)
// - Ability to decrypt code with base password and use "quick-password"
// - Index secret
// - Recover identity using unlock key
// - Store previous identities and be able to access them
// - Handle special "Ask" functionality
#[derive(Debug, PartialEq)]
pub struct SqrlClient {
    user_configuration: UserConfiguration,
    identity_unlock: IdentityUnlock,
    previous_identities: Option<PreviousIdentityData>,
}

impl SqrlClient {
    pub fn new() -> (Self, String) {
        // 1. Generate a random 256-bit value (Known as the Identity Unlock Key)
        let mut random = StdRng::from_entropy();
        let mut identity_unlock_key: [u8; 32] = [0; 32];
        random.fill_bytes(&mut identity_unlock_key);

        // TODO
        // 2. Use ECDHA (Diffie-Helman with EC) to create a "Encrypted Identity Lock Key"

        // 3. EnHash the IUK to become the Identity Master Key
        let identity_master_key = en_hash(&identity_unlock_key);

        // 4. EnScrypt the password and use it to encrypt the IUK
        let mut user_configuration = UserConfiguration::new();
        user_configuration.identity_master_key = IdentityKey::Plaintext(identity_master_key);

        (
            SqrlClient {
                user_configuration: user_configuration,
                identity_unlock: IdentityUnlock::new(),
                previous_identities: None,
            },
            "TODO".to_owned(),
        )
    }

    pub fn unlock_with_rescue_code(&mut self, rescue_code: &str) {}

    pub fn verify(&mut self, password: &str) -> Result<(), SqrlError> {
        self.user_configuration
            .unencrypt_identity_master_key(password)?;
        Ok(())
    }

    pub fn sign_request(
        &self,
        url: &str,
        alternate_identity: Option<&str>,
        request: &str,
    ) -> Result<[u8; 64], SqrlError> {
        let parse = Url::parse(url)?;
        let host = match parse
            .host()
            .ok_or(SqrlError::new(format!("Invalid host in url: {}", url)))?
        {
            Host::Domain(host) => host.to_owned(),
            Host::Ipv4(host) => host.to_string(),
            Host::Ipv6(host) => host.to_string(),
        };

        let keys = self.get_keys(&host, alternate_identity)?;
        Ok(keys.sign(request.as_bytes()))
    }

    pub fn get_keys(
        &self,
        hostname: &str,
        alternate_identity: Option<&str>,
    ) -> Result<KeyPair, SqrlError> {
        let data = match alternate_identity {
            Some(id) => format!("{}{}", hostname, id),
            None => hostname.to_owned(),
        };

        let key = match self.user_configuration.identity_master_key {
            IdentityKey::Plaintext(key) => key,
            IdentityKey::Encrypted(_) => {
                return Err(SqrlError::new(
                    "Identity encrypted and cannot be used".to_owned(),
                ))
            }
        };

        let mut hmac = Hmac::new(Sha256::new(), &key);
        hmac.input(data.as_bytes());
        let (public, private) = keypair(hmac.result().code());

        Ok(KeyPair {
            public_key: public,
            private_key: private,
        })
    }

    pub fn get_index_secret(
        &self,
        hostname: &str,
        secret_index: &str,
    ) -> Result<String, SqrlError> {
        let keys = self.get_keys(hostname, None)?;
        let hash = en_hash(&keys.private_key);
        let mut hmac = Hmac::new(Sha256::new(), &hash);
        hmac.input(secret_index.as_bytes());

        Ok(base64::encode_config(
            hmac.result().code(),
            base64::URL_SAFE,
        ))
    }

    fn from_binary(mut binary: VecDeque<u8>) -> Result<Self, SqrlError> {
        match str::from_utf8(binary.next_sub_array(8)?.as_slice()) {
            Ok(x) => {
                if x != FILE_HEADER {
                    return Err(SqrlError::new(format!(
                        "Invalid file. Header text not valid: {}",
                        x
                    )));
                }
            }
            Err(_) => {
                return Err(SqrlError::new(
                    "Invalid file. Could not parse header text.".to_string(),
                ));
            }
        }

        let mut user_configuration: Option<UserConfiguration> = None;
        let mut identity_unlock: Option<IdentityUnlock> = None;
        let mut previous_identities: Option<PreviousIdentityData> = None;

        loop {
            if binary.len() == 0 {
                break;
            }

            // TODO: Do we need to worry about the length?
            binary.skip(2);
            let block_type = DataType::from_binary(&mut binary)?;

            match block_type {
                DataType::UserAccess => {
                    if user_configuration != None {
                        return Err(SqrlError::new(
                            "Duplicate password information found!".to_owned(),
                        ));
                    }

                    user_configuration = Some(UserConfiguration::from_binary(&mut binary)?)
                }
                DataType::RescueCode => {
                    if identity_unlock != None {
                        return Err(SqrlError::new(
                            "Duplicate rescue code data found!".to_owned(),
                        ));
                    }

                    identity_unlock = Some(IdentityUnlock::from_binary(&mut binary)?)
                }
                DataType::PreviousIdentity => {
                    if previous_identities != None {
                        return Err(SqrlError::new(
                            "Duplicate previous identity data found!".to_owned(),
                        ));
                    }

                    previous_identities = Some(PreviousIdentityData::from_binary(&mut binary)?)
                }
            };
        }

        // We need to make sure we have all of the data we expect
        let user_access_check =
            user_configuration.ok_or(SqrlError::new("No password data found!".to_owned()))?;

        let rescue_code_check =
            identity_unlock.ok_or(SqrlError::new("No rescue code data found!".to_owned()))?;

        Ok(SqrlClient {
            user_configuration: user_access_check,
            identity_unlock: rescue_code_check,
            previous_identities: previous_identities,
        })
    }

    fn to_binary(&self) -> Result<Vec<u8>, SqrlError> {
        // Start by writing the header
        let mut result = Vec::new();
        for c in FILE_HEADER.bytes() {
            result.push(c);
        }

        // Make sure to write out all the sub data
        self.user_configuration.to_binary(&mut result)?;
        self.identity_unlock.to_binary(&mut result)?;
        match &self.previous_identities {
            Some(previous) => previous.to_binary(&mut result)?,
            _ => (),
        };

        Ok(result)
    }
}

impl SqrlStorage for SqrlClient {
    fn from_file(file_path: &str) -> Result<Self, SqrlError> {
        SqrlClient::from_binary(convert_vec(std::fs::read(file_path)?))
    }

    fn to_file(&self, file_path: &str) -> Result<(), SqrlError> {
        let mut file = File::create(file_path)?;
        let data = self.to_binary()?;
        file.write(&data)?;

        Ok(())
    }

    fn from_base64(input: &str) -> Result<Self, SqrlError> {
        // Confirm the beginning looks like what we expected
        if input.len() < 8 || input[0..8] != FILE_HEADER.to_uppercase() {
            return Err(SqrlError::new(format!(
                "Invalid base64. Header text not valid: {}",
                &input[0..8]
            )));
        }

        // Decode the rest using base64
        let data = match base64::decode_config(&input[8..], base64::URL_SAFE) {
            Ok(data) => data,
            Err(_) => return Err(SqrlError::new("Invalid binary data".to_owned())),
        };

        let mut binary = convert_vec(data);

        // Add back the proper file header
        for b in FILE_HEADER.bytes().rev() {
            binary.push_front(b);
        }

        Ok(SqrlClient::from_binary(binary)?)
    }

    fn to_base64(&self) -> Result<String, SqrlError> {
        let data = self.to_binary()?;
        Ok(base64::encode_config(data, base64::URL_SAFE))
    }

    fn from_textual_identity_format(input: &str) -> Result<Self, SqrlError> {
        // TODO
        let mut line_num: u8 = 0;
        let mut output: [u8; 32] = [0; 32];
        let mut hasher = Sha256::new();
        for line in input.lines() {
            // Take each character and convert it to value
            let mut bytes: Vec<u8> = Vec::new();
            for (_, c) in line[..line.len() - 1].char_indices() {
                let character_value = match TEXT_IDENTITY_ALPHABET.match_indices(c).next() {
                    Some((index, _)) => index,
                    None => {
                        return Err(SqrlError::new(
                            "Unable to decode textual identity format!".to_string(),
                        ))
                    }
                };
                bytes.push(character_value as u8);
            }
            // Add the line number (0-based) as last
            bytes.push(line_num);

            // Hash the results
            hasher.input(&bytes);
            hasher.result(&mut output);

            // mod 56 the result and compare with the last character
            // TODO

            // Get ready for the next iteration
            hasher.reset();
            line_num += 1;
        }

        let (client, _) = SqrlClient::new();
        Ok(client)
    }

    fn to_textual_identity_format(&self) -> Result<String, SqrlError> {
        // TODO
        Ok("".to_owned())
    }
}

#[derive(Debug, PartialEq)]
struct UserConfiguration {
    aes_gcm_iv: [u8; 12],
    scrypt_config: ScryptConfig,
    option_flags: u16,
    hint_length: u8,
    pw_verify_sec: u8,
    idle_timeout_min: u16,
    identity_master_key: IdentityKey,
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

#[derive(Debug, PartialEq)]
struct IdentityUnlock {
    scrypt_config: ScryptConfig,
    identity_unlock_key: IdentityKey,
    verification_data: [u8; 16],
}

impl IdentityUnlock {
    pub fn new() -> Self {
        IdentityUnlock {
            scrypt_config: ScryptConfig::new(),
            identity_unlock_key: IdentityKey::Plaintext([0; 32]),
            verification_data: [0; 16],
        }
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
            identity_unlock_key: IdentityKey::from_binary(binary)?,
            verification_data: binary.next_sub_array(16)?.as_slice().try_into()?,
        })
    }

    fn to_binary_inner(&self, output: &mut Vec<u8>) -> Result<(), SqrlError> {
        self.scrypt_config.to_binary(output)?;
        self.identity_unlock_key.to_binary(output)?;
        output.write(&self.verification_data)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
struct PreviousIdentityData {
    edition: u16,
    previous_identity_unlock_keys: Vec<IdentityKey>,
    verification_data: [u8; 16],
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

#[derive(Debug, PartialEq)]
enum IdentityKey {
    Encrypted([u8; 32]),
    Plaintext([u8; 32]),
}

impl IdentityKey {
    fn from_binary(binary: &mut VecDeque<u8>) -> Result<Self, SqrlError> {
        Ok(IdentityKey::Encrypted(
            binary.next_sub_array(32)?.as_slice().try_into()?,
        ))
    }

    fn to_binary(&self, output: &mut Vec<u8>) -> Result<(), SqrlError> {
        match self {
            IdentityKey::Encrypted(data) => {
                output.write(data)?;
            }
            IdentityKey::Plaintext(_) => {
                return Err(SqrlError::new(
                    "Cannot safe unencrypted identity key!".to_owned(),
                ))
            }
        };

        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
enum DataType {
    UserAccess = 1,
    RescueCode = 2,
    PreviousIdentity = 3,
}

impl DataType {
    fn from_binary(binary: &mut VecDeque<u8>) -> Result<Self, SqrlError> {
        match binary.next_u16()? {
            1 => Ok(DataType::UserAccess),
            2 => Ok(DataType::RescueCode),
            3 => Ok(DataType::PreviousIdentity),
            _ => Err(SqrlError::new("Invalid data type".to_owned())),
        }
    }

    fn to_binary(&self, output: &mut Vec<u8>) -> Result<(), SqrlError> {
        output.write_u16::<LittleEndian>(*self as u16)?;

        Ok(())
    }
}

pub struct KeyPair {
    pub private_key: [u8; 32],
    pub public_key: [u8; 64],
}

impl KeyPair {
    pub fn sign(&self, request: &[u8]) -> [u8; 64] {
        signature(request, &self.private_key)
    }
}

#[derive(Debug, PartialEq)]
struct ScryptConfig {
    random_salt: [u8; 16],
    log_n_factor: u8,
    iteration_factor: Option<u32>,
}

impl ScryptConfig {
    pub fn new() -> Self {
        let mut random = StdRng::from_entropy();
        let mut salt: [u8; 16] = [0; 16];
        random.fill_bytes(&mut salt);

        ScryptConfig {
            random_salt: salt,
            log_n_factor: SCRYPT_DEFAULT_LOG_N,
            iteration_factor: None,
        }
    }

    fn from_binary(binary: &mut VecDeque<u8>) -> Result<Self, SqrlError> {
        Ok(ScryptConfig {
            random_salt: binary.next_sub_array(16)?.as_slice().try_into()?,
            log_n_factor: binary
                .pop_front()
                .ok_or(SqrlError::new("Invalid data".to_owned()))?,
            iteration_factor: Some(binary.next_u32()?),
        })
    }

    fn to_binary(&self, output: &mut Vec<u8>) -> Result<(), SqrlError> {
        output.write(&self.random_salt)?;
        output.push(self.log_n_factor);
        let iteration_factor = match self.iteration_factor {
            Some(x) => x,
            None => {
                return Err(SqrlError::new(
                    "Cannot write a ScrptConfig without iteration factor set".to_owned(),
                ))
            }
        };
        output.write_u32::<LittleEndian>(iteration_factor)?;
        Ok(())
    }
}

trait WritableDataBlock {
    fn get_type(&self) -> DataType;
    fn len(&self) -> u16;
    fn from_binary(binary: &mut VecDeque<u8>) -> Result<Self, SqrlError>
    where
        Self: std::marker::Sized;
    fn to_binary_inner(&self, output: &mut Vec<u8>) -> Result<(), SqrlError>;

    fn to_binary(&self, output: &mut Vec<u8>) -> Result<(), SqrlError> {
        let length = self.len();
        if length > 0 {
            output.write_u16::<LittleEndian>(length)?;
            self.get_type().to_binary(output)?;
            self.to_binary_inner(output)?;
        }

        Ok(())
    }
}

trait ReadableVector {
    fn next_u16(&mut self) -> Result<u16, SqrlError>;
    fn next_u32(&mut self) -> Result<u32, SqrlError>;
    fn next_sub_array(&mut self, size: u32) -> Result<Vec<u8>, SqrlError>;
    fn skip(&mut self, count: u32);
}

impl ReadableVector for VecDeque<u8> {
    fn next_u16(&mut self) -> Result<u16, SqrlError> {
        let mut holder: [u8; 2] = [0; 2];
        for i in 0..2 {
            holder[i] = self
                .pop_front()
                .ok_or(SqrlError::new("Invalid binary data".to_owned()))?;
        }
        Ok(u16::from_le_bytes(holder))
    }

    fn next_u32(&mut self) -> Result<u32, SqrlError> {
        let mut holder: [u8; 4] = [0; 4];
        for i in 0..4 {
            holder[i] = self
                .pop_front()
                .ok_or(SqrlError::new("Invalid binary data".to_owned()))?;
        }
        Ok(u32::from_le_bytes(holder))
    }

    fn next_sub_array(&mut self, size: u32) -> Result<Vec<u8>, SqrlError> {
        let mut sub_array = Vec::new();
        for _ in 0..size {
            match self.pop_front() {
                Some(x) => sub_array.push(x),
                None => return Err(SqrlError::new("Invalid binary data".to_owned())),
            };
        }

        Ok(sub_array)
    }

    fn skip(&mut self, count: u32) {
        for _ in 0..count {
            self.pop_front();
        }
    }
}

fn en_hash(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.input(input);
    let mut output: [u8; 32] = [0; 32];
    let mut hash_result: [u8; 32] = [0; 32];
    for _ in 0..16 {
        hasher.result(&mut hash_result);
        hasher.reset();
        hasher.input(&hash_result);
        xor(&mut output, &hash_result);
    }

    output
}

fn en_scrypt(password: &[u8], scrypt_config: &mut ScryptConfig, pw_verify_sec: u8) -> [u8; 32] {
    let mut output: [u8; 32] = [0; 32];
    let mut input: [u8; 32] = [0; 32];
    let mut temp: [u8; 32] = [0; 32];

    let params = ScryptParams::new(
        scrypt_config.log_n_factor,
        SCRYPT_DEFAULT_R,
        SCRYPT_DEFAULT_P,
    );

    match scrypt_config.iteration_factor {
        Some(factor) => {
            for i in 0..factor {
                if i == 0 {
                    scrypt(password, &scrypt_config.random_salt, &params, &mut temp);
                } else {
                    scrypt(password, &input, &params, &mut temp);
                }

                xor(&mut output, &temp);
                input = temp;
            }
        }
        None => {
            let now = Instant::now();
            let mut count = 0;
            loop {
                if count == 0 {
                    scrypt(password, &scrypt_config.random_salt, &params, &mut temp);
                } else {
                    scrypt(password, &input, &params, &mut temp);
                }

                xor(&mut output, &temp);
                input = temp;
                count += 1;

                if now.elapsed().as_secs() >= pw_verify_sec.into() {
                    break;
                }
            }
            scrypt_config.iteration_factor = Some(count);
        }
    }

    output
}

fn xor(output: &mut [u8], other: &[u8]) {
    for i in 0..output.len() {
        output[i] = output[i] ^ other[i];
    }
}

fn convert_vec(mut input: Vec<u8>) -> VecDeque<u8> {
    let mut new_vec = VecDeque::new();
    loop {
        match input.pop() {
            Some(x) => new_vec.push_front(x),
            None => break,
        };
    }

    new_vec
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use std::fs::remove_file;

    #[test]
    fn load_test_data() {
        let mut client =
            SqrlClient::from_file("/Users/chris/src/Spec-Vectors-Identity.sqrl").unwrap();
        client.verify("Zingo-Bingo-Slingo-Dingo").unwrap();
    }

    #[test]
    fn it_can_write_and_read_empty() {
        let mut random = StdRng::from_entropy();
        let file = format!("test{}.bin", random.next_u64());
        let (mut client, _) = SqrlClient::new();

        client.previous_identities = Some(PreviousIdentityData {
            edition: 1,
            previous_identity_unlock_keys: vec![IdentityKey::Encrypted([17; 32])],
            verification_data: [0; 16],
        });

        client
            .to_file(&file)
            .expect("Failed to write identity information");
        let read_client = SqrlClient::from_file(&file).expect("Did not read successfully");
        assert_eq!(client, read_client);

        remove_file(file).expect("Failed to delete test file");
    }

    #[test]
    fn it_can_write_and_read_empty_previous_identity() {
        let mut random = StdRng::from_entropy();
        let file = format!("test{}.bin", random.next_u64());
        let (client, _) = SqrlClient::new();

        client
            .to_file(&file)
            .expect("Failed to write identity information");
        let read_client = SqrlClient::from_file(&file).expect("Did not read successfully");
        assert_eq!(client, read_client);

        remove_file(file).expect("Failed to delete test file");
    }
}
