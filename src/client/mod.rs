mod identity_unlock;
mod previous_identity;
mod readable_vector;
pub(crate) mod scrypt_config;
mod user_configuration;
mod writable_datablock;

use self::{
    identity_unlock::IdentityUnlock, previous_identity::PreviousIdentityData,
    readable_vector::ReadableVector, user_configuration::UserConfiguration,
    writable_datablock::WritableDataBlock,
};
use crate::{
    common::{convert_vec, en_hash},
    error::SqrlError,
};
use byteorder::{LittleEndian, WriteBytesExt};
use crypto::{
    digest::Digest,
    ed25519::{keypair, signature},
    hmac::Hmac,
    mac::Mac,
    sha2::Sha256,
};
use rand::{prelude::StdRng, RngCore, SeedableRng};
use std::{collections::VecDeque, fs::File, io::Write};
use url::{Host, Url};

// The configuration options for the SqrlClient
// TODO: Is this something that should be handled by the client and not the lib
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
pub(crate) const SCRYPT_DEFAULT_LOG_N: u8 = 9;
pub(crate) const SCRYPT_DEFAULT_R: u32 = 256;
pub(crate) const SCRYPT_DEFAULT_P: u32 = 1;
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
    pub fn new(password: &str) -> Result<Self, SqrlError> {
        // 1. Generate a random 256-bit value (Known as the Identity Unlock Key)
        let mut random = StdRng::from_entropy();
        let mut identity_unlock_key: [u8; 32] = [0; 32];
        random.fill_bytes(&mut identity_unlock_key);
        let identity_master_key = en_hash(&identity_unlock_key);

        
        let (identity_unlock, rescue_code) = IdentityUnlock::new(identity_unlock_key);

        // 2. Use ECDHA (Diffie-Helman with EC) to create a "Encrypted Identity Lock Key"
        // 3. EnHash the IUK to become the Identity Master Key

        // 4. EnScrypt the password and use it to encrypt the IUK
        let user_configuration = UserConfiguration::new(identity_master_key);

        Ok(SqrlClient {
            user_configuration: user_configuration,
            identity_unlock: identity_unlock,
            previous_identities: None,
        })
    }

    // TODO
    pub fn unlock_with_rescue_code(&mut self, _rescue_code: &str) {}

    pub fn verify(&mut self, password: &str) -> Result<(), SqrlError> {
        self.user_configuration.verify(password)?;
        Ok(())
    }

    pub fn sign_request(
        &self,
        password: &str,
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

        let keys = self.get_keys(password, &host, alternate_identity)?;
        Ok(keys.sign(request.as_bytes()))
    }

    pub fn get_keys(
        &self,
        password: &str,
        hostname: &str,
        alternate_identity: Option<&str>,
    ) -> Result<KeyPair, SqrlError> {
        let data = match alternate_identity {
            Some(id) => format!("{}{}", hostname, id),
            None => hostname.to_owned(),
        };

        // TODO: Don't require mutability when decrypting things (need to change ScryptConfig)
        let key = self.user_configuration.decrypt_user_identity_key(password)?;
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
        password: &str,
        hostname: &str,
        secret_index: &str,
    ) -> Result<String, SqrlError> {
        let keys = self.get_keys(password, hostname, None)?;
        let hash = en_hash(&keys.private_key);
        let mut hmac = Hmac::new(Sha256::new(), &hash);
        hmac.input(secret_index.as_bytes());

        Ok(base64::encode_config(
            hmac.result().code(),
            base64::URL_SAFE,
        ))
    }

    fn from_binary(mut binary: VecDeque<u8>) -> Result<Self, SqrlError> {
        match std::str::from_utf8(binary.next_sub_array(8)?.as_slice()) {
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

            // Make sure the length matches
            let block_length = binary.next_u16()?;
            if binary.len() < block_length.into() {
                return Err(SqrlError::new("Invalid binary data".to_string()));
            }

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

        SqrlClient::new("password")
    }

    fn to_textual_identity_format(&self) -> Result<String, SqrlError> {
        // TODO
        Ok("".to_owned())
    }
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum DataType {
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
        let mut client = SqrlClient::new("password").unwrap();

        client.previous_identities = Some(PreviousIdentityData::new());
        match &mut client.previous_identities {
            Some(previous_identities) => previous_identities.add_previous_identity([17; 32]),
            _ => ()
        }

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
        let client = SqrlClient::new("password").unwrap();

        client
            .to_file(&file)
            .expect("Failed to write identity information");
        let read_client = SqrlClient::from_file(&file).expect("Did not read successfully");
        assert_eq!(client, read_client);

        remove_file(file).expect("Failed to delete test file");
    }
}
