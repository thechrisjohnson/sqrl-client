mod common;
mod identity_unlock;
mod previous_identity;
mod readable_vector;
pub(crate) mod scrypt;
mod user_configuration;
mod writable_datablock;

use self::{
    common::xor, identity_unlock::IdentityUnlockData, previous_identity::PreviousIdentityData,
    readable_vector::ReadableVector, user_configuration::UserConfiguration,
    writable_datablock::WritableDataBlock,
};
use crate::error::SqrlError;
use byteorder::{LittleEndian, WriteBytesExt};
use crypto::{
    curve25519::ge_scalarmult_base,
    digest::Digest,
    ed25519::{keypair, signature},
    hmac::Hmac,
    mac::Mac,
    sha2::Sha256,
};
use num_bigint::BigUint;
use num_traits::{FromPrimitive, ToPrimitive};
use rand::{prelude::StdRng, RngCore, SeedableRng};
use std::{collections::VecDeque, fs::File, io::Write};
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
const TEXT_IDENTITY_ALPHABET: [char; 56] = [
    '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L',
    'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
];

trait SqrlStorage
where
    Self: Sized,
{
    fn from_file(file_path: &str) -> Result<Self, SqrlError>;
    fn to_file(&self, file_path: &str) -> Result<(), SqrlError>;
    fn from_base64(input: &str) -> Result<Self, SqrlError>;
    fn to_base64(&self) -> Result<String, SqrlError>;
    fn from_textual_identity_format(
        input: &str,
        rescue_code: &str,
        new_password: &str,
    ) -> Result<Self, SqrlError>;
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
    identity_unlock: IdentityUnlockData,
    previous_identities: Option<PreviousIdentityData>,
}

impl SqrlClient {
    pub fn new(password: &str) -> Result<(Self, String), SqrlError> {
        // Generate a random identity unlock key base
        let mut random = StdRng::from_entropy();
        let mut identity_unlock_key: [u8; 32] = [0; 32];
        random.fill_bytes(&mut identity_unlock_key);

        // From the identity unlock key, generate the identity lock key and identity master key
        // NOTE: The identity_lock_key is the "public key" for an ECDHKA ED25519 where the private key is the identity unlock key
        let identity_master_key = en_hash(&identity_unlock_key);
        let identity_lock_key = ge_scalarmult_base(&identity_unlock_key).to_bytes();

        // Encrypt the identity unlock key with a random rescue code to return
        let (identity_unlock, rescue_code) = IdentityUnlockData::new(identity_unlock_key)?;

        // Encrypt the identity master key and identity lock key in
        let user_configuration =
            UserConfiguration::new(password, identity_master_key, identity_lock_key)?;

        Ok((
            SqrlClient {
                user_configuration,
                identity_unlock,
                previous_identities: None,
            },
            rescue_code,
        ))
    }

    fn from_identity_unlock(
        identity_unlock: IdentityUnlockData,
        rescue_code: &str,
        new_password: &str,
    ) -> Result<Self, SqrlError> {
        let identity_unlock_key = identity_unlock.decrypt_identity_unlock_key(rescue_code)?;

        // From the identity unlock key, generate the identity lock key and identity master key
        // NOTE: The identity_lock_key is the "public key" for an ECDHKA ED25519 where the private key is the identity unlock key
        let identity_master_key = en_hash(&identity_unlock_key);
        let identity_lock_key = ge_scalarmult_base(&identity_unlock_key).to_bytes();

        // Encrypt the identity master key and identity lock key in
        let user_configuration =
            UserConfiguration::new(new_password, identity_master_key, identity_lock_key)?;

        Ok(SqrlClient {
            user_configuration,
            identity_unlock,
            previous_identities: None,
        })
    }

    // TODO: Do I just want to get the rescue code, and then regenerate everything else?
    pub fn unlock_with_rescue_code(&self, rescue_code: &str) -> Result<[u8; 32], SqrlError> {
        self.identity_unlock
            .decrypt_identity_unlock_key(rescue_code)
    }

    pub fn verify_password(&mut self, password: &str) -> Result<(), SqrlError> {
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

    pub fn rekey_identity(
        &mut self,
        password: &str,
        rescue_code: &str,
    ) -> Result<String, SqrlError> {
        // Verify we can decrypt the current identity unlock key
        let current_identity_unlock_key = self
            .identity_unlock
            .decrypt_identity_unlock_key(rescue_code)?;

        // Generate a new identity unlock key
        let mut random = StdRng::from_entropy();
        let mut new_identity_unlock_key: [u8; 32] = [0; 32];
        random.fill_bytes(&mut new_identity_unlock_key);

        // From the identity unlock key, generate the new identity lock key and identity master key
        let new_identity_master_key = en_hash(&new_identity_unlock_key);
        let new_identity_lock_key = ge_scalarmult_base(&new_identity_unlock_key).to_bytes();

        // Encrypt the identity unlock key with a random rescue code to return
        let (new_identity_unlock, new_rescue_code) =
            IdentityUnlockData::new(new_identity_unlock_key)?;
        self.identity_unlock = new_identity_unlock;

        // Decrypt the previous identities and add the new one, re-encrypting with the new identity master key
        if let Some(ref mut previous_identities) = self.previous_identities {
            let current_identity_master_key = self
                .user_configuration
                .decrypt_identity_master_key(&password)?;

            previous_identities.rekey_previous_identities(
                &current_identity_master_key,
                &new_identity_master_key,
                Some(current_identity_unlock_key),
            )?;
        } else {
            let mut previous_identities = PreviousIdentityData::new();
            previous_identities
                .add_previous_identity(&new_identity_master_key, current_identity_unlock_key)?;
            self.previous_identities = Some(previous_identities);
        }

        self.user_configuration.update_keys(
            password,
            new_identity_master_key,
            new_identity_lock_key,
        )?;

        Ok(new_rescue_code)
    }

    fn get_keys(
        &self,
        password: &str,
        hostname: &str,
        alternate_identity: Option<&str>,
    ) -> Result<KeyPair, SqrlError> {
        let data = match alternate_identity {
            Some(id) => format!("{}{}", hostname, id),
            None => hostname.to_owned(),
        };

        let key = self
            .user_configuration
            .decrypt_identity_master_key(password)?;
        let mut hmac = Hmac::new(Sha256::new(), &key);
        hmac.input(data.as_bytes());
        let (public, private) = keypair(hmac.result().code());

        Ok(KeyPair {
            public_key: public,
            private_key: private,
        })
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
        let mut identity_unlock: Option<IdentityUnlockData> = None;
        let mut previous_identities: Option<PreviousIdentityData> = None;

        loop {
            if binary.len() == 0 {
                break;
            }

            // Make sure the length matches
            // But add two after removing the first two bytes for size
            let block_length = binary.next_u16()?;
            if binary.len() + 2 < block_length.into() {
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

                    identity_unlock = Some(IdentityUnlockData::from_binary(&mut binary)?)
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
            user_configuration.ok_or(SqrlError::new("No key data found!".to_owned()))?;

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

    fn from_textual_identity_format(
        input: &str,
        rescue_code: &str,
        new_password: &str,
    ) -> Result<Self, SqrlError> {
        validate_textual_identity(input)?;
        let mut data = decode_textual_identity(input)?;
        let identity_unlock = IdentityUnlockData::from_binary(&mut data)?;
        SqrlClient::from_identity_unlock(identity_unlock, rescue_code, new_password)
    }

    fn to_textual_identity_format(&self) -> Result<String, SqrlError> {
        // TODO
        encode_textual_identity(self)
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

fn validate_textual_identity(textual_identity: &str) -> Result<(), SqrlError> {
    let mut line_num: u8 = 0;
    let mut output: [u8; 32] = [0; 32];
    let mut hasher = Sha256::new();
    for line in textual_identity.lines() {
        // Take each character and convert it to value
        let mut bytes: Vec<u8> = Vec::new();
        let trimmed_line = line.trim();
        for c in trimmed_line[..trimmed_line.len() - 1].chars() {
            if c == ' ' {
                continue;
            }
            bytes.push(c as u8);
        }
        // Add the line number (0-based) as last
        bytes.push(line_num);

        // Hash the results
        hasher.input(&bytes);
        hasher.result(&mut output);

        // mod 56 the result and compare with the last character
        let hash = BigUint::from_bytes_le(&output);
        if let Some(result) = (hash % 56u8).to_usize() {
            // If they don't match, the line is invalid
            if TEXT_IDENTITY_ALPHABET[result]
                != trimmed_line.chars().nth(trimmed_line.len() - 1).unwrap()
            {
                return Err(SqrlError::new(
                    "Unable to decode textual identity format! Checksum fail.".to_string(),
                ));
            }
        } else {
            return Err(SqrlError::new(
                "Unable to decode textual identity format! Checksum fail".to_string(),
            ));
        }

        // Get ready for the next iteration
        hasher.reset();
        line_num += 1;
    }

    Ok(())
}

// TODO:
fn encode_textual_identity(client: &SqrlClient) -> Result<String, SqrlError> {
    let mut textual_identity = String::new();
    // Get the binary representation of the identity unlock key
    let mut data = Vec::new();
    client.identity_unlock.to_binary(&mut data)?;

    // Based on the number of numbers we're going to need,
    // calculate the textual identity
    let mut num = BigUint::from_bytes_le(&data);
    let mut line = String::new();
    for _ in 1..calculate_encoded_text_size(&data) {
        if let Some(index) = (&num % 56u8).to_usize() {
            num /= 56u8;
            let c = TEXT_IDENTITY_ALPHABET[index];
            line.push(c);
            textual_identity.push(c);

            if line.len() == 19 {}
        }
    }

    Ok(textual_identity)
}

fn calculate_encoded_text_size(data: &Vec<u8>) -> u8 {
    // Create a max value
    let mut max = Vec::<u8>::new();
    for _ in data {
        max.push(u8::MAX);
    }

    // While we're not zero, keep dividing
    let zero = BigUint::from_u8(0).unwrap();
    let mut max_int = BigUint::from_bytes_le(&max);
    let mut count = 0u8;

    while max_int > zero {
        max_int /= 56u8;
        count += 1;
    }

    count
}

fn decode_textual_identity(textual_identity: &str) -> Result<VecDeque<u8>, SqrlError> {
    let mut data = BigUint::from_u8(0).unwrap();
    let mut power = BigUint::from_u8(0).unwrap();
    let zero = BigUint::from_u8(0).unwrap();

    for line in textual_identity.lines() {
        let trimmed_line = line.trim();
        // Go through the line from the back to the front (after removing the last character)
        for c in trimmed_line[..trimmed_line.len() - 1].chars() {
            if c == ' ' {
                continue;
            }

            if power == zero {
                power += 1u32;
            } else {
                power *= 56u32;
            }

            if let Some(index) = find_char_in_array(&TEXT_IDENTITY_ALPHABET, c) {
                data += index * &power;
            } else {
                return Err(SqrlError::new(
                    "Unable to decode textual identity!".to_string(),
                ));
            }
        }
    }

    Ok(convert_vec(data.to_bytes_le()))
}

fn find_char_in_array(array: &[char], character: char) -> Option<usize> {
    for i in 0..array.len() {
        if array[i] == character {
            return Some(i);
        }
    }

    None
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

    const TEST_FILE_PATH: &str = "test_resources/Spec-Vectors-Identity.sqrl";
    const TEST_FILE_PASSWORD: &str = "Zingo-Bingo-Slingo-Dingo";
    const TEST_FILE_RESCUE_CODE: &str = "1198-8748-7132-2838-8318-7570";
    const TEST_FILE_TEXTUAL_IDENTITY: &str = "KKcC 3BaX akxc Xwbf xki7\nk7mF GHhg jQes gzWd 6TrK\nvMsZ dBtB pZbC zsz8 cUWj\nDtS2 ZK2s ZdAQ 8Yx3 iDyt\nQuXt CkTC y6gc qG8n Xfj9\nbHDA 422";

    #[test]
    fn load_test_data() {
        let mut client = SqrlClient::from_file(TEST_FILE_PATH).unwrap();
        client.verify_password(TEST_FILE_PASSWORD).unwrap();
    }

    #[test]
    fn load_then_write_test_data() {
        let mut client = SqrlClient::from_file(TEST_FILE_PATH).unwrap();
        client.verify_password(TEST_FILE_PASSWORD).unwrap();
        let written_file_path = "load_then_write_test_data.sqrl";
        client.to_file(written_file_path).unwrap();
        let expected = std::fs::read(TEST_FILE_PATH).unwrap();
        let actual = std::fs::read(written_file_path).unwrap();
        assert_eq!(expected, actual, "Output did not match test file!");
        let _ = std::fs::remove_file(written_file_path);
    }

    #[test]
    fn try_rescue_code() {
        let client = SqrlClient::from_file(TEST_FILE_PATH).unwrap();
        client
            .unlock_with_rescue_code(TEST_FILE_RESCUE_CODE)
            .unwrap();
    }

    #[test]
    fn try_textual_identity_loading() {
        let mut client = SqrlClient::from_textual_identity_format(
            TEST_FILE_TEXTUAL_IDENTITY,
            TEST_FILE_RESCUE_CODE,
            TEST_FILE_PASSWORD,
        )
        .unwrap();
        client.verify_password(TEST_FILE_PASSWORD).unwrap();
    }
}
