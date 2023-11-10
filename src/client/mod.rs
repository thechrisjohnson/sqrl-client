//! All of the code needed to create your own sqrl client

mod identity_information;
mod identity_unlock;
mod previous_identity;
mod readable_vector;
pub(crate) mod scrypt;
mod writable_datablock;

use self::{
    identity_information::IdentityInformation, identity_unlock::IdentityUnlockData,
    previous_identity::PreviousIdentityData, readable_vector::ReadableVector,
    writable_datablock::WritableDataBlock,
};
use crate::{
    common::{en_hash, vec_to_u8_32, IdentityUnlockKeys, SqrlUrl},
    error::SqrlError,
    protocol::client_request::ClientRequest,
};
use aes_gcm::aead::OsRng;
use base64::{prelude::BASE64_URL_SAFE, Engine};
use byteorder::{LittleEndian, WriteBytesExt};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use num_traits::{FromPrimitive, ToPrimitive};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{collections::VecDeque, fs::File, io::Write};
use x25519_dalek::{PublicKey, StaticSecret};

pub(crate) type AesVerificationData = [u8; 16];
pub(crate) type IdentityKey = [u8; 32];

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
// - Recover identity using unlock key
// - Store previous identities and be able to access them
// - Handle special "Ask" functionality

/// A SQRL client
///
/// A SQRLClient contains all of the code needed to interact with SQRL requests
/// including:
///
/// - Generating identities
/// - Signing requests
#[derive(Debug, PartialEq)]
pub struct SqrlClient {
    user_configuration: IdentityInformation,
    identity_unlock: IdentityUnlockData,
    previous_identities: Option<PreviousIdentityData>,
}

impl SqrlClient {
    /// Create a new SQRL client protecting the data with the password
    pub fn new(password: &str) -> Result<(Self, String), SqrlError> {
        // Generate a random identity unlock key base
        let mut identity_unlock_key: [u8; 32] = [0; 32];
        OsRng.fill_bytes(&mut identity_unlock_key);

        // Encrypt the identity unlock key with a random rescue code to return
        let (identity_unlock, rescue_code) = IdentityUnlockData::new(identity_unlock_key)?;

        // Encrypt the identity master key and identity lock key in
        let user_configuration =
            IdentityInformation::from_identity_unlock_key(password, identity_unlock_key)?;

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

        // Encrypt the identity master key and identity lock key in
        let user_configuration =
            IdentityInformation::from_identity_unlock_key(new_password, identity_unlock_key)?;

        Ok(SqrlClient {
            user_configuration,
            identity_unlock,
            previous_identities: None,
        })
    }

    /// Recreate the SQRL data from a rescue code
    pub fn recreate_from_rescue_code(
        &self,
        rescue_code: &str,
        new_password: &str,
    ) -> Result<Self, SqrlError> {
        let identity_unlock_key = self
            .identity_unlock
            .decrypt_identity_unlock_key(rescue_code)?;

        let user_configuration =
            IdentityInformation::from_identity_unlock_key(new_password, identity_unlock_key)?;

        Ok(SqrlClient {
            user_configuration,
            identity_unlock: self.identity_unlock.clone(),
            previous_identities: self.previous_identities.clone(),
        })
    }

    /// Change the password for the encrypted client data
    /// ```rust
    /// use sqrl::client::SqrlClient;
    ///
    /// let (mut client, _) = SqrlClient::new("password").unwrap();
    /// client.change_password("password", "new_password").unwrap();
    /// ```
    pub fn change_password(
        &mut self,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), SqrlError> {
        self.user_configuration
            .change_password(current_password, new_password)
    }

    /// Verify that the password is the correct password
    pub fn verify_password(&mut self, password: &str) -> Result<(), SqrlError> {
        self.user_configuration.verify(password)?;
        Ok(())
    }

    /// Sign a client request with the key generated by the url and alternate identity
    pub fn sign_request(
        &self,
        password: &str,
        url: &str,
        alternate_identity: Option<&str>,
        request: &mut ClientRequest,
        previous_key_index: Option<usize>,
    ) -> Result<(), SqrlError> {
        let sqrl_url = SqrlUrl::parse(url)?;
        let private_key =
            self.get_private_key(password, &sqrl_url.get_auth_domain(), alternate_identity)?;

        request.client_params.identity_key = private_key.verifying_key();

        if let Some(prev) = &self.previous_identities {
            let key_index = previous_key_index.unwrap_or(0);
            let identity_master_key = self
                .user_configuration
                .decrypt_identity_master_key(password)?;

            if let Some(previous_key) =
                prev.get_previous_identity(&identity_master_key, key_index)?
            {
                let previous_private_key = previous_key
                    .get_private_key(&sqrl_url.get_auth_domain(), alternate_identity)?;
                request.client_params.previous_identity_key =
                    Some(previous_private_key.verifying_key());
                request.previous_identity_signature =
                    Some(previous_private_key.sign(request.get_signed_string().as_bytes()));
            }
        }

        // Sign last, as we need to set the current and previous key ids
        request.identity_signature = private_key.sign(request.get_signed_string().as_bytes());

        Ok(())
    }

    /// Get a sin value based on the url and alternate identity
    pub fn get_secret_index_key(
        &self,
        password: &str,
        url: &str,
        alternate_identity: Option<&str>,
        secret_index: &str,
    ) -> Result<String, SqrlError> {
        let private_key = self.get_private_key(
            password,
            &SqrlUrl::parse(url)?.get_auth_domain(),
            alternate_identity,
        )?;
        let hash = en_hash(&private_key.to_bytes());
        let mut hmac = Hmac::<Sha256>::new_from_slice(&hash)?;
        hmac.update(secret_index.as_bytes());
        Ok(BASE64_URL_SAFE.encode(hmac.finalize().into_bytes()))
    }

    /// Generate a new identity, storing the previous identity in the list of previous identities
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
        let mut new_identity_unlock_key: [u8; 32] = [0; 32];
        OsRng.fill_bytes(&mut new_identity_unlock_key);

        // From the identity unlock key, generate the new identity lock key and identity master key
        let new_identity_master_key = en_hash(&new_identity_unlock_key);
        let secret_key = StaticSecret::from(new_identity_unlock_key);
        let public_key = PublicKey::from(&secret_key);
        let new_identity_lock_key = public_key.to_bytes();

        // Encrypt the identity unlock key with a random rescue code to return
        let (new_identity_unlock, new_rescue_code) =
            IdentityUnlockData::new(new_identity_unlock_key)?;
        self.identity_unlock = new_identity_unlock;

        // Decrypt the previous identities and add the new one, re-encrypting with the new identity master key
        if let Some(ref mut previous_identities) = self.previous_identities {
            let current_identity_master_key = self
                .user_configuration
                .decrypt_identity_master_key(password)?;

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

    ///
    pub fn get_public_identity(
        &self,
        password: &str,
        url: &str,
        alternate_identity: Option<&str>,
    ) -> Result<VerifyingKey, SqrlError> {
        Ok(self
            .get_private_key(
                password,
                &SqrlUrl::parse(url)?.get_auth_domain(),
                alternate_identity,
            )?
            .verifying_key())
    }

    /// Generate the server unlock and verify unlock keys needed for unlocking
    /// an identity with a server
    pub fn generate_server_unlock_and_verify_unlock_keys(
        &self,
        password: &str,
        _hostname: &str,
        _alternate_identity: Option<&str>,
    ) -> Result<IdentityUnlockKeys, SqrlError> {
        self.user_configuration
            .generate_server_unlock_and_verify_unlock_keys(password)
    }

    /// Generate the signing key needed to sign an unlock identity request
    pub fn generate_unlock_request_signing_key(
        &self,
        rescue_code: &str,
        server_unlock_key: [u8; 32],
    ) -> Result<SigningKey, SqrlError> {
        self.identity_unlock
            .generate_unlock_request_signing_key(rescue_code, server_unlock_key)
    }

    /// Update the configuration settings stored in the encrypted file
    pub fn upate_cofig_settings(
        &mut self,
        password: &str,
        option_flags: Option<Vec<ConfigOptions>>,
        hint_length: Option<u8>,
        pw_verify_sec: Option<u8>,
        idle_timeout_min: Option<u16>,
    ) -> Result<(), SqrlError> {
        self.user_configuration.update_setings(
            password,
            option_flags,
            hint_length,
            pw_verify_sec,
            idle_timeout_min,
        )
    }

    fn get_private_key(
        &self,
        password: &str,
        auth_domain: &str,
        alternate_identity: Option<&str>,
    ) -> Result<SigningKey, SqrlError> {
        let key = self
            .user_configuration
            .decrypt_identity_master_key(password)?;

        key.get_private_key(auth_domain, alternate_identity)
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

        let mut user_configuration: Option<IdentityInformation> = None;
        let mut identity_unlock: Option<IdentityUnlockData> = None;
        let mut previous_identities: Option<PreviousIdentityData> = None;

        loop {
            if binary.is_empty() {
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
                    if user_configuration.is_some() {
                        return Err(SqrlError::new(
                            "Duplicate password information found!".to_owned(),
                        ));
                    }

                    user_configuration = Some(IdentityInformation::from_binary(&mut binary)?)
                }
                DataType::RescueCode => {
                    if identity_unlock.is_some() {
                        return Err(SqrlError::new(
                            "Duplicate rescue code data found!".to_owned(),
                        ));
                    }

                    identity_unlock = Some(IdentityUnlockData::from_binary(&mut binary)?)
                }
                DataType::PreviousIdentity => {
                    if previous_identities.is_some() {
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
            previous_identities,
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
        if let Some(previous) = &self.previous_identities {
            previous.to_binary(&mut result)?;
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
        file.write_all(&data)?;

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
        let data = match BASE64_URL_SAFE.decode(&input[8..]) {
            Ok(data) => data,
            Err(_) => return Err(SqrlError::new("Invalid binary data".to_owned())),
        };

        let mut binary = convert_vec(data);

        // Add back the proper file header
        for b in FILE_HEADER.bytes().rev() {
            binary.push_front(b);
        }

        SqrlClient::from_binary(binary)
    }

    fn to_base64(&self) -> Result<String, SqrlError> {
        let data = self.to_binary()?;
        Ok(BASE64_URL_SAFE.encode(data))
    }

    fn from_textual_identity_format(
        input: &str,
        rescue_code: &str,
        new_password: &str,
    ) -> Result<Self, SqrlError> {
        validate_textual_identity(input)?;
        let mut data = decode_textual_identity(input)?;
        if data.next_u16()? != 73 || DataType::from_binary(&mut data)? != DataType::RescueCode {
            return Err(SqrlError::new("Invalid textual identity.".to_owned()));
        }

        let identity_unlock = IdentityUnlockData::from_binary(&mut data)?;
        SqrlClient::from_identity_unlock(identity_unlock, rescue_code, new_password)
    }

    fn to_textual_identity_format(&self) -> Result<String, SqrlError> {
        encode_textual_identity(self)
    }
}

/// The configuration options that can be set on a SQRLClient
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConfigOptions {
    /// Have the client automatically check for updates to the client
    CheckForUpdates = 0x1,
    /// TODO:
    UpdateAnonymously = 0x2,
    /// Let the servers know to request only SQRL be used for authentication
    SqrlOnlyLogin = 0x4,
    /// Do not bypass SQRL auth
    NoSqrlBypass = 0x8,
    /// Warn if there is a detected man-in-the-middle attack
    WarnManInTheMiddle = 0x10,
    /// If the system is performing a suspend, clear anything stored in RAM
    ClearDataOnSuspend = 0x20,
    /// If the system is performing a logout, clear anything stored in RAM
    ClearDataOnUserSwitch = 0x40,
    /// If the system is idle, clear anything stored in RAM
    ClearDataOnIdle = 0x80,
    /// Warn if the system isn't using CPS
    WarnNonCPS = 0x100,
}

impl ConfigOptions {
    pub(crate) fn from_u16(value: u16) -> Vec<ConfigOptions> {
        let mut ret = Vec::new();

        if value & ConfigOptions::CheckForUpdates as u16 > 0 {
            ret.push(ConfigOptions::CheckForUpdates);
        }
        if value & ConfigOptions::UpdateAnonymously as u16 > 0 {
            ret.push(ConfigOptions::UpdateAnonymously);
        }
        if value & ConfigOptions::SqrlOnlyLogin as u16 > 0 {
            ret.push(ConfigOptions::SqrlOnlyLogin);
        }
        if value & ConfigOptions::NoSqrlBypass as u16 > 0 {
            ret.push(ConfigOptions::NoSqrlBypass);
        }
        if value & ConfigOptions::WarnManInTheMiddle as u16 > 0 {
            ret.push(ConfigOptions::WarnManInTheMiddle);
        }
        if value & ConfigOptions::ClearDataOnSuspend as u16 > 0 {
            ret.push(ConfigOptions::ClearDataOnSuspend);
        }
        if value & ConfigOptions::ClearDataOnUserSwitch as u16 > 0 {
            ret.push(ConfigOptions::ClearDataOnUserSwitch);
        }
        if value & ConfigOptions::ClearDataOnIdle as u16 > 0 {
            ret.push(ConfigOptions::ClearDataOnIdle);
        }
        if value & ConfigOptions::WarnNonCPS as u16 > 0 {
            ret.push(ConfigOptions::WarnNonCPS);
        }

        ret
    }
}

pub(crate) fn config_options_to_u16(options: &Vec<ConfigOptions>) -> u16 {
    let mut ret: u16 = 0;
    for t in options {
        ret |= *t as u16;
    }

    ret
}

#[derive(Debug, Copy, Clone, PartialEq)]
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

    fn to_binary(self, output: &mut Vec<u8>) -> Result<(), SqrlError> {
        output.write_u16::<LittleEndian>(self as u16)?;

        Ok(())
    }
}

trait GetKey {
    fn get_private_key(
        &self,
        url: &str,
        alternate_identity: Option<&str>,
    ) -> Result<SigningKey, SqrlError>;
}

impl GetKey for IdentityKey {
    fn get_private_key(
        &self,
        auth_domain: &str,
        alternate_identity: Option<&str>,
    ) -> Result<SigningKey, SqrlError> {
        let holder;
        let data = match alternate_identity {
            Some(id) => {
                holder = format!("{}{}", auth_domain, id);
                &holder
            }
            None => auth_domain,
        };

        let mut hmac = Hmac::<Sha256>::new_from_slice(self)?;
        hmac.update(data.as_bytes());
        let mut temp = Vec::new();
        for i in hmac.finalize().into_bytes() {
            temp.push(i);
        }

        Ok(SigningKey::from_bytes(&vec_to_u8_32(&temp)?))
    }
}

pub(crate) const EMPTY_NONCE: [u8; 12] = [0; 12];

fn validate_textual_identity(textual_identity: &str) -> Result<(), SqrlError> {
    let mut line_num: u8 = 0;
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
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let output: [u8; 32] = hasher.finalize().into();

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
        line_num += 1;
    }

    Ok(())
}

fn encode_textual_identity(client: &SqrlClient) -> Result<String, SqrlError> {
    let mut textual_identity = String::new();
    let mut bytes: Vec<u8> = Vec::new();
    let mut line_number: u8 = 0;

    // Get the binary representation of the identity unlock key
    let mut data = Vec::new();
    client.identity_unlock.to_binary(&mut data)?;

    // Based on the number of numbers we're going to need,
    // calculate the textual identity
    let mut num = BigUint::from_bytes_le(&data);
    let encoded_size = calculate_encoded_text_size(&data);
    for character in 0..encoded_size {
        if let Some(index) = (&num % 56u8).to_usize() {
            num /= 56u8;
            let c = TEXT_IDENTITY_ALPHABET[index];
            bytes.push(c as u8);
            textual_identity.push(c);

            // If we're at a multiple of 4, add a space
            if bytes.len() % 4 == 0 {
                textual_identity.push(' ');
            } else if bytes.len() == 19 || character == encoded_size {
                bytes.push(line_number);
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let output: [u8; 32] = hasher.finalize().into();
                // mod 56 the result and compare with the last character
                let hash = BigUint::from_bytes_le(&output);
                if let Some(result) = (hash % 56u8).to_usize() {
                    textual_identity.push(TEXT_IDENTITY_ALPHABET[result]);
                } else {
                    return Err(SqrlError::new(
                        "Unexpected error creating textual identity. This is a bug in the code."
                            .to_string(),
                    ));
                }

                // Now reset for the next line
                if character != encoded_size {
                    line_number += 1;
                    bytes.clear();
                    textual_identity.push('\n');
                }
            }
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
    let divisor = BigUint::from_u8(56).unwrap();

    while max_int > zero {
        // This means we're going to have a remainder that won't show up
        if max_int < divisor {
            count += 1;
        }

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

            if let Some(index) = TEXT_IDENTITY_ALPHABET.iter().position(|&r| r == c) {
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

fn convert_vec(mut input: Vec<u8>) -> VecDeque<u8> {
    let mut new_vec = VecDeque::new();
    while let Some(x) = input.pop() {
        new_vec.push_front(x);
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
    //const TEST_URL: &str = "sqrl://sqrl.grc.com/cli.sqrl?nut=fXkb4MBToCm7&can=aHR0cHM6Ly9zcXJsLmdyYy5jb20vZGVtbw";

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
        let second_client = client
            .recreate_from_rescue_code(TEST_FILE_RESCUE_CODE, "password")
            .unwrap();

        assert_eq!(
            second_client
                .user_configuration
                .decrypt_identity_master_key("password")
                .unwrap(),
            client
                .user_configuration
                .decrypt_identity_master_key(TEST_FILE_PASSWORD)
                .unwrap()
        );
        assert_eq!(
            second_client
                .user_configuration
                .decrypt_identity_lock_key("password")
                .unwrap(),
            client
                .user_configuration
                .decrypt_identity_lock_key(TEST_FILE_PASSWORD)
                .unwrap()
        )
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

    #[test]
    fn decode_encode_textual_identity() {
        let client = SqrlClient::from_textual_identity_format(
            TEST_FILE_TEXTUAL_IDENTITY,
            TEST_FILE_RESCUE_CODE,
            "password",
        )
        .unwrap();

        let output = client.to_textual_identity_format().unwrap();
        assert_eq!(
            output, TEST_FILE_TEXTUAL_IDENTITY,
            "Textual identity formats do not match!"
        );
    }

    #[test]
    fn encode_textual_identity_from_file() {
        let client = SqrlClient::from_file(TEST_FILE_PATH).unwrap();
        let output = client.to_textual_identity_format().unwrap();
        assert_eq!(
            output, TEST_FILE_TEXTUAL_IDENTITY,
            "Textual identity format not correct!"
        );
    }
}
