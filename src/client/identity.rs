use error::SqrlError;
use std::collections::VecDeque;
use std::convert::TryInto;
use std::fs::File;
use std::io::prelude::*;
use std::str;

const FILE_HEADER: &str = "sqrldata";
const TEXT_IDENTITY_ALPHABET: &str = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz";

#[derive(Debug, PartialEq)]
pub struct IdentityInformation {
    user_access_data: UserAccessData,
    rescue_code_data: RescueCodeData,
    previous_identity_data: Option<PreviousIdentityData>,
}

#[derive(Debug, PartialEq)]
struct UserAccessData {
    aes_gcm_iv: [u8; 12],
    scrypt_config: ScryptConfig,
    option_flags: u16,
    hint_length: u8,
    pw_verify_sec: u8,
    idle_timeout_min: u16,
    identity_master_key: IdentityKey,
    identity_lock_key: IdentityKey,
}

#[derive(Debug, PartialEq)]
struct RescueCodeData {
    scrypt_config: ScryptConfig,
    identity_unlock_key: IdentityKey,
}

#[derive(Debug, PartialEq)]
struct PreviousIdentityData {
    edition: u16,
    previous_identity_unlock_keys: Vec<IdentityKey>,
}

#[derive(Debug, PartialEq)]
struct ScryptConfig {
    random_salt: [u8; 16],
    log_n_factor: u8,
    iteration_factor: u32,
}

#[derive(Debug, PartialEq)]
pub enum IdentityKey {
    Encrypted([u8; 32]),
    Unencrypted([u8; 32]),
}

#[derive(Debug, Copy, Clone)]
pub enum DataType {
    UserAccess = 1,
    RescueCode = 2,
    PreviousIdentity = 3,
}

trait WritableIdentityData {
    fn get_type(&self) -> DataType;
    fn len(&self) -> u16;
    fn from_binary(binary: &mut VecDeque<u8>) -> Result<Self, SqrlError>
    where
        Self: std::marker::Sized;
    fn to_binary_inner(&self, output: &mut Vec<u8>) -> Result<(), SqrlError>;

    fn to_binary(&self, output: &mut Vec<u8>) -> Result<(), SqrlError> {
        let length = self.len();
        if length > 0 {
            for b in length.to_le_bytes() {
                output.push(b);
            }
            self.get_type().to_binary(output)?;

            return self.to_binary_inner(output);
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

fn convert_vec(mut input: Vec<u8>) -> VecDeque<u8> {
    let mut new_vec = VecDeque::new();
    loop {
        match input.pop() {
            Some(x) => new_vec.push_front(x),
            None => break
        };
    }

    new_vec
}

impl IdentityInformation {
    pub fn new() -> Self {
        IdentityInformation {
            user_access_data: UserAccessData::new(),
            rescue_code_data: RescueCodeData::new(),
            previous_identity_data: None,
        }
    }

    pub fn from_base64(data: &str) -> Result<Self, SqrlError> {
        // Confirm the beginning looks like what we expected
        if data.len() < 8 || data[0..8] != FILE_HEADER.to_uppercase() {
            return Err(SqrlError::new(format!(
                "Invalid base64. Header text not valid: {}",
                &data[0..8]
            )));
        }

        // Decode the rest using base64
        let data = match base64::decode_config(&data[8..], base64::URL_SAFE) {
            Ok(data) => data,
            Err(_) => return Err(SqrlError::new("Invalid binary data".to_owned())),
        };

        let mut binary = convert_vec(data);

        // Add back the proper file header
        for b in FILE_HEADER.bytes().rev() {
            binary.push_front(b);
        }


        Ok(IdentityInformation::from_binary(binary)?)
    }

    pub fn to_base64(&self) -> Result<String, SqrlError> {
        let data = self.to_binary()?;
        Ok(base64::encode_config(data, base64::URL_SAFE))
    }

    pub fn from_file(file_path: &str) -> Result<Self, SqrlError> {
        IdentityInformation::from_binary(convert_vec(std::fs::read(file_path)?))
    }

    pub fn to_file(&self, file_path: &str) -> Result<(), SqrlError> {
        let mut file = File::create(file_path)?;
        let data = self.to_binary()?;
        file.write(&data)?;

        Ok(())
    }

    pub fn from_textual_identity_format(_text: &str) -> Result<Self, SqrlError> {
        // TODO
        Ok(IdentityInformation::new())
    }

    pub fn to_textual_identity_format(&self) -> Result<String, SqrlError> {
        // TODO
        Ok("".to_owned())
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

        let mut user_access_data: Option<UserAccessData> = None;
        let mut rescue_code_data: Option<RescueCodeData> = None;
        let mut previous_identity_data: Option<PreviousIdentityData> = None;

        loop {
            if binary.len() == 0 {
                break;
            }

            // TODO: Do we need to worry about the length?
            binary.skip(2);
            let block_type = DataType::from_binary(&mut binary)?;

            println!("{:?}", block_type);

            match block_type {
                DataType::UserAccess => {
                    if user_access_data != None {
                        return Err(SqrlError::new(
                            "Duplicate password information found!".to_owned(),
                        ));
                    }

                    println!("UserAccess");

                    user_access_data = Some(UserAccessData::from_binary(&mut binary)?)
                }
                DataType::RescueCode => {
                    if rescue_code_data != None {
                        return Err(SqrlError::new(
                            "Duplicate rescue code data found!".to_owned(),
                        ));
                    }

                    println!("RescueCode");

                    rescue_code_data = Some(RescueCodeData::from_binary(&mut binary)?)
                }
                DataType::PreviousIdentity => {
                    if previous_identity_data != None {
                        return Err(SqrlError::new(
                            "Duplicate previous identity data found!".to_owned(),
                        ));
                    }

                    println!("UnlockKeys");
                    previous_identity_data = Some(PreviousIdentityData::from_binary(&mut binary)?)
                }
            };
        }

        // We need to make sure we have all of the data we expect
        let user_access_check =
            user_access_data.ok_or(SqrlError::new("No password data found!".to_owned()))?;

        let rescue_code_check =
            rescue_code_data.ok_or(SqrlError::new("No rescue code data found!".to_owned()))?;

        Ok(IdentityInformation {
            user_access_data: user_access_check,
            rescue_code_data: rescue_code_check,
            previous_identity_data: previous_identity_data,
        })
    }

    pub fn to_binary(&self) -> Result<Vec<u8>, SqrlError> {
        // Start by writing the header
        let mut result = Vec::new();
        for c in FILE_HEADER.bytes() {
            result.push(c);
        }

        // Make sure to write out all the sub data
        self.user_access_data.to_binary(&mut result)?;
        self.rescue_code_data.to_binary(&mut result)?;
        match &self.previous_identity_data {
            Some(previous) => previous.to_binary(&mut result)?,
            _ => (),
        };

        Ok(result)
    }
}

impl UserAccessData {
    pub fn new() -> Self {
        UserAccessData {
            aes_gcm_iv: [0; 12],
            scrypt_config: ScryptConfig::new(),
            option_flags: 0,
            hint_length: 0,
            pw_verify_sec: 0,
            idle_timeout_min: 0,
            identity_master_key: IdentityKey::Encrypted([0; 32]),
            identity_lock_key: IdentityKey::Encrypted([0; 32]),
        }
    }
}

impl WritableIdentityData for UserAccessData {
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

        Ok(UserAccessData {
            aes_gcm_iv: aes_gcm_iv,
            scrypt_config: scrypt_config,
            option_flags: option_flags,
            hint_length: hint_length,
            pw_verify_sec: pw_verify_sec,
            idle_timeout_min: idle_timeout_min,
            identity_master_key: identity_master_key,
            identity_lock_key: identity_lock_key,
        })
    }

    fn to_binary_inner(&self, output: &mut Vec<u8>) -> Result<(), SqrlError> {
        for b in (45 as u16).to_le_bytes().iter() {
            output.push(*b);
        }
        for b in self.aes_gcm_iv.iter() {
            output.push(*b);
        }
        self.scrypt_config.to_binary(output)?;
        for b in self.option_flags.to_le_bytes().iter() {
            output.push(*b);
        }
        output.push(self.hint_length);
        output.push(self.pw_verify_sec);
        for b in self.idle_timeout_min.to_le_bytes().iter() {
            output.push(*b);
        }
        self.identity_master_key.to_binary(output)?;
        self.identity_lock_key.to_binary(output)?;

        Ok(())
    }
}

impl RescueCodeData {
    fn new() -> Self {
        RescueCodeData {
            scrypt_config: ScryptConfig::new(),
            identity_unlock_key: IdentityKey::Encrypted([0; 32]),
        }
    }
}

impl WritableIdentityData for RescueCodeData {
    fn get_type(&self) -> DataType {
        DataType::RescueCode
    }

    fn len(&self) -> u16 {
        73
    }

    fn from_binary(binary: &mut VecDeque<u8>) -> Result<Self, SqrlError> {
        Ok(RescueCodeData {
            scrypt_config: ScryptConfig::from_binary(binary)?,
            identity_unlock_key: IdentityKey::from_binary(binary)?,
        })
    }

    fn to_binary_inner(&self, output: &mut Vec<u8>) -> Result<(), SqrlError> {
        self.scrypt_config.to_binary(output)?;
        self.identity_unlock_key.to_binary(output)?;
        Ok(())
    }
}

impl WritableIdentityData for PreviousIdentityData {
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

        Ok(PreviousIdentityData {
            edition: edition,
            previous_identity_unlock_keys: previous_identity_unlock_keys,
        })
    }

    fn to_binary_inner(&self, output: &mut Vec<u8>) -> Result<(), SqrlError> {
        if self.edition == 0 {
            return Ok(());
        }

        for b in self.edition.to_le_bytes() {
            output.push(b);
        }

        for key in &self.previous_identity_unlock_keys {
            key.to_binary(output)?;
        }

        Ok(())
    }
}

impl ScryptConfig {
    fn new() -> Self {
        ScryptConfig {
            random_salt: [0; 16],
            log_n_factor: 0,
            iteration_factor: 0,
        }
    }

    fn from_binary(binary: &mut VecDeque<u8>) -> Result<Self, SqrlError> {
        Ok(ScryptConfig {
            random_salt: binary.next_sub_array(16)?.as_slice().try_into()?,
            log_n_factor: binary
                .pop_front()
                .ok_or(SqrlError::new("Invalid data".to_owned()))?,
            iteration_factor: binary.next_u32()?,
        })
    }

    fn to_binary(&self, output: &mut Vec<u8>) -> Result<(), SqrlError> {
        for b in self.random_salt.iter() {
            output.push(*b);
        }
        output.push(self.log_n_factor);
        for b in self.iteration_factor.to_le_bytes().iter() {
            output.push(*b);
        }
        Ok(())
    }
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
        for b in u16::to_le_bytes(*self as u16).iter() {
            output.push(*b);
        }

        Ok(())
    }
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
                for b in data {
                    output.push(*b);
                }
            }
            IdentityKey::Unencrypted(_) => {
                return Err(SqrlError::new(
                    "Cannot safe unencrypted identity key!".to_owned(),
                ))
            }
        };

        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_can_write_and_read_empty() {
        let file = "/Users/chris/src/test.bin";
        let mut identity = IdentityInformation::new();

        identity.previous_identity_data = Some(PreviousIdentityData {
            edition: 1,
            previous_identity_unlock_keys: vec![IdentityKey::Encrypted([17; 32])],
        });

        identity
            .to_file(file)
            .expect("Failed to write identity information");
        let read_identity =
            IdentityInformation::from_file(file).expect("Did not read successfully");
        assert_eq!(identity, read_identity);

        // remove_file(file).expect("Failed to delete test file");
    }

    // #[test]
    // fn it_can_write_and_read() {
    //     let file = "test.bin";
    //     let mut identity = IdentityInformation::new();
    //     identity.password_data.push(UserAccessData {
    //         aes_gcm_iv:  [0; 12],
    //         scrypt_random_salt: [1; 16],
    //         scrypt_log_n_factor: 0,
    //         scrypt_iteration_factor: [0; 4],
    //         option_flags: 7,
    //         hint_length: 1,
    //         pw_verify_sec: 10,
    //         idle_timeout_min: 22
    //     });

    //     if let Ok(()) = identity.save(file) {
    //         if let Ok(other) = IdentityInformation::load(file) {
    //             assert_eq!(identity, other);
    //         } else {
    //             panic!("Did not get a result back!");
    //         }
    //     } else {
    //         panic!("Failed to save file");
    //     }
    // }
}
