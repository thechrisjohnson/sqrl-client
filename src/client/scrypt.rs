use super::{readable_vector::ReadableVector, xor};
use crate::error::SqrlError;
use byteorder::{LittleEndian, WriteBytesExt};
use rand::{prelude::StdRng, RngCore, SeedableRng};
use scrypt::{scrypt, Params};
use std::{collections::VecDeque, convert::TryInto, io::Write, time::Instant};

pub(crate) const SCRYPT_DEFAULT_LOG_N: u8 = 9;
pub(crate) const SCRYPT_DEFAULT_R: u32 = 256;
pub(crate) const SCRYPT_DEFAULT_P: u32 = 1;

#[derive(Debug, PartialEq)]
pub(crate) struct ScryptConfig {
    pub random_salt: [u8; 16],
    pub log_n_factor: u8,
    pub iteration_factor: Option<u32>,
}

impl ScryptConfig {
    pub(crate) fn new() -> Self {
        let mut random = StdRng::from_entropy();
        let mut salt: [u8; 16] = [0; 16];
        random.fill_bytes(&mut salt);

        ScryptConfig {
            random_salt: salt,
            log_n_factor: SCRYPT_DEFAULT_LOG_N,
            iteration_factor: None,
        }
    }

    pub(crate) fn from_binary(binary: &mut VecDeque<u8>) -> Result<Self, SqrlError> {
        Ok(ScryptConfig {
            random_salt: binary.next_sub_array(16)?.as_slice().try_into()?,
            log_n_factor: binary
                .pop_front()
                .ok_or(SqrlError::new("Invalid data".to_owned()))?,
            iteration_factor: Some(binary.next_u32()?),
        })
    }

    pub(crate) fn to_binary(&self, output: &mut Vec<u8>) -> Result<(), SqrlError> {
        output.write_all(&self.random_salt)?;
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

pub(crate) fn mut_en_scrypt(
    password: &[u8],
    scrypt_config: &mut ScryptConfig,
    pw_verify_sec: u8,
) -> Result<[u8; 32], SqrlError> {
    let mut output: [u8; 32] = [0; 32];
    let mut input: [u8; 32] = [0; 32];
    let mut temp: [u8; 32] = [0; 32];

    let params = Params::new(
        scrypt_config.log_n_factor,
        SCRYPT_DEFAULT_R,
        SCRYPT_DEFAULT_P,
        32,
    )?;

    match scrypt_config.iteration_factor {
        Some(factor) => {
            for i in 0..factor {
                if i == 0 {
                    scrypt(password, &scrypt_config.random_salt, &params, &mut temp)?;
                } else {
                    scrypt(password, &input, &params, &mut temp)?;
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
                    scrypt(password, &scrypt_config.random_salt, &params, &mut temp)?;
                } else {
                    scrypt(password, &input, &params, &mut temp)?;
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

    Ok(output)
}

pub(crate) fn en_scrypt(
    password: &[u8],
    scrypt_config: &ScryptConfig,
) -> Result<[u8; 32], SqrlError> {
    let mut output: [u8; 32] = [0; 32];
    let mut input: [u8; 32] = [0; 32];
    let mut temp: [u8; 32] = [0; 32];

    let params = Params::new(
        scrypt_config.log_n_factor,
        SCRYPT_DEFAULT_R,
        SCRYPT_DEFAULT_P,
        32,
    )?;

    match scrypt_config.iteration_factor {
        Some(factor) => {
            for i in 0..factor {
                if i == 0 {
                    scrypt(password, &scrypt_config.random_salt, &params, &mut temp)?;
                } else {
                    scrypt(password, &input, &params, &mut temp)?;
                }

                xor(&mut output, &temp);
                input = temp;
            }
        }
        None => {
            return Err(SqrlError::new(
                "ScryptConfig iteration factor not set".to_string(),
            ))
        }
    }

    Ok(output)
}
