use super::{readable_vector::ReadableVector, SCRYPT_DEFAULT_LOG_N};
use crate::error::SqrlError;
use byteorder::{LittleEndian, WriteBytesExt};
use rand::{prelude::StdRng, RngCore, SeedableRng};
use std::{collections::VecDeque, convert::TryInto, io::Write};

#[derive(Debug, PartialEq)]
pub struct ScryptConfig {
    pub random_salt: [u8; 16],
    pub log_n_factor: u8,
    pub iteration_factor: Option<u32>,
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
