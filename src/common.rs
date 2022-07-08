use crate::{
    client::{scrypt_config::ScryptConfig, SCRYPT_DEFAULT_P, SCRYPT_DEFAULT_R},
    error::SqrlError,
};
use crypto::{
    digest::Digest,
    scrypt::{scrypt, ScryptParams},
    sha2::Sha256,
};
use num_bigint::BigUint;
use num_traits::{FromPrimitive, ToPrimitive};
use rand::{prelude::StdRng, RngCore, SeedableRng};
use std::{collections::VecDeque, time::Instant};

const RESCUE_CODE_ALPHABET: [char; 10] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];
const TEXT_IDENTITY_ALPHABET: [char; 56] = [
    '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L',
    'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
];

pub(crate) const EMPTY_NONCE: [u8; 12] = [0; 12];

pub(crate) fn en_hash(input: &[u8]) -> [u8; 32] {
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

pub(crate) fn mut_en_scrypt(
    password: &[u8],
    scrypt_config: &mut ScryptConfig,
    pw_verify_sec: u8,
) -> [u8; 32] {
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

pub(crate) fn en_scrypt(
    password: &[u8],
    scrypt_config: &ScryptConfig,
) -> Result<[u8; 32], SqrlError> {
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
            return Err(SqrlError::new(
                "ScryptConfig iteration factor not set".to_string(),
            ))
        }
    }

    Ok(output)
}

pub(crate) fn xor(output: &mut [u8], other: &[u8]) {
    for i in 0..output.len() {
        output[i] = output[i] ^ other[i];
    }
}

pub(crate) fn convert_vec(mut input: Vec<u8>) -> VecDeque<u8> {
    let mut new_vec = VecDeque::new();
    loop {
        match input.pop() {
            Some(x) => new_vec.push_front(x),
            None => break,
        };
    }

    new_vec
}

pub(crate) fn generate_rescue_code() -> String {
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

pub(crate) fn decode_rescue_code(rescue_code: &str) -> String {
    let mut result = String::new();
    for c in rescue_code.chars() {
        if c == '-' {
            continue;
        }
        result.push(c);
    }

    result
}

pub(crate) fn validate_textual_identity(textual_identity: &str) -> Result<(), SqrlError> {
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

pub(crate) fn decode_textual_identity(textual_identity: &str) -> Result<VecDeque<u8>, SqrlError> {
    let mut data = BigUint::from_u8(0).unwrap();
    for line in textual_identity.lines().rev() {
        let trimmed_line = line.trim();
        // Go through the line from the back to the front (after removing the last character)
        for c in trimmed_line[..trimmed_line.len() - 1].chars().rev() {
            if c == ' ' {
                continue;
            }

            if let Some(index) = find_char_in_array(&TEXT_IDENTITY_ALPHABET, c) {
                data *= 56u32;
                data += index;
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
