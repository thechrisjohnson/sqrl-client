use crate::{
    client::{scrypt_config::ScryptConfig, SCRYPT_DEFAULT_P, SCRYPT_DEFAULT_R},
    error::SqrlError,
};
use crypto::{
    digest::Digest,
    scrypt::{scrypt, ScryptParams},
    sha2::Sha256,
};
use num_bigint::{BigUint, ToBigUint};
use num_traits::ToPrimitive;
use rand::{prelude::StdRng, RngCore, SeedableRng};
use std::{
    collections::VecDeque,
    io::Read,
    ops::{DivAssign, Rem},
    time::Instant,
};

const RESCUE_CODE_ALPHABET: [char; 10] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];

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

    let mut num = BigUint::from_bytes_le(&rescue_code_data);
    let mut rescue_code = String::new();
    let zero = 0.to_biguint().unwrap();
    while num > zero {
        let remainder = &num % 10u8;
        num.div_assign(10u8);
        let character = RESCUE_CODE_ALPHABET[remainder.to_usize().unwrap()];
        rescue_code.push(character);
    }

    rescue_code
}

pub(crate) fn decode_rescue_code(rescue_code: &str) -> [u8; 32] {
    let mut num = 0u8.to_biguint().unwrap();
    for c in rescue_code.chars() {
        let index = RESCUE_CODE_ALPHABET.iter().position(|&x| x == c).unwrap();
        num += index;
        num *= 10u8;
    }

    // TODO: Should I change this to a Vec?
    [0; 32]
}
