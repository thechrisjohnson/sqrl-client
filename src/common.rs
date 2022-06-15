use crypto::{
    digest::Digest,
    scrypt::{scrypt, ScryptParams},
    sha2::Sha256,
};
use std::{collections::VecDeque, time::Instant};

use crate::client::{scrypt_config::ScryptConfig, SCRYPT_DEFAULT_P, SCRYPT_DEFAULT_R};

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

pub(crate) fn en_scrypt(
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
