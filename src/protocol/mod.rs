//! Code needed for SQRL client and server communication

pub mod client_request;
pub mod protocol_version;
pub mod server_response;

use crate::{
    common::{vec_to_u8_32, vec_to_u8_64},
    error::SqrlError,
};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::HashMap;

/// The current list of supported versions
pub const PROTOCOL_VERSIONS: &str = "1";

pub(crate) fn get_or_error(
    map: &HashMap<String, String>,
    key: &str,
    error_message: &str,
) -> Result<String, SqrlError> {
    match map.get(key) {
        Some(x) => Ok(x.to_owned()),
        None => Err(SqrlError::new(error_message.to_owned())),
    }
}

pub(crate) fn parse_query_data(query: &str) -> Result<HashMap<String, String>, SqrlError> {
    let mut map = HashMap::<String, String>::new();
    for token in query.split('&') {
        if let Some((key, value)) = token.split_once('=') {
            map.insert(key.to_owned(), value.to_owned());
        } else {
            return Err(SqrlError::new("Invalid query data".to_owned()));
        }
    }
    Ok(map)
}

pub(crate) fn decode_public_key(key: &str) -> Result<VerifyingKey, SqrlError> {
    let bytes: [u8; 32];
    match BASE64_URL_SAFE_NO_PAD.decode(key) {
        Ok(x) => bytes = vec_to_u8_32(&x)?,
        Err(_) => {
            return Err(SqrlError::new(format!(
                "Failed to decode base64 encoded public key {}",
                key
            )))
        }
    }

    match VerifyingKey::from_bytes(&bytes) {
        Ok(x) => Ok(x),
        Err(e) => Err(SqrlError::new(format!(
            "Failed to generate public key from {}: {}",
            key, e
        ))),
    }
}

pub(crate) fn decode_signature(key: &str) -> Result<Signature, SqrlError> {
    let bytes: [u8; 64];
    match BASE64_URL_SAFE_NO_PAD.decode(key) {
        Ok(x) => bytes = vec_to_u8_64(&x)?,
        Err(_) => {
            return Err(SqrlError::new(format!(
                "Failed to decode base64 encoded signature {}",
                key
            )))
        }
    }

    Ok(Signature::from_bytes(&bytes))
}

pub(crate) fn parse_newline_data(data: &str) -> Result<HashMap<String, String>, SqrlError> {
    let mut map = HashMap::<String, String>::new();
    for token in data.split('\n') {
        if let Some((key, value)) = token.split_once('=') {
            map.insert(key.to_owned(), value.trim().to_owned());
        } else if !token.is_empty() {
            return Err(SqrlError::new(format!("Invalid newline data {}", token)));
        }
    }

    Ok(map)
}

pub(crate) fn encode_newline_data(map: &HashMap<&str, &str>) -> String {
    let mut result = String::new();
    for (key, value) in map.iter() {
        result += &format!("\n{key}={value}");
    }

    result
}
