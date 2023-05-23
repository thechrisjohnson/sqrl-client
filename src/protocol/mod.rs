pub mod client_request;
pub mod protocol_version;
pub mod server_response;

use crate::error::SqrlError;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{PublicKey, Signature};
use std::collections::HashMap;

// The list of supported versions
pub const PROTOCOL_VERSIONS: &str = "1";

// Constants for the Server TIF
pub const SERVER_TIF_CURRENT_ID_MATCH: u16 = 0x1;
pub const SERVER_TIF_PREV_ID_MATCH: u16 = 0x2;
pub const SERVER_TIF_IPS_MATCH: u16 = 0x4;
pub const SERVER_TIF_SQRL_DISABLED: u16 = 0x8;
pub const SERVER_TIF_FUNCTION_NOT_SUPPORTED: u16 = 0x10;
pub const SERVER_TIF_TRANSIENT_ERROR: u16 = 0x20;
pub const SERVER_TIF_COMMAND_FAILED: u16 = 0x40;
pub const SERVER_TIF_CLIENT_FAILURE: u16 = 0x80;
pub const SERVER_TIF_BAD_ID: u16 = 0x100;
pub const SERVER_TIF_IDENTITY_SUPERSEDED: u16 = 0x200;

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
        }
    }
    Ok(map)
}

pub(crate) fn decode_public_key(key: &str) -> Result<PublicKey, SqrlError> {
    let bytes: Vec<u8>;
    match BASE64_URL_SAFE_NO_PAD.decode(key) {
        Ok(x) => bytes = x,
        Err(_) => {
            return Err(SqrlError::new(format!(
                "Failed to decode base64 encoded public key {}",
                key
            )))
        }
    }

    match PublicKey::from_bytes(&bytes) {
        Ok(x) => Ok(x),
        Err(e) => Err(SqrlError::new(format!(
            "Failed to generate public key from {}: {}",
            key, e
        ))),
    }
}

pub(crate) fn decode_signature(key: &str) -> Result<Signature, SqrlError> {
    let bytes: Vec<u8>;
    match BASE64_URL_SAFE_NO_PAD.decode(key) {
        Ok(x) => bytes = x,
        Err(_) => {
            return Err(SqrlError::new(format!(
                "Failed to decode base64 encoded signature {}",
                key
            )))
        }
    }

    match Signature::from_bytes(&bytes) {
        Ok(x) => Ok(x),
        Err(e) => Err(SqrlError::new(format!(
            "Failed to generate signature from {}: {}",
            key, e
        ))),
    }
}
