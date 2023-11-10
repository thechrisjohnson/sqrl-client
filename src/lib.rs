//! An implementation of the SQRL protocol in rust.
//!
//! <https://grc.com/sqrl>

#![deny(missing_docs)]
pub mod client;
pub mod common;
pub mod error;
pub mod protocol;
pub mod server;

extern crate aes_gcm;
extern crate base64;
extern crate byteorder;
extern crate ed25519_dalek;
extern crate hmac;
extern crate num_bigint;
extern crate num_traits;
extern crate rand;
extern crate scrypt;
extern crate sha2;
extern crate url;
extern crate x25519_dalek;
