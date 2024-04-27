//! Common code used by both SQRL clients and servers

use crate::error::SqrlError;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey;

/// THe keys needed to unlock a SQRL identity
pub struct IdentityUnlockKeys {
    /// The server unlock key (aka the public portion of a Diffie-Helman key)
    pub server_unlock_key: PublicKey,
    /// The verify unlock key (aka the public portion of a signing keypair)
    pub verify_unlock_key: VerifyingKey,
}

impl IdentityUnlockKeys {
    /// Create an identity unlock key pair from existing keys
    pub fn new(server_unlock_key: PublicKey, verify_unlock_key: VerifyingKey) -> Self {
        IdentityUnlockKeys {
            server_unlock_key,
            verify_unlock_key,
        }
    }
}

pub(crate) fn slice_to_u8_32(slice: &[u8]) -> Result<[u8; 32], SqrlError> {
    let mut result = [0; 32];
    if slice.len() != 32 {
        return Err(SqrlError::new(format!(
            "Error converting vec<u8> to [u8; 32]: Expected 32 bytes, but found {}",
            slice.len()
        )));
    }

    result[..32].copy_from_slice(&slice[..32]);
    Ok(result)
}

pub(crate) fn en_hash(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let mut output: [u8; 32] = [0; 32];
    for _ in 0..16 {
        let hash_result: [u8; 32] = hasher.finalize().into();
        hasher = Sha256::new();
        hasher.update(hash_result);
        xor(&mut output, &hash_result);
    }

    output
}

pub(crate) fn xor(output: &mut [u8], other: &[u8]) {
    for i in 0..output.len() {
        output[i] ^= other[i];
    }
}
