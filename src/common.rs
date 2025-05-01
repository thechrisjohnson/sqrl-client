//! Common code used by both SQRL clients and servers

use ed25519_dalek::VerifyingKey;
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
