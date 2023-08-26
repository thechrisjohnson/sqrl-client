use crate::{error::SqrlError, protocol::client_request::ClientRequest};
use ed25519_dalek::PublicKey;

// TODO:
pub fn validate_client_request(
    client_request: &ClientRequest,
    expected_key: &PublicKey,
) -> Result<(), SqrlError> {
    // Try to verify the signatures
    expected_key.verify_strict(
        client_request.get_signed_string().as_bytes(),
        &client_request.ids,
    )?;

    Ok(())
}
