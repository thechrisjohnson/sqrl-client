use crate::{error::SqrlError, protocol::client_request::ClientRequest};
use ed25519_dalek::{Verifier, VerifyingKey};

// TODO:
pub fn validate_client_request(
    client_request: &ClientRequest,
    expected_key: &VerifyingKey,
) -> Result<(), SqrlError> {
    // Try to verify the signatures
    expected_key.verify(
        client_request.get_signed_string().as_bytes(),
        &client_request.ids,
    )?;

    Ok(())
}
