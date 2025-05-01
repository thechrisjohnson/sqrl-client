//! A SQRL client SDK developed in rust.
//!
//! <https://grc.com/sqrl>

#![deny(missing_docs)]
pub mod common;
pub mod data;
pub mod error;

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
extern crate sqrl_protocol;
extern crate url;
extern crate x25519_dalek;

use crate::error::SqrlError;
use ed25519_dalek::SigningKey;
use reqwest::Client;
use sqrl_protocol::{
    client_request::{ClientCommand, ClientParameters, ClientRequest, ServerData},
    server_response::{ServerResponse, TIFValue},
    SqrlUrl,
};
use std::{collections::{HashMap, VecDeque}, result};

/// A Result type to simplify return of functions
pub type Result<T> = result::Result<T, SqrlError>;

pub(crate) type AesVerificationData = [u8; 16];
pub(crate) type IdentityKey = [u8; 32];

/// An http client to temporarily use for authenticating the calls
pub struct SqrlClient<DataProvider>
where
    DataProvider: SqrlDataProvider,
{
    sqrl_data_provider: DataProvider,
    http_client: Client,
    previous_sqrl_urls: HashMap<SqrlUrl, ServerData>,
}

impl<DataProvider> SqrlClient<DataProvider>
where
    DataProvider: SqrlDataProvider,
{
    /// Create a new http client with the passed in SqrlData
    pub fn new(sqrl_data_provider: DataProvider) -> Self {
        Self {
            sqrl_data_provider,
            http_client: Client::new(),
            previous_sqrl_urls: HashMap::new(),
        }
    }

    /// Authenticate against a specific url
    pub async fn authenticate(
        &mut self,
        password: &str,
        url: &str,
        alternate_identity: Option<&str>,
    ) -> Result<()> {
        self.sqrl_data_provider.verify_password(password)?;
        let sqrl_url = SqrlUrl::parse(url)?;

        // Go query and figure out which identity we know for this site
        let known_signing_key = self.get_known_signing_key(password, url, alternate_identity).await?;

        let ident_client_params =
            ClientParameters::new(ClientCommand::Ident, known_signing_key.verifying_key());
        let query_server_data = ServerData::Url {
            url: sqrl_url.clone(),
        };

        let previous_signing_keys = self.sqrl_data_provider.get_previous_signing_keys(password, url, alternate_identity)?;

        let client_request = ClientRequest::new(
            query_client_params,
            query_server_data,
            &mut current_signing_key,
            None,
        );

        Ok(())
    }

    pub async fn get_known_signing_key(
        &mut self,
        password: &str,
        url: &str,
        alternate_identity: Option<&str>,
    ) -> Result<SigningKey> {
        self.sqrl_data_provider.verify_password(password)?;
        let sqrl_url = SqrlUrl::parse(url)?;

        // Start with the current identity, and see if we match
        let mut current_signing_key =
            self.sqrl_data_provider
                .get_signing_key(password, url, alternate_identity)?;
        let query_client_params =
            ClientParameters::new(ClientCommand::Query, current_signing_key.verifying_key());
        let query_server_data = ServerData::Url {
            url: sqrl_url.clone(),
        };

        let previous_signing_keys = self.sqrl_data_provider.get_previous_signing_keys(password, url, alternate_identity)?;

        let client_request = ClientRequest::new(
            query_client_params,
            query_server_data,
            &mut current_signing_key,
            None,
        );

        // First look and see if we can find a 

        // Push the request up
        let server_response = self.send_request(&sqrl_url, &client_request).await?;

        // If it works, we want to ident now
        if server_response
            .transaction_indication_flags
            .contains(&TIFValue::CurrentIdMatch)
        {
        } else if server_response
            .transaction_indication_flags
            .contains(&TIFValue::PreviousIdMatch)
        {
        }
    }


    async fn send_request(
        &mut self,
        sqrl_url: &SqrlUrl,
        client_request: &ClientRequest,
    ) -> Result<ServerResponse> {
        let request_url = sqrl_url.get_request_url()?;
        match self
            .http_client
            .post(&request_url)
            .body(client_request.to_query_string())
            .send()
            .await
        {
            Ok(res) => match res.text().await {
                Ok(text) => 
                {
                    let response = ServerResponse::from_base64(&text)?;
                    Ok()
                }

                Err(error) => {
                    return Err(SqrlError::new(format!(
                        "Failed to read POST response data for SQRL url {}: {}",
                        sqrl_url, error
                    )));
                }
            },
            Err(error) => {
                return Err(SqrlError::new(format!(
                    "Failed to POST data to SQRL url {}: {}",
                    sqrl_url, error
                )));
            }
        }
    }
}

/// A trait for implementing a SqrlDataProvider
pub trait SqrlDataProvider {
    /// Get a secret index key
    fn get_secret_index_key(
        &self,
        password: &str,
        url: &str,
        alternate_identity: Option<&str>,
        secret_index: &str,
    ) -> Result<String>;

    /// Get a signing key for the url and alternate_identity combination
    fn get_signing_key(
        &self,
        password: &str,
        url: &str,
        alternate_identity: Option<&str>,
    ) -> Result<SigningKey>;

    /// Get the list of previous identity signing keys
    fn get_previous_signing_keys(
        &self,
        password: &str,
        url: &str,
        alternate_identity: Option<&str>,
    ) -> Result<Option<VecDeque<SigningKey>>>;

    /// Verify that the password can decrypt the stored data
    fn verify_password(&self, password: &str) -> Result<()>;
}
