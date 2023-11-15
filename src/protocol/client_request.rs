//! All of the code needed for sending client requests to a SQRL server

use super::{
    decode_public_key, decode_signature, get_or_error, parse_newline_data, parse_query_data,
    protocol_version::ProtocolVersion,
    server_response::{ServerResponse, TIFValue},
    PROTOCOL_VERSIONS,
};
use crate::{common::SqrlUrl, error::SqrlError, protocol::encode_newline_data};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use std::{collections::HashMap, convert::TryFrom, fmt, str::FromStr};

// Keys used for encoding ClientRequest
const CLIENT_PARAMETERS_KEY: &str = "client";
const SERVER_DATA_KEY: &str = "server";
const IDENTITY_SIGNATURE_KEY: &str = "ids";
const PREVIOUS_IDENTITY_SIGNATURE_KEY: &str = "pids";
const UNLOCK_REQUEST_SIGNATURE_KEY: &str = "urs";

// Keys used for encoding ClientParameters
const PROTOCOL_VERSION_KEY: &str = "ver";
const COMMAND_KEY: &str = "cmd";
const IDENTITY_KEY_KEY: &str = "idk";
const OPTIONS_KEY: &str = "opt";
const BUTTON_KEY: &str = "btn";
const PREVIOUS_IDENTITY_KEY_KEY: &str = "pidk";
const INDEX_SECRET_KEY: &str = "ins";
const PREVIOUS_INDEX_SECRET_KEY: &str = "pins";
const SERVER_UNLOCK_KEY_KEY: &str = "suk";
const VERIFY_UNLOCK_KEY_KEY: &str = "vuk";

/// A client request to a server
pub struct ClientRequest {
    /// The client parameters
    pub client_params: ClientParameters,
    /// The previous server response, or the sqrl url if the first request
    pub server_data: ServerData,
    /// The signature of this request (ids)
    pub identity_signature: Signature,
    /// The signature of this request using a previous identity (pids)
    pub previous_identity_signature: Option<Signature>,
    /// The unlock request signature for an identity unlock (urs)
    pub unlock_request_signature: Option<String>,
}

impl ClientRequest {
    /// Generate a new client request
    pub fn new(
        client_params: ClientParameters,
        server_data: ServerData,
        identity_signature: Signature,
    ) -> Self {
        ClientRequest {
            client_params,
            server_data,
            identity_signature,
            previous_identity_signature: None,
            unlock_request_signature: None,
        }
    }

    /// Parse a client request from a query string
    pub fn from_query_string(query_string: &str) -> Result<Self, SqrlError> {
        let map = parse_query_data(query_string)?;
        let client_parameters_string = get_or_error(
            &map,
            CLIENT_PARAMETERS_KEY,
            "Invalid client request: No client parameters",
        )?;
        let client_params = ClientParameters::from_base64(&client_parameters_string)?;
        let server_string = get_or_error(
            &map,
            SERVER_DATA_KEY,
            "Invalid client request: No server value",
        )?;
        let server_data = ServerData::from_base64(&server_string)?;
        let ids_string = get_or_error(
            &map,
            IDENTITY_SIGNATURE_KEY,
            "Invalid client request: No ids value",
        )?;
        let identity_signature = decode_signature(&ids_string)?;
        let previous_identity_signature = match map.get(PREVIOUS_IDENTITY_SIGNATURE_KEY) {
            Some(x) => Some(decode_signature(x)?),
            None => None,
        };

        let unlock_request_signature = map.get(UNLOCK_REQUEST_SIGNATURE_KEY).map(|x| x.to_string());

        Ok(ClientRequest {
            client_params,
            server_data,
            identity_signature,
            previous_identity_signature,
            unlock_request_signature,
        })
    }

    /// Convert a client request to the query string to add in the request
    pub fn to_query_string(&self) -> String {
        let mut result = format!(
            "{}={}",
            CLIENT_PARAMETERS_KEY,
            self.client_params.to_base64()
        );
        result += &format!("&{}={}", SERVER_DATA_KEY, self.server_data);
        result += &format!(
            "&{}={}",
            IDENTITY_SIGNATURE_KEY,
            BASE64_URL_SAFE_NO_PAD.encode(self.identity_signature.to_bytes())
        );

        if let Some(pids) = &self.previous_identity_signature {
            result += &format!(
                "&{}={}",
                PREVIOUS_IDENTITY_SIGNATURE_KEY,
                BASE64_URL_SAFE_NO_PAD.encode(pids.to_bytes())
            );
        }
        if let Some(urs) = &self.unlock_request_signature {
            result += &format!(
                "&{}={}",
                UNLOCK_REQUEST_SIGNATURE_KEY,
                BASE64_URL_SAFE_NO_PAD.encode(urs)
            );
        }

        result
    }

    /// Get the portion of the client request that is signed
    pub fn get_signed_string(&self) -> String {
        format!(
            "{}{}",
            self.client_params.to_base64(),
            &self.server_data.to_base64()
        )
    }

    /// Validate that the values input in the client request are valid
    pub fn validate(&self) -> Result<(), SqrlError> {
        self.client_params.validate()?;

        // If the pik is set the pids must also (and vice-versa)
        if self.previous_identity_signature.is_some()
            && self.client_params.previous_identity_key.is_none()
        {
            return Err(SqrlError::new(
                "Previous identity signature set, but no previous identity key set".to_owned(),
            ));
        } else if self.previous_identity_signature.is_none()
            && self.client_params.previous_identity_key.is_some()
        {
            return Err(SqrlError::new(
                "Previous identity key set, but no previous identity signature".to_owned(),
            ));
        }

        // If the enable or remove commands are set, the unlock request signature must also be set
        if (self.client_params.command == ClientCommand::Enable
            || self.client_params.command == ClientCommand::Remove)
            && self.unlock_request_signature.is_none()
        {
            return Err(SqrlError::new(
                "When attempting to enable identity, unlock request signature (urs) must be set"
                    .to_owned(),
            ));
        }

        match &self.server_data {
            ServerData::ServerResponse {
                server_response, ..
            } if !server_response
                .transaction_indication_flags
                .contains(&TIFValue::CurrentIdMatch) =>
            {
                if self.client_params.server_unlock_key.is_none() {
                    return Err(SqrlError::new("If attempting to re-enable identity (cmd=enable), must include server unlock key (suk)".to_owned()));
                } else if self.client_params.verify_unlock_key.is_none() {
                    return Err(SqrlError::new("If attempting to re-enable identity (cmd=enable), must include verify unlock key (vuk)".to_owned()));
                }
            }
            _ => (),
        }

        Ok(())
    }
}

/// Parameters used for sending requests to the client
#[derive(Debug, PartialEq)]
pub struct ClientParameters {
    /// The supported protocol versions of the client (ver)
    pub protocol_version: ProtocolVersion,
    /// The client command requested to be performed (cmd)
    pub command: ClientCommand,
    /// The client identity used to sign the request (idk)
    pub identity_key: VerifyingKey,
    /// Optional options requested by the client (opt)
    pub options: Option<Vec<ClientOption>>,
    /// The button pressed in response to a server query (btn)
    pub button: Option<u8>,
    /// A previous client identity used to sign the request (pidk)
    pub previous_identity_key: Option<VerifyingKey>,
    /// The current identity indexed secret in response to a server query (ins)
    pub index_secret: Option<String>,
    /// The previous identity indexed secret in response to a server query (pins)
    pub previous_index_secret: Option<String>,
    /// The server unlock key used for unlocking an identity (suk)
    pub server_unlock_key: Option<String>,
    /// The verify unlock key used for unlocking an identity (vuk)
    pub verify_unlock_key: Option<String>,
}

impl ClientParameters {
    /// Create a new client parameter using the command and verifying key
    pub fn new(command: ClientCommand, identity_key: VerifyingKey) -> ClientParameters {
        ClientParameters {
            protocol_version: ProtocolVersion::new(PROTOCOL_VERSIONS).unwrap(),
            command,
            identity_key,
            options: None,
            button: None,
            previous_identity_key: None,
            index_secret: None,
            previous_index_secret: None,
            server_unlock_key: None,
            verify_unlock_key: None,
        }
    }

    /// Parse a base64-encoded client parameter value
    pub fn from_base64(base64_string: &str) -> Result<Self, SqrlError> {
        let query_string = String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(base64_string)?)?;
        Self::from_str(&query_string)
    }

    /// base64-encode this client parameter object
    pub fn to_base64(&self) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(self.to_string().as_bytes())
    }

    /// Verify the client request is valid
    pub fn validate(&self) -> Result<(), SqrlError> {
        Ok(())
    }
}

impl fmt::Display for ClientParameters {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut map = HashMap::<&str, &str>::new();
        let protocol = self.protocol_version.to_string();
        map.insert(PROTOCOL_VERSION_KEY, &protocol);
        let command = self.command.to_string();
        map.insert(COMMAND_KEY, &command);

        let identity_key = BASE64_URL_SAFE_NO_PAD.encode(self.identity_key.as_bytes());
        map.insert(IDENTITY_KEY_KEY, &identity_key);

        let options_string: String;
        if let Some(options) = &self.options {
            options_string = ClientOption::to_option_string(options);
            map.insert(OPTIONS_KEY, &options_string);
        }
        let button_string: String;
        if let Some(button) = &self.button {
            button_string = button.to_string();
            map.insert(BUTTON_KEY, &button_string);
        }
        let previous_identity_key_string: String;
        if let Some(previous_identity_key) = &self.previous_identity_key {
            previous_identity_key_string =
                BASE64_URL_SAFE_NO_PAD.encode(previous_identity_key.as_bytes());
            map.insert(PREVIOUS_IDENTITY_KEY_KEY, &previous_identity_key_string);
        }
        if let Some(index_secret) = &self.index_secret {
            map.insert(INDEX_SECRET_KEY, index_secret);
        }
        if let Some(previous_index_secret) = &self.previous_index_secret {
            map.insert(PREVIOUS_INDEX_SECRET_KEY, previous_index_secret);
        }
        if let Some(server_unlock_key) = &self.server_unlock_key {
            map.insert(SERVER_UNLOCK_KEY_KEY, server_unlock_key);
        }
        if let Some(verify_unlock_key) = &self.verify_unlock_key {
            map.insert(VERIFY_UNLOCK_KEY_KEY, verify_unlock_key);
        }

        write!(f, "{}", &encode_newline_data(&map))
    }
}

impl FromStr for ClientParameters {
    type Err = SqrlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let map = parse_newline_data(s)?;
        // Validate the protocol version is supported
        let ver_string = get_or_error(
            &map,
            PROTOCOL_VERSION_KEY,
            "Invalid client request: No version number",
        )?;
        let protocol_version = ProtocolVersion::new(&ver_string)?;

        let cmd_string = get_or_error(&map, COMMAND_KEY, "Invalid client request: No cmd value")?;
        let command = ClientCommand::from(cmd_string);
        let idk_string = get_or_error(
            &map,
            IDENTITY_KEY_KEY,
            "Invalid client request: No idk value",
        )?;
        let identity_key = decode_public_key(&idk_string)?;

        let button = match map.get(BUTTON_KEY) {
            Some(s) => match s.parse::<u8>() {
                Ok(b) => Some(b),
                Err(_) => {
                    return Err(SqrlError::new(format!(
                        "Invalid client request: Unable to parse btn {}",
                        s
                    )))
                }
            },
            None => None,
        };

        let previous_identity_key = match map.get(PREVIOUS_IDENTITY_KEY_KEY) {
            Some(x) => Some(decode_public_key(x)?),
            None => None,
        };

        let options = match map.get(OPTIONS_KEY) {
            Some(x) => Some(ClientOption::from_option_string(x)?),
            None => None,
        };

        let index_secret = map.get(INDEX_SECRET_KEY).map(|x| x.to_string());
        let previous_index_secret = map.get(PREVIOUS_INDEX_SECRET_KEY).map(|x| x.to_string());
        let server_unlock_key = map.get(SERVER_UNLOCK_KEY_KEY).map(|x| x.to_string());
        let verify_unlock_key = map.get(VERIFY_UNLOCK_KEY_KEY).map(|x| x.to_string());

        Ok(ClientParameters {
            protocol_version,
            command,
            identity_key,
            options,
            button,
            previous_identity_key,
            index_secret,
            previous_index_secret,
            server_unlock_key,
            verify_unlock_key,
        })
    }
}

/// The commands a client can request of the server
#[derive(Debug, PartialEq)]
pub enum ClientCommand {
    /// A query to determine which client identity the server knows
    Query,
    /// A request to verify and accept the client's identity assertion
    Ident,
    /// A request to disable the client identity on the server
    Disable,
    /// A request to re-enable the client identity on the server
    Enable,
    /// A request to remove the client identity from the server
    Remove,
}

impl fmt::Display for ClientCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ClientCommand::Query => write!(f, "query"),
            ClientCommand::Ident => write!(f, "ident"),
            ClientCommand::Disable => write!(f, "disable"),
            ClientCommand::Enable => write!(f, "enable"),
            ClientCommand::Remove => write!(f, "remove"),
        }
    }
}

impl From<String> for ClientCommand {
    fn from(value: String) -> Self {
        match value.as_str() {
            "query" => ClientCommand::Query,
            "ident" => ClientCommand::Ident,
            "disable" => ClientCommand::Disable,
            "enable" => ClientCommand::Enable,
            "remove" => ClientCommand::Remove,
            _ => panic!("Not this!"),
        }
    }
}

/// Request options included in a client request
#[derive(Debug, PartialEq)]
pub enum ClientOption {
    /// A request to the server to not restrict client requests from only the
    /// ip address that initially queried the server
    NoIPTest,
    /// A request to the server to only allow SQRL auth for authentication
    SQRLOnly,
    /// A request to the server to not allow side-channel auth change requests
    /// e.g. email, backup code, etc.
    Hardlock,
    /// An option to inform the server that the SQRL client has a secure method
    /// of sending data back to the client's web browser
    ClientProvidedSession,
    /// A request to the server to return the client identity's server unlock
    /// key
    ServerUnlockKey,
}

impl ClientOption {
    fn from_option_string(opt: &str) -> Result<Vec<Self>, SqrlError> {
        let mut options: Vec<ClientOption> = Vec::new();
        for option in opt.split('~') {
            options.push(ClientOption::try_from(option)?)
        }

        Ok(options)
    }

    fn to_option_string(opt: &Vec<Self>) -> String {
        let mut options = "".to_owned();
        for option in opt {
            if options.is_empty() {
                options += &format!("{}", option);
            } else {
                options += &format!("~{}", option);
            }
        }

        options
    }
}

impl fmt::Display for ClientOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientOption::NoIPTest => write!(f, "noiptest"),
            ClientOption::SQRLOnly => write!(f, "sqrlonly"),
            ClientOption::Hardlock => write!(f, "hardlock"),
            ClientOption::ClientProvidedSession => write!(f, "cps"),
            ClientOption::ServerUnlockKey => write!(f, "suk"),
        }
    }
}

impl TryFrom<&str> for ClientOption {
    type Error = SqrlError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "noiptest" => Ok(ClientOption::NoIPTest),
            "sqrlonly" => Ok(ClientOption::SQRLOnly),
            "hardlock" => Ok(ClientOption::Hardlock),
            "cps" => Ok(ClientOption::ClientProvidedSession),
            "suk" => Ok(ClientOption::ServerUnlockKey),
            _ => Err(SqrlError::new(format!("Invalid client option {}", value))),
        }
    }
}

/// The previous server response to add to the next client request, or the
/// SQRL url for the first request
#[derive(Debug, PartialEq)]
pub enum ServerData {
    /// During the first request sent to a server, the server data is set as
    /// the first SQRL protocol url used to auth against the server
    Url {
        /// The first SQRL url called
        url: SqrlUrl,
    },
    /// Any request after the first one includes the server response to the
    /// previous client request
    ServerResponse {
        /// The parsed previous response to the client's request
        server_response: ServerResponse,
        /// The original previous response to the client's request
        original_response: String,
    },
}

impl ServerData {
    /// Parse the base64-encoded server data
    pub fn from_base64(base64_string: &str) -> Result<Self, SqrlError> {
        let data = String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(base64_string)?)?;
        if let Ok(parsed) = SqrlUrl::parse(&data) {
            return Ok(ServerData::Url { url: parsed });
        }

        match ServerResponse::from_str(&data) {
            Ok(server_response) => Ok(ServerData::ServerResponse {
                server_response,
                original_response: base64_string.to_owned(),
            }),
            Err(_) => Err(SqrlError::new(format!("Invalid server data: {}", &data))),
        }
    }

    /// base64-encode the server data
    pub fn to_base64(&self) -> String {
        match self {
            ServerData::Url { url } => BASE64_URL_SAFE_NO_PAD.encode(url.to_string().as_bytes()),
            ServerData::ServerResponse {
                original_response, ..
            } => original_response.clone(),
        }
    }
}

impl fmt::Display for ServerData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ServerData::Url { url } => {
                write!(f, "{}", url)
            }
            ServerData::ServerResponse {
                original_response, ..
            } => {
                write!(f, "{}", &original_response)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CLIENT_REQUEST: &str = "client=dmVyPTENCmNtZD1xdWVyeQ0KaWRrPWlnZ2N1X2UtdFdxM3NvZ2FhMmFBRENzeFJaRUQ5b245SDcxNlRBeVBSMHcNCnBpZGs9RTZRczJnWDdXLVB3aTlZM0tBbWJrdVlqTFNXWEN0S3lCY3ltV2xvSEF1bw0Kb3B0PWNwc35zdWsNCg&server=c3FybDovL3Nxcmwuc3RldmUuY29tL2NsaS5zcXJsP3g9MSZudXQ9ZTd3ZTZ3Q3RvU3hsJmNhbj1hSFIwY0hNNkx5OXNiMk5oYkdodmMzUXZaR1Z0Ynk1MFpYTjA&ids=hcXWTPx3EgP9R_AjtoCIrie_YgZxVD72nd5_pjMOnhUEYmhdjLUYs3jjcJT_GQuzNKXyAwY1ns1R6QJn1YKzCA";
    const TEST_CLIENT_PARAMS: &str = "dmVyPTENCmNtZD1xdWVyeQ0KaWRrPWlnZ2N1X2UtdFdxM3NvZ2FhMmFBRENzeFJaRUQ5b245SDcxNlRBeVBSMHcNCnBpZGs9RTZRczJnWDdXLVB3aTlZM0tBbWJrdVlqTFNXWEN0S3lCY3ltV2xvSEF1bw0Kb3B0PWNwc35zdWsNCg";
    const TEST_SERVER_RESPONSE: &str = "dmVyPTENCm51dD0xV005bGZGMVNULXoNCnRpZj01DQpxcnk9L2NsaS5zcXJsP251dD0xV005bGZGMVNULXoNCnN1az1CTUZEbTdiUGxzUW9qdUpzb0RUdmxTMU1jbndnU2N2a3RGODR2TGpzY0drDQo";
    const TEST_SQRL_URL: &str = "c3FybDovL3Rlc3R1cmwuY29t";
    const TEST_INVALID_URL: &str = "aHR0cHM6Ly9nb29nbGUuY29t";

    #[test]
    fn client_request_validate_example() {
        ClientRequest::from_query_string(TEST_CLIENT_REQUEST).unwrap();
    }

    #[test]
    fn client_parameters_encode_decode() {
        let mut params = ClientParameters::new(
            ClientCommand::Query,
            decode_public_key("iggcu_e-tWq3sogaa2aADCsxRZED9on9H716TAyPR0w").unwrap(),
        );
        params.previous_identity_key =
            Some(decode_public_key("E6Qs2gX7W-Pwi9Y3KAmbkuYjLSWXCtKyBcymWloHAuo").unwrap());
        params.options = Some(vec![
            ClientOption::ClientProvidedSession,
            ClientOption::ServerUnlockKey,
        ]);

        let decoded = ClientParameters::from_base64(&params.to_base64()).unwrap();
        assert_eq!(params, decoded);
    }

    #[test]
    fn client_parameters_decode_example() {
        let client_parameters = ClientParameters::from_base64(TEST_CLIENT_PARAMS).unwrap();

        assert_eq!(client_parameters.protocol_version.to_string(), "1");
        assert_eq!(client_parameters.command, ClientCommand::Query);
        assert_eq!(
            BASE64_URL_SAFE_NO_PAD.encode(client_parameters.identity_key.as_bytes()),
            "iggcu_e-tWq3sogaa2aADCsxRZED9on9H716TAyPR0w"
        );
        match &client_parameters.previous_identity_key {
            Some(s) => assert_eq!(
                BASE64_URL_SAFE_NO_PAD.encode(s.as_bytes()),
                "E6Qs2gX7W-Pwi9Y3KAmbkuYjLSWXCtKyBcymWloHAuo"
            ),
            None => panic!(),
        }
        match &client_parameters.options {
            Some(s) => assert_eq!(
                s,
                &vec![
                    ClientOption::ClientProvidedSession,
                    ClientOption::ServerUnlockKey
                ]
            ),
            None => panic!(),
        }
    }

    #[test]
    fn server_data_parse_sqrl_url() {
        let data = ServerData::from_base64(TEST_SQRL_URL).unwrap();
        match data {
            ServerData::Url { url } => assert_eq!(url.to_string(), "sqrl://testurl.com"),
            ServerData::ServerResponse { .. } => {
                panic!("Did not expect a ServerResponse");
            }
        };
    }

    #[test]
    fn server_data_parse_nonsqrl_url() {
        let result = ServerData::from_base64(TEST_INVALID_URL);
        if result.is_ok() {
            panic!("Got back a real result");
        }
    }

    #[test]
    fn server_data_parse_server_data() {
        let data = ServerData::from_base64(TEST_SERVER_RESPONSE).unwrap();
        match data {
            ServerData::Url { url: _ } => panic!("Did not expect a url"),
            ServerData::ServerResponse {
                server_response,
                original_response,
                ..
            } => {
                assert_eq!(server_response.nut, "1WM9lfF1ST-z");
                assert_eq!(original_response, TEST_SERVER_RESPONSE);
            }
        };
    }
}
