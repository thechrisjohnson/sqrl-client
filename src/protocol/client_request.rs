//! All of the code needed for sending client requests to a SQRL server

use super::{
    decode_public_key, decode_signature, get_or_error, parse_newline_data, parse_query_data,
    protocol_version::ProtocolVersion, server_response::ServerResponse, PROTOCOL_VERSIONS,
};
use crate::{common::SqrlUrl, error::SqrlError};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use std::{convert::TryFrom, fmt, str::FromStr};

/// A client request to a server
pub struct ClientRequest {
    /// The client parameters
    pub client_params: ClientParameters,
    /// The previous server response, or the sqrl url if the first request
    pub server: ServerData,
    /// The signature of this request
    pub ids: Signature,
    /// The signature of this request using a previous identity
    pub pids: Option<Signature>,
    /// The unlock request signature for an identity unlock
    pub urs: Option<String>,
}

impl ClientRequest {
    /// Generate a new client request
    pub fn new(client_params: ClientParameters, server: ServerData, ids: Signature) -> Self {
        ClientRequest {
            client_params,
            server,
            ids,
            pids: None,
            urs: None,
        }
    }

    /// Parse a client request from a query string
    pub fn from_query_string(query_string: &str) -> Result<Self, SqrlError> {
        let map = parse_query_data(query_string)?;
        let client_parameters_string = get_or_error(
            &map,
            "client",
            "Invalid client request: No client parameters",
        )?;
        let client_params = ClientParameters::from_base64(&client_parameters_string)?;
        let server_string =
            get_or_error(&map, "server", "Invalid client request: No server value")?;
        let server = ServerData::from_base64(&server_string)?;
        let ids_string = get_or_error(&map, "ids", "Invalid client request: No ids value")?;
        let ids = decode_signature(&ids_string)?;
        let pids = match map.get("pids") {
            Some(x) => Some(decode_signature(x)?),
            None => None,
        };

        let urs = map.get("urs").map(|x| x.to_string());

        Ok(ClientRequest {
            client_params,
            server,
            ids,
            pids,
            urs,
        })
    }

    /// Convert a client request to the query string to add in the request
    pub fn to_query_string(&self) -> String {
        let mut result = format!("client={}", self.client_params.encode());
        result += &format!("&server={}", self.server);
        result += &format!(
            "&ids={}",
            BASE64_URL_SAFE_NO_PAD.encode(self.ids.to_bytes())
        );

        if let Some(pids) = &self.pids {
            result += &format!("&pids={}", BASE64_URL_SAFE_NO_PAD.encode(pids.to_bytes()));
        }
        if let Some(urs) = &self.urs {
            result += &format!("&urs={}", BASE64_URL_SAFE_NO_PAD.encode(urs));
        }

        result
    }

    /// Get the portion of the client request that is signed
    pub fn get_signed_string(&self) -> String {
        format!(
            "{}{}",
            self.client_params.encode(),
            &self.server.to_base64()
        )
    }
}

/// Parameters used for sending requests to the client
#[derive(Debug, PartialEq)]
pub struct ClientParameters {
    /// The supported protocol versions of the client
    pub ver: ProtocolVersion,
    /// The client command requested to be performed
    pub cmd: ClientCommand,
    /// The client identity used to sign the request
    pub idk: VerifyingKey,
    /// Optional options requested by the client
    pub opt: Option<Vec<ClientOption>>,
    /// The button pressed in response to a server query
    pub btn: Option<u8>,
    /// A previous client identity used to sign the request
    pub pidk: Option<VerifyingKey>,
    /// The current identity secret index in response to a server query
    pub ins: Option<String>,
    /// The previous identity secret index in response to a server query
    pub pins: Option<String>,
    /// The server unlock key used for unlocking an identity
    pub suk: Option<String>,
    /// The verify unlock key used for unlocking an identity
    pub vuk: Option<String>,
}

impl ClientParameters {
    /// Create a new client parameter using the command and verifying key
    pub fn new(cmd: ClientCommand, idk: VerifyingKey) -> ClientParameters {
        ClientParameters {
            ver: ProtocolVersion::new(PROTOCOL_VERSIONS).unwrap(),
            cmd,
            idk,
            opt: None,
            btn: None,
            pidk: None,
            ins: None,
            pins: None,
            suk: None,
            vuk: None,
        }
    }

    /// Parse a base64-encoded client parameter value
    pub fn from_base64(base64_string: &str) -> Result<Self, SqrlError> {
        let query_string = String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(base64_string)?)?;
        let map = parse_newline_data(&query_string)?;

        // Validate the protocol version is supported
        let ver_string = get_or_error(&map, "ver", "Invalid client request: No version number")?;
        let ver = ProtocolVersion::new(&ver_string)?;

        let cmd_string = get_or_error(&map, "cmd", "Invalid client request: No cmd value")?;
        let cmd = ClientCommand::from(cmd_string);
        let idk_string = get_or_error(&map, "idk", "Invalid client request: No idk value")?;
        let idk = decode_public_key(&idk_string)?;

        let btn = match map.get("btn") {
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

        let pidk = match map.get("pidk") {
            Some(x) => Some(decode_public_key(x)?),
            None => None,
        };

        let opt = match map.get("opt") {
            Some(x) => Some(ClientOption::from_option_string(x)?),
            None => None,
        };

        let ins = map.get("ins").map(|x| x.to_string());
        let pins = map.get("pins").map(|x| x.to_string());
        let suk = map.get("suk").map(|x| x.to_string());
        let vuk = map.get("vuk").map(|x| x.to_string());

        Ok(ClientParameters {
            ver,
            cmd,
            idk,
            opt,
            btn,
            pidk,
            ins,
            pins,
            suk,
            vuk,
        })
    }

    /// base64-encode this client parameter object
    pub fn encode(&self) -> String {
        let mut result = format!("ver={}", self.ver);
        result += &format!("\ncmd={}", self.cmd);
        result += &format!(
            "\nidk={}",
            BASE64_URL_SAFE_NO_PAD.encode(self.idk.as_bytes())
        );

        if let Some(opt) = &self.opt {
            result += &format!("\nopt={}", ClientOption::to_option_string(opt));
        }
        if let Some(btn) = &self.btn {
            result += &format!("\nbtn={}", btn);
        }
        if let Some(pidk) = &self.pidk {
            result += &format!("\npidk={}", BASE64_URL_SAFE_NO_PAD.encode(pidk.as_bytes()));
        }
        if let Some(ins) = &self.ins {
            result += &format!("\nins={}", ins);
        }
        if let Some(pins) = &self.pins {
            result += &format!("\npins={}", pins);
        }
        if let Some(suk) = &self.suk {
            result += &format!("\nsuk={}", suk);
        }
        if let Some(vuk) = &self.vuk {
            result += &format!("\nvuk={}", vuk);
        }

        BASE64_URL_SAFE_NO_PAD.encode(result)
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
        /// The previous response to the client's request
        server_response: ServerResponse,
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
            Ok(server_response) => Ok(ServerData::ServerResponse { server_response }),
            Err(_) => Err(SqrlError::new(format!("Invalid server data: {}", &data))),
        }
    }

    /// base64-encode the server data
    pub fn to_base64(&self) -> String {
        match self {
            ServerData::Url { url } => BASE64_URL_SAFE_NO_PAD.encode(url.to_string().as_bytes()),
            ServerData::ServerResponse { server_response } => server_response.to_base64(),
        }
    }
}

impl fmt::Display for ServerData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ServerData::Url { url } => {
                write!(f, "{}", url)
            }
            ServerData::ServerResponse { server_response } => {
                write!(f, "{}", server_response)
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
        params.pidk =
            Some(decode_public_key("E6Qs2gX7W-Pwi9Y3KAmbkuYjLSWXCtKyBcymWloHAuo").unwrap());
        params.opt = Some(vec![
            ClientOption::ClientProvidedSession,
            ClientOption::ServerUnlockKey,
        ]);

        let decoded = ClientParameters::from_base64(&params.encode()).unwrap();
        assert_eq!(params, decoded);
    }

    #[test]
    fn client_parameters_decode_example() {
        let client_parameters = ClientParameters::from_base64(TEST_CLIENT_PARAMS).unwrap();

        assert_eq!(client_parameters.ver.to_string(), "1");
        assert_eq!(client_parameters.cmd, ClientCommand::Query);
        assert_eq!(
            BASE64_URL_SAFE_NO_PAD.encode(client_parameters.idk.as_bytes()),
            "iggcu_e-tWq3sogaa2aADCsxRZED9on9H716TAyPR0w"
        );
        match &client_parameters.pidk {
            Some(s) => assert_eq!(
                BASE64_URL_SAFE_NO_PAD.encode(s.as_bytes()),
                "E6Qs2gX7W-Pwi9Y3KAmbkuYjLSWXCtKyBcymWloHAuo"
            ),
            None => panic!(),
        }
        match &client_parameters.opt {
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
            ServerData::ServerResponse { server_response: _ } => {
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
            ServerData::ServerResponse { server_response } => {
                assert_eq!(server_response.nut, "1WM9lfF1ST-z");
            }
        };
    }
}
