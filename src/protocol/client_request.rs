use super::{get_or_error, parse_query_data, protocol_version::ProtocolVersion, PROTOCOL_VERSIONS};
use crate::error::SqrlError;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use std::{collections::HashMap, fmt};

pub struct ClientRequest {
    pub client_params: ClientParameters,
    pub server: String,
    pub ids: String,
    pub pids: Option<String>,
    pub urs: Option<String>,
}

impl ClientRequest {
    pub fn new(client_params: ClientParameters, server: String, ids: String) -> Self {
        ClientRequest {
            client_params,
            server,
            ids,
            pids: None,
            urs: None,
        }
    }

    pub fn from_query_string(query_string: &str) -> Result<Self, SqrlError> {
        let map = parse_query_data(query_string)?;
        let client_parameters_string = get_or_error(
            &map,
            "client",
            "Invalid client request: No client parameters",
        )?;
        let client_params = ClientParameters::from_base64(&client_parameters_string)?;
        let server = get_or_error(&map, "server", "Invalid client request: No server value")?;
        let ids = get_or_error(&map, "ids", "Invalid client request: No ids value")?;

        let pids = map.get("pids").map(|x| x.to_string());
        let urs = map.get("urs").map(|x| x.to_string());

        Ok(ClientRequest {
            client_params,
            server,
            ids,
            pids,
            urs,
        })
    }

    // TODO: Actually encode the data
    pub fn encode(&self) -> String {
        let mut result = format!("client={}", self.client_params.encode());
        result = result + &format!("&server={}", self.server);
        result
    }
}

#[derive(Debug, PartialEq)]
pub struct ClientParameters {
    pub ver: ProtocolVersion,
    pub cmd: ClientCommand,
    pub idk: String,
    pub opt: Option<String>,
    pub btn: Option<u8>,
    pub pidk: Option<String>,
    pub ins: Option<String>,
    pub pins: Option<String>,
    pub suk: Option<String>,
    pub vuk: Option<String>,
}

impl ClientParameters {
    pub fn new(cmd: ClientCommand, idk: String) -> ClientParameters {
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

    pub fn from_base64(base64_string: &str) -> Result<Self, SqrlError> {
        let query_string = String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(base64_string)?)?;

        // Client parameters use a newline
        let mut map = HashMap::<String, String>::new();
        for token in query_string.split('\n') {
            if let Some((key, value)) = token.split_once('=') {
                map.insert(key.to_owned(), value.trim().to_owned());
            }
        }

        // Validate the protocol version is supported
        let ver_string = get_or_error(&map, "ver", "Invalid client request: No version number")?;
        let ver = ProtocolVersion::new(&ver_string)?;

        let cmd_string = get_or_error(&map, "cmd", "Invalid client request: No cmd value")?;
        let cmd = ClientCommand::from(cmd_string);
        let idk = get_or_error(&map, "idk", "Invalid client request: No idk value")?;

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

        let opt = map.get("opt").map(|x| x.to_string());
        let pidk = map.get("pidk").map(|x| x.to_string());
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

    pub fn encode(&self) -> String {
        let mut result = format!("ver={}", self.ver);
        result = result + &format!("\ncmd={}", self.cmd);
        result = result + &format!("\nidk={}", self.idk);

        if let Some(opt) = &self.opt {
            result = result + &format!("\nopt={}", opt);
        }
        if let Some(btn) = &self.btn {
            result = result + &format!("\nbtn={}", btn);
        }
        if let Some(pidk) = &self.pidk {
            result = result + &format!("\npidk={}", pidk);
        }
        if let Some(ins) = &self.ins {
            result = result + &format!("\nins={}", ins);
        }
        if let Some(pins) = &self.pins {
            result = result + &format!("\npins={}", pins);
        }
        if let Some(suk) = &self.suk {
            result = result + &format!("\nsuk={}", suk);
        }
        if let Some(vuk) = &self.vuk {
            result = result + &format!("\nvuk={}", vuk);
        }

        BASE64_URL_SAFE_NO_PAD.encode(result)
    }
}

#[derive(Debug, PartialEq)]
pub enum ClientCommand {
    Query,
    Ident,
    Disable,
    Enable,
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

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_QUERY: &str = "dmVyPTENCmNtZD1xdWVyeQ0KaWRrPWlnZ2N1X2UtdFdxM3NvZ2FhMmFBRENzeFJaRUQ5b245SDcxNlRBeVBSMHcNCnBpZGs9RTZRczJnWDdXLVB3aTlZM0tBbWJrdVlqTFNXWEN0S3lCY3ltV2xvSEF1bw0Kb3B0PWNwc35zdWsNCg";

    #[test]
    fn decode_example_client_parameters() {
        let client_parameters = ClientParameters::from_base64(TEST_QUERY).unwrap();

        assert_eq!(client_parameters.ver.to_string(), "1");
        assert_eq!(client_parameters.cmd, ClientCommand::Query);
        assert_eq!(
            client_parameters.idk,
            "iggcu_e-tWq3sogaa2aADCsxRZED9on9H716TAyPR0w"
        );
        match client_parameters.pidk {
            Some(s) => assert_eq!(&s, "E6Qs2gX7W-Pwi9Y3KAmbkuYjLSWXCtKyBcymWloHAuo"),
            None => assert!(false),
        }
        match client_parameters.opt {
            Some(s) => assert_eq!(&s, "cps~suk"),
            None => assert!(false),
        }
    }

    #[test]
    fn encode_example_client_parameters() {
        let mut params = ClientParameters::new(
            ClientCommand::Query,
            "iggcu_e-tWq3sogaa2aADCsxRZED9on9H716TAyPR0w".to_owned(),
        );
        params.pidk = Some("E6Qs2gX7W-Pwi9Y3KAmbkuYjLSWXCtKyBcymWloHAuo".to_owned());
        params.opt = Some("cps-suk".to_owned());

        // TODO: Write the base64 encoding code and finish this test
    }
}
