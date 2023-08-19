use super::{
    decode_public_key, decode_signature, get_or_error, parse_query_data,
    protocol_version::ProtocolVersion, PROTOCOL_VERSIONS,
};
use crate::error::SqrlError;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{PublicKey, Signature};
use std::{collections::HashMap, fmt};

pub struct ClientRequest {
    pub client_params: ClientParameters,
    pub server: String,
    pub ids: Signature,
    pub pids: Option<Signature>,
    pub urs: Option<String>,
}

impl ClientRequest {
    pub fn new(client_params: ClientParameters, server: String, ids: Signature) -> Self {
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
        let ids_string = get_or_error(&map, "ids", "Invalid client request: No ids value")?;
        let ids = decode_signature(&ids_string)?;
        let pids = match map.get("pids") {
            Some(x) => Some(decode_signature(x)?),
            None => None,
        };

        let urs = map.get("urs").map(|x| x.to_string());

        // TODO: Should we validate when we load?
        // Also, validate that the signature is correct
        // let signed_portion = format!("{}{}", &client_parameters_string, &server);
        // client_params.idk.verify(signed_portion.as_bytes(), &ids)?;

        Ok(ClientRequest {
            client_params,
            server,
            ids,
            pids,
            urs,
        })
    }

    pub fn encode(&self) -> String {
        let mut result = format!("client={}", self.client_params.encode());
        result += &format!("&server={}", self.server);
        result += &format!("&ids={}", BASE64_URL_SAFE_NO_PAD.encode(self.ids));

        if let Some(pids) = &self.pids {
            result += &format!("&pids={}", BASE64_URL_SAFE_NO_PAD.encode(pids));
        }
        if let Some(urs) = &self.urs {
            result += &format!("&urs={}", BASE64_URL_SAFE_NO_PAD.encode(urs));
        }

        result
    }

    pub fn get_signed_string(&self) -> String {
        format!("{}{}", self.client_params.encode(), &self.server)
    }
}

#[derive(Debug, PartialEq)]
pub struct ClientParameters {
    pub ver: ProtocolVersion,
    pub cmd: ClientCommand,
    pub idk: PublicKey,
    pub opt: Option<Vec<ClientOption>>,
    pub btn: Option<u8>,
    pub pidk: Option<PublicKey>,
    pub ins: Option<String>,
    pub pins: Option<String>,
    pub suk: Option<String>,
    pub vuk: Option<String>,
}

impl ClientParameters {
    pub fn new(cmd: ClientCommand, idk: PublicKey) -> ClientParameters {
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
            Some(x) => {
                let mut options: Vec<ClientOption> = Vec::new();
                for option in x.split('~') {
                    options.push(ClientOption::from(option.to_string()))
                }
                Some(options)
            }
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

    pub fn encode(&self) -> String {
        let mut result = format!("ver={}", self.ver);
        result += &format!("\ncmd={}", self.cmd);
        result += &format!(
            "\nidk={}",
            BASE64_URL_SAFE_NO_PAD.encode(self.idk.as_bytes())
        );

        if let Some(opt) = &self.opt {
            let mut options = "".to_owned();
            for option in opt {
                if options.is_empty() {
                    options += &format!("{}", option);
                } else {
                    options += &format!("~{}", option);
                }
            }

            result += &format!("\nopt={}", options);
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

#[derive(Debug, PartialEq)]
pub enum ClientOption {
    NoIPTest,
    SQRLOnly,
    Hardlock,
    ClientProvidedSession,
    ServerUnlockKey,
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

impl From<String> for ClientOption {
    fn from(value: String) -> Self {
        match value.as_str() {
            "noiptest" => ClientOption::NoIPTest,
            "sqrlonly" => ClientOption::SQRLOnly,
            "hardlock" => ClientOption::Hardlock,
            "cps" => ClientOption::ClientProvidedSession,
            "suk" => ClientOption::ServerUnlockKey,
            _ => panic!("Not this!"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CLIENT_REQUEST: &str = "client=dmVyPTENCmNtZD1xdWVyeQ0KaWRrPWlnZ2N1X2UtdFdxM3NvZ2FhMmFBRENzeFJaRUQ5b245SDcxNlRBeVBSMHcNCnBpZGs9RTZRczJnWDdXLVB3aTlZM0tBbWJrdVlqTFNXWEN0S3lCY3ltV2xvSEF1bw0Kb3B0PWNwc35zdWsNCg&server=c3FybDovL3Nxcmwuc3RldmUuY29tL2NsaS5zcXJsP3g9MSZudXQ9ZTd3ZTZ3Q3RvU3hsJmNhbj1hSFIwY0hNNkx5OXNiMk5oYkdodmMzUXZaR1Z0Ynk1MFpYTjA&ids=hcXWTPx3EgP9R_AjtoCIrie_YgZxVD72nd5_pjMOnhUEYmhdjLUYs3jjcJT_GQuzNKXyAwY1ns1R6QJn1YKzCA";
    const TEST_CLIENT_PARAMS: &str = "dmVyPTENCmNtZD1xdWVyeQ0KaWRrPWlnZ2N1X2UtdFdxM3NvZ2FhMmFBRENzeFJaRUQ5b245SDcxNlRBeVBSMHcNCnBpZGs9RTZRczJnWDdXLVB3aTlZM0tBbWJrdVlqTFNXWEN0S3lCY3ltV2xvSEF1bw0Kb3B0PWNwc35zdWsNCg";

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
            None => assert!(false),
        }
        match &client_parameters.opt {
            Some(s) => assert_eq!(
                s,
                &vec![
                    ClientOption::ClientProvidedSession,
                    ClientOption::ServerUnlockKey
                ]
            ),
            None => assert!(false),
        }
    }
}
