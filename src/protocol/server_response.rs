//! Code for a server to respond to client requests

use super::{
    encode_newline_data, get_or_error, parse_newline_data, protocol_version::ProtocolVersion,
    PROTOCOL_VERSIONS,
};
use crate::error::SqrlError;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use std::{collections::HashMap, fmt, str::FromStr};

const VER_KEY: &str = "ver";
const NUT_KEY: &str = "nut";
const TIF_KEY: &str = "tif";
const QRY_KEY: &str = "qry";
const URL_KEY: &str = "url";
const CAN_KEY: &str = "can";
const SIN_KEY: &str = "sin";
const SUK_KEY: &str = "suk";
const ASK_KEY: &str = "ask";

/// An object representing a response from the server
#[derive(Debug, PartialEq)]
pub struct ServerResponse {
    /// The SQRL protocol versions supported by the server
    pub ver: ProtocolVersion,
    /// The nut to be used for signing the next request
    pub nut: String,
    /// A collection of transaction indication flags
    pub tif: Vec<TIFValue>,
    /// The server object to query in the next request
    pub qry: String,
    /// If CPS set, the url to redirect the client's browser to after
    /// successful authentication
    pub url: Option<String>,
    /// If CPS set, a url to use to cancel a user's authentication
    pub can: Option<String>,
    /// The secret index used for requesting a client to return an indexed
    /// secret
    pub sin: Option<String>,
    /// The server unlock key requested by the client
    pub suk: Option<String>,
    /// A way for the server to request that the client display a prompt to the
    /// client user and return the selection
    pub ask: Option<String>,
}

impl ServerResponse {
    /// Create a new server response object from the nut and tif values
    pub fn new(nut: String, tif: Vec<TIFValue>, qry: String) -> ServerResponse {
        ServerResponse {
            ver: ProtocolVersion::new(PROTOCOL_VERSIONS).unwrap(),
            nut,
            tif,
            qry,
            url: None,
            can: None,
            sin: None,
            suk: None,
            ask: None,
        }
    }

    /// Decode a server response from a base64-encoded value
    pub fn from_base64(base64_string: &str) -> Result<Self, SqrlError> {
        // Decode the response
        let server_data = String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(base64_string)?)?;
        Self::from_str(&server_data)
    }

    /// Return the base64-encoded value of the server response
    pub fn to_base64(&self) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(self.to_string().as_bytes())
    }
}

impl fmt::Display for ServerResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut map = HashMap::<String, String>::new();
        map.insert(VER_KEY.to_owned(), format!("{}", self.ver));
        map.insert(NUT_KEY.to_owned(), self.nut.to_owned());

        let mut tif: u16 = 0;
        for t in &self.tif {
            tif |= *t as u16;
        }

        map.insert(TIF_KEY.to_owned(), format!("{}", tif));
        map.insert(QRY_KEY.to_owned(), self.qry.to_owned());

        if let Some(url) = &self.url {
            map.insert(URL_KEY.to_owned(), url.to_owned());
        }
        if let Some(can) = &self.can {
            map.insert(CAN_KEY.to_owned(), can.to_owned());
        }
        if let Some(sin) = &self.sin {
            map.insert(SIN_KEY.to_owned(), sin.to_owned());
        }
        if let Some(suk) = &self.suk {
            map.insert(SUK_KEY.to_owned(), suk.to_owned());
        }
        if let Some(ask) = &self.ask {
            map.insert(ASK_KEY.to_owned(), ask.to_owned());
        }

        write!(f, "{}", &encode_newline_data(&map))
    }
}

impl FromStr for ServerResponse {
    type Err = SqrlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = parse_newline_data(s)?;

        // Validate the protocol version is supported
        let ver_string = get_or_error(&data, VER_KEY, "No version number in server response")?;
        let ver = ProtocolVersion::new(&ver_string)?;
        let nut = get_or_error(&data, NUT_KEY, "No nut in server response")?;
        let tif_string = get_or_error(&data, TIF_KEY, "No status code (tif) in server response")?;
        let tif = TIFValue::parse_str(&tif_string)?;

        let qry = get_or_error(&data, QRY_KEY, "No status code (tif) in server response")?;

        // The rest of these are optional
        let url = data.get(URL_KEY).map(|x| x.to_string());
        let can = data.get(CAN_KEY).map(|x| x.to_string());
        let sin = data.get(SIN_KEY).map(|x| x.to_string());
        let suk = data.get(SUK_KEY).map(|x| x.to_string());
        let ask = data.get(ASK_KEY).map(|x| x.to_string());

        Ok(ServerResponse {
            ver,
            nut,
            tif,
            qry,
            url,
            can,
            sin,
            suk,
            ask,
        })
    }
}

/// Transaction information flags
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TIFValue {
    /// A response indicating the current identity (idk) matches the known
    /// server identity
    CurrentIdMatch = 0x1,
    /// A response indicating the previous identity (pidk) matches the known
    /// server identity
    PreviousIdMatch = 0x2,
    /// A response indicating the client ip address matches the first ip
    /// address to query the server
    IpsMatch = 0x4,
    /// Response that indicates SQRL is disabled for this user
    SqrlDisabled = 0x8,
    /// Response that indicates the server does not support the previous request
    FunctionNotSupported = 0x10,
    /// Response that indicates the server experienced a transient error
    /// and the request should be retried
    TransientError = 0x20,
    /// Response that indicates the client command failed
    CommandFailed = 0x40,
    /// Response that indicates that the client query was incorrect
    ClientFailure = 0x80,
    /// Response that indicates that the identities used in the client query do not
    /// match the server's
    BadId = 0x100,
    /// Response that indicates the client identity used has been superseded
    IdentitySuperseded = 0x200,
}

impl TIFValue {
    /// Parse the TIF values based on a string
    pub fn parse_str(value: &str) -> Result<Vec<Self>, SqrlError> {
        match value.parse::<u16>() {
            Ok(x) => Ok(Self::from_u16(x)),
            Err(_) => Err(SqrlError::new(format!(
                "Unable to parse server response status code (tif): {}",
                value
            ))),
        }
    }

    /// Parse the TIF values based on a u16
    pub fn from_u16(value: u16) -> Vec<Self> {
        let mut ret = Vec::new();

        if value & TIFValue::CurrentIdMatch as u16 > 0 {
            ret.push(TIFValue::CurrentIdMatch);
        }
        if value & TIFValue::PreviousIdMatch as u16 > 0 {
            ret.push(TIFValue::PreviousIdMatch);
        }
        if value & TIFValue::IpsMatch as u16 > 0 {
            ret.push(TIFValue::IpsMatch);
        }
        if value & TIFValue::SqrlDisabled as u16 > 0 {
            ret.push(TIFValue::SqrlDisabled);
        }
        if value & TIFValue::FunctionNotSupported as u16 > 0 {
            ret.push(TIFValue::FunctionNotSupported);
        }
        if value & TIFValue::TransientError as u16 > 0 {
            ret.push(TIFValue::TransientError);
        }
        if value & TIFValue::CommandFailed as u16 > 0 {
            ret.push(TIFValue::CommandFailed);
        }
        if value & TIFValue::ClientFailure as u16 > 0 {
            ret.push(TIFValue::ClientFailure);
        }
        if value & TIFValue::BadId as u16 > 0 {
            ret.push(TIFValue::BadId);
        }
        if value & TIFValue::IdentitySuperseded as u16 > 0 {
            ret.push(TIFValue::IdentitySuperseded);
        }

        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{distributions::Alphanumeric, thread_rng, Rng};

    const TEST_SERVER_RESPONSE: &str = "dmVyPTENCm51dD0xV005bGZGMVNULXoNCnRpZj01DQpxcnk9L2NsaS5zcXJsP251dD0xV005bGZGMVNULXoNCnN1az1CTUZEbTdiUGxzUW9qdUpzb0RUdmxTMU1jbndnU2N2a3RGODR2TGpzY0drDQo";

    #[test]
    fn server_response_validate_example() {
        let response = ServerResponse::from_base64(TEST_SERVER_RESPONSE).unwrap();
        assert_eq!(response.ver.to_string(), "1");
        assert_eq!(response.nut, "1WM9lfF1ST-z");
        assert_eq!(response.qry, "/cli.sqrl?nut=1WM9lfF1ST-z");
        assert_eq!(
            response.suk.unwrap(),
            "BMFDm7bPlsQojuJsoDTvlS1McnwgScvktF84vLjscGk"
        )
    }

    #[test]
    fn server_response_encode_decode() {
        let nut: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(30)
            .map(char::from)
            .collect();
        let qry: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(30)
            .map(char::from)
            .collect();
        let tif: u16 = thread_rng().gen_range(0..1023);

        let initial_response = ServerResponse::new(nut, TIFValue::from_u16(tif), qry);
        let decoded_response = ServerResponse::from_base64(&initial_response.to_base64()).unwrap();

        assert_eq!(initial_response, decoded_response);
    }

    #[test]
    fn tif_value_from_string() {
        let resp = TIFValue::parse_str("674").unwrap();
        assert_eq!(4, resp.len());
        assert!(resp.contains(&TIFValue::PreviousIdMatch));
        assert!(resp.contains(&TIFValue::TransientError));
        assert!(resp.contains(&TIFValue::ClientFailure));
        assert!(resp.contains(&TIFValue::IdentitySuperseded));
    }

    #[test]
    fn tif_value_from_u16() {
        let resp = TIFValue::from_u16(73);
        assert_eq!(3, resp.len());
        assert!(resp.contains(&TIFValue::CurrentIdMatch));
        assert!(resp.contains(&TIFValue::SqrlDisabled));
        assert!(resp.contains(&TIFValue::CommandFailed));
    }
}
