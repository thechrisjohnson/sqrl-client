use super::{get_or_error, parse_query_data, protocol_version::ProtocolVersion, PROTOCOL_VERSIONS};
use crate::error::SqrlError;

pub struct ServerResponse {
    pub ver: ProtocolVersion,
    pub nut: String,
    pub tif: u16,
    pub qry: String,
    pub url: Option<String>,
    pub can: Option<String>,
    pub sin: Option<String>,
    pub suk: Option<String>,
    pub ask: Option<String>,
}

impl ServerResponse {
    pub fn new(nut: String, tif: u16, qry: String) -> ServerResponse {
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

    // TODO: Actually test this out
    pub fn from_server_response(query: &str) -> Result<ServerResponse, SqrlError> {
        // Decode the response
        let data = parse_query_data(query)?;

        // Validate the protocol version is supported
        let ver_string = get_or_error(&data, "ver", "No version number in server response")?;
        let ver = ProtocolVersion::new(&ver_string)?;
        let nut = get_or_error(&data, "nut", "No nut in server response")?;
        let tif_string = get_or_error(&data, "tif", "No status code (tif) in server response")?;
        let tif = match tif_string.parse::<u16>() {
            Ok(x) => x,
            Err(_) => {
                return Err(SqrlError::new(format!(
                    "Unable to parse server response status code (tif): {}",
                    tif_string
                )))
            }
        };

        let qry = get_or_error(&data, "qry", "No status code (tif) in server response")?;

        // The rest of these are optional
        let url = data.get("url").map(|x| x.to_string());
        let can = data.get("can").map(|x| x.to_string());
        let sin = data.get("sin").map(|x| x.to_string());
        let suk = data.get("suk").map(|x| x.to_string());
        let ask = data.get("ask").map(|x| x.to_string());

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
