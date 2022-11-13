// The current version of the sqrl protocol
pub const PROTOCOL_VERSION: u64 = 1;

// Constants for the Server TIF
pub const SERVER_TIF_CURRENT_ID_MATCH: u16 = 0x1;
pub const SERVER_TIF_PREV_ID_MATCH: u16 = 0x2;
pub const SERVER_TIF_IPS_MATCH: u16 = 0x4;
pub const SERVER_TIF_SQRL_DISABLED: u16 = 0x8;
pub const SERVER_TIF_FUNCTION_NOT_SUPPORTED: u16 = 0x10;
pub const SERVER_TIF_TRANSIENT_ERROR: u16 = 0x20;
pub const SERVER_TIF_COMMAND_FAILED: u16 = 0x40;
pub const SERVER_TIF_CLIENT_FAILURE: u16 = 0x80;
pub const SERVER_TIF_BAD_ID: u16 = 0x100;
pub const SERVER_TIF_IDENTITY_SUPERSEDED: u16 = 0x200;

pub struct ClientRequest {
    pub client: ClientParameters,
    pub server: String,
    pub ids: String,
    pub pids: Option<String>,
    pub urs: Option<String>,
}

impl ClientRequest {
    pub fn new(client_params: ClientParameters, server: String, ids: String) -> ClientRequest {
        ClientRequest {
            client: client_params,
            server,
            ids,
            pids: None,
            urs: None,
        }
    }

    // TODO: Actuall encode the data
    pub fn encode(&self) -> String {
        let result = self.client.encode();

        result
    }
}

pub struct ClientParameters {
    pub ver: u64,
    pub cmd: ClientCommand,
    pub idk: String,
    pub pidk: Option<String>,
    pub btn: Option<u8>,
}

impl ClientParameters {
    pub fn new(
        cmd: ClientCommand,
        idk: String,
        pidk: Option<String>,
        btn: Option<u8>,
    ) -> ClientParameters {
        ClientParameters {
            ver: PROTOCOL_VERSION,
            cmd,
            idk,
            pidk,
            btn,
        }
    }

    // TODO: Encode all the parameters
    pub fn encode(&self) -> String {
        base64::encode_config("", base64::URL_SAFE)
    }
}

pub enum ClientCommand {
    Query,
    Ident,
    Disable,
    Enable,
    Remove,
}

pub struct ServerResponse {
    pub ver: u64,
    pub nut: String,
    pub tif: u16,
    pub qry: String,
}

impl ServerResponse {
    pub fn new(nut: String, tif: u16, qry: String) -> ServerResponse {
        ServerResponse {
            ver: PROTOCOL_VERSION,
            nut,
            tif,
            qry,
        }
    }
}
