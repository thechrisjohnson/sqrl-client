use std::fmt;

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

    // TODO: Actually encode the data
    pub fn encode(&self) -> String {
        let mut result = format!("client={}", self.client.encode());
        result = result + &format!("&server={}", self.server);
        result
    }
}

pub struct ClientParameters {
    pub ver: u64,
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
    pub fn new(
        cmd: ClientCommand,
        idk: String,
        opt: Option<String>,
        btn: Option<u8>,
        pidk: Option<String>,
        ins: Option<String>,
        pins: Option<String>,
        suk: Option<String>,
        vuk: Option<String>
    ) -> ClientParameters {
        ClientParameters {
            ver: PROTOCOL_VERSION,
            cmd,
            idk,
            opt,
            btn,
            pidk,
            ins,
            pins,
            suk,
            vuk
        }
    }

    pub fn encode(&self) -> String {
        let mut result = format!("ver={}", self.ver);
        result = result + &format!("\ncmd={}", self.cmd.to_string());
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

        base64::encode_config(result, base64::URL_SAFE)
    }
}

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
            ClientCommand::Remove => write!(f, "remove")
        }
    }
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
