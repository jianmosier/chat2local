use serde::{Deserialize, Serialize};

pub const MAX_MESSAGE_BYTES: usize = 512 * 1024;
pub const MAX_FILE_BYTES: u64 = 65536;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub v: u8,
    pub id: String,
    pub op: Operation,
    pub args: Arguments,
    pub authority: Authority,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    ReadFile,
    ListDirectory,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Arguments {
    pub root_id: String,
    pub path: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Authority {
    pub paused: bool,
    pub device_id: Option<String>,
    pub resource: Option<String>,
    pub root: Root,
    pub access: Option<Access>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Root {
    pub id: String,
    pub path: String,
    pub kind: RootKind,
    pub connection_id: Option<String>,
    pub write_mode: Mode,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RootKind {
    Legacy,
    Account,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    ReadOnly,
    Review,
    Direct,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Access {
    pub version: u8,
    pub connection_id: String,
    pub device_id: String,
    pub resource: String,
    pub roots: Vec<Share>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Share {
    pub root_id: String,
    pub mode: Mode,
}

#[derive(Debug, Serialize)]
pub struct Failure {
    pub code: &'static str,
    pub message: &'static str,
}

impl Failure {
    pub fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
}

pub type Result<T> = std::result::Result<T, Failure>;

/// Local parent-to-child protocol; none of these additional fields are tool input.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WriteRequest {
    pub request: Request,
    pub operation_id: String,
    pub authorization: WriteAuthorization,
    pub expected_hash: Option<String>,
    pub content: String,
    pub state_dir: String,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum WriteAuthorization {
    DirectoryDirect,
    LocalReview,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommitRequest {
    pub id: String,
    pub operation_id: String,
    pub intent: String,
}
