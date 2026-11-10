//! Compatibility port of the enabled @cloudflare/workers-oauth-provider 0.10.3
//! profile. Original MIT attribution is in LICENSE.oauth-provider.txt.
mod operations;
mod runtime;
mod value;
pub use runtime::Engine;
use serde_json::{Value as Json, json};
type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Debug)]
enum Error {
    Core,
    Host {
        handle: u32,
        name: String,
        message: Vec<u16>,
    },
    Normal {
        name: String,
        message: Vec<u16>,
    },
    SyntaxJson(Vec<u16>),
    CycleJson(Json),
    OAuth {
        code: String,
        description: Vec<u16>,
        status: u16,
        headers: Json,
    },
    Authorization {
        code: String,
        description: Vec<u16>,
        redirect: Option<Json>,
    },
}
trait IntoText {
    fn units(self) -> Vec<u16>;
}
impl IntoText for &str {
    fn units(self) -> Vec<u16> {
        self.encode_utf16().collect()
    }
}
impl IntoText for String {
    fn units(self) -> Vec<u16> {
        self.encode_utf16().collect()
    }
}
impl IntoText for Vec<u16> {
    fn units(self) -> Vec<u16> {
        self
    }
}
impl Error {
    fn normal(name: &str, message: impl IntoText) -> Self {
        Self::Normal {
            name: name.into(),
            message: message.units(),
        }
    }
    fn oauth(code: &str, description: impl IntoText) -> Self {
        Self::OAuth {
            code: code.into(),
            description: description.units(),
            status: 400,
            headers: json!({}),
        }
    }
    fn auth(code: &str, description: impl IntoText) -> Self {
        Self::Authorization {
            code: code.into(),
            description: description.units(),
            redirect: None,
        }
    }
    fn wire(&self) -> Json {
        match self {
            Self::Core => json!({"kind":"core"}),
            Self::Host {
                handle,
                name,
                message,
            } => json!({"kind":"host","handle":handle,"name":name,"message":message}),
            Self::Normal { name, message } => json!({"kind":"error","name":name,"message":message}),
            Self::SyntaxJson(input) => json!({"kind":"syntax_json","input":input}),
            Self::CycleJson(input) => json!({"kind":"cycle_json","input":input}),
            Self::OAuth {
                code,
                description,
                status,
                headers,
            } => {
                json!({"kind":"oauth","code":code,"description":description,"status":status,"headers":headers})
            }
            Self::Authorization {
                code,
                description,
                redirect,
            } => {
                json!({"kind":"authorization","code":code,"description":description,"redirect":redirect})
            }
        }
    }
}
pub fn dispatch(engine: &mut Engine, input: &[u8]) -> Option<Vec<u8>> {
    engine
        .dispatch(input)
        .ok()
        .and_then(|v| serde_json::to_vec(&v).ok())
}
