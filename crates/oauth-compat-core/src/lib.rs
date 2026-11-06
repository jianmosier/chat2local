//! Bounded bearer-only compatibility with workers-oauth-provider 0.10.3.
//! The host supplies storage, time, WHATWG URL parsing and WebCrypto primitives;
//! all token/claims decisions, crypto inputs and JSON semantics live here.
pub mod provider;
mod value;
use chat2local_js_value_compat::{Document, Value};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use value::{LIMITS, base64, number, property, string, truthy};
pub const FRAME_BYTES: usize = 1_048_576;
pub const MAX_WIRE_BYTES: usize = 160 * 1024 * 1024;
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Url {
    pub origin: String,
    pub pathname: String,
    pub search: String,
}
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Start {
        header: Option<Vec<u16>>,
        resource: String,
        url: Url,
        scopes: Vec<String>,
    },
    Resume {
        sequence: u32,
        value: Primitive,
    },
}
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Primitive {
    Kv { text: Option<String> },
    Clock { millis: f64 },
    Url { value: Option<Url> },
    Key { id: u32 },
    Bytes { base64: String },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    v: u32,
    serial: u32,
    command: Command,
}
#[derive(Default)]
pub struct Engine {
    serial: u32,
    sequence: u32,
    state: Option<State>,
    started: bool,
}
enum State {
    Kv(Context),
    Clock(Context, Document),
    Url(Context, Document),
    Import(Context, Document),
    Unwrap(Context, Document),
    Decrypt,
}
struct Context {
    token: String,
    resource: String,
    url: Url,
    challenge: String,
}
impl Engine {
    fn effect(&mut self, state: State, op: serde_json::Value) -> serde_json::Value {
        self.sequence += 1;
        self.state = Some(state);
        json!({"kind":"effect","sequence":self.sequence,"op":op})
    }
    fn run(&mut self, command: Command) -> Result<serde_json::Value, ()> {
        match command {
            Command::Start {
                header,
                resource,
                url,
                scopes,
            } => {
                if self.started || resource.is_empty() || resource.len() > 8192 || scopes.len() > 64
                {
                    return Err(());
                }
                self.started = true;
                let mut protected_scopes = Vec::new();
                for scope in scopes {
                    if scope != "offline_access" && !protected_scopes.contains(&scope) {
                        protected_scopes.push(scope);
                    }
                }
                let scopes = protected_scopes;
                let challenge = format!(
                    "Bearer realm=\"OAuth\", resource_metadata=\"{}/.well-known/oauth-protected-resource{}\"",
                    url.origin, url.pathname
                );
                let context = Context {
                    token: String::new(),
                    resource,
                    url,
                    challenge: format!(
                        "{challenge}{}",
                        if scopes.is_empty() {
                            String::new()
                        } else {
                            format!(", scope=\"{}\"", scopes.join(" "))
                        }
                    ),
                };
                let prefix: Vec<u16> = "Bearer ".encode_utf16().collect();
                let Some(header) = header.filter(|s| s.starts_with(&prefix)) else {
                    return Ok(reject(&context, None));
                };
                if header.len() > LIMITS.input_units {
                    return Err(());
                }
                let token = String::from_utf16_lossy(&header[7..]);
                let parts: Vec<_> = token.split(':').collect();
                if parts.len() != 3 {
                    return Ok(reject(&context, Some("Invalid access token")));
                }
                let digest = Sha256::digest(token.as_bytes())
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                let key = format!("token:{}:{}:{digest}", parts[0], parts[1]);
                Ok(self.effect(
                    State::Kv(Context { token, ..context }),
                    json!({"type":"kv_get","key":key}),
                ))
            }
            Command::Resume { sequence, value } => {
                if sequence != self.sequence {
                    return Err(());
                }
                match (self.state.take().ok_or(())?, value) {
                    (State::Kv(ctx), Primitive::Kv { text }) => {
                        let Some(text) = text else {
                            return Ok(reject(&ctx, Some("Invalid access token")));
                        };
                        let doc = Document::parse_str(&text, LIMITS).map_err(|_| ())?;
                        if !truthy(&doc, doc.root())? {
                            return Ok(reject(&ctx, Some("Invalid access token")));
                        }
                        let audience = property(&doc, doc.root(), "audience")?;
                        let expected: Vec<u16> = ctx.resource.encode_utf16().collect();
                        let exact = match audience
                            .map(|id| doc.value(id))
                            .transpose()
                            .map_err(|_| ())?
                        {
                            Some(Value::String(s)) => *s == expected,
                            Some(Value::Array(a)) if a.len() == 1 => {
                                matches!(doc.value(a[0]).map_err(|_| ())?, Value::String(s) if *s == expected)
                            }
                            _ => false,
                        };
                        if !exact {
                            return Ok(reject(
                                &ctx,
                                Some("Access token is not bound to the configured resource"),
                            ));
                        }
                        Ok(self.effect(State::Clock(ctx, doc), json!({"type":"clock"})))
                    }
                    (State::Clock(ctx, doc), Primitive::Clock { millis }) => {
                        if !millis.is_finite() || millis.fract() != 0.0 {
                            return Err(());
                        }
                        if number(&doc, property(&doc, doc.root(), "expiresAt")?)?
                            < (millis / 1000.0).floor()
                        {
                            return Ok(reject(&ctx, Some("Access token expired")));
                        }
                        let op = json!({"type":"url_parse","input":ctx.resource});
                        Ok(self.effect(State::Url(ctx, doc), op))
                    }
                    (State::Url(ctx, doc), Primitive::Url { value }) => {
                        let matches = value.is_some_and(|aud| {
                            ctx.url.origin == aud.origin
                                && (aud.search.is_empty() || ctx.url.search == aud.search)
                                && (aud.pathname == "/"
                                    || aud.pathname.is_empty()
                                    || ctx.url.pathname == aud.pathname
                                    || ctx.url.pathname.starts_with(&(aud.pathname + "/")))
                        });
                        if !matches {
                            return Ok(reject(
                                &ctx,
                                Some("Token audience does not match resource server"),
                            ));
                        }
                        let bytes = wrapping_key(ctx.token.as_bytes());
                        Ok(self.effect(State::Import(ctx, doc), json!({"type":"import_key","format":"raw","bytes":value::encode_base64(&bytes),"algorithm":"AES-KW","extractable":false,"usages":["wrapKey","unwrapKey"]})))
                    }
                    (State::Import(ctx, doc), Primitive::Key { id }) if id == self.sequence => {
                        let bytes = base64(&string(
                            &doc,
                            property(&doc, doc.root(), "wrappedEncryptionKey")?,
                        )?)?;
                        Ok(self.effect(State::Unwrap(ctx, doc), json!({"type":"unwrap_key","key":id,"format":"raw","bytes":value::encode_base64(&bytes),"algorithm":"AES-KW","unwrappedAlgorithm":"AES-GCM","extractable":true,"usages":["encrypt","decrypt"]})))
                    }
                    (State::Unwrap(_ctx, doc), Primitive::Key { id }) if id == self.sequence => {
                        let grant = property(&doc, doc.root(), "grant")?.ok_or(())?;
                        let bytes =
                            base64(&string(&doc, property(&doc, grant, "encryptedProps")?)?)?;
                        Ok(self.effect(State::Decrypt, json!({"type":"decrypt","key":id,"algorithm":"AES-GCM","iv":[0,0,0,0,0,0,0,0,0,0,0,0],"bytes":value::encode_base64(&bytes)})))
                    }
                    (State::Decrypt, Primitive::Bytes { base64: encoded }) => {
                        let value = base64(&encoded.encode_utf16().collect::<Vec<_>>())?;
                        // TextDecoder's default UTF-8 replacement and BOM policy.
                        let text = String::from_utf8_lossy(&value);
                        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
                        // Validate in Rust, then transport the validated text.
                        // JSON.stringify would erase -0 and replace infinities
                        // with null before the application's handler sees them.
                        Document::parse_str(text, LIMITS).map_err(|_| ())?;
                        Ok(json!({"kind":"accept","propsJson":text}))
                    }
                    _ => Err(()),
                }
            }
        }
    }
}
fn reject(ctx: &Context, description: Option<&str>) -> serde_json::Value {
    let challenge = if description.is_some() {
        ctx.challenge
            .replacen(", scope=", ", error=\"invalid_token\", scope=", 1)
    } else {
        ctx.challenge.clone()
    };
    let challenge = if description.is_some() && !challenge.contains("error=\"") {
        format!("{challenge}, error=\"invalid_token\"")
    } else {
        challenge
    };
    let challenge = if description == Some("Token audience does not match resource server") {
        format!("{challenge}, error_description=\"Invalid audience\"")
    } else {
        challenge
    };
    let mut headers =
        json!({"Cache-Control":"no-store","Pragma":"no-cache","WWW-Authenticate":challenge});
    let body = description.map(|description| {
        headers["Content-Type"] = json!("application/json");
        json!({"error":"invalid_token","error_description":description}).to_string()
    });
    json!({"kind":"reject","status":401,"headers":headers,"body":body})
}
fn wrapping_key(token: &[u8]) -> Vec<u8> {
    const KEY: [u8; 32] = [
        34, 126, 38, 134, 141, 241, 225, 109, 128, 112, 234, 23, 151, 91, 71, 166, 130, 24, 250,
        135, 40, 174, 222, 133, 181, 29, 74, 217, 150, 202, 202, 67,
    ];
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for (i, byte) in KEY.iter().enumerate() {
        inner[i] ^= byte;
        outer[i] ^= byte;
    }
    let mut hash = Sha256::new();
    hash.update(inner);
    hash.update(token);
    let digest = hash.finalize();
    let mut hash = Sha256::new();
    hash.update(outer);
    hash.update(digest);
    hash.finalize().to_vec()
}
pub fn dispatch(engine: &mut Engine, input: &[u8]) -> Option<Vec<u8>> {
    let result = (|| {
        if input.len() > MAX_WIRE_BYTES {
            return None;
        }
        let frame: Frame = serde_json::from_slice(input).ok()?;
        if frame.v != 1 || frame.serial != engine.serial.checked_add(1)? {
            return None;
        }
        engine.serial = frame.serial;
        let result = engine.run(frame.command).ok()?;
        let bytes =
            serde_json::to_vec(&json!({"v":1,"serial":frame.serial,"result":result})).ok()?;
        (bytes.len() <= MAX_WIRE_BYTES).then_some(bytes)
    })();
    if result.is_none() {
        engine.state = None;
        engine.started = true;
        engine.serial = u32::MAX;
    }
    result
}

#[cfg(test)]
mod tests;
