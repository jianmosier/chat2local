//! Local-only platform probe. No production auth, device routes or bindings.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use worker::*;

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let namespace = env.durable_object("PROBE")?;
    namespace
        .id_from_name("compatibility-fixture")?
        .get_stub()?
        .fetch_with_request(req)
        .await
}

#[durable_object]
pub struct Probe {
    state: State,
    incarnation: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Attachment {
    version: u32,
    connected_at: f64,
    last_seen_at: f64,
    retired: bool,
    messages: u32,
    connection_access: bool,
    terminal: bool,
}

impl DurableObject for Probe {
    fn new(state: State, _env: Env) -> Self {
        Self {
            state,
            incarnation: js_sys::Math::random().to_string(),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        match req.path().as_str() {
            "/record" => {
                let record = self.state.storage().get::<Value>("identity").await?;
                Response::from_json(&record)
            }
            "/update" => {
                // Preserve unknown JSON fields rather than rebuilding a narrower struct.
                let mut record = self
                    .state
                    .storage()
                    .get::<Value>("identity")
                    .await?
                    .ok_or_else(|| Error::RustError("Fixture missing".into()))?;
                record["description"]["name"] = json!("Rust 更新 🦀");
                // Default serde_wasm_bindgen maps serialize to JS Map and null to
                // undefined. Legacy JS readers require ordinary objects and null.
                let value = record.serialize(&serde_wasm_bindgen::Serializer::json_compatible())?;
                self.state.storage().put_raw("identity", value).await?;
                Response::ok("updated")
            }
            "/counter" => Response::from_json(&self.state.storage().get::<u32>("counter").await?),
            "/increment" => {
                self.state
                    .storage()
                    .transaction(|tx| async move {
                        let current: u32 = tx.get("counter").await?;
                        tx.put("counter", current + 1).await?;
                        Ok(())
                    })
                    .await?;
                Response::ok("incremented")
            }
            "/rollback" => {
                let result = self
                    .state
                    .storage()
                    .transaction(|tx| async move {
                        tx.put("counter", 999_u32).await?;
                        Err(Error::RustError("Injected transaction failure".into()))
                    })
                    .await;
                let reached_injected_failure = result.err().is_some_and(|error| {
                    error.to_string().contains("Injected transaction failure")
                });
                Response::from_json(&json!({"rolledBack": reached_injected_failure}))
            }
            "/connect" => {
                if req.headers().get("Upgrade")?.as_deref() != Some("websocket") {
                    return Response::error("WebSocket required", 400);
                }
                let pair = WebSocketPair::new()?;
                self.state
                    .accept_websocket_with_tags(&pair.server, &["device"]);
                let now = Date::now().as_millis() as f64;
                pair.server.serialize_attachment(Attachment {
                    version: 1,
                    connected_at: now,
                    last_seen_at: now,
                    retired: false,
                    messages: 0,
                    connection_access: true,
                    terminal: true,
                })?;
                Response::from_websocket(pair.client)
            }
            "/sockets" => Response::from_json(&json!({
                "count": self.state.get_websockets_with_tag("device").len(),
                "incarnation": self.incarnation,
            })),
            "/closed" => Response::from_json(&self.state.storage().get::<u32>("closed").await?),
            _ => Response::error("Not found", 404),
        }
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let WebSocketIncomingMessage::String(text) = message else {
            return ws.close(Some(1003), Some("Text messages required"));
        };
        if text != "ping" {
            return ws.close(Some(1008), Some("Probe accepts ping only"));
        }
        let Some(mut lease) = ws.deserialize_attachment::<Attachment>()? else {
            return ws.close(Some(1008), Some("Missing attachment"));
        };
        let now = Date::now().as_millis() as f64;
        if lease.version != 1 || lease.retired || now - lease.last_seen_at >= 75_000.0 {
            return ws.close(Some(1008), Some("Expired attachment"));
        }
        lease.messages += 1;
        lease.last_seen_at = now.max(lease.last_seen_at);
        ws.serialize_attachment(&lease)?;
        ws.send(&json!({"type":"pong", "lease":lease, "incarnation":self.incarnation}))
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        _code: usize,
        _reason: String,
        _clean: bool,
    ) -> Result<()> {
        ws.close(Some(1000), Some("Probe complete"))?;
        self.state.storage().put("closed", 1_u32).await
    }

    async fn websocket_error(&self, ws: WebSocket, _error: Error) -> Result<()> {
        ws.close(Some(1011), Some("Probe socket failed"))
    }
}
