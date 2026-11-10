use super::{
    Error, Result,
    value::{Arena, J},
};
use serde_json::{Value as Json, json};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll, Waker},
};
type Task = Pin<Box<dyn Future<Output = Result<J>>>>;
struct Pending {
    descriptor: Json,
    confirmed: bool,
    result: Option<Result<J>>,
}
#[derive(Default)]
struct State {
    next: u32,
    operation: String,
    active_child: u32,
    emitted: Vec<Json>,
    waiting: BTreeMap<u32, Pending>,
    tasks: Vec<(u32, Option<Task>)>,
    completed: BTreeMap<u32, Result<J>>,
    next_task: u32,
}
#[derive(Clone, Default)]
pub(super) struct C {
    pub arena: Arena,
    state: Rc<RefCell<State>>,
}
impl C {
    pub async fn effect(&self, kind: &str, args: Json) -> Result<J> {
        Effect {
            c: self.clone(),
            kind: kind.into(),
            args,
            id: None,
        }
        .await
    }
    pub fn spawn(&self, f: impl Future<Output = Result<J>> + 'static) -> u32 {
        let mut s = self.state.borrow_mut();
        s.next_task += 1;
        let id = s.next_task;
        s.tasks.push((id, Some(Box::pin(f))));
        id
    }
    pub async fn join(&self, ids: Vec<u32>, settled: bool) -> Result<Vec<J>> {
        Join {
            c: self.clone(),
            ids,
            settled,
        }
        .await
    }
}
struct Effect {
    c: C,
    kind: String,
    args: Json,
    id: Option<u32>,
}
impl Future for Effect {
    type Output = Result<J>;
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(id) = self.id {
            let mut s = self.c.state.borrow_mut();
            return if let Some(v) = s.waiting.get_mut(&id).and_then(|p| p.result.take()) {
                s.waiting.remove(&id);
                Poll::Ready(v)
            } else {
                Poll::Pending
            };
        }
        let id = {
            let mut s = self.c.state.borrow_mut();
            s.next = s.next.checked_add(1).expect("effect IDs");
            let id = s.next;
            let descriptor = json!({"id":id,"operation":s.operation,"child":s.active_child,"kind":self.kind,"args":self.args});
            s.waiting.insert(
                id,
                Pending {
                    descriptor: descriptor.clone(),
                    confirmed: false,
                    result: None,
                },
            );
            s.emitted.push(descriptor);
            id
        };
        self.id = Some(id);
        Poll::Pending
    }
}
struct Join {
    c: C,
    ids: Vec<u32>,
    settled: bool,
}
impl Future for Join {
    type Output = Result<Vec<J>>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let s = self.c.state.borrow();
        let mut values = Vec::new();
        for id in &self.ids {
            match s.completed.get(id) {
                Some(Ok(v)) => values.push(v.clone()),
                Some(Err(Error::Core)) => return Poll::Ready(Err(Error::Core)),
                Some(Err(e)) if !self.settled => return Poll::Ready(Err(e.clone())),
                Some(Err(_)) => values.push(self.c.arena.undef()),
                None => {
                    if self.settled {
                        return Poll::Pending;
                    }
                }
            }
        }
        if self.ids.iter().any(|id| !s.completed.contains_key(id)) {
            Poll::Pending
        } else {
            Poll::Ready(Ok(values))
        }
    }
}
#[derive(Default)]
pub struct Engine {
    serial: u32,
    c: C,
    main: Option<Task>,
    result: Option<Result<J>>,
    started: bool,
}
impl Engine {
    pub(super) fn dispatch(&mut self, input: &[u8]) -> Result<Json> {
        let v: Json = serde_json::from_slice(input).map_err(|_| Error::Core)?;
        self.serial = self.serial.checked_add(1).ok_or(Error::Core)?;
        if v["v"] != 2 || v["serial"] != self.serial {
            return Err(Error::Core);
        }
        match v["command"]["type"].as_str() {
            Some("start") if !self.started => {
                self.started = true;
                let a = self.c.arena.decode(&v["command"]["args"])?;
                let op = v["command"]["operation"]
                    .as_str()
                    .ok_or(Error::Core)?
                    .to_owned();
                self.c.state.borrow_mut().operation = op.clone();
                self.main = Some(Box::pin(super::operations::run(self.c.clone(), op, a)));
            }
            Some("confirm") if self.started => {
                let descriptor = &v["command"]["effect"];
                let id = descriptor["id"]
                    .as_u64()
                    .and_then(|x| u32::try_from(x).ok())
                    .ok_or(Error::Core)?;
                let mut s = self.c.state.borrow_mut();
                let pending = s.waiting.get_mut(&id).ok_or(Error::Core)?;
                if pending.confirmed || pending.descriptor != *descriptor {
                    return Err(Error::Core);
                }
                pending.confirmed = true;
                return Ok(json!({"v":2,"serial":self.serial,"result":{"confirmed":id}}));
            }
            Some("resume") if self.started => {
                let id = v["command"]["id"]
                    .as_u64()
                    .and_then(|x| u32::try_from(x).ok())
                    .ok_or(Error::Core)?;
                let response = &v["command"]["result"];
                let result = if response["ok"] == true {
                    Ok(self.c.arena.decode(&response["value"])?)
                } else if response["ok"] == false {
                    Err(Error::Host {
                        handle: response["handle"]
                            .as_u64()
                            .and_then(|v| u32::try_from(v).ok())
                            .ok_or(Error::Core)?,
                        name: response["name"].as_str().ok_or(Error::Core)?.into(),
                        message: self.c.arena.decode(&response["message"])?.string()?,
                    })
                } else {
                    return Err(Error::Core);
                };
                let mut s = self.c.state.borrow_mut();
                let slot = s.waiting.get_mut(&id).ok_or(Error::Core)?;
                if !slot.confirmed || slot.result.is_some() {
                    return Err(Error::Core);
                }
                if let Ok(value) = &result {
                    validate_primitive(&slot.descriptor, value)?;
                }
                slot.result = Some(result);
            }
            _ => return Err(Error::Core),
        }
        self.poll()?;
        let mut s = self.c.state.borrow_mut();
        let effects = std::mem::take(&mut s.emitted);
        let outcome = match self.result.take() {
            Some(Ok(v)) => Some(json!({"ok":true,"value":v.wire()?})),
            Some(Err(Error::Core)) => return Err(Error::Core),
            Some(Err(e)) => Some(json!({"ok":false,"error":e.wire()})),
            None => None,
        };
        Ok(
            json!({"v":2,"serial":self.serial,"result":{"effects":effects,"outcome":outcome,"drained":self.main.is_none()&&s.tasks.iter().all(|(_,t)|t.is_none())&&s.waiting.is_empty()}}),
        )
    }
    fn poll(&mut self) -> Result<()> {
        let w = Waker::noop();
        let mut cx = Context::from_waker(w);
        loop {
            let before = (
                self.c.state.borrow().next,
                self.c.state.borrow().completed.len(),
            );
            self.c.state.borrow_mut().active_child = 0;
            if let Some(main) = &mut self.main
                && let Poll::Ready(r) = main.as_mut().poll(&mut cx)
            {
                self.result = Some(r);
                self.main = None;
            }
            let mut index = 0;
            loop {
                let task = {
                    let mut s = self.c.state.borrow_mut();
                    if index >= s.tasks.len() {
                        break;
                    }
                    let (id, t) = &mut s.tasks[index];
                    (*id, t.take())
                };
                if let (id, Some(mut t)) = task {
                    self.c.state.borrow_mut().active_child = id;
                    match t.as_mut().poll(&mut cx) {
                        Poll::Ready(r) => {
                            if matches!(r, Err(Error::Core)) {
                                return Err(Error::Core);
                            }
                            self.c.state.borrow_mut().completed.insert(id, r);
                        }
                        Poll::Pending => self.c.state.borrow_mut().tasks[index].1 = Some(t),
                    }
                }
                index += 1;
            }
            let after = (
                self.c.state.borrow().next,
                self.c.state.borrow().completed.len(),
            );
            if before == after {
                break;
            }
        }
        Ok(())
    }
}
fn validate_primitive(effect: &Json, value: &J) -> Result<()> {
    use chat2local_js_value_compat::Value;
    let valid=match effect["kind"].as_str().ok_or(Error::Core)? {
        "kv_get"=>matches!(value.val(),Value::Null|Value::String(_)),
        "kv_put"|"kv_delete"=>value.undefined(),
        "clock"=>matches!(value.val(),Value::Number(_)),
        "import_key"|"generate_key"|"unwrap_key"=>matches!(value.val(),Value::Number(n) if Some(n)==effect["id"].as_f64()),
        "request_text"|"url_set"|"decode_component"=>matches!(value.val(),Value::String(_)),
        "digest"|"sign"|"encrypt"|"decrypt"|"wrap_key"=>matches!(value.val(),Value::String(_))&&crate::value::base64(&value.string()?).is_ok(),
        "random"=>value.array().is_ok_and(|v|Some(v.len() as u64)==effect["args"]["length"].as_u64()&&v.iter().all(|v|matches!(v.val(),Value::Number(n) if (0.0..=255.0).contains(&n)&&n.fract()==0.0))),
        "url"=>matches!(value.val(),Value::Null)||matches!(value.val(),Value::Object(_))&&["href","origin","protocol","hostname","pathname","search","hash"].iter().all(|k|value.get(k).is_ok_and(|v|matches!(v.val(),Value::String(_))))&&value.get("params")?.array().is_ok(),
        "request_form"=>value.array().is_ok_and(|rows|rows.iter().all(|row|row.array().is_ok_and(|p|p.len()==2&&p.iter().all(|v|matches!(v.val(),Value::String(_)))))),
        "kv_list"=>matches!(value.val(),Value::Object(_))&&matches!(value.get("list_complete")?.val(),Value::Bool(_))&&value.get("keys")?.array().is_ok_and(|keys|keys.iter().all(|key|key.get("name").is_ok_and(|v|matches!(v.val(),Value::String(_))))),
        _=>false,
    };
    if valid { Ok(()) } else { Err(Error::Core) }
}
