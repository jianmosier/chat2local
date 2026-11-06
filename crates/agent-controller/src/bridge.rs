//! Persistent Bridge resources execute lifecycle effects once, outside the core lock.
use crate::{Error, Result, management, runtime::Host, tools};
use chat2local_agent_transport::{HttpRequest, Limits, Target, WsEvent, WsSender};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{sync::mpsc, task::JoinSet};
pub use tools::Call;
#[derive(Clone, PartialEq, Eq)]
struct Token {
    generation: String,
    attempt: String,
}
impl Token {
    fn from(effect: &Value) -> Result<Self> {
        Ok(Self {
            generation: effect["generation"]
                .as_str()
                .ok_or_else(|| Error::new(503, "Invalid effect token."))?
                .into(),
            attempt: effect["attempt"]
                .as_str()
                .ok_or_else(|| Error::new(503, "Invalid effect token."))?
                .into(),
        })
    }
    fn command(&self, op: &str) -> Value {
        json!({"op":op,"generation":self.generation,"attempt":self.attempt})
    }
    fn event(&self, host: &Host, event: &str) {
        if host.faulted() || host.closing.load(Ordering::SeqCst) {
            return;
        }
        let mut jitter = [0u8; 2];
        if openssl::rand::rand_bytes(&mut jitter).is_err() {
            host.poison();
            return;
        }
        let mut c = self.command("bridgeEvent");
        c["event"] = json!(event);
        c["now"] = json!(management::now() as u64);
        c["jitter"] = json!(u16::from_le_bytes(jitter) % 500);
        let _ = host.command(c);
    }
}
pub struct Socket {
    token: Token,
    identity: tools::Identity,
    open: AtomicBool,
    network: Arc<crate::network::Prepared>,
    out: mpsc::Sender<Outbound>,
}
impl Socket {
    pub fn current(&self, host: &Host) -> bool {
        self.permit(host) && self.identity(host)
    }
    pub fn with_current<T>(
        &self,
        host: &Host,
        call: &Call,
        expected: &str,
        work: impl FnOnce(&mut crate::runtime::State) -> Result<T>,
    ) -> Result<T> {
        let mut core = host.core.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = self.token.command("replyPermit");
        command["open"] = json!(self.open.load(Ordering::SeqCst));
        let permit = host.execute_locked(&mut core, &command);
        if let Err(error) = permit {
            drop(core);
            host.poison();
            return Err(error);
        }
        if permit.unwrap()["result"] != true {
            return Err(Error::new(
                403,
                "Original Bridge attempt is no longer current.",
            ));
        }
        let mut state = host.lock_state();
        if host.faulted()
            || host.closing.load(Ordering::SeqCst)
            || tools::identity(&state.secrets).map_or(true, |i| i != self.identity)
            || tools::prepare(&state, call).map_or(true, |p| p.fingerprint != expected)
        {
            return Err(Error::new(
                403,
                "Current authority no longer permits this result.",
            ));
        }
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            #[cfg(feature = "fixture")]
            host.hooks.check("business")?;
            work(&mut state)
        })) {
            Ok(result) => result,
            Err(panic) => {
                // Freeze dispatch before unwinding the held authority guards. The owned
                // business task then observes JoinError and applies the recovery overlay.
                host.latch_while_locked(&mut core);
                std::panic::resume_unwind(panic)
            }
        }
    }
    fn permit(&self, host: &Host) -> bool {
        if host.faulted()
            || host.closing.load(Ordering::SeqCst)
            || !self.open.load(Ordering::SeqCst)
        {
            return false;
        }
        let mut c = self.token.command("replyPermit");
        c["open"] = json!(true);
        host.command(c).is_ok_and(|v| v["result"] == true)
    }
    fn identity(&self, host: &Host) -> bool {
        tools::identity(&host.lock_state().secrets).is_ok_and(|id| id == self.identity)
    }
    fn send(&self, host: &Host, out: Outbound) {
        if self.permit(host) && self.identity(host) && self.out.try_send(out).is_err() {
            self.token.event(host, "failed");
        }
    }
}
struct Guard(Arc<Socket>);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.open.store(false, Ordering::SeqCst);
    }
}
enum Outbound {
    Ping,
    Flush,
    Reply {
        call: Call,
        body: String,
        fingerprint: Option<String>,
    },
}
pub struct Pending {
    socket: Arc<Socket>,
    call: Call,
    body: String,
    fingerprint: Option<String>,
}
impl Pending {
    pub async fn deliver(self, host: &Arc<Host>) {
        self.socket.send(
            host,
            Outbound::Reply {
                call: self.call,
                body: self.body,
                fingerprint: self.fingerprint,
            },
        );
    }
}
fn error(id: &str, error: &str) -> String {
    json!({"kind":"result","id":id,"error":error}).to_string()
}
pub async fn dispatch(host: &Arc<Host>, call: Call, socket: Arc<Socket>) -> Option<Pending> {
    if !socket.permit(host) || !socket.identity(host) {
        return None;
    }
    {
        let mut core = host.core.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = socket.token.command("replyPermit");
        command["open"] = json!(socket.open.load(Ordering::SeqCst));
        let permit = host.execute_locked(&mut core, &command);
        if permit.is_err() {
            drop(core);
            host.poison();
            return None;
        }
        let mut state = host.lock_state();
        if permit.ok()?["result"] != true
            || host.closing.load(Ordering::SeqCst)
            || tools::identity(&state.secrets).ok().as_ref() != Some(&socket.identity)
        {
            return None;
        }
        crate::guide::observe(&mut state, &call);
    }
    let (body, fingerprint) = match tools::execute(host, &call, &socket).await {
        Ok((result, fingerprint)) => (
            format!(
                "{{\"kind\":\"result\",\"id\":{},\"result\":{result}}}",
                json!(call.id)
            ),
            Some(fingerprint),
        ),
        Err(e) => (error(&call.id, &e.message), None),
    };
    Some(Pending {
        socket,
        call,
        body,
        fingerprint,
    })
}
async fn writer(
    weak: Weak<Host>,
    socket: Arc<Socket>,
    mut sender: WsSender,
    mut receive: mpsc::Receiver<Outbound>,
) -> Result<()> {
    while let Some(out) = receive.recv().await {
        if matches!(out, Outbound::Flush) {
            sender
                .flush()
                .await
                .map_err(|_| Error::new(503, "Socket flush failed."))?;
            continue;
        }
        #[cfg(feature = "fixture")]
        if matches!(out, Outbound::Reply { .. })
            && let Some(host) = weak.upgrade()
        {
            host.hooks.wait_async("reply").await;
        }
        sender
            .ready()
            .await
            .map_err(|_| Error::new(503, "Socket write readiness failed."))?;
        let Some(host) = weak.upgrade() else { break };
        if !socket.permit(&host) {
            continue;
        }
        // No await between the final authority check and synchronous socket submission.
        {
            let mut core = host.core.lock().unwrap_or_else(|e| e.into_inner());
            let mut permit = socket.token.command("replyPermit");
            permit["open"] = json!(socket.open.load(Ordering::SeqCst));
            let allowed = host.execute_locked(&mut core, &permit);
            if allowed.as_ref().map_or(true, |v| v["result"] != true) {
                drop(core);
                if allowed.is_err() {
                    host.poison();
                }
                continue;
            }
            let state = host.lock_state();
            if host.faulted()
                || host.closing.load(Ordering::SeqCst)
                || !socket.open.load(Ordering::SeqCst)
                || tools::identity(&state.secrets).map_or(true, |i| i != socket.identity)
            {
                continue;
            }
            let text = match out {
                Outbound::Ping => "ping".into(),
                Outbound::Reply {
                    call,
                    body,
                    fingerprint,
                } => {
                    if let Some(expected) = fingerprint
                        && tools::prepare(&state, &call).map_or(true, |p| p.fingerprint != expected)
                    {
                        continue;
                    }
                    body
                }
                Outbound::Flush => unreachable!(),
            };
            sender
                .start_text(text)
                .map_err(|_| Error::new(503, "Socket submission failed."))?;
        }
        drop(host);
        sender
            .flush()
            .await
            .map_err(|_| Error::new(503, "Socket flush failed."))?;
    }
    let _ = sender.close().await;
    Ok(())
}
async fn connection(
    weak: Weak<Host>,
    socket: Arc<Socket>,
    target: Target,
    receive: mpsc::Receiver<Outbound>,
) {
    let _guard = Guard(socket.clone());
    let Some(host) = weak.upgrade() else {
        return;
    };
    let mut attempt = match host.network.attempt(&socket.network) {
        Ok(a) => a,
        Err(_) => {
            socket.token.event(&host, "failed");
            return;
        }
    };
    attempt.set_publication_gate(host.network.guard(
        weak.clone(),
        socket.network.clone(),
        Some(socket.identity.clone()),
        Some(socket.token.command("snapshot")),
    ));
    let mut protocols = format!(
        "chat2local-v1, device.{}, connection-access-v1",
        socket.identity.key
    );
    if host.terminal.available() {
        protocols.push_str(", terminal-jobs-v1");
    }
    let transport = host.network.config.transport.clone();
    drop(host);
    let connected = transport
        .websocket_connect(
            &socket.network.plan,
            &target,
            socket.network.profile,
            vec![("sec-websocket-protocol".into(), protocols)],
            &mut attempt,
        )
        .await;
    let Ok((sender, mut receiver)) = connected else {
        if let Some(host) = weak.upgrade() {
            host.lock_state().bridge_warning = Some(connected.err().unwrap().to_string());
            socket.token.event(&host, "failed");
        }
        return;
    };
    let Some(owner) = weak.upgrade() else {
        return;
    };
    let gate = owner.network.guard(
        weak.clone(),
        socket.network.clone(),
        Some(socket.identity.clone()),
        Some(socket.token.command("snapshot")),
    );
    if !gate(&mut || socket.open.store(true, Ordering::SeqCst)) {
        socket.token.event(&owner, "failed");
        return;
    }
    drop(owner);
    if let Some(host) = weak.upgrade() {
        host.lock_state().bridge_warning = None;
        socket.token.event(&host, "open");
    } else {
        return;
    }
    let reader = async {
        loop {
            let frame = receiver
                .receive()
                .await
                .map_err(|_| Error::new(400, "Invalid Bridge frame."))?;
            let Some(host) = weak.upgrade() else {
                return Ok::<(), Error>(());
            };
            match frame {
                WsEvent::Closed => return Ok(()),
                WsEvent::Control => {
                    if socket.out.try_send(Outbound::Flush).is_err() {
                        return Err(Error::new(429, "Socket control capacity reached."));
                    }
                }
                WsEvent::Text(raw) => {
                    if raw == "pong" {
                        socket.token.event(&host, "pong");
                        continue;
                    }
                    let Ok(call) = Call::parse(&raw) else {
                        continue;
                    };
                    if !socket.permit(&host) || !socket.identity(&host) {
                        continue;
                    }
                    let mut c = socket.token.command("bridgeCall");
                    c["id"] = json!(call.id);
                    let Ok(admission) = host.command(c) else {
                        continue;
                    };
                    if admission["result"] == "duplicate" {
                        let body = error(&call.id, "Duplicate command identifier.");
                        socket.send(
                            &host,
                            Outbound::Reply {
                                call,
                                body,
                                fingerprint: None,
                            },
                        );
                    } else if admission["result"] == "execute" {
                        // The lifecycle owns duplicate admission and the aggregate 24-ticket FIFO.
                        let id = call.id.clone();
                        if let Err(e) = host.remote(call, socket.clone()) {
                            // A refusal has no sensitive result and remains bound to this socket.
                            let fallback =
                                Call::parse(&format!("{{\"kind\":\"call\",\"id\":{}}}", json!(id)))
                                    .unwrap();
                            socket.send(
                                &host,
                                Outbound::Reply {
                                    call: fallback,
                                    body: error(&id, &e.message),
                                    fingerprint: None,
                                },
                            );
                        }
                    }
                }
            }
        }
    };
    tokio::select! {_=reader=>{},_=writer(weak.clone(),socket.clone(),sender,receive)=>{}}
    if let Some(host) = weak.upgrade() {
        socket.token.event(&host, "close");
    }
}
struct Prepared {
    token: Token,
    identity: tools::Identity,
    network: Arc<crate::network::Prepared>,
    target: Target,
}
async fn retire(tasks: &mut JoinSet<()>, socket: &mut Option<Arc<Socket>>) {
    if let Some(socket) = socket.take() {
        socket.open.store(false, Ordering::SeqCst);
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}
pub async fn run(weak: Weak<Host>, mut effects: mpsc::Receiver<Value>) {
    let Some(host) = weak.upgrade() else {
        return;
    };
    let mut stop = host.bridge_stop.subscribe();
    drop(host);
    let mut tasks = JoinSet::new();
    let mut preparing = JoinSet::new();
    let mut timers = JoinSet::new();
    let mut socket: Option<Arc<Socket>> = None;
    let mut prepared: Option<Prepared> = None;
    let (prepared_send, mut prepared_receive) = mpsc::channel::<(Token, Result<Prepared>)>(4);
    loop {
        if *stop.borrow() {
            break;
        }
        tokio::select! {biased;
            _=stop.changed()=>break,
            Some(result)=preparing.join_next(),if !preparing.is_empty()=>{if result.is_err()&&let Some(host)=weak.upgrade(){host.poison();}},
            Some(result)=tasks.join_next(),if !tasks.is_empty()=>{if result.is_err()&&let Some(host)=weak.upgrade(){host.poison();}},
            Some(result)=timers.join_next(),if !timers.is_empty()=>{if result.is_err()&&let Some(host)=weak.upgrade(){host.poison();}},
            Some((token,result))=prepared_receive.recv()=>{if let Some(host)=weak.upgrade(){let snapshot=host.command(json!({"op":"snapshot"}));if snapshot.is_ok_and(|s|s["result"]["bridge"]["generation"]==token.generation&&s["result"]["bridge"]["attempt"]==token.attempt){match result{Ok(p)=>{prepared=Some(p);token.event(&host,"prepared");},Err(e)=>{host.lock_state().bridge_warning=Some(e.message);token.event(&host,"failed");}}}}},
            effect=effects.recv()=>{
                let Some(effect)=effect else{break;};let Some(host)=weak.upgrade()else{break;};
                if host.faulted(){break;}
                #[cfg(feature="fixture")] if std::panic::catch_unwind(std::panic::AssertUnwindSafe(||host.hooks.check("effect"))).map_or(true,|r|r.is_err()){host.poison();break;}
                let kind=effect["type"].as_str().unwrap_or("");
                if kind=="clearBridge"{retire(&mut tasks,&mut socket).await;preparing.abort_all();while preparing.join_next().await.is_some(){}timers.abort_all();while timers.join_next().await.is_some(){}prepared=None;continue;}
                let token=match Token::from(&effect){Ok(t)=>t,Err(_)=>{host.poison();break;}};
                match kind{
                    "armTimer"=>{
                        if timers.len()>=4{host.poison();break;}
                        let Some(at)=effect["at"].as_u64()else{host.poison();break;};let Some(event)=effect["timer"].as_str()else{host.poison();break;};let event=event.to_owned();let weak=weak.clone();
                        timers.spawn(async move{tokio::time::sleep(Duration::from_millis(at.saturating_sub(management::now() as u64))).await;if let Some(host)=weak.upgrade(){token.event(&host,&event);}});
                    },
                    "cancelTimers"=>{timers.abort_all();while timers.join_next().await.is_some(){}},
                    "retireAttempt"=>{retire(&mut tasks,&mut socket).await;preparing.abort_all();while preparing.join_next().await.is_some(){}timers.abort_all();while timers.join_next().await.is_some(){}prepared=None;},
                    "prepareNetwork"=>{
                        let send=prepared_send.clone();let token=token.clone();let owner=host.clone();
                        preparing.spawn(async move{let result=async{let identity=tools::identity(&owner.lock_state().secrets)?;let target=Target::parse(&format!("{}/device/{}/connect",identity.origin.replacen("http","ws",1),identity.device)).map_err(|_|Error::new(400,"Invalid Bridge origin."))?;let network=owner.network.prepare(&owner,&identity.origin,false).await?;Ok(Prepared{token:token.clone(),identity,network,target})}.await;let _=send.send((token,result)).await;});                    },
                    "openSocket"=>{
                        let Some(p)=prepared.take().filter(|p|p.token==token)else{host.poison();break;};
                        if !tasks.is_empty()||socket.is_some(){host.poison();break;}
                        let (out,receive)=mpsc::channel(32);let s=Arc::new(Socket{token,identity:p.identity,open:AtomicBool::new(false),network:p.network,out});socket=Some(s.clone());tasks.spawn(connection(weak.clone(),s,p.target,receive));
                    },
                    "sendPing"=>{if let Some(s)=socket.as_ref().filter(|s|s.token==token){s.send(&host,Outbound::Ping);}},
                    "publishMetadata"=>{
                        let Some(s)=socket.as_ref().filter(|s|s.token==token)else{continue;};
                        if tasks.len()>=2{host.poison();break;}
                        let identity=s.identity.clone();let network=s.network.clone();let token=s.token.command("snapshot");let owner=host.clone();
                        if let Ok(target)=Target::parse(&format!("{}/device/{}/metadata",identity.origin,identity.device))&&let Ok(description)=tools::description(){tasks.spawn(async move{let Ok(mut attempt)=owner.network.attempt(&network)else{return;};attempt.set_publication_gate(owner.network.guard(Arc::downgrade(&owner),network.clone(),Some(identity.clone()),Some(token)));let _=owner.network.config.transport.request_once(&network.plan,&target,network.profile,HttpRequest{method:"POST".into(),headers:vec![("authorization".into(),format!("Bearer {}",identity.key)),("content-type".into(),"application/json".into())],body:description.to_string().into_bytes()},Limits{timeout:Duration::from_secs(5),body_bytes:512*1024},&mut attempt).await;});}                    },
                    _=>{host.poison();break;}
                }
            }
        }
    }
    preparing.abort_all();
    while preparing.join_next().await.is_some() {}
    retire(&mut tasks, &mut socket).await;
    timers.abort_all();
    while timers.join_next().await.is_some() {}
}
