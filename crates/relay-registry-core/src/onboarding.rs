use crate::common::{active_session, array_or_empty, numeric, p};
use crate::{Context, Result, Stop, V, fail};
#[derive(Clone, Copy, PartialEq)]
enum CleanupPhase {
    Expiry,
    BindingDelete,
    RowDelete,
    Count,
    Done,
}
pub(crate) struct RecordsCheckpoint {
    input: V,
    list: V,
    rows: Vec<V>,
    prefix_cursor: usize,
    read_id: usize,
    completed: usize,
    phase: CleanupPhase,
    row: usize,
    active: usize,
    key: String,
    binding: String,
}
// Only the two records.put cleanup loops are resumed here. Every saved cursor
// follows an acknowledged effect; a pending effect leaves this cursor unchanged.
fn cleanup_records(cx: &mut Context<'_>, input: &V, list: V) -> Result<()> {
    if !cx.nodes.is_empty() || !cx.patches.is_empty() || cx.next != crate::NEW_BASE {
        return Err(Stop::Invalid);
    }
    let mut state = match cx.records_checkpoint.take() {
        Some(state) => state,
        None => {
            if cx.cursor != cx.observed.len() {
                return Err(Stop::Invalid);
            }
            RecordsCheckpoint {
                input: input.clone(),
                list: list.clone(),
                rows: cx.array(&list)?,
                prefix_cursor: cx.cursor,
                read_id: cx.read_id,
                completed: cx.cursor,
                phase: CleanupPhase::Expiry,
                row: 0,
                active: 0,
                key: String::new(),
                binding: String::new(),
            }
        }
    };
    if state.input != *input
        || state.list != list
        || state.prefix_cursor != cx.cursor
        || state.read_id != cx.read_id
        || state.completed > cx.observed.len()
        || (state.phase != CleanupPhase::Done && cx.observed.len() > state.completed + 1)
    {
        return Err(Stop::Invalid);
    }
    cx.cursor = state.completed;
    let result = (|| {
        loop {
            match state.phase {
                CleanupPhase::Expiry => {
                    if state.row == state.rows.len() {
                        state.row = 0;
                        state.phase = CleanupPhase::Count;
                        continue;
                    }
                    let row = &state.rows[state.row];
                    let item = p(cx, row, "value")?;
                    let until = numeric(&p(cx, &item, "until")?)?;
                    let now = cx.now()?;
                    state.completed = cx.cursor;
                    if until <= now {
                        state.key = p(cx, row, "key")?.text();
                        let binding = p(cx, &item, "bindingId")?;
                        state.phase = if binding.truthy() {
                            state.binding =
                                format!("onboarding:v1:session-binding:{}", binding.text());
                            CleanupPhase::BindingDelete
                        } else {
                            CleanupPhase::RowDelete
                        };
                    } else {
                        state.row += 1;
                    }
                }
                CleanupPhase::BindingDelete => {
                    cx.delete(state.binding.clone())?;
                    state.completed = cx.cursor;
                    state.phase = CleanupPhase::RowDelete;
                }
                CleanupPhase::RowDelete => {
                    cx.delete(state.key.clone())?;
                    state.completed = cx.cursor;
                    state.row += 1;
                    state.phase = CleanupPhase::Expiry;
                }
                CleanupPhase::Count => {
                    if state.row == state.rows.len() {
                        state.phase = CleanupPhase::Done;
                        continue;
                    }
                    let until =
                        numeric(&p(cx, &p(cx, &state.rows[state.row], "value")?, "until")?)?;
                    if until > cx.now()? {
                        state.active += 1;
                    }
                    state.completed = cx.cursor;
                    state.row += 1;
                }
                CleanupPhase::Done => {
                    return if state.active >= 1000 {
                        fail("Too many active account sessions; try later.", 429)
                    } else {
                        Ok(())
                    };
                }
            }
        }
    })();
    cx.records_checkpoint = Some(state);
    result
}
fn flow_key(id: &V) -> String {
    format!("onboarding:v1:flow:{}", id.text())
}
fn reply(cx: &mut Context<'_>, key: &str) -> V {
    cx.object(vec![(key, V::Bool(true))])
}
pub fn execute(cx: &mut Context<'_>, op: &str, input: &V) -> Result<V> {
    cx.branch = op.trim_start_matches("onboarding.").into();
    match op {
        "onboarding.records" => records(cx, input),
        "onboarding.flow.create" => {
            let actor = p(cx, input, "actor")?;
            active_session(cx, &actor)?;
            let rows = cx.rows("onboarding:v1:flow:", 201)?;
            for row in &rows {
                let value = p(cx, row, "value")?;
                if numeric(&p(cx, &value, "until")?)? <= cx.now()? {
                    cx.delete(p(cx, row, "key")?.text())?
                }
            }
            let mut active = 0;
            for row in &rows {
                if numeric(&p(cx, &p(cx, row, "value")?, "until")?)? > cx.now()? {
                    active += 1
                }
            }
            if active >= 200 {
                return fail("Connection setup is busy.", 429);
            }
            cx.put(flow_key(&p(cx, input, "id")?), p(cx, input, "value")?)?;
            Ok(V::Undefined)
        }
        "onboarding.device.provision" => provision(cx, input),
        "onboarding.native.start" => native_start(cx, input),
        "onboarding.finish.take" => {
            active_session(cx, &p(cx, input, "actor")?)?;
            let id = p(cx, input, "flowId")?;
            let latest = cx.read(flow_key(&id))?;
            if !latest.truthy()
                || p(cx, &latest, "finishTaken")?.truthy()
                || p(cx, &latest, "browserHash")? != p(cx, input, "browserHash")?
            {
                return fail("Authorization continuation was already used.", 409);
            }
            cx.set(&latest, "finishTaken", V::Bool(true))?;
            cx.put(flow_key(&id), latest)?;
            Ok(V::Undefined)
        }
        _ => Err(Stop::Invalid),
    }
}
fn records(cx: &mut Context<'_>, input: &V) -> Result<V> {
    let action = p(cx, input, "action")?;
    cx.branch = format!("records-{}", action.text());
    let key = p(cx, input, "key")?;
    let current = cx.read(key.text())?;
    let value = p(cx, input, "value")?;
    if action.is("get") {
        let until = cx.get(&current, "until");
        let now = cx.now()?;
        return Ok(if current.truthy() && numeric(&until)? > now {
            p(cx, &current, "value")?
        } else {
            V::Null
        });
    }
    if action.is("take") {
        if !current.truthy()
            || numeric(&p(cx, &current, "until")?)? <= cx.now()?
            || !cx.get(&value, "browserHash").hex(64)
            || p(cx, &value, "browserHash")? != p(cx, &p(cx, &current, "value")?, "browserHash")?
        {
            return fail(
                "Identity callback expired or belongs to another browser.",
                401,
            );
        }
        cx.delete(key.text())?;
        return p(cx, &current, "value");
    }
    if action.is("delete") {
        let binding = cx.get(&current, "bindingId");
        if binding.truthy() {
            cx.delete(format!("onboarding:v1:session-binding:{}", binding.text()))?
        }
        cx.delete(key.text())?;
        return Ok(reply(cx, "deleted"));
    }
    if !action.is("put") {
        return Err(Stop::Invalid);
    }
    let ttl = p(cx, input, "ttl")?;
    let valid = matches!(ttl, V::Number(_))
        && ttl.number().is_finite()
        && ttl.number().fract() == 0.0
        && (1.0..=43200.0).contains(&ttl.number());
    if !valid || numeric(&cx.compute("jsonLength", value.clone())?)? > 16000.0 || current.truthy() {
        return fail("Invalid or duplicate identity record.", 400);
    }
    let kind = p(cx, input, "kind")?;
    let rows = cx.rows_ref(&format!("onboarding:v1:{}:", kind.text()), 1025)?;
    cleanup_records(cx, input, rows)?;
    let until = cx.now()? + ttl.number() * 1000.0;
    let binding = p(cx, input, "binding")?;
    let mut fields = vec![("value", value.clone()), ("until", V::num(until))];
    if binding.truthy() {
        fields.push(("bindingId", p(cx, &binding, "id")?))
    }
    let record = cx.object(fields);
    cx.put(key.text(), record)?;
    if binding.truthy() {
        let bounded = until.min(numeric(&p(cx, &value, "expiresAt")?)?);
        let record = cx.object(vec![
            ("identityKey", p(cx, &binding, "identityKey")?),
            ("until", V::num(bounded)),
        ]);
        cx.put(
            format!(
                "onboarding:v1:session-binding:{}",
                p(cx, &binding, "id")?.text()
            ),
            record,
        )?
    }
    Ok(reply(cx, "saved"))
}
fn provision(cx: &mut Context<'_>, input: &V) -> Result<V> {
    let id = p(cx, input, "flowId")?;
    let flow = cx.read(flow_key(&id))?;
    if flow.truthy() {
        active_session(cx, &p(cx, &flow, "actor")?)?
    }
    if !flow.truthy()
        || p(cx, &flow, "bootstrapHash")? != p(cx, input, "proofHash")?
        || cx.now()? > numeric(&p(cx, &flow, "createdAt")?)? + 300000.0
    {
        return fail("Sign in before registering a computer.", 401);
    }
    let device = p(cx, input, "deviceId")?;
    let session = p(cx, input, "sessionHash")?;
    let hash = p(cx, input, "keyHash")?;
    let provision = p(cx, &flow, "provision")?;
    let bound = p(cx, &flow, "device")?;
    if bound.truthy()
        && (!provision.truthy()
            || p(cx, &bound, "deviceId")? != device
            || p(cx, &flow, "nativeHash")? != session)
    {
        return fail(
            "This setup is already bound to another native identity.",
            403,
        );
    }
    if provision.truthy()
        && (p(cx, &provision, "deviceId")? != device
            || p(cx, &provision, "keyHash")? != hash
            || p(cx, &provision, "sessionHash")? != session)
    {
        return fail(
            "This setup is already bound to another native identity.",
            403,
        );
    }
    let registration = cx.read(format!("device:{}", device.text()))?;
    let account = p(cx, &flow, "accountId")?;
    if registration.truthy() {
        if !p(cx, &registration, "kind")?.is("account")
            || p(cx, &registration, "accountId")? != account
            || p(cx, &registration, "keyHash")? != hash
        {
            return fail("Existing device identity cannot be replaced.", 409);
        }
    } else {
        let raw = cx.read("deviceCount".into())?;
        let count = if raw.truthy() { numeric(&raw)? } else { 0.0 };
        let index = format!("onboarding:v1:registered:{}", account.text());
        let raw = cx.read(index.clone())?;
        let mut owned = array_or_empty(cx, &raw)?;
        if count >= 100.0 || owned.len() >= 20 {
            return fail("Account or service device limit reached.", 429);
        }
        let record = cx.object(vec![
            ("kind", V::str("account")),
            ("accountId", account),
            ("keyHash", hash.clone()),
        ]);
        cx.put(format!("device:{}", device.text()), record)?;
        cx.put("deviceCount".into(), V::num(count + 1.0))?;
        owned.push(device.clone());
        let owned = cx.list(owned);
        cx.put(index, owned)?;
    }
    let provision = cx.object(vec![
        ("deviceId", device),
        ("keyHash", hash),
        ("sessionHash", session),
    ]);
    cx.set(&flow, "provision", provision)?;
    cx.put(flow_key(&id), flow)?;
    Ok(reply(cx, "reserved"))
}
fn native_start(cx: &mut Context<'_>, input: &V) -> Result<V> {
    let id = p(cx, input, "flowId")?;
    let item = cx.read(flow_key(&id))?;
    if item.truthy() {
        active_session(cx, &p(cx, &item, "actor")?)?
    }
    if !item.truthy()
        || numeric(&p(cx, &item, "until")?)? <= cx.now()?
        || p(cx, &item, "bootstrapHash")? != p(cx, input, "credentialHash")?
        || cx.now()? > numeric(&p(cx, &item, "createdAt")?)? + 300000.0
    {
        return fail("This account setup link expired.", 401);
    }
    let device = p(cx, input, "device")?;
    let hash = p(cx, input, "nativeHash")?;
    let provision = p(cx, &item, "provision")?;
    if provision.truthy()
        && (p(cx, &provision, "deviceId")? != p(cx, &device, "deviceId")?
            || p(cx, &provision, "sessionHash")? != hash)
    {
        return fail("Native enrollment receipt does not match.", 403);
    }
    let previous = p(cx, &item, "device")?;
    if previous.truthy()
        && (p(cx, &previous, "deviceId")? != p(cx, &device, "deviceId")?
            || p(cx, &previous, "epoch")? != p(cx, &device, "epoch")?
            || p(cx, &item, "nativeHash")? != hash)
    {
        return fail("Setup link already belongs to another native session.", 403);
    }
    let selected = cx.object(vec![
        ("deviceId", p(cx, &device, "deviceId")?),
        ("epoch", p(cx, &device, "epoch")?),
    ]);
    cx.set(&item, "device", selected)?;
    cx.set(&item, "nativeHash", hash)?;
    cx.put(flow_key(&id), item.clone())?;
    Ok(item)
}
