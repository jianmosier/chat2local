use chat2local_protocol::{CommitRequest, MAX_MESSAGE_BYTES, WriteRequest};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{BufRead, Write};

fn frame(input: &mut impl BufRead) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        let next = input.fill_buf()?;
        if next.is_empty() {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        let n = next
            .iter()
            .position(|b| *b == b'\n')
            .map_or(next.len(), |n| n + 1);
        if bytes.len() + n > MAX_MESSAGE_BYTES {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        bytes.extend_from_slice(&next[..n]);
        input.consume(n);
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            return Ok(bytes);
        }
    }
}
fn send(value: Value) -> std::io::Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, &value)?;
    out.write_all(b"\n")?;
    out.flush()
}
fn run() -> std::io::Result<()> {
    let mut input = std::io::stdin().lock();
    let raw = frame(&mut input)?;
    let write: WriteRequest =
        serde_json::from_slice(&raw).map_err(|_| std::io::ErrorKind::InvalidData)?;
    let intent = hex::encode(Sha256::digest(&raw));
    let id = &write.request.id;
    let operation_id = &write.operation_id;
    let mut prepared = match chat2local_agent_platform::PreparedWrite::prepare(&write, &intent) {
        Ok(prepared) => prepared,
        Err(error) => {
            return send(
                json!({"v":1,"type":"error","id":id,"operationId":operation_id,"intent":intent,"code":error.code}),
            );
        }
    };
    send(json!({"v":1,"type":"ready","id":id,"operationId":operation_id,"intent":intent}))?;
    let commit: CommitRequest =
        serde_json::from_slice(&frame(&mut input)?).map_err(|_| std::io::ErrorKind::InvalidData)?;
    if commit.id != *id || commit.operation_id != *operation_id || commit.intent != intent {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    match prepared.commit() {
        Ok(result) => send(
            json!({"v":1,"type":"result","id":id,"operationId":operation_id,"intent":intent,"result":result}),
        ),
        Err(error) => send(
            json!({"v":1,"type":"error","id":id,"operationId":operation_id,"intent":intent,"code":error.code}),
        ),
    }
}
fn main() {
    if run().is_err() {
        std::process::exit(1);
    }
}
