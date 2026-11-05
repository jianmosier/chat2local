use chat2local_protocol::{MAX_MESSAGE_BYTES, Request};
use serde_json::json;
use std::io::{Read, Write};

fn run() -> std::io::Result<()> {
    let mut input = Vec::new();
    std::io::stdin()
        .take((MAX_MESSAGE_BYTES + 1) as u64)
        .read_to_end(&mut input)?;
    if input.len() > MAX_MESSAGE_BYTES {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let request: Request =
        serde_json::from_slice(&input).map_err(|_| std::io::ErrorKind::InvalidData)?;
    let response = match chat2local_agent_platform::execute(&request) {
        Ok(value) => json!({"v": 1, "id": request.id, "ok": true, "result": value}),
        Err(error) => json!({"v": 1, "id": request.id, "ok": false, "error": error}),
    };
    let output = serde_json::to_vec(&response).map_err(|_| std::io::ErrorKind::InvalidData)?;
    if output.len() > MAX_MESSAGE_BYTES {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    std::io::stdout().write_all(&output)
}

fn main() {
    // Never expose paths, request bodies or OS errors through stderr.
    if run().is_err() {
        std::process::exit(1);
    }
}
