use serde::Deserialize;
use serde_json::json;
use std::io::{Read, Write};
const FRAME: u64 = 1024 * 1024 + 64 * 1024;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    v: u32,
    nonce: String,
    state_dir: String,
    op: String,
    request_id: String,
    record_json: Option<String>,
}
fn main() {
    let mut input = Vec::new();
    if std::io::stdin()
        .take(FRAME + 1)
        .read_to_end(&mut input)
        .is_err()
        || input.len() as u64 > FRAME
    {
        std::process::exit(2);
    }
    let Ok(request) = serde_json::from_slice::<Request>(&input) else {
        std::process::exit(2)
    };
    if request.v != 1 {
        std::process::exit(2);
    }
    let response = match chat2local_agent_platform::terminal_record(
        &request.state_dir,
        &request.op,
        &request.request_id,
        &request.nonce,
        request.record_json.as_deref(),
    ) {
        Ok(result) => json!({"v":1,"nonce":request.nonce,"ok":true,"result":result}),
        Err(error) => json!({"v":1,"nonce":request.nonce,"ok":false,"code":error.code}),
    };
    let output = serde_json::to_vec(&response).expect("fixed response");
    if output.len() as u64 > FRAME {
        std::process::exit(3);
    }
    if std::io::stdout()
        .write_all(&output)
        .and_then(|_| std::io::stdout().flush())
        .is_err()
    {
        std::process::exit(3);
    }
}
