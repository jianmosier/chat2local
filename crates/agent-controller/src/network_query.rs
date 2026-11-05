//! Fixed current-user .NET proxy primitive, with independently owned child drainage.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
#[cfg(feature = "fixture")]
use serde_json::json;
use std::{
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::watch,
    time::Instant,
};
const SCRIPT: &str = "$ErrorActionPreference='Stop'; $u=[Uri]([Console]::In.ReadToEnd()); $p=[Net.WebRequest]::GetSystemWebProxy(); $r=$p.GetProxy($u); if($null -eq $r -or $r.AbsoluteUri -eq $u.AbsoluteUri){@{proxy='';source='system-direct'}|ConvertTo-Json -Compress}else{@{proxy=$r.AbsoluteUri;source='system-proxy'}|ConvertTo-Json -Compress}";
#[cfg(feature = "fixture")]
const FIXTURE_SCRIPT: &str = "$ErrorActionPreference='Stop';$v=([Console]::In.ReadToEnd()|ConvertFrom-Json);if($v.delayMs -gt 0){Start-Sleep -Milliseconds $v.delayMs};switch($v.mode){'direct'{@{proxy='';source='system-direct'}|ConvertTo-Json -Compress}'proxy'{@{proxy=$v.proxy;source='system-proxy'}|ConvertTo-Json -Compress}'invalid'{[Console]::Out.Write('invalid')}'nonzero'{exit 7}'overflow'{[Console]::Out.Write(('x'*9000))}'stall'{Start-Sleep -Seconds 30}default{exit 9}}";
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mode {
    pub mode: String,
    #[serde(default)]
    pub delay_ms: u64,
    #[serde(default)]
    pub proxy: String,
}
impl Default for Mode {
    fn default() -> Self {
        Self {
            mode: "normal".into(),
            delay_ms: 0,
            proxy: String::new(),
        }
    }
}
impl Mode {
    #[cfg(feature = "fixture")]
    pub fn validate(&self) -> Result<()> {
        if ![
            "normal", "direct", "proxy", "invalid", "nonzero", "overflow", "stall",
        ]
        .contains(&self.mode.as_str())
            || self.delay_ms > 10000
            || self.proxy.len() > 2048
        {
            return Err(Error::new(400, "Invalid bounded query fixture."));
        }
        Ok(())
    }
}
#[derive(Default)]
pub struct Observations {
    pub starts: AtomicUsize,
    pub active: AtomicUsize,
    pub pids: Mutex<Vec<u32>>,
}
fn refused() -> Error {
    Error::new(
        400,
        "无法读取系统代理，请检查网络设置，或在本面板选择直连／指定代理。不会静默改为直连。",
    )
}
pub async fn query(
    origin: String,
    mode: Mode,
    mut revision: watch::Receiver<u64>,
    expected: u64,
    observations: Arc<Observations>,
    #[cfg(feature = "fixture")] hooks: Arc<crate::fixture::Hooks>,
) -> Result<String> {
    if *revision.borrow() != expected {
        return Err(refused());
    }
    let trusted = chat2local_agent_platform::system_powershell().map_err(|_| refused())?;
    let mut command = tokio::process::Command::new(&trusted.path);
    command.env_clear();
    for key in [
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
    ] {
        if let Some(v) = std::env::var_os(key) {
            command.env(key, v);
        }
    }
    #[cfg(feature = "fixture")]
    let (script, input) = if mode.mode == "normal" {
        (SCRIPT, origin)
    } else {
        (
            FIXTURE_SCRIPT,
            json!({"origin":origin,"mode":mode.mode,"delayMs":mode.delay_ms,"proxy":mode.proxy})
                .to_string(),
        )
    };
    #[cfg(not(feature = "fixture"))]
    let (script, input) = {
        let _ = mode;
        (SCRIPT, origin)
    };
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    let mut child = command.spawn().map_err(|_| refused())?;
    drop(command);
    let pid = child.id().ok_or_else(refused)?;
    observations.starts.fetch_add(1, Ordering::SeqCst);
    observations.active.fetch_add(1, Ordering::SeqCst);
    observations.pids.lock().unwrap().push(pid);
    let mut stdin = child.stdin.take().ok_or_else(refused)?;
    let stdout = child.stdout.take().ok_or_else(refused)?;
    let writer = tokio::spawn(async move {
        stdin.write_all(input.as_bytes()).await?;
        stdin.shutdown().await
    });
    let mut reader = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stdout
            .take(8193)
            .read_to_end(&mut bytes)
            .await
            .map(|_| bytes)
    });
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut output = None;
    let mut status = None;
    let first = tokio::select! {biased;_=revision.changed()=>false,_=tokio::time::sleep_until(deadline)=>false,r=&mut reader=>{output=Some(r);true},s=child.wait()=>{status=Some(s);true}};
    let valid_output = output.as_ref().is_none_or(|r| {
        r.as_ref()
            .is_ok_and(|r| r.as_ref().is_ok_and(|b| b.len() <= 8192))
    });
    let mut success = first && valid_output && *revision.borrow() == expected;
    if success && status.is_none() {
        status = tokio::select! {biased;_=revision.changed()=>None,_=tokio::time::sleep_until(deadline)=>None,s=child.wait()=>Some(s)};
    }
    success &= status
        .as_ref()
        .is_some_and(|s| s.as_ref().is_ok_and(|s| s.success()))
        && *revision.borrow() == expected;
    if !success {
        // The owned test barrier precedes real cancellation/reaping. No Host or
        // Service mutex is held, and the Child and pipe tasks remain owned here.
        #[cfg(feature = "fixture")]
        hooks.wait_async("network:drain").await;
        let _ = child.start_kill();
    }
    // Cancellation requests do not release the process or pipe owner. A wait
    // error retains the actual Child and retries until closure is proved.
    if status.as_ref().is_none_or(|s| s.is_err()) {
        loop {
            match child.wait().await {
                Ok(_) => break,
                Err(_) => {
                    let _ = child.start_kill();
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    let written = writer.await.is_ok_and(|r| r.is_ok());
    let output = match output {
        Some(v) => v,
        None => reader.await,
    };
    observations.pids.lock().unwrap().retain(|p| *p != pid);
    observations.active.fetch_sub(1, Ordering::SeqCst);
    drop(trusted);
    let bytes = output.map_err(|_| refused())?.map_err(|_| refused())?;
    if !success || !written || bytes.len() > 8192 {
        return Err(refused());
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| refused())?;
    let proxy = value["proxy"].as_str().ok_or_else(refused)?;
    if !proxy.is_empty() {
        chat2local_agent_transport::Proxy::parse(proxy, true).map_err(|_| refused())?;
    }
    Ok(proxy.to_owned())
}
