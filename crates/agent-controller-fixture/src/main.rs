use chat2local_agent_controller::{
    Options, PlatformConfig,
    fixture::{Hooks, TransportConfig},
    run, version,
};
use std::{
    io::{BufRead, Write},
    sync::Arc,
};
#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--version"] {
        println!("{}", version());
        return;
    }
    let result=async{
        if args.len()<5||args[0]!="--synthetic-state"||args[2]!="--port"||args[4]!="--fixture-only"{return Err("Usage: --synthetic-state ABS --port N --fixture-only [--fixture-transport ABS_JSON] [--control-stdin]".to_string());}
        let directory=std::path::PathBuf::from(&args[1]);
        if std::fs::read(directory.join(".chat2local-synthetic-fixture")).map_err(|e|e.to_string())?!=b"synthetic-only\n"{return Err("Synthetic fixture marker required.".into());}
        let port=args[3].parse::<u16>().map_err(|e|e.to_string())?;
        let mut transport=TransportConfig::default();let mut platform=PlatformConfig::default();let mut control=false;let mut i=5;
        while i<args.len(){match args[i].as_str(){"--control-stdin" if !control=>{control=true;i+=1;},"--fixture-transport"|"--fixture-platform" if i+1<args.len()=>{let path=std::path::Path::new(&args[i+1]);if !path.is_absolute(){return Err("Absolute fixture transport input required.".into());}let bytes=std::fs::read(path).map_err(|e|e.to_string())?;if bytes.len()>512*1024{return Err("Fixture input too large.".into());}
                    if args[i]=="--fixture-platform"{platform=serde_json::from_slice(&bytes).map_err(|e|e.to_string())?;}else{transport=serde_json::from_slice(&bytes).map_err(|e|e.to_string())?;}i+=2;},_=>return Err("Invalid fixture argument.".into())}}
        let hooks=Arc::new(Hooks::default());
        run(Options{directory,port,hooks,transport,platform,publication_delay_ms:std::env::var("CHAT2LOCAL_CONTROLLER_FIXTURE_PUBLICATION_DELAY_MS").ok().map(|s|s.parse::<u64>()).transpose().map_err(|e|e.to_string())?.unwrap_or(0)},move|ready|{
            println!("{}",serde_json::json!({"fixtureOnly":true,"fullAgent":false,"name":chat2local_agent_controller::NAME,"origin":ready.origin,"instanceId":ready.instance_id,"port":ready.port}));
            if control{let runtime=tokio::runtime::Handle::current();std::thread::spawn(move||{
                let stdin=std::io::stdin();let mut input=stdin.lock();
                loop{
                    let mut bytes=Vec::new();let mut oversized=false;
                    loop{let buf=match input.fill_buf(){Ok(v)=>v,Err(_)=>return};if buf.is_empty(){return;}let n=buf.iter().position(|b|*b==b'\n').map(|n|n+1).unwrap_or(buf.len());let done=buf[n-1]==b'\n';if bytes.len()+n>8192{oversized=true;}
                    if !oversized{bytes.extend_from_slice(&buf[..n]);}input.consume(n);if done{break;}}
                    if oversized{println!("{}",serde_json::json!({"control":null,"ok":false,"error":"Control limit exceeded."}));continue;}
                    let v:serde_json::Value=match serde_json::from_slice(&bytes){Ok(v)=>v,Err(_)=>continue};
                    if v["op"]=="platform-browser"{let control=ready.control.clone();runtime.spawn(async move{let output=match control.platform(&v).await{Ok(result)=>serde_json::json!({"control":v["id"],"ok":true,"result":result}),Err(e)=>serde_json::json!({"control":v["id"],"ok":false,"error":e.message})};println!("{output}");let _=std::io::stdout().flush();});continue;}
                    if ["network-prepare","network-system-query"].contains(&v["op"].as_str().unwrap_or("")){let control=ready.control.clone();runtime.spawn(async move{let output=match control.network(&v).await{Ok(result)=>serde_json::json!({"control":v["id"],"ok":true,"result":result}),Err(e)=>serde_json::json!({"control":v["id"],"ok":false,"error":e.message})};println!("{output}");let _=std::io::stdout().flush();});continue;}
                    let output=match ready.control.execute(&v){Ok(result)=>serde_json::json!({"control":v["id"],"ok":true,"result":result}),Err(e)=>serde_json::json!({"control":v["id"],"ok":false,"error":e.message})};
                    println!("{output}");let _=std::io::stdout().flush();
                }
            });}
        }).await.map_err(|e|e.to_string())
    }.await;
    if let Err(error) = result {
        eprintln!("Native controller fixture: {error}");
        std::process::exit(1);
    }
}
