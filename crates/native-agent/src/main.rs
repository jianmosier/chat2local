#[tokio::main]
async fn main() {
    if let Err(error) =
        chat2local_agent_controller::native::entry(std::env::args().skip(1).collect()).await
    {
        eprintln!("Native Agent: {}", error.message);
        std::process::exit(1);
    }
}
