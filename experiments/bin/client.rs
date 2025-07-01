use clap::Parser;
use curve25519_dalek::RistrettoPoint;
use hlagg::{net::client::Client, protocol::DiscreteLog};
use rand::Rng;
use std::path::PathBuf;

mod config;
use config::Config;

#[derive(Parser)]
#[command(name = "client")]
struct Args {
    #[arg(short, long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Load configuration
    tracing::info!("Starting client with config: {:?}", args.config);
    let config = Config::from_file(&args.config)?;
    let _guard = config.setup_logging("client");
    config.log_startup("client", &args.config);

    // Create client
    let mut client = Client::<DiscreteLog<RistrettoPoint>>::new(
        &config.network.decryptor_addr,
        &config.network.aggregator_addr,
    );

    // Register with decryptor
    client.register().await?;

    // Generate random inputs (0 or 1 for each position)
    let mut rng = rand::thread_rng();
    let mut inputs = Vec::with_capacity(config.protocol.length);
    for _ in 0..config.protocol.length {
        inputs.push(rng.gen_bool(0.5) as u32);
    }

    // Send encoding to aggregator with retry logic
    let start_time = std::time::Instant::now();
    let timeout_duration = std::time::Duration::from_secs(10);
    
    loop {
        match client.send_encoding(&inputs).await {
            Ok(()) => {
                tracing::info!("Client sent encoding of {:?} successfully", inputs);
                break;
            }
            Err(e) => {
                if start_time.elapsed() >= timeout_duration {
                    return Err(e.context("Failed to send encoding after 10 seconds"));
                }
                tracing::warn!("Failed to send encoding, retrying in 500ms: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
        }
    }

    Ok(())
}
