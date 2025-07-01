use clap::Parser;
use curve25519_dalek::RistrettoPoint;
use hlagg::{net::aggregator::Aggregator, protocol::DiscreteLog};
use std::path::PathBuf;
use tokio::sync::mpsc;

mod config;
use config::Config;

#[derive(Parser)]
#[command(name = "aggregator")]
struct Args {
    #[arg(short, long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Load configuration
    tracing::info!("Starting aggregator with config: {:?}", args.config);
    let config = Config::from_file(&args.config)?;
    let _guard = config.setup_logging("aggregator");
    config.log_startup("aggregator", &args.config);

    // Create a channel for receiving results
    let (result_sender, mut result_receiver) = mpsc::channel(1);

    // Create and run aggregator
    let aggregator = Aggregator::<DiscreteLog<RistrettoPoint>>::new(
        &config.network.aggregator_addr,
        &config.network.decryptor_addr,
        result_sender,
    );

    // Spawn the aggregator in the background and wait for results
    let aggregator_handle = tokio::spawn(async move {
        if let Err(e) = aggregator.run().await {
            tracing::error!("Aggregator error: {}", e);
            panic!("Aggregator error: {}", e);
        }
    });
    tokio::spawn(async move {
        if let Some(results) = result_receiver.recv().await {
            tracing::info!("Received final results: {:?}", results);
        }
    });

    // Wait for the aggregator to complete
    aggregator_handle.await?;

    Ok(())
}
