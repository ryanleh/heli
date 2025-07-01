use clap::Parser;
use curve25519_dalek::RistrettoPoint;
use hlagg::{net::decryptor::Decryptor, protocol::DiscreteLog};
use std::path::PathBuf;

mod config;
use config::Config;

#[derive(Parser)]
#[command(name = "decryptor")]
struct Args {
    #[arg(short, long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Load configuration
    tracing::info!("Starting decryptor with config: {:?}", args.config);
    let config = Config::from_file(&args.config)?;
    let _guard = config.setup_logging("decryptor");
    config.log_startup("decryptor", &args.config);

    // Create and run decryptor
    let decryptor = Decryptor::<DiscreteLog<RistrettoPoint>>::new(
        &config.network.decryptor_addr,
        &config.network.aggregator_addr,
        config.protocol.num_clients,
        config.protocol.length,
    );

    if let Err(e) = decryptor.run().await {
        tracing::error!("Decryptor error: {}", e);
        return Err(e);
    }

    Ok(())
}
