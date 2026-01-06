mod config;
mod keys;

use anyhow::Result;
use clap::Parser;
use config::ExperimentConfig;
use heli::system::Decryptor;
use keys::decryptor_keys;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "decryptor", about = "Run the decryptor server")]
struct Args {
    /// Path to the experiment config JSON file
    config: PathBuf,

    /// Clear the database before starting (for fresh runs)
    #[arg(long)]
    clear_db: bool,
}

fn init_tracing() {
    let filter = EnvFilter::from_default_env()
        .add_directive("sled=off".parse().unwrap())
        .add_directive("heli=info".parse().unwrap());

    tracing_subscriber::fmt().with_env_filter(filter).init();
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

    let config = ExperimentConfig::from_file(&args.config)?;
    info!("Loaded config: {:?}", config);

    // Load HPKE keys
    let hpke_keys = decryptor_keys();

    // Derive decryptor's db path from main db path
    let decryptor_db_path = format!("{}_decryptor", config.db_path);

    // Clear database if requested
    if args.clear_db {
        info!("Clearing database at {}", decryptor_db_path);
        if std::path::Path::new(&decryptor_db_path).exists() {
            std::fs::remove_dir_all(&decryptor_db_path)?;
        }
    }

    // Open the database
    let db = sled::open(&decryptor_db_path)?;

    let decryptor = Decryptor::new(
        &config.decryptor_addr,
        &config.aggregator_addr,
        config.num_clients,
        config.threshold,
        hpke_keys,
        db,
    );

    info!("Starting decryptor on {}", config.decryptor_addr);
    decryptor.run().await?;

    Ok(())
}
