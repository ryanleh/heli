mod config;
mod keys;

use anyhow::Result;
use clap::Parser;
use config::ExperimentConfig;
use heli::system::Aggregator;
use keys::aggregator_keys;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "aggregator", about = "Run the aggregator server")]
struct Args {
    /// Path to the experiment config JSON file
    config: PathBuf,

    /// Clear stored reports before starting
    #[arg(long)]
    clear_reports: bool,

    /// Fully clear database
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

    // Clear DB if requested
    if args.clear_db {
        info!("Clearing database at {}", config.db_path);
        if std::path::Path::new(&config.db_path).exists() {
            std::fs::remove_dir_all(&config.db_path)?;
        }
    }

    // Open the database
    info!("Opening database at {}", config.db_path);
    let db = sled::open(&config.db_path)?;
    info!("Database opened, {} total keys", db.len());

    // Clear reports if requested
    if args.clear_reports {
        info!("Clearing reports from database");
        let mut count = 0usize;
        let mut batch = sled::Batch::default();
        for key_result in db.scan_prefix(b"r/").keys() {
            if let Ok(key) = key_result {
                batch.remove(key);
                count += 1;
                if count % 100_000 == 0 {
                    info!("Queued {} keys for deletion...", count);
                }
            }
        }
        info!("Applying batch delete of {} keys...", count);
        db.apply_batch(batch)?;
        db.flush()?;
        info!("Cleared {} report keys", count);
    }

    // Load HPKE keys
    let hpke_keys = aggregator_keys();

    let aggregator = Aggregator::new(
        &config.aggregator_addr,
        config.num_clients,
        config.threshold,
        config.prover.to_prover_type(),
        db,
        hpke_keys,
        config.agg_chunk_size,
    );

    info!("Starting aggregator on {}", config.aggregator_addr);
    aggregator.run().await?;

    Ok(())
}
