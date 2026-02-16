mod config;
mod keys;

use anyhow::{Result, anyhow};
use clap::Parser;
use config::{ExperimentConfig, ProverConfig};
use heli::{
    crypto::hpke::HpkeEnvelope,
    system::{
        Client,
        messages::{
            Message, bytes_recv, bytes_sent, read_message, reset_byte_counters, write_message,
        },
    },
};
use keys::{aggregator_keys, decryptor_keys};
use rand::{Rng, SeedableRng, rngs::StdRng, seq::SliceRandom};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sled::{Db, IVec};
use std::{
    collections::HashSet,
    path::PathBuf,
    sync::Arc,
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};
use tokio::{net::TcpStream, sync::Semaphore, task::JoinSet};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

const BATCH_REPORT_SIZE: usize = 1024;
const CLIENT_DB_PATH: &str = "/tmp/heli_client.db";

#[derive(Parser, Debug)]
#[command(name = "client")]
struct Args {
    /// Path to the experiment config JSON file
    config: PathBuf,

    /// Run mode: setup (register clients), sim-setup (simulated setup, no attestation), generate, submit, or aggregate
    #[arg(long, default_value = "setup")]
    mode: String,

    /// Maximum number of concurrent connections (default: 1000)
    #[arg(long, short = 'c', default_value = "1000")]
    max_concurrency: usize,

    /// Clear the client database before running
    #[arg(long)]
    clear_clients: bool,

    /// Clear stored reports before running
    #[arg(long)]
    clear_reports: bool,
}

// Struct for persisting clients to disk
#[derive(Serialize, Deserialize, Debug, Clone)]
struct StoredClient {
    id: u32,
    eval_key: heli::agg_only_enc::EvalKey,
    prover_key: heli::proofs::ProverKey,
}

fn init_tracing() {
    let filter = EnvFilter::from_default_env()
        .add_directive("sled=off".parse().unwrap())
        .add_directive("heli=info".parse().unwrap());

    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// Send a batch of reports to the aggregator.
/// Takes a vector of (id, context, envelope) tuples and the aggregator address.
async fn send_batch_reports(
    reports: Vec<(u32, u32, heli::crypto::hpke::HpkeEnvelope)>,
    aggregator_addr: &str,
) -> Result<()> {
    if reports.is_empty() {
        return Ok(());
    }

    let mut socket = TcpStream::connect(aggregator_addr).await?;

    let batch_message = Message::BatchEncryptedClientReports { reports };
    heli::system::messages::make_request(&mut socket, &batch_message)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to upload batch: {e:?}"))?;
    Ok(())
}

/// Encode length and bitwidth into a context value
fn encode_context(length: usize, bitwidth: usize) -> u32 {
    let length_u32 = length.min(0xFFFF) as u32;
    let bitwidth_u32 = bitwidth.min(0xFFFF) as u32;
    (bitwidth_u32 << 16) | length_u32
}

fn save_client_to_db(db: &Db, client: &Client) -> Result<()> {
    let stored = StoredClient {
        id: client.id,
        eval_key: client.eval_key.clone(),
        prover_key: client.prover_key.clone(),
    };

    let key = format!("client_{}", client.id);
    let value = bincode::serialize(&stored)?;
    db.insert(key.as_bytes(), IVec::from(value))?;
    db.flush()?;
    Ok(())
}

fn load_client_from_db(
    db: &Db,
    id: u32,
    aggregator_addr: &str,
    aggregator_keys: &heli::crypto::hpke::ServerKeys,
) -> Result<Client> {
    let key = format!("client_{}", id);

    if let Some(value) = db.get(key.as_bytes())? {
        let stored: StoredClient = bincode::deserialize(&value)?;
        Ok(Client {
            aggregator_addr: aggregator_addr.to_string(),
            aggregator_pk: aggregator_keys.pk.clone(),
            id: stored.id,
            eval_key: stored.eval_key,
            prover_key: stored.prover_key,
        })
    } else {
        Err(anyhow!("Client {id} doesn't exist in DB"))
    }
}

fn save_report_to_db(db: &Db, id: u32, context: u32, envelope: HpkeEnvelope) -> Result<()> {
    let key = format!("report_{}_{}", id, context);
    let value = bincode::serialize(&envelope)?;
    db.insert(key.as_bytes(), IVec::from(value))?;
    db.flush()?;
    Ok(())
}

fn load_report_from_db(db: &Db, id: u32, context: u32) -> Result<HpkeEnvelope> {
    let key = format!("report_{}_{}", id, context);

    if let Some(value) = db.get(key.as_bytes())? {
        let stored: HpkeEnvelope = bincode::deserialize(&value)?;
        Ok(stored)
    } else {
        Err(anyhow!("Failed to fetch report"))
    }
}

fn clear_reports_from_db(db: &Db) -> Result<()> {
    let keys: Vec<Vec<u8>> = db
        .scan_prefix(b"report_")
        .keys()
        .map(|res| res.map(|k| k.to_vec()))
        .collect::<Result<_, _>>()?;

    for key in keys {
        db.remove(key)?;
    }
    db.flush()?;
    Ok(())
}

fn clear_clients_from_db(db: &Db) -> Result<()> {
    let keys: Vec<Vec<u8>> = db
        .scan_prefix(b"client_")
        .keys()
        .map(|res| res.map(|k| k.to_vec()))
        .collect::<Result<_, _>>()?;

    for key in keys {
        db.remove(key)?;
    }
    db.flush()?;
    Ok(())
}

async fn run_setup(config: &ExperimentConfig, max_concurrency: usize, db: Arc<Db>) -> Result<()> {
    let decryptor_keys = Arc::new(decryptor_keys());
    let aggregator_keys = Arc::new(aggregator_keys());
    let prover_type = config.prover.to_prover_type();

    // Semaphore to limit concurrent connections
    let semaphore = Arc::new(Semaphore::new(max_concurrency));

    // Phase 1: Registration
    info!("=== Phase 1: Client Registration ===");
    info!("Registering {} clients...", config.num_clients);

    let registration_start = Instant::now();
    let registered_count = Arc::new(AtomicUsize::new(0));
    let loaded_count = Arc::new(AtomicUsize::new(0));

    // Try to load clients from DB first
    let mut clients = Vec::new();
    let mut clients_to_register = Vec::new();

    for i in 0..config.num_clients {
        match load_client_from_db(&db, i as u32, &config.aggregator_addr, &aggregator_keys) {
            Ok(client) => {
                clients.push(client);
                let count = loaded_count.fetch_add(1, Ordering::SeqCst) + 1;
                if count % 10000 == 0 || count == config.num_clients {
                    info!("Loaded {}/{} clients from DB", count, config.num_clients);
                }
            }
            Err(_) => {
                clients_to_register.push(i);
            }
        }
    }

    if !clients_to_register.is_empty() {
        info!(
            "Loaded {} clients from DB, need to register {} new clients",
            clients.len(),
            clients_to_register.len()
        );
    } else {
        info!("Loaded all {} clients from DB", clients.len());
    }

    // Register missing clients concurrently
    let mut join_set = JoinSet::new();
    let num_to_register = clients_to_register.len();
    for i in clients_to_register {
        let decryptor_addr = config.decryptor_addr.clone();
        let aggregator_addr = config.aggregator_addr.clone();
        let decryptor_keys = decryptor_keys.clone();
        let aggregator_keys = aggregator_keys.clone();
        let registered_count = registered_count.clone();
        let semaphore = semaphore.clone();
        let db = db.clone();

        join_set.spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            let result = Client::register(
                &decryptor_addr,
                &aggregator_addr,
                prover_type,
                &decryptor_keys,
                &aggregator_keys,
            )
            .await;

            match result {
                Ok(client) => {
                    // Save to DB
                    if let Err(e) = save_client_to_db(&db, &client) {
                        warn!("Failed to save client {} to DB: {:?}", client.id, e);
                    }

                    let count = registered_count.fetch_add(1, Ordering::SeqCst) + 1;
                    if count % 10000 == 0 || count == num_to_register {
                        info!("Registered {}/{} new clients", count, num_to_register);
                    }
                    Some(client)
                }
                Err(e) => {
                    error!("Failed to register client {}: {:?}", i, e);
                    None
                }
            }
        });
    }

    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(Some(client)) => clients.push(client),
            Ok(None) => {} // Registration failed, already logged
            Err(e) => error!("Task panicked: {:?}", e),
        }
    }

    let registration_time = registration_start.elapsed();
    info!(
        "Registration complete: {} clients in {:?} ({:.2} clients/sec)",
        clients.len(),
        registration_time,
        clients.len() as f64 / registration_time.as_secs_f64()
    );
    info!(
        "Sent {:?} bytes ({:.2} per-client)",
        bytes_sent(),
        (bytes_sent() as f64 / clients.len() as f64),
    );
    info!(
        "Recv {:?} bytes ({:.2} per-client)",
        bytes_recv(),
        (bytes_recv() as f64 / clients.len() as f64),
    );
    reset_byte_counters();

    Ok(())
}

/// Simulated setup: one RPC to decryptor (SimulateSetup), then create all clients locally from hardcoded PRF key.
/// No attestation; use for fast e2e with large N.
async fn run_sim_setup(config: &ExperimentConfig, db: Arc<Db>) -> Result<()> {
    let aggregator_keys = Arc::new(aggregator_keys());
    let prover_type = config.prover.to_prover_type();

    info!("=== Simulated Setup (no attestation) ===");
    info!("Setting up {} clients...", config.num_clients);

    let setup_start = Instant::now();
    let mut clients = Vec::new();
    let mut clients_to_create = Vec::new();

    for i in 0..config.num_clients {
        match load_client_from_db(&db, i as u32, &config.aggregator_addr, &aggregator_keys) {
            Ok(client) => clients.push(client),
            Err(_) => clients_to_create.push(i),
        }
    }

    if clients_to_create.is_empty() {
        info!("Loaded all {} clients from DB", clients.len());
    } else {
        info!(
            "Loaded {} clients from DB, creating {} via sim-setup",
            clients.len(),
            clients_to_create.len()
        );

        Client::trigger_simulate_setup(&config.decryptor_addr).await?;
        info!("Triggered simulated setup on decryptor");

        let num_to_create = clients_to_create.len();
        let aggregator_addr = config.aggregator_addr.clone();
        let db_clone = db.clone();
        let aggregator_keys_clone = aggregator_keys.clone();

        // Parallel create + insert; flush once at the end (save_client_to_db flushes every time = very slow)
        tokio::task::spawn_blocking(move || {
            clients_to_create.par_iter().for_each(|&i| {
                let client = Client::new_simulated(
                    i as u32,
                    &aggregator_addr,
                    &aggregator_keys_clone,
                    prover_type,
                );
                let stored = StoredClient {
                    id: client.id,
                    eval_key: client.eval_key.clone(),
                    prover_key: client.prover_key.clone(),
                };
                let key = format!("client_{}", i);
                let value = bincode::serialize(&stored).expect("serialize client");
                db_clone.insert(key.as_bytes(), IVec::from(value)).expect("insert client");
            });
            db_clone.flush().expect("flush client db");
        })
        .await?;

        info!("Created {} simulated clients (parallel, single flush)", num_to_create);
    }

    let setup_time = setup_start.elapsed();
    info!(
        "Sim-setup complete: {} clients in {:?}",
        config.num_clients,
        setup_time
    );

    Ok(())
}

async fn run_generate(config: &ExperimentConfig, db: Arc<Db>) -> Result<()> {
    let aggregator_keys = Arc::new(aggregator_keys());

    // Load clients from DB
    let mut clients = Vec::new();
    for i in 0..config.num_clients {
        match load_client_from_db(&db, i as u32, &config.aggregator_addr, &aggregator_keys) {
            Ok(client) => clients.push(client),
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "Client {} not found in DB. Run 'setup' mode first.",
                    i
                ));
            }
        }
    }

    info!("Loaded {} clients from DB", clients.len());

    // Randomly select clients to drop out
    let dropout_set: HashSet<u32> = if config.dropouts > 0 {
        let mut rng = rand::thread_rng();
        let mut client_ids: Vec<u32> = clients.iter().map(|c| c.id).collect();
        client_ids.shuffle(&mut rng);
        client_ids.into_iter().take(config.dropouts).collect()
    } else {
        HashSet::new()
    };

    // Filter to participating clients
    let clients: Vec<Arc<Client>> = clients
        .into_iter()
        .filter(|c| !dropout_set.contains(&c.id))
        .map(Arc::new)
        .collect();

    info!(
        "{} participating clients, {} dropouts",
        clients.len(),
        dropout_set.len()
    );

    // Generate context
    let bitwidth = match &config.prover {
        ProverConfig::Binary => 1,
        ProverConfig::Range { bitlength } => *bitlength,
    };
    let max_value = 1 << bitwidth;
    let context = encode_context(config.length, bitwidth);
    let num_participating = clients.len() as usize;

    info!("=== Report Generation ===");
    let generation_start = Instant::now();
    let generated_count = Arc::new(AtomicUsize::new(0));
    let db_clone = db.clone();

    let length = config.length;
    let mut join_set = JoinSet::new();
    for client in &clients {
        let client = client.clone();
        let generated_count = generated_count.clone();
        let db_clone = db_clone.clone();

        let num_participating_clone = num_participating;
        join_set.spawn(tokio::task::spawn_blocking(move || {
            // Generate random input data
            let mut rng = StdRng::from_entropy();
            let inputs: Vec<u64> = (0..length).map(|_| rng.gen_range(0..max_value)).collect();

            match client.generate_report(context, &inputs) {
                Ok(Message::EncryptedClientReport {
                    id,
                    context,
                    envelope,
                }) => {
                    if let Err(e) = save_report_to_db(&db_clone, id, context, envelope) {
                        error!("Failed to save report for client {}: {:?}", id, e);
                        return false;
                    }

                    let count = generated_count.fetch_add(1, Ordering::SeqCst) + 1;
                    if count % 10000 == 0 || count == num_participating_clone {
                        info!("Generated {}/{} reports", count, num_participating_clone);
                    }
                    true
                }
                Ok(_) => {
                    error!("Unexpected message type from generate_report");
                    false
                }
                Err(e) => {
                    error!(
                        "Failed to generate report for client {}: {:?}",
                        client.id, e
                    );
                    false
                }
            }
        }));
    }

    // Wait for all generations to complete
    while join_set.join_next().await.is_some() {}

    let generation_time = generation_start.elapsed();
    let generated = generated_count.load(Ordering::SeqCst);
    info!(
        "Report generation complete: {} reports in {:?} ({:.2} reports/sec)",
        generated,
        generation_time,
        generated as f64 / generation_time.as_secs_f64()
    );

    Ok(())
}

async fn run_submit(config: &ExperimentConfig, max_concurrency: usize, db: Arc<Db>) -> Result<()> {
    // Semaphore to limit concurrent connections
    let semaphore = Arc::new(Semaphore::new(max_concurrency));
    info!("Max concurrency: {}", max_concurrency);

    info!("=== Report Submission ===");
    let submission_start = Instant::now();
    let submitted_count = Arc::new(AtomicUsize::new(0));

    // Load reports from DB
    let bitwidth = match &config.prover {
        ProverConfig::Binary => 1,
        ProverConfig::Range { bitlength } => *bitlength,
    };
    let context = encode_context(config.length, bitwidth);

    let mut reports = Vec::new();
    for i in 0..config.num_clients {
        match load_report_from_db(&db, i as u32, context) {
            Ok(envelope) => reports.push((i as u32, context, envelope)),
            Err(_) => {}
        }
    }

    let num_reports = reports.len();
    info!("Loaded {} reports from DB", num_reports);

    if num_reports == 0 {
        return Err(anyhow::anyhow!(
            "No reports found in DB. Run 'generate' mode first."
        ));
    }

    // Collect all reports into batches
    let aggregator_addr = config.aggregator_addr.clone();
    let mut batches = Vec::new();
    for chunk in reports.chunks(BATCH_REPORT_SIZE) {
        let batch: Vec<_> = chunk
            .iter()
            .map(|(id, ctx, env)| {
                let env_bytes = bincode::serialize(env).unwrap();
                let env_clone: heli::crypto::hpke::HpkeEnvelope =
                    bincode::deserialize(&env_bytes).unwrap();
                (*id, *ctx, env_clone)
            })
            .collect();
        batches.push(batch);
    }

    info!(
        "Sending {} batches (batch size: {})",
        batches.len(),
        BATCH_REPORT_SIZE
    );

    // Send batches concurrently
    let mut join_set = JoinSet::new();
    for batch in batches.into_iter() {
        let aggregator_addr = aggregator_addr.clone();
        let submitted_count = submitted_count.clone();
        let semaphore = semaphore.clone();
        let batch_size = batch.len();

        join_set.spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            let result = send_batch_reports(batch, &aggregator_addr).await;

            match result {
                Ok(()) => {
                    let count = submitted_count.fetch_add(batch_size, Ordering::SeqCst);
                    if count % 10000 == 0 || count >= num_reports {
                        info!("Submitted {}/{} reports", count, num_reports);
                    }
                }
                Err(e) => {
                    error!("Failed to send batch of {} reports: {:?}", batch_size, e);
                }
            }
        });
    }

    // Wait for all submissions to complete
    while join_set.join_next().await.is_some() {}

    let submission_time = submission_start.elapsed();
    let submitted = submitted_count.load(Ordering::SeqCst);
    let bytes_sent_total = bytes_sent();
    let bytes_recv_total = bytes_recv();

    info!(
        "Report submission complete: {} reports in {:?} ({:.2} reports/sec)",
        submitted,
        submission_time,
        submitted as f64 / submission_time.as_secs_f64()
    );
    info!(
        "Sent {:?}B ({:.2}B per-report)",
        bytes_sent_total,
        (bytes_sent_total as f64 / num_reports as f64),
    );
    info!(
        "Recv {:?}B ({:.2}B per-report)",
        bytes_recv_total,
        (bytes_recv_total as f64 / num_reports as f64),
    );

    // Calculate throughput in Gbit/s
    let total_bytes = bytes_sent_total + bytes_recv_total;
    let total_bits = total_bytes as f64 * 8.0;
    let time_secs = submission_time.as_secs_f64();
    let throughput_gbps = if time_secs > 0.0 {
        total_bits / time_secs / 1_000_000_000.0
    } else {
        0.0
    };

    info!(
        "Throughput: {:.2} Gbit/s (sent: {:.2} Gbit/s, recv: {:.2} Gbit/s)",
        throughput_gbps,
        (bytes_sent_total as f64 * 8.0) / time_secs / 1_000_000_000.0,
        (bytes_recv_total as f64 * 8.0) / time_secs / 1_000_000_000.0,
    );

    reset_byte_counters();

    Ok(())
}

async fn run_aggregate(config: &ExperimentConfig) -> Result<()> {
    info!("=== Aggregation ===");

    // Get bitwidth from config
    let bitwidth = match &config.prover {
        ProverConfig::Binary => 1,
        ProverConfig::Range { bitlength } => *bitlength,
    };

    // Encode context with length and bitwidth
    let context = encode_context(config.length, bitwidth);

    // Connect to aggregator and request aggregation
    let mut socket = TcpStream::connect(&config.aggregator_addr).await?;
    write_message(&mut socket, &Message::AggregationRequest { context }).await?;

    let response = read_message(&mut socket).await?;
    match response {
        Message::AggregationResponse { result } => {
            info!("Aggregation successful: {:?}", result);
        }
        Message::Error(e) => {
            return Err(anyhow::anyhow!("Aggregation failed: {}", e));
        }
        _ => {
            return Err(anyhow::anyhow!("Unexpected response from aggregator"));
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

    let config = ExperimentConfig::from_file(&args.config)?;
    info!("Loaded config: {:?}", config);

    let db = Arc::new(sled::Config::default().path(CLIENT_DB_PATH).open()?);

    // Clear clients if requested
    if args.clear_clients {
        clear_clients_from_db(&db)?;
        info!("Cleared all clients from database");
    }

    // Clear reports if requested
    if args.clear_reports {
        clear_reports_from_db(&db)?;
        info!("Cleared all reports from database");
    }

    match args.mode.as_str() {
        "setup" => run_setup(&config, args.max_concurrency, db).await,
        "sim-setup" => run_sim_setup(&config, db).await,
        "generate" => run_generate(&config, db).await,
        "submit" => run_submit(&config, args.max_concurrency, db).await,
        "aggregate" => run_aggregate(&config).await,
        _ => Err(anyhow::anyhow!(
            "Invalid mode: {}. Must be 'setup', 'sim-setup', 'generate', 'submit', or 'aggregate'",
            args.mode
        )),
    }
}
