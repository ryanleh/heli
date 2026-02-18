mod config;
mod keys;

use anyhow::{Result, anyhow};
use clap::Parser;
use config::{ExperimentConfig, ProverConfig};
use heli::{
    crypto::hpke::HpkeEnvelope,
    system::{Client, messages::*},
};
use keys::{aggregator_keys, decryptor_keys};
use rand::{Rng, SeedableRng, rngs::StdRng, seq::SliceRandom};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sled::{Db, IVec};
use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{Arc, atomic::{AtomicUsize, Ordering}},
    time::Instant,
};
use tokio::{net::TcpStream, sync::Semaphore, task::JoinSet};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use heli::BATCH_REPORT_SIZE;
const CLIENT_DB_PATH: &str = "/tmp/heli_client.db";

#[derive(Parser, Debug)]
#[command(name = "client")]
struct Args {
    /// Path to the experiment config JSON file
    config: PathBuf,

    /// Run mode: setup, sim-setup, generate, sim-generate (one batch only), submit, or aggregate
    #[arg(long, default_value = "setup")]
    mode: String,

    /// Maximum number of concurrent connections (default: 1000)
    #[arg(long, short = 'c', default_value = "1000")]
    max_concurrency: usize,

    /// Clear the client database (delete entire DB) before running
    #[arg(long)]
    clear_db: bool,

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

async fn send_batch_reports(socket: &mut TcpStream, context: u32, reports: Vec<(u32, Vec<u8>)>) -> Result<()> {
    if reports.is_empty() {
        return Ok(());
    }
    write_message(socket, &Message::BatchEncryptedClientReports { context, reports }).await?;
    Ok(())
}

async fn connect_with_retry(addr: &str, max_retries: usize) -> Result<TcpStream> {
    let mut delay = std::time::Duration::from_millis(10);
    for attempt in 0..max_retries {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(_) if attempt + 1 < max_retries => {
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(std::time::Duration::from_secs(1));
            }
            Err(e) => return Err(e.into()),
        }
    }
    unreachable!()
}

fn encode_context(length: usize, bitwidth: usize) -> u32 {
    ((bitwidth.min(0xFFFF) as u32) << 16) | (length.min(0xFFFF) as u32)
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
    prover_type: heli::system::ProverType,
) -> Result<Client> {
    let data = db.get(format!("client_{id}").as_bytes())?.ok_or_else(|| anyhow!("Client {id} not in DB"))?;
    let stored: StoredClient = bincode::deserialize(&data)?;
    Ok(Client {
        aggregator_addr: aggregator_addr.to_string(),
        aggregator_pk: aggregator_keys.pk.clone(),
        id: stored.id,
        eval_key: stored.eval_key,
        prover_key: Client::adapt_prover_key_to(stored.prover_key, prover_type),
    })
}

fn save_report_to_db(db: &Db, id: u32, context: u32, envelope: &HpkeEnvelope) -> Result<()> {
    db.insert(format!("report_{id}_{context}").as_bytes(), bincode::serialize(envelope)?)?;
    Ok(())
}

fn load_report_bytes_from_db(db: &Db, id: u32, context: u32) -> Result<Vec<u8>> {
    let data = db.get(format!("report_{id}_{context}").as_bytes())?.ok_or_else(|| anyhow!("Report not found"))?;
    Ok(data.to_vec())
}

/// Load all reports for a context using parallel iteration
async fn load_all_reports_parallel(db: &Db, context: u32, num_clients: usize) -> Vec<(u32, Vec<u8>)> {
    use rayon::prelude::*;
    let db = db.clone();
    tokio::task::spawn_blocking(move || {
        (0..num_clients)
            .into_par_iter()
            .filter_map(|i| {
                let id = i as u32;
                load_report_bytes_from_db(&db, id, context).ok().map(|bytes| (id, bytes))
            })
            .collect()
    })
    .await
    .unwrap_or_default()
}

fn clear_reports_from_db(db: &Db) -> Result<()> {
    for key in db.scan_prefix(b"report_").keys() {
        db.remove(key?)?;
    }
    db.flush()?;
    Ok(())
}

async fn run_setup(config: &ExperimentConfig, max_concurrency: usize, db: Arc<Db>) -> Result<()> {
    let decryptor_keys = Arc::new(decryptor_keys());
    let aggregator_keys = Arc::new(aggregator_keys());

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

    let prover_type = config.prover.to_prover_type();
    for i in 0..config.num_clients {
        match load_client_from_db(
            &db,
            i as u32,
            &config.aggregator_addr,
            &aggregator_keys,
            prover_type,
        ) {
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
        match load_client_from_db(
            &db,
            i as u32,
            &config.aggregator_addr,
            &aggregator_keys,
            prover_type,
        ) {
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

        Client::trigger_sim_setup(&config.decryptor_addr).await?;
        info!("Triggered simulated setup on decryptor");

        let num_to_create = clients_to_create.len();
        let num_clients = config.num_clients;
        let initial_count = clients.len();
        let aggregator_addr = config.aggregator_addr.clone();
        let db_clone = db.clone();
        let aggregator_keys_clone = aggregator_keys.clone();
        let created_count = Arc::new(AtomicUsize::new(0));

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

                let prev = created_count.fetch_add(1, Ordering::SeqCst);
                let current = prev + 1;
                let total_done = initial_count + current;
                if total_done % 100_000 == 0 || current >= num_to_create {
                    info!("Created {}/{} simulated clients", total_done, num_clients);
                }
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
    // Clear sim_generate so submit uses full report list
    let _ = db.remove(b"sim_generate");
    db.flush()?;

    let aggregator_keys = Arc::new(aggregator_keys());
    let prover_type = config.prover.to_prover_type();

    // Load clients from DB
    let mut clients = Vec::new();
    for i in 0..config.num_clients {
        match load_client_from_db(
            &db,
            i as u32,
            &config.aggregator_addr,
            &aggregator_keys,
            prover_type,
        ) {
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
                    if let Err(e) = save_report_to_db(&db_clone, id, context, &envelope) {
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

    db.flush()?;

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

/// Generate reports for only the first BATCH_REPORT_SIZE clients; set flag so submit duplicates them.
/// Respects config.dropouts - will only send (num_clients - dropouts) reports during submit.
async fn run_sim_generate(config: &ExperimentConfig, db: Arc<Db>) -> Result<()> {
    let aggregator_keys = Arc::new(aggregator_keys());
    let prover_type = config.prover.to_prover_type();
    let n = BATCH_REPORT_SIZE.min(config.num_clients);

    let mut clients = Vec::new();
    for i in 0..n {
        match load_client_from_db(&db, i as u32, &config.aggregator_addr, &aggregator_keys, prover_type) {
            Ok(client) => clients.push(client),
            Err(_) => return Err(anyhow!("Client {} not found in DB. Run 'setup' or 'sim-setup' first.", i)),
        }
    }

    let num_participating = config.num_clients - config.dropouts;
    info!("Sim-generate: generating {} reports ({} clients, {} dropouts)", n, config.num_clients, config.dropouts);

    let bitwidth = match &config.prover {
        ProverConfig::Binary => 1,
        ProverConfig::Range { bitlength } => *bitlength,
    };
    let max_value = 1 << bitwidth;
    let context = encode_context(config.length, bitwidth);
    let length = config.length;

    let generation_start = Instant::now();
    let generated_count = Arc::new(AtomicUsize::new(0));
    let db_clone = db.clone();

    let clients: Vec<Arc<Client>> = clients.into_iter().map(Arc::new).collect();
    let mut join_set = JoinSet::new();
    for client in &clients {
        let client = client.clone();
        let generated_count = generated_count.clone();
        let db_clone = db_clone.clone();

        join_set.spawn(tokio::task::spawn_blocking(move || {
            let mut rng = StdRng::from_entropy();
            let inputs: Vec<u64> = (0..length).map(|_| rng.gen_range(0..max_value)).collect();

            match client.generate_report(context, &inputs) {
                Ok(Message::EncryptedClientReport { id, context, envelope }) => {
                    if let Err(e) = save_report_to_db(&db_clone, id, context, &envelope) {
                        error!("Failed to save report for client {}: {:?}", id, e);
                        return false;
                    }
                    let count = generated_count.fetch_add(1, Ordering::SeqCst) + 1;
                    if count % 1000 == 0 || count == n {
                        info!("Generated {}/{} reports", count, n);
                    }
                    true
                }
                Ok(_) => { error!("Unexpected message type"); false }
                Err(e) => { error!("Failed to generate report for client {}: {:?}", client.id, e); false }
            }
        }));
    }

    while join_set.join_next().await.is_some() {}

    // Store sim_generate flag and dropout count so submit knows how many reports to send
    db.insert(b"sim_generate", b"1")?;
    db.insert(b"sim_dropouts", &config.dropouts.to_le_bytes())?;
    db.flush()?;

    let generation_time = generation_start.elapsed();
    let generated = generated_count.load(Ordering::SeqCst);
    info!(
        "Sim-generate complete: {} reports in {:?} (submit will send {} reports, duplicated from {} unique)",
        generated, generation_time, num_participating, BATCH_REPORT_SIZE.min(n)
    );

    Ok(())
}

async fn run_submit(config: &ExperimentConfig, max_concurrency: usize, db: Arc<Db>) -> Result<()> {
    info!("=== Report Submission ===");
    let submitted_count = Arc::new(AtomicUsize::new(0));

    // Load reports from DB
    let bitwidth = match &config.prover {
        ProverConfig::Binary => 1,
        ProverConfig::Range { bitlength } => *bitlength,
    };
    let context = encode_context(config.length, bitwidth);

    let sim_generate = db.get(b"sim_generate")?.as_deref() == Some(b"1");

    info!("Loading reports from DB...");
    let load_start = Instant::now();

    // Load reports as raw bytes (skip deserialize/serialize round-trip)
    let batches: Vec<Vec<(u32, Vec<u8>)>> = if sim_generate {
        // Load dropout count stored during sim-generate
        let dropouts = db.get(b"sim_dropouts")?
            .map(|v| usize::from_le_bytes(v.as_ref().try_into().unwrap_or([0; 8])))
            .unwrap_or(config.dropouts);
        let num_participating = config.num_clients - dropouts;

        // Load unique reports once
        let unique_count = BATCH_REPORT_SIZE.min(num_participating);
        let unique_reports: Vec<Vec<u8>> = (0..unique_count)
            .map(|i| {
                load_report_bytes_from_db(&db, i as u32, context)
                    .map_err(|_| anyhow!("sim_generate set but report {} not found. Run 'sim-generate' first.", i))
            })
            .collect::<Result<Vec<_>>>()?;

        info!(
            "Loaded {} unique reports, duplicating to {} participating ({} dropouts)",
            unique_reports.len(), num_participating, dropouts
        );

        // Build batches by duplicating
        (0..num_participating)
            .collect::<Vec<_>>()
            .chunks(BATCH_REPORT_SIZE)
            .map(|chunk| {
                chunk.iter().map(|&i| {
                    let src_id = i % BATCH_REPORT_SIZE;
                    (i as u32, unique_reports[src_id].clone())
                }).collect()
            })
            .collect()
    } else {
        // Load all reports in parallel
        let reports = load_all_reports_parallel(&db, context, config.num_clients).await;
        info!("Loaded {} reports from DB", reports.len());

        if reports.is_empty() {
            return Err(anyhow!("No reports found in DB. Run 'generate' first."));
        }

        // Already have (id, bytes), just chunk into batches
        reports
            .chunks(BATCH_REPORT_SIZE)
            .map(|chunk| chunk.to_vec())
            .collect()
    };

    let num_reports: usize = batches.iter().map(|b| b.len()).sum();
    if num_reports == 0 {
        return Err(anyhow!("No reports found in DB. Run 'generate' or 'sim-generate' first."));
    }

    info!("Loaded {} reports in {:?}", num_reports, load_start.elapsed());
    let submission_start = Instant::now();
    let aggregator_addr = config.aggregator_addr.clone();

    // Register context config before submitting reports
    let (binary, bitlength) = match &config.prover {
        ProverConfig::Binary => (true, None),
        ProverConfig::Range { bitlength } => (false, Some(*bitlength)),
    };
    // For simulated mode, the "dropout" clients are the ones we didn't submit
    // i.e., IDs from num_participating to num_clients-1
    let sim_dropouts: Vec<u32> = if sim_generate {
        let dropouts = db.get(b"sim_dropouts")?
            .map(|v| usize::from_le_bytes(v.as_ref().try_into().unwrap_or([0; 8])))
            .unwrap_or(config.dropouts);
        let num_participating = config.num_clients - dropouts;
        (num_participating as u32..config.num_clients as u32).collect()
    } else {
        vec![]
    };
    {
        let mut socket = TcpStream::connect(&aggregator_addr).await?;
        write_message(
            &mut socket,
            &Message::SetContextConfig {
                context,
                binary,
                bitlength,
                simulated: sim_generate,
                sim_dropouts,
            },
        )
        .await?;
        let response = read_message(&mut socket).await?;
        if !matches!(response, Message::Success {}) {
            return Err(anyhow::anyhow!(
                "Aggregator did not accept SetContextConfig: {:?}",
                response
            ));
        }
    }

    info!(
        "Sending {} batches (batch size: {}) over {} connections",
        batches.len(),
        BATCH_REPORT_SIZE,
        max_concurrency
    );

    // Partition batches across N persistent connections
    let num_connections = max_concurrency.min(batches.len());
    let mut batch_groups: Vec<Vec<Vec<(u32, Vec<u8>)>>> = (0..num_connections).map(|_| Vec::new()).collect();
    for (i, batch) in batches.into_iter().enumerate() {
        batch_groups[i % num_connections].push(batch);
    }

    // Spawn a task per connection that streams all its batches
    let mut join_set = JoinSet::new();
    for group in batch_groups {
        let aggregator_addr = aggregator_addr.clone();
        let submitted_count = submitted_count.clone();
        let num_batches = group.len();

        join_set.spawn(async move {
            let mut socket = match connect_with_retry(&aggregator_addr, 10).await {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to connect after retries: {e}");
                    return;
                }
            };
            socket.set_nodelay(true).ok();

            // Tell server how many batches to expect
            if let Err(e) = write_message(&mut socket, &Message::BatchStreamStart { num_batches }).await {
                error!("Failed to send BatchStreamStart: {e}");
                return;
            }

            for batch in group {
                let batch_size = batch.len();
                if let Err(e) = send_batch_reports(&mut socket, context, batch).await {
                    error!("Failed to send batch: {e}");
                    return;
                }
                let prev = submitted_count.fetch_add(batch_size, Ordering::SeqCst);
                let current = prev + batch_size;
                if current % 102_400 == 0 || current >= num_reports {
                    info!("Submitted {}/{} reports", current, num_reports);
                }
            }
        });
    }

    // Wait for all connections to finish sending
    while join_set.join_next().await.is_some() {}

    let submission_time = submission_start.elapsed();
    let submitted = submitted_count.load(Ordering::SeqCst);
    let bytes_sent_total = bytes_sent();
    let bytes_recv_total = bytes_recv();

    if submitted != num_reports {
        return Err(anyhow::anyhow!(
            "Submitted {}/{} reports. Some batches failed to reach the aggregator. \
             Ensure the aggregator is running and config aggregator_addr ({}) is correct.",
            submitted,
            num_reports,
            aggregator_addr
        ));
    }

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

    let db = Arc::new(if args.clear_db {
        if std::path::Path::new(CLIENT_DB_PATH).exists() {
            std::fs::remove_dir_all(CLIENT_DB_PATH)?;
        }
        info!("Cleared database");
        sled::Config::default().path(CLIENT_DB_PATH).open()?
    } else {
        sled::Config::default().path(CLIENT_DB_PATH).open()?
    });

    // Clear reports if requested
    if args.clear_reports {
        clear_reports_from_db(&db)?;
        info!("Cleared all reports from database");
    }

    match args.mode.as_str() {
        "setup" => run_setup(&config, args.max_concurrency, db).await,
        "sim-setup" => run_sim_setup(&config, db).await,
        "generate" => run_generate(&config, db).await,
        "sim-generate" => run_sim_generate(&config, db).await,
        "submit" => run_submit(&config, args.max_concurrency, db).await,
        "aggregate" => run_aggregate(&config).await,
        _ => Err(anyhow::anyhow!(
            "Invalid mode: {}. Must be 'setup', 'sim-setup', 'generate', 'sim-generate', 'submit', or 'aggregate'",
            args.mode
        )),
    }
}
