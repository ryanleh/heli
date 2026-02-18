use crate::{
    agg_only_enc::{AggOnlyEnc, Ciphertext},
    crypto::{
        G,
        hpke::{ServerKeys, hpke_decrypt},
        prf::ScalarPRF,
    },
    proofs::{Proof, VerifierKey},
    system::{ProverType, messages::{*, pack_indices}},
};

use anyhow::{Result, anyhow};
use group::Group;
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use rayon::prelude::*;
use sled::Db;
use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, OnceCell, RwLock, mpsc},
};
use tracing::{debug, error, info};

const VERIFY_BATCH_SIZE: usize = 128;
const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

#[inline]
fn hex_encode_u32(val: u32, out: &mut [u8]) {
    out[0] = HEX_CHARS[((val >> 28) & 0xF) as usize];
    out[1] = HEX_CHARS[((val >> 24) & 0xF) as usize];
    out[2] = HEX_CHARS[((val >> 20) & 0xF) as usize];
    out[3] = HEX_CHARS[((val >> 16) & 0xF) as usize];
    out[4] = HEX_CHARS[((val >> 12) & 0xF) as usize];
    out[5] = HEX_CHARS[((val >> 8) & 0xF) as usize];
    out[6] = HEX_CHARS[((val >> 4) & 0xF) as usize];
    out[7] = HEX_CHARS[(val & 0xF) as usize];
}

pub struct Aggregator {
    addr: String,
    state: Arc<AggregatorState>,
}

pub struct AggregatorState {
    num_clients: usize,
    threshold: usize,
    db: Db,
    hpke_keys: ServerKeys,
    current_ctx: RwLock<Option<u32>>,
    request_send: OnceCell<mpsc::Sender<Message>>,
    mask_recv: Mutex<Option<mpsc::Receiver<Message>>>,
    reporting_start: RwLock<Option<Instant>>,
    num_reported: AtomicUsize,
    // Channel for funneling all report writes through a single thread (std channel for use with std::thread)
    report_write_tx: std::sync::mpsc::Sender<(u32, Vec<(u32, Vec<u8>)>)>,
    // Number of reports to load before starting verification
    agg_chunk_size: usize,
}

impl Aggregator {
    pub fn new(
        addr: &str,
        num_clients: usize,
        threshold: usize,
        _prover: ProverType,
        db: Db,
        hpke_keys: ServerKeys,
        agg_chunk_size: usize,
    ) -> Self {
        let (report_write_tx, report_write_rx) = std::sync::mpsc::channel();

        // Spawn dedicated writer thread
        let writer_db = db.clone();
        std::thread::spawn(move || {
            Self::report_writer_thread(writer_db, report_write_rx);
        });

        let state = Arc::new(AggregatorState {
            num_clients,
            threshold,
            db,
            hpke_keys,
            current_ctx: RwLock::new(None),
            request_send: OnceCell::new(),
            mask_recv: Mutex::new(None),
            reporting_start: RwLock::new(None),
            num_reported: AtomicUsize::new(0),
            report_write_tx,
            agg_chunk_size,
        });

        Self { addr: addr.to_string(), state }
    }

    fn report_writer_thread(db: Db, rx: std::sync::mpsc::Receiver<(u32, Vec<(u32, Vec<u8>)>)>) {
        let mut key = [0u8; 19];
        key[0] = b'r';
        key[1] = b'/';
        key[10] = b'/';

        while let Ok((context, reports)) = rx.recv() {
            let mut batch = sled::Batch::default();
            hex_encode_u32(context, &mut key[2..10]);

            for (id, envelope_bytes) in reports {
                hex_encode_u32(id, &mut key[11..19]);
                batch.insert(&key[..], envelope_bytes);
            }
            db.apply_batch(batch).ok();
        }
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.addr).await?;
        info!("Aggregator listening on {}", self.addr);

        loop {
            let (socket, addr) = listener.accept().await?;
            debug!("Connection from {}", addr);
            tokio::spawn(Self::handle_connection(socket, self.state.clone()));
        }
    }

    async fn handle_connection(mut socket: TcpStream, state: Arc<AggregatorState>) {
        let message = match read_message(&mut socket).await {
            Ok(msg) => msg,
            Err(e) => {
                send_error_message(&mut socket, &format!("Failed to read: {e}")).await.ok();
                return;
            }
        };

        match message {
            Message::DecryptorInit {} => {
                Self::handle_decryptor_init(socket, state).await;
            }
            Message::EncryptedClientReport { id, context, envelope } => {
                Self::respond(&mut socket, Self::store_client_report(state, id, context, envelope).await).await;
            }
            Message::BatchEncryptedClientReports { context, reports } => {
                Self::respond(&mut socket, Self::store_batch_client_reports(state, context, reports).await).await;
            }
            Message::BatchStreamStart { num_batches } => {
                Self::handle_batch_stream(&mut socket, state, num_batches).await;
            }
            Message::SetContextConfig { context, binary, bitlength, simulated, sim_dropouts } => {
                Self::respond(&mut socket, Self::set_context_config(state, context, binary, bitlength, simulated, sim_dropouts).await).await;
            }
            Message::AggregationRequest { context } => {
                Self::handle_aggregation_request(&mut socket, state, context).await;
            }
            _ => {
                send_error_message(&mut socket, "Invalid request").await.ok();
            }
        }
    }

    async fn handle_batch_stream(socket: &mut TcpStream, state: Arc<AggregatorState>, num_batches: usize) {
        let mut total_reports = 0usize;
        let mut context_set = false;
        let mut batches_received = 0usize;

        // If num_batches is 0, stream until connection closes; otherwise read exactly num_batches
        loop {
            if num_batches > 0 && batches_received >= num_batches {
                break;
            }

            let message = match read_message(socket).await {
                Ok(msg) => msg,
                Err(_) => break, // Connection closed or error
            };
            if let Message::BatchEncryptedClientReports { context, reports } = message {
                batches_received += 1;
                if reports.is_empty() {
                    continue;
                }

                // First batch sets up context
                if !context_set {
                    if Self::require_context_registered(&state, context).is_err() {
                        continue;
                    }
                    Self::set_or_check_context(&state, context).await.ok();
                    Self::start_reporting_timer(&state).await;
                    context_set = true;
                }

                total_reports += reports.len();
                // Send to dedicated writer thread - won't block
                state.report_write_tx.send((context, reports)).ok();
            }
        }

        // Update counters
        if total_reports > 0 {
            Self::maybe_log_threshold_reached(&state, total_reports).await;
        }
    }

    async fn respond(socket: &mut TcpStream, result: Result<()>) {
        match result {
            Ok(()) => { write_message(socket, &Message::Success {}).await.ok(); }
            Err(e) => { send_error_message(socket, &e.to_string()).await.ok(); }
        }
    }

    async fn handle_decryptor_init(socket: TcpStream, state: Arc<AggregatorState>) {
        let (request_send, request_recv) = mpsc::channel(10);
        let (mask_send, mask_recv) = mpsc::channel(10);
        state.request_send.set(request_send).ok();
        *state.mask_recv.lock().await = Some(mask_recv);

        tokio::spawn(async move {
            if let Err(e) = Self::handle_decryptor_connection(socket, state, request_recv, mask_send).await {
                error!("Decryptor connection error: {e:?}");
            }
        });
    }

    async fn set_context_config(
        state: Arc<AggregatorState>,
        context: u32,
        binary: bool,
        bitlength: Option<usize>,
        simulated: bool,
        sim_dropouts: Vec<u32>,
    ) -> Result<()> {
        let proof_type = if binary {
            "binary".to_string()
        } else {
            format!("range:{}", bitlength.ok_or_else(|| anyhow!("bitlength required for range"))?)
        };

        let state_clone = state.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            state_clone.db.insert(format!("pt/{context:08x}").as_bytes(), proof_type.as_bytes())?;
            if simulated {
                state_clone.db.insert(format!("sim/{context:08x}").as_bytes(), b"1")?;
                // Store the simulated dropout list
                let dropouts_bytes = bincode::serialize(&sim_dropouts).map_err(|e| anyhow!("{e}"))?;
                state_clone.db.insert(format!("sim_dropouts/{context:08x}").as_bytes(), dropouts_bytes)?;
            } else {
                state_clone.db.remove(format!("sim/{context:08x}").as_bytes())?;
                state_clone.db.remove(format!("sim_dropouts/{context:08x}").as_bytes())?;
            }
            state_clone.db.flush()?;
            Ok(())
        }).await??;
        Ok(())
    }

    async fn handle_aggregation_request(socket: &mut TcpStream, state: Arc<AggregatorState>, context: u32) {
        let start = Instant::now();
        info!("Aggregation request for context {context}");

        let is_simulated = state.db.get(format!("sim/{context:08x}").as_bytes()).ok().flatten().is_some();

        let result = Self::aggregate(state.clone(), context, is_simulated).await;

        match result {
            Ok(data) => {
                write_message(socket, &Message::AggregationResponse { result: data }).await.ok();
            }
            Err(e) => {
                send_error_message(socket, &format!("Aggregation failed: {e}")).await.ok();
            }
        }

        info!("Aggregation wall-clock time: {:?}", start.elapsed());

        // Reset for next round
        *state.current_ctx.write().await = None;
        *state.reporting_start.write().await = None;
        state.num_reported.store(0, Ordering::SeqCst);
    }

    async fn handle_decryptor_connection(
        mut socket: TcpStream,
        state: Arc<AggregatorState>,
        mut request_recv: mpsc::Receiver<Message>,
        mask_send: mpsc::Sender<Message>,
    ) -> Result<()> {
        if state.db.contains_key(b"kc")? {
            info!("Key commitments already exist, skipping setup");
            write_message(&mut socket, &Message::SetupAlreadyComplete {}).await?;
        } else {
            Self::receive_key_commitments(&mut socket, &state).await?;
        }

        // Forward decryption mask requests to decryptor and relay responses
        while let Some(request) = request_recv.recv().await {
            write_message(&mut socket, &request).await?;
            let response = read_message(&mut socket).await?;
            mask_send.send(response).await.ok();
        }
        Ok(())
    }

    async fn receive_key_commitments(socket: &mut TcpStream, state: &AggregatorState) -> Result<()> {
        write_message(socket, &Message::Success {}).await?;

        let setup_start = Instant::now();
        let mut key_commitments = vec![G::generator(); state.num_clients];

        let first_message = read_message(socket).await?;
        match first_message {
            Message::SimulateSetup {} => {
                let num_clients = state.num_clients;
                let g_comm = Proof::get_g_comm();
                key_commitments = tokio::task::spawn_blocking(move || {
                    let prf = ScalarPRF::new(&SIMULATE_PRF_KEY);
                    (0..num_clients).into_par_iter().map(|i| g_comm * prf.evaluate(i as u64)).collect()
                }).await?;
                info!("Simulated setup: computed {num_clients} key commitments in {:?}", setup_start.elapsed());
                write_message(socket, &Message::Success {}).await?;
            }
            Message::KeyCommsBatch { key_comms } => {
                let mut received = Self::apply_key_comms(&mut key_commitments, key_comms);
                write_message(socket, &Message::Success {}).await?;

                while received < state.num_clients {
                    let batch = match read_message(socket).await? {
                        Message::KeyCommsBatch { key_comms } => key_comms,
                        _ => return Err(anyhow!("Expected KeyCommsBatch")),
                    };
                    received += Self::apply_key_comms(&mut key_commitments, batch);
                    write_message(socket, &Message::Success {}).await?;
                }
            }
            _ => return Err(anyhow!("Expected SimulateSetup or KeyCommsBatch")),
        }

        // Persist key commitments - serialize in parallel chunks for speed
        let db = state.db.clone();
        let num_clients = state.num_clients;
        tokio::task::spawn_blocking(move || -> Result<()> {
            use rayon::prelude::*;
            
            let serialize_start = Instant::now();
            
            // Serialize chunks in parallel
            const CHUNK_SIZE: usize = 100_000;
            let serialized_chunks: Vec<Vec<u8>> = key_commitments
                .par_chunks(CHUNK_SIZE)
                .map(|chunk| bincode::serialize(chunk).unwrap())
                .collect();
            
            // Combine chunks with length prefixes for deserialization
            let total_len: usize = serialized_chunks.iter().map(|c| c.len()).sum();
            let mut serialized = Vec::with_capacity(total_len + 8 + serialized_chunks.len() * 8);
            serialized.extend_from_slice(&(num_clients as u64).to_le_bytes());
            for chunk in serialized_chunks {
                serialized.extend_from_slice(&(chunk.len() as u64).to_le_bytes());
                serialized.extend(chunk);
            }
            
            info!("Serialized {} key commitments in {:?}", num_clients, serialize_start.elapsed());
            
            let write_start = Instant::now();
            db.insert(b"kc", serialized)?;
            db.flush()?;
            info!("Wrote key commitments to DB in {:?}", write_start.elapsed());
            
            Ok(())
        }).await??;

        info!("Setup complete: {} key commitments in {:?}", state.num_clients, setup_start.elapsed());
        info!("Sent {}B, Recv {}B", bytes_sent(), bytes_recv());
        reset_byte_counters();
        Ok(())
    }

    fn apply_key_comms(commitments: &mut [G], batch: Vec<(u32, G)>) -> usize {
        let count = batch.len();
        for (idx, kc) in batch {
            commitments[idx as usize] = kc;
        }
        count
    }

    async fn store_client_report(
        state: Arc<AggregatorState>,
        id: u32,
        context: u32,
        envelope: crate::crypto::hpke::HpkeEnvelope,
    ) -> Result<()> {
        Self::require_context_registered(&state, context)?;
        Self::set_or_check_context(&state, context).await?;
        Self::start_reporting_timer(&state).await;

        let db = state.db.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let key = format!("r/{context:08x}/{id:08x}");
            db.insert(key.as_bytes(), bincode::serialize(&envelope)?)?;
            db.flush()?;
            Ok(())
        }).await??;

        Self::maybe_log_threshold_reached(&state, 1).await;
        Ok(())
    }

    async fn store_batch_client_reports(
        state: Arc<AggregatorState>,
        context: u32,
        reports: Vec<(u32, Vec<u8>)>,
    ) -> Result<()> {
        if reports.is_empty() {
            return Ok(());
        }

        Self::require_context_registered(&state, context)?;
        Self::set_or_check_context(&state, context).await?;
        Self::start_reporting_timer(&state).await;

        let batch_size = reports.len();
        let db = state.db.clone();

        // Build batch in blocking task to avoid blocking async runtime
        tokio::task::spawn_blocking(move || {
            let mut batch = sled::Batch::default();
            // Pre-allocate key buffer: "r/" + 8 hex + "/" + 8 hex = 19 bytes
            let mut key = [0u8; 19];
            key[0] = b'r';
            key[1] = b'/';
            key[10] = b'/';
            // Write context once
            hex_encode_u32(context, &mut key[2..10]);
            
            for (id, envelope_bytes) in reports {
                hex_encode_u32(id, &mut key[11..19]);
                batch.insert(&key[..], envelope_bytes);
            }
            db.apply_batch(batch)
        }).await??;

        Self::maybe_log_threshold_reached(&state, batch_size).await;
        Ok(())
    }

    // --- Helper functions for report storage ---

    fn require_context_registered(state: &AggregatorState, context: u32) -> Result<()> {
        if Self::get_proof_type_from_db(state, context)?.is_none() {
            return Err(anyhow!("Context {context:08x} not registered; send SetContextConfig first"));
        }
        Ok(())
    }

    async fn set_or_check_context(state: &AggregatorState, context: u32) -> Result<()> {
        let mut current = state.current_ctx.write().await;
        match *current {
            None => *current = Some(context),
            Some(c) if c != context => return Err(anyhow!("Context mismatch: expected {c}, got {context}")),
            _ => {}
        }
        Ok(())
    }

    async fn start_reporting_timer(state: &AggregatorState) {
        let mut start = state.reporting_start.write().await;
        if start.is_none() {
            *start = Some(Instant::now());
        }
    }

    async fn maybe_log_threshold_reached(state: &AggregatorState, count: usize) {
        let prev = state.num_reported.fetch_add(count, Ordering::SeqCst);
        let total = prev + count;
        if total >= state.threshold && prev < state.threshold {
            if let Some(start) = state.reporting_start.read().await.as_ref() {
                info!("Threshold reached ({total} reports) in {:?}", start.elapsed());
                info!("Sent {}B, Recv {}B", bytes_sent(), bytes_recv());
                reset_byte_counters();
            }
        }
    }

    // --- Proof type and verifier key helpers ---

    fn get_proof_type_from_db(state: &AggregatorState, context: u32) -> Result<Option<(bool, Option<usize>)>> {
        let Some(value) = state.db.get(format!("pt/{context:08x}").as_bytes())? else {
            return Ok(None);
        };
        let s = std::str::from_utf8(&value)?;
        Ok(Some(if s == "binary" {
            (true, None)
        } else if let Some(bits) = s.strip_prefix("range:") {
            (false, Some(bits.parse()?))
        } else {
            return Err(anyhow!("Unknown proof type: {s}"));
        }))
    }

    fn get_vk(state: Arc<AggregatorState>, context: u32) -> Result<VerifierKey> {
        let g_comm = Proof::get_g_comm();
        let data = state.db.get(b"kc")?.ok_or_else(|| anyhow!("No key commitments in DB"))?;
        let key_commitments = Self::deserialize_key_commitments(&data)?;

        let (is_binary, bitlength) = Self::get_proof_type_from_db(&state, context)?
            .ok_or_else(|| anyhow!("Proof type not found for context {context:08x}"))?;

        Ok(if is_binary {
            VerifierKey::Binary { g_comm, key_commitments }
        } else {
            VerifierKey::Range { g_comm, key_commitments, bitlength: bitlength.unwrap() }
        })
    }

    fn deserialize_key_commitments(data: &[u8]) -> Result<Vec<G>> {
        use rayon::prelude::*;
        
        // Format: num_clients (u64) + [chunk_len (u64) + chunk_data]*
        let num_clients = u64::from_le_bytes(data[0..8].try_into()?) as usize;
        let mut offset = 8;
        let mut chunks_data = Vec::new();
        
        while offset < data.len() {
            let chunk_len = u64::from_le_bytes(data[offset..offset+8].try_into()?) as usize;
            offset += 8;
            chunks_data.push(&data[offset..offset+chunk_len]);
            offset += chunk_len;
        }
        
        // Deserialize chunks in parallel
        let chunks: Vec<Vec<G>> = chunks_data
            .into_par_iter()
            .map(|chunk_data| bincode::deserialize(chunk_data).unwrap())
            .collect();
        
        let mut result = Vec::with_capacity(num_clients);
        for chunk in chunks {
            result.extend(chunk);
        }
        
        Ok(result)
    }

    // --- Aggregation ---

    async fn aggregate(state: Arc<AggregatorState>, context: u32, simulated: bool) -> Result<Vec<u64>> {
        Self::validate_aggregation_context(&state, context).await?;

        let wall_start = Instant::now();
        let vk = Self::get_vk(state.clone(), context)?;

        // Build list of client IDs to process
        let num_to_process = if simulated {
            // For simulated mode, get participating count from stored dropout info
            let dropouts = Self::get_sim_dropouts(&state, context).unwrap_or_default();
            state.num_clients - dropouts.len()
        } else {
            state.num_clients
        };
        info!("Processing {} reports (simulated: {})", num_to_process, simulated);

        let db = state.db.clone();
        let hpke_sk = state.hpke_keys.sk.clone();
        let load_chunk_size = state.agg_chunk_size;

        fn process_chunk(
            hpke_sk: &<hpke::kem::X25519HkdfSha256 as hpke::Kem>::PrivateKey,
            vk: &VerifierKey,
            context: u32,
            reports: Vec<(u32, Vec<u8>)>,
        ) -> (Vec<u32>, Option<Ciphertext>, std::time::Duration, std::time::Duration, std::time::Duration) {
            // Parallel decrypt
            let decrypt_start = Instant::now();
            let decrypted: Vec<_> = reports.into_par_iter().filter_map(|(id, data)| {
                let envelope: crate::crypto::hpke::HpkeEnvelope = bincode::deserialize(&data).ok()?;
                let (report_bytes, _) = hpke_decrypt(hpke_sk, &envelope, b"", b"").ok()?;
                let Message::ClientReport { proof, ciphertext } = bincode::deserialize(&report_bytes).ok()? else {
                    return None;
                };
                Some((id, proof, ciphertext))
            }).collect();
            let decrypt_time = decrypt_start.elapsed();

            // Parallel verify in batches
            let verify_start = Instant::now();
            let verify_chunks: Vec<_> = decrypted.chunks(VERIFY_BATCH_SIZE).collect();
            let verified: Vec<_> = verify_chunks.into_par_iter().filter_map(|chunk| {
                let ids: Vec<u32> = chunk.iter().map(|(id, _, _)| *id).collect();
                let proofs: Vec<_> = chunk.iter().map(|(_, p, _)| p.clone()).collect();
                let cts: Vec<_> = chunk.iter().map(|(_, _, c)| c.clone()).collect();
                
                let mut seed = [0u8; 32];
                OsRng.fill_bytes(&mut seed);
                Proof::batch_verify(vk, &cts, context, &proofs, &ids, &mut ChaCha20Rng::from_seed(seed))
                    .ok().map(|_| (ids, cts))
            }).collect();
            let verify_time = verify_start.elapsed();

            // Aggregate
            let agg_start = Instant::now();
            let mut online = Vec::new();
            let mut agg: Option<Ciphertext> = None;
            for (ids, cts) in verified {
                online.extend(ids);
                let chunk_agg = cts.into_iter().reduce(|a, b| a + b);
                agg = match (agg, chunk_agg) {
                    (Some(a), Some(b)) => Some(a + b),
                    (Some(a), None) => Some(a),
                    (None, b) => b,
                };
            }
            let agg_time = agg_start.elapsed();

            (online, agg, decrypt_time, verify_time, agg_time)
        }

        // Use a channel to pipeline loading and processing
        // Loader thread fills the channel, processor thread(s) drain it
        let (chunk_tx, chunk_rx) = std::sync::mpsc::sync_channel::<Vec<(u32, Vec<u8>)>>(4);

        // Spawn loader thread
        let loader_db = db.clone();
        let loader_handle = std::thread::spawn(move || -> (std::time::Duration, usize) {
            let mut total_load = std::time::Duration::ZERO;
            let prefix = format!("r/{context:08x}/");

            if simulated {
                // Load all unique reports first
                let load_start = Instant::now();
                let unique_reports: Vec<Vec<u8>> = loader_db.scan_prefix(prefix.as_bytes())
                    .filter_map(|r| r.ok())
                    .map(|(_, data)| data.to_vec())
                    .collect();
                total_load = load_start.elapsed();

                if unique_reports.is_empty() {
                    return (total_load, 0);
                }

                info!("Loaded {} unique reports in {:?}, generating {} simulated reports", 
                      unique_reports.len(), total_load, num_to_process);

                // Generate chunks by duplicating from unique reports
                let total_chunks = (num_to_process + load_chunk_size - 1) / load_chunk_size;
                for chunk_idx in 0..total_chunks {
                    let chunk_start = chunk_idx * load_chunk_size;
                    let chunk_end = (chunk_start + load_chunk_size).min(num_to_process);
                    
                    let reports: Vec<(u32, Vec<u8>)> = (chunk_start..chunk_end).map(|i| {
                        let id = i as u32;
                        let src_idx = i % unique_reports.len();
                        (id, unique_reports[src_idx].clone())
                    }).collect();

                    if chunk_tx.send(reports).is_err() {
                        break;
                    }
                }
                (total_load, unique_reports.len())
            } else {
                // Stream from DB, send chunks as they fill up
                let mut chunk = Vec::with_capacity(load_chunk_size);
                let mut total_loaded = 0usize;

                for item in loader_db.scan_prefix(prefix.as_bytes()) {
                    let load_start = Instant::now();
                    if let Ok((key, data)) = item {
                        if let Some(id) = std::str::from_utf8(&key).ok()
                            .and_then(|s| s.rsplit('/').next())
                            .and_then(|h| u32::from_str_radix(h, 16).ok())
                        {
                            chunk.push((id, data.to_vec()));
                            total_loaded += 1;
                        }
                    }
                    total_load += load_start.elapsed();

                    if chunk.len() >= load_chunk_size {
                        if chunk_tx.send(std::mem::take(&mut chunk)).is_err() {
                            break;
                        }
                        chunk = Vec::with_capacity(load_chunk_size);
                    }
                }

                // Send remaining
                if !chunk.is_empty() {
                    chunk_tx.send(chunk).ok();
                }
                (total_load, total_loaded)
            }
        });

        // Process chunks as they arrive (in the current blocking context)
        let result = tokio::task::spawn_blocking(move || {
            let mut total_decrypt = std::time::Duration::ZERO;
            let mut total_verify = std::time::Duration::ZERO;
            let mut total_agg = std::time::Duration::ZERO;

            let mut all_online = Vec::new();
            let mut aggregate: Option<Ciphertext> = None;
            let mut chunks_processed = 0usize;

            while let Ok(reports) = chunk_rx.recv() {
                let (online, agg, dt, vt, at) = process_chunk(&hpke_sk, &vk, context, reports);
                total_decrypt += dt;
                total_verify += vt;
                total_agg += at;
                all_online.extend(online);
                aggregate = match (aggregate, agg) {
                    (Some(a), Some(b)) => Some(a + b),
                    (Some(a), None) => Some(a),
                    (None, b) => b,
                };

                chunks_processed += 1;
                if chunks_processed % 10 == 0 {
                    info!("Processed {} chunks ({} reports so far)", chunks_processed, all_online.len());
                }
            }

            // Wait for loader to finish and get timing
            let (total_load, num_loaded) = loader_handle.join().unwrap();
            info!("Loader finished: {} reports loaded in {:?}", num_loaded, total_load);

            info!("\n\tLoad: {:?}\n\tDecrypt: {:?}\n\tVerify: {:?}\n\tAggregate: {:?}",
                total_load, total_decrypt, total_verify, total_agg);
            Ok::<_, anyhow::Error>((all_online, aggregate))
        }).await;

        let online_count = result.as_ref().ok().and_then(|r| r.as_ref().ok()).map(|(c, _)| c.len()).unwrap_or(0);
        info!("Aggregation for context {context}: {online_count} online clients (simulated: {simulated})");

        let (online_clients, aggregate) = result??;
        let aggregate = aggregate.ok_or_else(|| anyhow!("No valid reports"))?;

        // Request decryption mask
        let decrypt_start = Instant::now();
        let dropouts: Vec<usize> = if simulated {
            // Use the pre-registered dropout list for simulated runs
            Self::get_sim_dropouts(&state, context)?
        } else {
            // Compute dropouts from actually missing reports
            let online_set: HashSet<_> = online_clients.iter().copied().collect();
            (0..state.num_clients).filter(|i| !online_set.contains(&(*i as u32))).collect()
        };

        let mask = Self::request_decryption_mask(&state, context, &dropouts, aggregate.len()).await?;
        let mask = match mask {
            Message::DecryptMaskResponse { mask } => mask,
            Message::Error(e) => return Err(anyhow!("Decryptor error: {e}")),
            _ => return Err(anyhow!("Unexpected decryptor response")),
        };

        // Decrypt aggregate using discrete log
        let (is_binary, bitlength) = Self::get_proof_type_from_db(&state, context)?
            .ok_or_else(|| anyhow!("Proof type missing for context {context:08x}"))?;
        let max_dlog = if is_binary {
            online_clients.len()
        } else {
            online_clients.len() * (1 << bitlength.unwrap_or(8))
        } as u64;

        let result = AggOnlyEnc::decrypt(&aggregate, &mask, max_dlog);
        info!("\n\tDecrypt time: {:?}\n\tWall-clock: {:?}", decrypt_start.elapsed(), wall_start.elapsed());
        info!("Sent {}B, Recv {}B", bytes_sent(), bytes_recv());
        reset_byte_counters();

        match result {
            Ok(r) => Ok(r),
            Err(_) if simulated => {
                info!("Simulated round - returning dummy result");
                let length = (context & 0xFFFF) as usize;
                Ok(vec![0u64; length.min(128)])
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn validate_aggregation_context(state: &AggregatorState, context: u32) -> Result<()> {
        let current = state.current_ctx.read().await;
        match *current {
            Some(c) if c == context => Ok(()),
            Some(c) => Err(anyhow!("Context mismatch: expected {c}, got {context}")),
            None => {
                let is_sim = state.db.get(format!("sim/{context:08x}").as_bytes()).ok().flatten().is_some();
                if is_sim { Ok(()) } else { Err(anyhow!("No reports submitted yet")) }
            }
        }
    }

    fn get_sim_dropouts(state: &AggregatorState, context: u32) -> Result<Vec<usize>> {
        let data = state.db.get(format!("sim_dropouts/{context:08x}").as_bytes())?
            .ok_or_else(|| anyhow!("No sim_dropouts for context {context:08x}"))?;
        let dropouts: Vec<u32> = bincode::deserialize(&data)?;
        Ok(dropouts.into_iter().map(|x| x as usize).collect())
    }

    async fn request_decryption_mask(
        state: &AggregatorState,
        context: u32,
        dropouts: &[usize],
        length: usize,
    ) -> Result<Message> {
        let sender = state.request_send.get().ok_or_else(|| anyhow!("Decryptor not connected"))?;
        let dropouts_packed = pack_indices(dropouts, state.num_clients);
        sender.send(Message::DecryptMaskRequest {
            context,
            num_clients: state.num_clients,
            dropout_count: dropouts.len(),
            dropouts_packed,
            invert: false,
            length,
        }).await.map_err(|_| anyhow!("Failed to send decrypt request"))?;

        let mut guard = state.mask_recv.lock().await;
        let recv = guard.as_mut().ok_or_else(|| anyhow!("Decryptor not connected"))?;
        recv.recv().await.ok_or_else(|| anyhow!("Decryptor disconnected"))
    }
}
