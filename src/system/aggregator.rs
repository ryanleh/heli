use crate::{
    agg_only_enc::{AggOnlyEnc, Ciphertext},
    crypto::{
        G,
        hpke::{ServerKeys, hpke_decrypt},
        prf::ScalarPRF,
    },
    proofs::{Proof, VerifierKey},
    system::{ProverType, messages::*},
};

use anyhow::{Result, anyhow};
use group::Group;
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use rayon::prelude::*;
use sled::{Db, IVec};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, OnceCell, RwLock, mpsc},
};
use tracing::{debug, error, info};

// Batch size for proof verification
const BATCH_SIZE: usize = 128;

pub struct Aggregator {
    addr: String,
    state: Arc<AggregatorState>,
}

pub struct AggregatorState {
    num_clients: usize,
    threshold: usize,
    prover: ProverType,
    db: Db,
    hpke_keys: ServerKeys,
    current_ctx: RwLock<Option<u32>>,
    simulated_round: std::sync::atomic::AtomicBool, // Used with simulated reports

    // Channels for communicating decryption masks and aggregation results
    request_send: OnceCell<mpsc::Sender<Message>>,
    mask_recv: Mutex<Option<mpsc::Receiver<Message>>>,

    // Benchmarking state
    reporting_start: RwLock<Option<time::Instant>>,
    num_reported: AtomicUsize,
}

// Low-level timing information for aggregation
#[derive(Debug, Clone)]
struct OpTiming {
    load: Duration,
    decrypt: Duration,
    decode: Duration,
    verify: Duration,
    aggregate: Duration,
}

impl Aggregator {
    pub fn new(
        addr: &str,
        num_clients: usize,
        threshold: usize,
        prover: ProverType,
        db: Db,
        hpke_keys: ServerKeys,
    ) -> Self {
        let state = Arc::new(AggregatorState {
            num_clients,
            threshold,
            prover,
            db,
            hpke_keys,
            current_ctx: RwLock::new(None),
            simulated_round: std::sync::atomic::AtomicBool::new(false),
            request_send: OnceCell::new(),
            mask_recv: Mutex::new(None),
            reporting_start: Mutex::new(None),
            num_reported: AtomicUsize::new(0),
        });

        Self {
            addr: addr.to_string(),
            state,
        }
    }

    pub async fn run(&self) -> Result<()> {
        debug!("Starting aggregator on {}", self.addr);
        let listener = TcpListener::bind(&self.addr).await?;
        info!("Aggregator listening on {}", self.addr);

        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    debug!("New connection from {}", addr);
                    tokio::spawn(Self::handle_connection(socket, self.state.clone()));
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    async fn handle_connection(mut socket: TcpStream, state: Arc<AggregatorState>) {
        let message = match read_message(&mut socket).await {
            Ok(msg) => msg,
            Err(e) => {
                let _ = send_error_message(&mut socket, &format!("Failed to read message: {}", e))
                    .await;
                return;
            }
        };

        // Handle the request
        match message {
            Message::DecryptorInit {} => {
                // Channel for asking for + receiving decryption masks
                let (request_send, request_recv) = mpsc::channel(10);
                let (mask_send, mask_recv) = mpsc::channel(10);
                state.request_send.set(request_send).unwrap();
                *state.mask_recv.lock().await = Some(mask_recv);
                tokio::spawn(async move {
                    if let Err(e) =
                        Self::handle_decryptor_connection(socket, state, request_recv, mask_send)
                            .await
                    {
                        error!("Error communicating with decryptor: {e:?}");
                    }
                });
            }
            Message::EncryptedClientReport {
                id,
                context,
                envelope,
            } => match Self::store_client_report(state, id, context, envelope).await {
                Ok(()) => {
                    write_message(&mut socket, &Message::Success {}).await.ok();
                }
                Err(e) => {
                    send_error_message(&mut socket, &format!("Saving report failed: {}", e))
                        .await
                        .ok();
                }
            },
            Message::SimulatedBatchComing {} => {
                state.simulated_round.store(true, Ordering::SeqCst);
                write_message(&mut socket, &Message::Success {}).await.ok();
            }
            Message::BatchEncryptedClientReports { reports } => {
                match Self::store_batch_client_reports(state, reports).await {
                    Ok(()) => {
                        write_message(&mut socket, &Message::Success {}).await.ok();
                    }
                    Err(e) => {
                        send_error_message(
                            &mut socket,
                            &format!("Saving batch reports failed: {}", e),
                        )
                        .await
                        .ok();
                    }
                }
            }
            Message::AggregationRequest { context } => {
                let request_start = time::Instant::now();
                info!("Aggregation request for context {}", context);
                match Self::aggregate(state.clone(), context).await {
                    Ok(result) => {
                        state.simulated_round.store(false, Ordering::SeqCst);
                        write_message(&mut socket, &Message::AggregationResponse { result })
                            .await
                            .ok();
                    }
                    Err(e) => {
                        if state.simulated_round.load(Ordering::SeqCst) {
                            info!("Simulated round");
                            info!(
                                "\n\tDecrypt time: {:?}\n\tWall-clock time: {:?}",
                                Duration::ZERO,
                                request_start.elapsed()
                            );
                            let length = (context & 0xFFFF) as usize;
                            let dummy = vec![0u64; length.min(1_000_000)];
                            state.simulated_round.store(false, Ordering::SeqCst);
                            write_message(
                                &mut socket,
                                &Message::AggregationResponse { result: dummy },
                            )
                            .await
                            .ok();
                        } else {
                            send_error_message(
                                &mut socket,
                                &format!("Aggregation failed: {}", e),
                            )
                            .await
                            .ok();
                        }
                    }
                }
                // Reset for next round so new reports can use a new context (success or failure)
                {
                    let mut current_ctx = state.current_ctx.write().await;
                    *current_ctx = None;
                }
                state.num_reported.store(0, Ordering::SeqCst);
            }
            _ => {
                send_error_message(&mut socket, &format!("Invalid request"))
                    .await
                    .ok();
            }
        };
    }

    /// Helper function for handling the connection with the decryptor
    async fn handle_decryptor_connection(
        mut socket: TcpStream,
        state: Arc<AggregatorState>,
        mut request_recv: mpsc::Receiver<Message>,
        mask_send: mpsc::Sender<Message>,
    ) -> Result<()> {
        // Check if key commitments already exist in DB
        let has_key_comms = state.db.contains_key(b"kc")?;

        if has_key_comms {
            // Setup already complete, notify decryptor and skip to mask requests
            info!("Key commitments already exist, skipping setup");
            write_message(&mut socket, &Message::SetupAlreadyComplete {}).await?;
        } else {
            // Normal setup: receive key commitments from decryptor or SimulateSetup
            write_message(&mut socket, &Message::Success {}).await?;

            let mut setup_start: time::Instant;
            let mut received_commitments = 0usize;
            let mut key_commitments = vec![G::generator(); state.num_clients];

            let first_message = read_message(&mut socket).await?;
            if matches!(first_message, Message::SimulateSetup {}) {
                // Simulated setup: compute key commitments locally from hardcoded PRF key
                setup_start = time::Instant::now();
                let num_clients = state.num_clients;
                let g_comm = Proof::get_g_comm();
                key_commitments = tokio::task::spawn_blocking(move || {
                    let prf = ScalarPRF::new(&SIMULATE_PRF_KEY);
                    (0..num_clients)
                        .into_par_iter()
                        .map(|i| g_comm * prf.evaluate(i as u64))
                        .collect::<Vec<_>>()
                })
                .await?;
                info!(
                    "Simulated setup: computed {} key commitments locally in {:?}",
                    num_clients,
                    setup_start.as_ref().unwrap().elapsed()
                );
                write_message(&mut socket, &Message::Success {}).await?;
            } else if let Message::KeyCommsBatch { key_comms } = first_message {
                setup_start = time::Instant::now();
                received_commitments += key_comms.len();
                for (idx, key_comm) in key_comms.into_iter() {
                    key_commitments[idx as usize] = key_comm;
                }
                if let Err(e) = write_message(&mut socket, &Message::Success {}).await {
                    return Err(anyhow!("Failed to send response to decryptor: {}", e));
                }

                // Receive remaining batches
                while received_commitments < state.num_clients {
                    let message = read_message(&mut socket).await?;
                    let key_comms_batch = match message {
                        Message::KeyCommsBatch { key_comms } => key_comms,
                        _ => {
                            let _ = send_error_message(&mut socket, &format!("Invalid message type"))
                                .await;
                            return Err(anyhow!("Invalid message type from decryptor"));
                        }
                    };
                    received_commitments += key_comms_batch.len();
                    for (idx, key_comm) in key_comms_batch.into_iter() {
                        key_commitments[idx as usize] = key_comm;
                    }
                    if let Err(e) = write_message(&mut socket, &Message::Success {}).await {
                        return Err(anyhow!("Failed to send response to decryptor: {}", e));
                    }
                }
            } else {
                let _ =
                    send_error_message(&mut socket, &format!("Invalid message type")).await;
                return Err(anyhow!("Invalid message type from decryptor"));
            }

            // Write key commitments to the database
            let num_clients = state.num_clients;
            let state_clone = state.clone();
            tokio::task::spawn_blocking(move || -> Result<()> {
                state_clone
                    .db
                    .insert(b"kc", bincode::serialize(&key_commitments)?)?;
                state_clone.db.flush()?;
                Ok(())
            })
            .await??;

            let setup_elapsed = start.elapsed();
            info!(
                "Setup complete: received {} key commitments in {:?}",
                num_clients, setup_elapsed
            );
            info!("Sent {:?}B", bytes_sent());
            info!("Recv {:?}B", bytes_recv());
            reset_byte_counters();
        }

        // Process requests for decryption masks
        while let Some(request) = request_recv.recv().await {
            write_message(&mut socket, &request).await?;
            let response = read_message(&mut socket).await?;
            if let Err(e) = mask_send.send(response).await {
                error!("Error sending mask internally: {e:?}");
            }
        }

        Ok(())
    }

    // Store client report in the local database
    async fn store_client_report(
        state: Arc<AggregatorState>,
        id: u32,
        context: u32,
        envelope: crate::crypto::hpke::HpkeEnvelope,
    ) -> Result<()> {
        // Set current_ctx on first submission
        {
            let mut current_ctx = state.current_ctx.write().await;
            if current_ctx.is_none() {
                *current_ctx = Some(context);
            } else if *current_ctx != Some(context) {
                return Err(anyhow!(
                    "Context mismatch: expected {:?}, got {}",
                    current_ctx,
                    context
                ));
            }
        }

        if !state.reporting_start.initialized() {
            state.reporting_start.set(time::Instant::now())?;
        }

        // Store the HPKE envelope directly in the database
        let state_clone = state.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let key = format!("r/{context:08x}/{id:08x}");
            let blob = bincode::serialize(&envelope)?;
            state_clone.db.insert(key.as_bytes(), IVec::from(blob))?;
            state_clone.db.flush()?;
            Ok(())
        })
        .await??;

        // If we've received enough client reports for aggregation, report stats
        let num = state.num_reported.fetch_add(1, Ordering::SeqCst);
        if num == state.threshold - 1 {
            let elapsed = state.reporting_start.get().unwrap().elapsed();
            info!(
                "Received enough reports for aggregation ({}) in {elapsed:?}",
                num + 1
            );
            info!("Sent {:?}B", bytes_sent());
            info!("Recv {:?}B", bytes_recv());
            reset_byte_counters();
        }

        Ok(())
    }

    // Store a batch of clients reports in the local database
    async fn store_batch_client_reports(
        state: Arc<AggregatorState>,
        reports: Vec<(u32, u32, crate::crypto::hpke::HpkeEnvelope)>,
    ) -> Result<()> {
        if reports.is_empty() {
            return Ok(());
        }

        // Set current_ctx on first submission (use first report's context)
        let first_context = reports[0].1;
        {
            let mut current_ctx = state.current_ctx.write().await;
            if current_ctx.is_none() {
                *current_ctx = Some(first_context);
            }
        }

        // Verify all reports have the same context
        {
            let current_ctx = state.current_ctx.read().await;
            let expected_ctx = current_ctx.ok_or(anyhow!("No context set"))?;
            for (_, context, _) in &reports {
                if *context != expected_ctx {
                    return Err(anyhow!(
                        "Context mismatch: expected {}, got {}",
                        expected_ctx,
                        context
                    ));
                }
            }
        }

        if !state.reporting_start.initialized() {
            state.reporting_start.set(time::Instant::now())?;
        }

        // Store all HPKE envelopes in the database in a single batch operation
        let state_clone = state.clone();
        let batch_size = reports.len();
        tokio::task::spawn_blocking(move || -> Result<()> {
            for (id, context, envelope) in reports {
                let key = format!("r/{context:08x}/{id:08x}");
                let blob = bincode::serialize(&envelope)?;
                state_clone.db.insert(key.as_bytes(), IVec::from(blob))?;
            }
            state_clone.db.flush()?;
            Ok(())
        })
        .await??;

        // If we've received enough client reports for aggregation, report stats
        let num = state.num_reported.fetch_add(batch_size, Ordering::SeqCst);
        let total = num + batch_size;
        if total >= state.threshold && num < state.threshold {
            let elapsed = state.reporting_start.get().unwrap().elapsed();
            info!(
                "Received enough reports for aggregation ({}) in {elapsed:?}",
                total
            );
        }

        Ok(())
    }

    // Deserialize the verification key from local database
    fn get_vk(state: Arc<AggregatorState>) -> Result<VerifierKey> {
        let g_comm = Proof::get_g_comm();
        let key_commitments: Vec<G> = bincode::deserialize(
            &state
                .db
                .get(b"kc")?
                .ok_or(anyhow!("Couldn't fetch key commitments"))?,
        )?;

        let vk = match state.prover {
            ProverType::Binary => VerifierKey::Binary {
                g_comm,
                key_commitments,
            },
            ProverType::Range(bitlength) => VerifierKey::Range {
                g_comm,
                key_commitments,
                bitlength,
            },
        };
        Ok(vk)
    }

    async fn aggregate(state: Arc<AggregatorState>, context: u32) -> Result<Vec<u64>> {
        // Check that context matches current_ctx (or in simulated mode allow proceeding with request context)
        let current_ctx = state.current_ctx.read().await;
        match *current_ctx {
            Some(expected_ctx) if expected_ctx == context => {
                // Context matches, proceed
            }
            Some(expected_ctx) => {
                return Err(anyhow!(
                    "Invalid context: expected {}, got {}",
                    expected_ctx,
                    context
                ));
            }
            None => {
                if !state.simulated_round.load(Ordering::SeqCst) {
                    return Err(anyhow!(
                        "No context set yet - need client submissions first"
                    ));
                }
                // Simulated mode: proceed with request context so verification/timing still runs (reports keyed by context in DB)
            }
        }
        drop(current_ctx);

        // Record wall-clock aggregation time
        let wall_clock_start = time::Instant::now();

        // Initialize the verification key
        let vk = Self::get_vk(state.clone())?;

        // Create channel for communicating timing stats
        let (timing_send, mut timing_recv) = mpsc::unbounded_channel();

        // Partition clients into chunks for parallel processing
        let num_clients = state.num_clients;
        let client_ranges: Vec<_> = (0..num_clients)
            .collect::<Vec<_>>()
            .chunks(BATCH_SIZE)
            .map(|chunk| (chunk[0], chunk[chunk.len() - 1]))
            .collect();

        // Process chunks in parallel (decrypt / decode + verify + aggregate in one pass)
        let state_clone = state.clone();
        let hpke_sk = state.hpke_keys.sk.clone();
        let client_ranges_clone = client_ranges.clone();
        let timing_send_clone = timing_send.clone();

        let block_result =
            tokio::task::spawn_blocking(move || -> Result<(Vec<u32>, Option<Ciphertext>)> {
                let results: Vec<_> = client_ranges_clone
                    .into_par_iter()
                    .map(|(start, end)| -> Result<Option<(Vec<u32>, Ciphertext)>> {
                        let vk = vk.clone();
                        let mut chunk_clients = Vec::with_capacity(BATCH_SIZE);
                        let mut chunk_proofs = Vec::with_capacity(BATCH_SIZE);
                        let mut chunk_ciphertexts = Vec::with_capacity(BATCH_SIZE);

                        // Process each client in the chunk
                        let mut load_time = Duration::ZERO;
                        let mut decode_time = Duration::ZERO;
                        let mut decrypt_time = Duration::ZERO;
                        for id in start..=end {
                            // Read from DB
                            let load_start = time::Instant::now();
                            let key = format!("r/{context:08x}/{id:08x}");
                            let value = match state_clone.db.get(key.as_bytes())? {
                                Some(v) => v,
                                None => continue, // Skip missing clients
                            };
                            load_time += load_start.elapsed();

                            // HPKE decrypt
                            let decrypt_start = time::Instant::now();
                            let envelope: crate::crypto::hpke::HpkeEnvelope =
                                bincode::deserialize(&value)?;
                            let (report_bytes, _) = hpke_decrypt(&hpke_sk, &envelope, b"", b"")?;
                            decrypt_time += decrypt_start.elapsed();

                            // Decode
                            //
                            // NOTE: This is a rather big overhead at the moment for some reason
                            let decode_start = time::Instant::now();
                            let report: Message = bincode::deserialize(&report_bytes)?;
                            let (proof, ciphertext) = match report {
                                Message::ClientReport {
                                    proof, ciphertext, ..
                                } => (proof, ciphertext),
                                _ => return Err(anyhow!("Invalid message type in envelope")),
                            };
                            decode_time += decode_start.elapsed();

                            // Add to chunk for batch verification
                            chunk_clients.push(id as u32);
                            chunk_proofs.push(proof);
                            chunk_ciphertexts.push(ciphertext);
                        }

                        // If all the clients in this chunk dropped out, skip
                        if chunk_clients.is_empty() {
                            return Ok(None);
                        }

                        // Batch verify
                        let verify_start = time::Instant::now();

                        // Seed a new (fast) RNG we can send across threads
                        let mut seed = [0u8; 32];
                        OsRng.fill_bytes(&mut seed);
                        let mut rng = ChaCha20Rng::from_seed(seed);

                        Proof::batch_verify(
                            &vk,
                            &chunk_ciphertexts,
                            context,
                            &chunk_proofs,
                            &chunk_clients,
                            &mut rng,
                        )?;
                        let verify_time = verify_start.elapsed();

                        // Aggregate
                        let aggregate_start = time::Instant::now();
                        let chunk_aggregate = chunk_ciphertexts
                            .into_iter()
                            .reduce(|a, b| a + b)
                            .ok_or(anyhow!("Empty chunk after filtering"))?;
                        let aggregate_time = aggregate_start.elapsed();

                        // Register timing info
                        let timing = OpTiming {
                            load: load_time,
                            decode: decode_time,
                            decrypt: decrypt_time,
                            verify: verify_time,
                            aggregate: aggregate_time,
                        };
                        let _ = timing_send_clone.send(timing);

                        Ok(Some((chunk_clients, chunk_aggregate)))
                    })
                    .collect::<Result<Vec<_>>>()?;

                // Combine results from all chunks
                let (online_clients, aggregate_opt) = results.into_iter().filter_map(|x| x).fold(
                    (Vec::new(), None),
                    |(mut clients, agg), (chunk_clients, chunk_agg)| {
                        clients.extend(chunk_clients);
                        let agg = match (agg, Some(chunk_agg)) {
                            (Some(a), Some(c)) => Some(a + c),
                            (None, Some(c)) => Some(c),
                            _ => unreachable!(),
                        };
                        (clients, agg)
                    },
                );

                Ok((online_clients, aggregate_opt))
            })
            .await;

        // Always collect and log report-processing timing (even when spawn_blocking failed, so simulated rounds get timing)
        drop(timing_send);
        let mut total_load_time = Duration::ZERO;
        let mut total_decode_time = Duration::ZERO;
        let mut total_decrypt_time = Duration::ZERO;
        let mut total_verify_time = Duration::ZERO;
        let mut total_aggregate_time = Duration::ZERO;
        while let Some(timing) = timing_recv.recv().await {
            total_load_time += timing.load;
            total_decode_time += timing.decode;
            total_decrypt_time += timing.decrypt;
            total_verify_time += timing.verify;
            total_aggregate_time += timing.aggregate;
        }
        let online_count = block_result
            .as_ref()
            .ok()
            .and_then(|r| r.as_ref().ok())
            .map(|(c, _)| c.len())
            .unwrap_or(0);
        info!(
            "Aggregation (report processing) for context {}: {} online clients",
            context,
            online_count
        );
        info!(
            "\n\tLoad time {:?}\n\tDecode time: {:?}\n\tHPKE-decryption time: {:?}\n\tVerify time: {:?}\n\tAggregate time: {:?}",
            total_load_time,
            total_decode_time,
            total_decrypt_time,
            total_verify_time,
            total_aggregate_time
        );

        let (online_clients, aggregate) = block_result??;
        let aggregate = aggregate.ok_or(anyhow!("No valid reports"))?;

        // Request decryption mask from the decryptor
        let decrypt_start = time::Instant::now();
        let request_send = state
            .request_send
            .get()
            .ok_or(anyhow!("Decryptor not connected"))?;

        // Compute dropouts (clients not in online_clients)
        //
        // TODO: Support large dropouts properly
        let online_set: std::collections::HashSet<_> = online_clients.iter().copied().collect();
        let dropouts: Vec<usize> = (0..state.num_clients)
            .filter(|id| !online_set.contains(&(*id as u32)))
            .collect();
        let request = Message::DecryptMaskRequest {
            context,
            dropouts,
            invert: false,
            length: aggregate.len(),
        };
        request_send
            .send(request)
            .await
            .map_err(|_| anyhow!("Failed to send decrypt request"))?;

        // Receive the decryption mask
        let mut mask_recv_guard = state.mask_recv.lock().await;
        let mask_recv = mask_recv_guard
            .as_mut()
            .ok_or(anyhow!("Decryptor not connected"))?;
        let response = mask_recv
            .recv()
            .await
            .ok_or(anyhow!("Decryptor connection closed"))?;

        let mask = match response {
            Message::DecryptMaskResponse { mask } => mask,
            Message::Error(e) => return Err(anyhow!("Decryptor error: {}", e)),
            _ => return Err(anyhow!("Unexpected response from decryptor")),
        };

        // Decrypt the aggregate
        let max_dlog = match state.prover {
            ProverType::Binary => online_clients.len(),
            ProverType::Range(bitlength) => online_clients.len() * (1 << bitlength),
        } as u64;
        let result = AggOnlyEnc::decrypt(&aggregate, &mask, max_dlog)?;

        let decrypt_elapsed = decrypt_start.elapsed();
        let wall_clock_elapsed = wall_clock_start.elapsed();

        info!(
            "\n\tDecrypt time: {:?}\n\tWall-clock time: {:?}",
            decrypt_elapsed, wall_clock_elapsed
        );
        info!("Sent {:?}B", bytes_sent());
        info!("Recv {:?}B", bytes_recv());
        reset_byte_counters();

        Ok(result)
    }
}
