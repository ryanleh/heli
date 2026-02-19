use crate::{
    BATCH_REPORT_SIZE,
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
    sync::Arc,
    time::Instant,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, OnceCell, RwLock, mpsc},
};
use tracing::{debug, error, info};

const VERIFY_BATCH_SIZE: usize = 128;

pub struct Aggregator {
    addr: String,
    state: Arc<AggregatorState>,
}

pub struct AggregatorState {
    num_clients: usize,
    #[allow(dead_code)]
    threshold: usize,
    db: Db,
    hpke_keys: ServerKeys,
    current_ctx: RwLock<Option<u32>>,
    request_send: OnceCell<mpsc::Sender<Message>>,
    mask_recv: Mutex<Option<mpsc::Receiver<Message>>>,
    max_pending_batches: usize,
    reports_per_chunk: usize,
}

impl Aggregator {
    pub fn new(
        addr: &str,
        num_clients: usize,
        threshold: usize,
        _prover: ProverType,
        db: Db,
        hpke_keys: ServerKeys,
        max_pending_batches: usize,
        reports_per_chunk: usize,
    ) -> Self {
        let state = Arc::new(AggregatorState {
            num_clients,
            threshold,
            db,
            hpke_keys,
            current_ctx: RwLock::new(None),
            request_send: OnceCell::new(),
            mask_recv: Mutex::new(None),
            max_pending_batches,
            reports_per_chunk,
        });

        Self { addr: addr.to_string(), state }
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
            Message::AggregateStreamStart { context, num_batches, binary, bitlength, simulated, sim_dropouts } => {
                Self::handle_aggregate_stream(
                    &mut socket, state, context, num_batches,
                    binary, bitlength, simulated, sim_dropouts,
                ).await;
            }
            _ => {
                send_error_message(&mut socket, "Invalid request").await.ok();
            }
        }
    }

    // --- Aggregate stream: combined submit + aggregate, fully in-memory ---

    async fn handle_aggregate_stream(
        socket: &mut TcpStream,
        state: Arc<AggregatorState>,
        context: u32,
        num_batches: usize,
        binary: bool,
        bitlength: Option<usize>,
        simulated: bool,
        sim_dropouts: Vec<u32>,
    ) {
        let wall_start = Instant::now();
        info!("Aggregate stream for context {context}: {num_batches} batches, simulated={simulated}");

        // Ensure no other aggregation is in progress
        {
            let mut current = state.current_ctx.write().await;
            if current.is_some() {
                send_error_message(socket, "Another aggregation is already in progress").await.ok();
                return;
            }
            *current = Some(context);
        }

        let result = Self::run_aggregate_stream(
            socket, &state, context, num_batches,
            binary, bitlength, simulated, sim_dropouts,
        ).await;

        match result {
            Ok(data) => {
                write_message(socket, &Message::AggregationResponse { result: data }).await.ok();
            }
            Err(e) => {
                error!("Aggregate stream failed: {e}");
                send_error_message(socket, &format!("Aggregation failed: {e}")).await.ok();
            }
        }

        info!("Aggregate stream wall-clock time: {:?}", wall_start.elapsed());
        info!("Sent {}B, Recv {}B", bytes_sent(), bytes_recv());
        reset_byte_counters();

        *state.current_ctx.write().await = None;
    }

    async fn run_aggregate_stream(
        socket: &mut TcpStream,
        state: &AggregatorState,
        context: u32,
        num_batches: usize,
        binary: bool,
        bitlength: Option<usize>,
        simulated: bool,
        sim_dropouts: Vec<u32>,
    ) -> Result<Vec<u64>> {
        let vk = Self::build_vk(state, binary, bitlength)?;
        let hpke_sk = state.hpke_keys.sk.clone();

        // Bounded channel: once full, the reader blocks, applying backpressure to the network
        let (batch_tx, mut batch_rx) =
            mpsc::channel::<Vec<(u32, Vec<u8>)>>(state.max_pending_batches);

        // Processor thread: pulls batches from the channel, decrypts/verifies/aggregates
        let proc_context = context;
        let processor_handle = std::thread::spawn(move || {
            let mut all_online = Vec::new();
            let mut aggregate: Option<Ciphertext> = None;
            let mut total_decrypt = std::time::Duration::ZERO;
            let mut total_verify = std::time::Duration::ZERO;
            let mut total_agg = std::time::Duration::ZERO;
            let mut chunks_processed = 0usize;

            while let Some(reports) = batch_rx.blocking_recv() {
                let (online, agg, dt, vt, at) =
                    process_chunk(&hpke_sk, &vk, proc_context, reports);
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
                info!("Processed {chunks_processed} chunks ({} reports)", all_online.len());
            }

            info!(
                "\n\tDecrypt: {:?}\n\tVerify: {:?}\n\tAggregate: {:?}",
                total_decrypt, total_verify, total_agg
            );
            (all_online, aggregate)
        });

        // Reader loop: read batches from network, combine into larger chunks,
        // then pipe to processor via bounded channel (backpressure when full).
        let recv_start = Instant::now();
        let mut total_reports = 0usize;
        let mut chunk = Vec::with_capacity(state.reports_per_chunk);
        for _ in 0..num_batches {
            let message = read_message(socket).await?;
            if let Message::BatchEncryptedClientReports { reports, .. } = message {
                total_reports += reports.len();
                if simulated {
                    chunk.extend(
                        reports.into_iter()
                            .map(|(id, data)| (id % BATCH_REPORT_SIZE as u32, data)),
                    );
                } else {
                    chunk.extend(reports);
                }
                if chunk.len() >= state.reports_per_chunk {
                    batch_tx.send(std::mem::replace(&mut chunk, Vec::with_capacity(state.reports_per_chunk)))
                        .await
                        .map_err(|_| anyhow!("Processor thread died"))?;
                }
            } else {
                return Err(anyhow!("Expected BatchEncryptedClientReports"));
            }
        }
        if !chunk.is_empty() {
            batch_tx.send(chunk).await
                .map_err(|_| anyhow!("Processor thread died"))?;
        }
        drop(batch_tx);
        info!(
            "Received {} reports in {} batches ({:?})",
            total_reports, num_batches, recv_start.elapsed()
        );

        // Wait for processor to finish
        let (online_clients, aggregate) = processor_handle
            .join()
            .map_err(|_| anyhow!("Processor thread panicked"))?;
        let aggregate = aggregate.ok_or_else(|| anyhow!("No valid reports"))?;

        let online_count = online_clients.len();
        info!("Aggregation: {online_count} online clients (simulated: {simulated})");

        // Request decryption mask
        let decrypt_start = Instant::now();
        let dropouts: Vec<usize> = if simulated {
            sim_dropouts.into_iter().map(|x| x as usize).collect()
        } else {
            let online_set: HashSet<_> = online_clients.iter().copied().collect();
            (0..state.num_clients)
                .filter(|i| !online_set.contains(&(*i as u32)))
                .collect()
        };

        let mask = Self::request_decryption_mask(state, context, &dropouts, aggregate.len()).await?;
        let mask = match mask {
            Message::DecryptMaskResponse { mask } => mask,
            Message::Error(e) => return Err(anyhow!("Decryptor error: {e}")),
            _ => return Err(anyhow!("Unexpected decryptor response")),
        };

        // Decrypt aggregate
        let max_dlog = if binary {
            online_count
        } else {
            online_count * (1 << bitlength.unwrap_or(8))
        } as u64;

        let result = AggOnlyEnc::decrypt(&aggregate, &mask, max_dlog);
        info!("\n\tDecrypt time: {:?}\n\tWall-clock: {:?}", decrypt_start.elapsed(), recv_start.elapsed());

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

    // --- Verifier key ---

    fn build_vk(state: &AggregatorState, binary: bool, bitlength: Option<usize>) -> Result<VerifierKey> {
        let g_comm = Proof::get_g_comm();
        let data = state.db.get(b"kc")?.ok_or_else(|| anyhow!("No key commitments in DB"))?;
        let key_commitments = Self::deserialize_key_commitments(&data)?;

        Ok(if binary {
            VerifierKey::Binary { g_comm, key_commitments }
        } else {
            VerifierKey::Range {
                g_comm,
                key_commitments,
                bitlength: bitlength.ok_or_else(|| anyhow!("bitlength required for range proof"))?,
            }
        })
    }

    fn deserialize_key_commitments(data: &[u8]) -> Result<Vec<G>> {
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

    // --- Decryptor connection ---

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

        let db = state.db.clone();
        let num_clients = state.num_clients;
        tokio::task::spawn_blocking(move || -> Result<()> {
            let serialize_start = Instant::now();

            const CHUNK_SIZE: usize = 100_000;
            let serialized_chunks: Vec<Vec<u8>> = key_commitments
                .par_chunks(CHUNK_SIZE)
                .map(|chunk| bincode::serialize(chunk).unwrap())
                .collect();

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

    // --- Decryption mask request ---

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

// --- Chunk processing (decrypt, verify, aggregate) ---

fn process_chunk(
    hpke_sk: &<hpke::kem::X25519HkdfSha256 as hpke::Kem>::PrivateKey,
    vk: &VerifierKey,
    context: u32,
    reports: Vec<(u32, Vec<u8>)>,
) -> (Vec<u32>, Option<Ciphertext>, std::time::Duration, std::time::Duration, std::time::Duration) {
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
