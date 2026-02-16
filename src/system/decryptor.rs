use crate::{
    agg_only_enc::{AggOnlyEnc, EvalKey, SecretKey},
    crypto::{
        G, Scalar,
        app_attest::{verify_app_attest, verify_sig},
        hpke::*,
        prf::ScalarPRF,
    },
    proofs::Proof,
    system::messages::{Message, *},
};

use anyhow::{Result, anyhow};
use rand_core::{OsRng, RngCore};
use sled::Db;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, OnceCell, RwLock, mpsc, oneshot},
};
use tracing::{debug, error, info};

pub struct Decryptor {
    addr: String,
    pub(crate) state: Arc<DecryptorState>,
}

/// Batch size for sending key commitments to the aggregator
const BATCH_SIZE: usize = 1024;

/// What to send to the aggregator during setup: key commitment batches (normal) or a Simulate signal.
enum SetupToAggregator {
    KeyCommsBatch(Vec<(u32, G)>),
    Simulate,
}

pub(crate) struct DecryptorState {
    num_clients: usize,
    threshold: usize,
    hpke_keypair: ServerKeys,
    pub(crate) secret_key: OnceCell<SecretKey>,
    current_ctx: RwLock<Option<u32>>,
    db: Db,

    // State for one-time setup
    keygen_prf: Arc<ScalarPRF>,
    next_client_index: AtomicUsize,
    ek_send: mpsc::UnboundedSender<(u32, Scalar)>, // TODO: Test speed of bounded
    sk_recv: Mutex<Option<oneshot::Receiver<Scalar>>>,
    /// Sends key commitment batches (normal setup) or Simulate (simulated setup) to aggregator_task
    setup_send: mpsc::UnboundedSender<SetupToAggregator>,

    // Benchmarking stuff
    setup_start: OnceCell<std::time::Instant>,
}

// NOTE: Lots of small race conditions here
impl Decryptor {
    pub fn new(
        addr: &str,
        aggregator_addr: &str,
        num_clients: usize,
        threshold: usize,
        hpke_keypair: ServerKeys,
        db: Db,
    ) -> Self {
        // Check if we have a saved secret key from a previous run
        let saved_secret_key: Option<SecretKey> = db
            .get(b"secret_key")
            .ok()
            .flatten()
            .and_then(|bytes| bincode::deserialize(&bytes).ok());

        // Channel for communicating evaluation keys
        let (ek_send, mut ek_recv) = mpsc::unbounded_channel();

        // Channel for communicating secret key after setup
        let (sk_send, sk_recv) = oneshot::channel();

        // Channel for setup: key commitment batches (normal) or Simulate (simulated setup)
        let (setup_send, setup_recv) = mpsc::unbounded_channel();
        let setup_send_for_key_agg = setup_send.clone();

        // Only spawn the key aggregation task if we don't have a saved key
        if saved_secret_key.is_none() {
            // Spawn task for aggregating evaluation keys and computing key commitments
            tokio::spawn(async move {
                let g_comm = Proof::get_g_comm();
                let mut prf_key = Scalar::ZERO;
                let mut key_comms: Vec<(u32, G)> = Vec::new();

                // Receive all of the evaluation keys
                let mut received_count = 0;
                while received_count < num_clients {
                    match ek_recv.recv().await {
                        Some((client_idx, ek)) => {
                            // Accumulate PRF key
                            prf_key += ek;

                            // Compute key commitment: g_comm * ek
                            let key_comm = g_comm * ek;
                            key_comms.push((client_idx, key_comm));
                            received_count += 1;

                            // If batch is full or this is the last key, send key_comms to the
                            // aggregator
                            if key_comms.len() >= BATCH_SIZE || received_count == num_clients {
                                let to_send = std::mem::take(&mut key_comms);
                                if let Err(e) =
                                    setup_send_for_key_agg.send(SetupToAggregator::KeyCommsBatch(to_send))
                                {
                                    error!("Error when sending key commitments: {}", e);
                                }
                            }
                        }
                        None => {
                            error!("Evaluation key channel closed early");
                            break;
                        }
                    }
                }

                // Return the final aggregate key
                if let Err(e) = sk_send.send(prf_key) {
                    error!("Failed to return secret key: {:?}", e);
                }
            });
        }

        // Initialize or load the keygen PRF
        let keygen_prf = if let Some(ref sk) = saved_secret_key {
            sk.keygen_prf.clone()
        } else {
            let mut keygen_prf_key = [0u8; 32];
            OsRng.fill_bytes(&mut keygen_prf_key);
            ScalarPRF::new(&keygen_prf_key)
        };

        let secret_key_cell = OnceCell::new();
        if let Some(sk) = saved_secret_key {
            info!("Loaded secret key from database");
            secret_key_cell.set(sk).ok();
        }

        let state = Arc::new(DecryptorState {
            num_clients,
            threshold,
            hpke_keypair,
            secret_key: secret_key_cell,
            current_ctx: RwLock::new(None),
            db,
            keygen_prf: Arc::new(keygen_prf),
            next_client_index: AtomicUsize::new(0),
            ek_send,
            sk_recv: Mutex::new(Some(sk_recv)),
            setup_send,
            setup_start: OnceCell::new(),
        });

        // Spawn task to communicate with the aggregator
        let aggregator_addr = aggregator_addr.to_string();
        let state_clone = state.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::aggregator_task(aggregator_addr, state_clone, setup_recv).await {
                error!("Error communicating with aggregator: {e:?}");
            }
        });

        Self {
            addr: addr.to_string(),
            state,
        }
    }

    pub async fn run(&self) -> Result<()> {
        debug!("Starting decryptor on {}", self.addr);
        let listener = TcpListener::bind(&self.addr).await?;
        info!("Decryptor listening on {}", self.addr);

        loop {
            match listener.accept().await {
                Ok((mut socket, _)) => {
                    let state_clone = self.state.clone();
                    tokio::spawn(async move {
                        let first = match read_message(&mut socket).await {
                            Ok(m) => m,
                            Err(e) => {
                                let _ = send_error_message(&mut socket, &format!("{e:?}")).await;
                                return;
                            }
                        };
                        if matches!(first, Message::SimulateSetup {}) {
                            if let Err(e) =
                                Self::handle_simulate_setup(&mut socket, state_clone).await
                            {
                                let _ = send_error_message(&mut socket, &format!("{e:?}")).await;
                            }
                        } else if let Err(e) = Self::handle_register_request_with_initial(
                            &mut socket, state_clone, first,
                        )
                        .await
                        {
                            let _ = send_error_message(&mut socket, &format!("{e:?}")).await;
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    /// Simulated setup: respond to client immediately, then do key computation and aggregator notify locally.
    async fn handle_simulate_setup(
        socket: &mut TcpStream,
        state: Arc<DecryptorState>,
    ) -> Result<()> {
        if state.secret_key.initialized() {
            return Err(anyhow!("Setup already complete"));
        }
        state.setup_start.set(std::time::Instant::now())?;

        // Respond to client immediately so it doesn't hang
        write_message(socket, &Message::Success {}).await?;

        // Do the rest in the background; client doesn't need to know if it fails
        let state_clone = state.clone();
        let num_clients = state.num_clients;
        tokio::spawn(async move {
            let secret_key = match tokio::task::spawn_blocking(move || {
                let keygen_prf = ScalarPRF::new(&SIMULATE_PRF_KEY);
                let mut prf_key = Scalar::ZERO;
                for i in 0..num_clients {
                    prf_key += keygen_prf.evaluate(i as u64);
                }
                SecretKey {
                    prf_key,
                    keygen_prf,
                }
            })
            .await
            {
                Ok(sk) => sk,
                Err(e) => {
                    error!("Simulated setup spawn_blocking failed: {:?}", e);
                    return;
                }
            };

            let bytes = match bincode::serialize(&secret_key) {
                Ok(b) => b,
                Err(e) => {
                    error!("Simulated setup serialize failed: {:?}", e);
                    return;
                }
            };
            if let Err(e) = state_clone.db.insert(b"secret_key", bytes) {
                error!("Simulated setup db insert failed: {:?}", e);
                return;
            }
            if let Err(e) = state_clone.db.flush() {
                error!("Simulated setup db flush failed: {:?}", e);
                return;
            }
            info!("Simulated setup: saved secret key ({} clients)", num_clients);

            if state_clone.secret_key.set(secret_key).is_err() {
                error!("Simulated setup: failed to set secret_key");
                return;
            }
            if state_clone
                .setup_send
                .send(SetupToAggregator::Simulate)
                .is_err()
            {
                error!("Simulated setup: setup_send closed");
            }
        });

        Ok(())
    }

    async fn handle_register_request_with_initial(
        socket: &mut TcpStream,
        state: Arc<DecryptorState>,
        message: Message,
    ) -> Result<()> {
        // Check if registration is already complete
        if state.secret_key.initialized() {
            return Err(anyhow!(
                "Registration is closed. Maximum number of clients reached."
            ));
        }

        // If this is the first client request start timing
        if !state.setup_start.initialized() {
            state.setup_start.set(std::time::Instant::now())?;
        }

        // HPKE unwrap (message already read)
        let state_clone = state.clone();
        let (mut ctx, request) = tokio::task::spawn_blocking(move || match message {
            Message::HpkeRequest { envelope } => {
                let (msg_buf, ctx) =
                    hpke_decrypt(&state_clone.hpke_keypair.sk, &envelope, b"", b"")?;
                let request: Message = bincode::deserialize(&msg_buf)?;
                Ok((ctx, request))
            }
            _ => Err(anyhow!("Invalid message type")),
        })
        .await??;

        // Check attestation
        tokio::task::spawn_blocking(move || match request {
            Message::RegisterRequest { attestation } => verify_app_attest(&attestation),
            _ => return Err(anyhow!("Invalid message type")),
        })
        .await??;

        // Generate and send challenge back to client
        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        write_message(socket, &Message::RegisterChallenge { challenge }).await?;

        // Receive response from client
        let response = read_message(socket)
            .await
            .map_err(|e| anyhow!("Failed to read response: {e:?}"))?;

        // Context unwrap
        let response = match response {
            Message::HpkeMessage { message } => {
                let msg_buf = hpke_decrypt_with_context(&mut ctx, &message, b"")?;
                let response: Message = bincode::deserialize(&msg_buf)?;
                response
            }
            _ => return Err(anyhow!("Invalid message type")),
        };

        // Verify response
        tokio::task::spawn_blocking(move || match response {
            Message::RegisterResponse { signature } => verify_sig(&challenge, &signature),
            _ => Err(anyhow!("Invalid message type")),
        })
        .await??;

        // If verification succeeded, give the client an index (0-indexed)
        let client_index = state.next_client_index.fetch_add(1, Ordering::SeqCst);
        if client_index >= state.num_clients {
            return Err(anyhow!(
                "Registration is closed. Maximum number of clients reached."
            ));
        }

        // Compute their evaluation key and send it to the aggregating thread
        let ek = state.keygen_prf.evaluate(client_index as u64);

        // Send the key share to the aggregating thread
        if let Err(e) = state.ek_send.send((client_index as u32, ek)) {
            error!(
                "Failed to send client {} eval key to aggregator thread: {}",
                client_index, e
            );
            return Err(anyhow!("Internal error: failed to update secret key"));
        }

        // Inform client of the success
        let success_msg = Message::RegisterSuccess {
            id: client_index as u32,
            eval_key: EvalKey(ek),
        };
        write_message(socket, &success_msg).await?;

        // If this was the last client do some additional steps
        if client_index == state.num_clients - 1 {
            // Receive the final prf_key from the aggregating thread
            let prf_key = {
                let mut recv_guard = state.sk_recv.lock().await;
                recv_guard.take().unwrap().await?
            };

            // Recreate the ScalarPRF from the stored key
            let keygen_prf = state.keygen_prf.as_ref().clone();

            let secret_key = SecretKey {
                prf_key,
                keygen_prf,
            };

            // Save to database
            state
                .db
                .insert(b"secret_key", bincode::serialize(&secret_key)?)?;
            state.db.flush()?;
            info!("Saved secret key to database");

            // Set the secret key
            state
                .secret_key
                .set(secret_key)
                .map_err(|_| anyhow!("Failed to set secret key"))?;
        }
        Ok(())
    }

    async fn aggregator_task(
        aggregator_addr: String,
        state: Arc<DecryptorState>,
        mut setup_recv: mpsc::UnboundedReceiver<SetupToAggregator>,
    ) -> Result<()> {
        let mut socket = TcpStream::connect(&aggregator_addr)
            .await
            .map_err(|e| anyhow!("Aggregator connection failed: {e:?}"))?;

        // Send an initialization message so the aggregator knows its the decryptor
        write_message(&mut socket, &Message::DecryptorInit {}).await?;

        // Read response - either SetupAlreadyComplete or Success (proceed with setup)
        let response = read_message(&mut socket).await?;
        match response {
            Message::SetupAlreadyComplete {} => {
                info!("Aggregator reports setup already complete, skipping key commitment phase");
                setup_recv.close();
                while setup_recv.recv().await.is_some() {}
            }
            Message::Success {} => {
                let mut received_commitments = 0usize;
                while received_commitments < state.num_clients {
                    match setup_recv.recv().await {
                        Some(SetupToAggregator::KeyCommsBatch(kc)) => {
                            received_commitments += kc.len();
                            if let Err(e) =
                                make_request(&mut socket, &Message::KeyCommsBatch { key_comms: kc }).await
                            {
                                error!("Failed to send key commitments to aggregator: {}", e);
                            }
                        }
                        Some(SetupToAggregator::Simulate) => {
                            write_message(&mut socket, &Message::SimulateSetup {}).await?;
                            let resp = read_message(&mut socket).await?;
                            if !matches!(resp, Message::Success {}) {
                                return Err(anyhow!("Aggregator failed simulated setup: {:?}", resp));
                            }
                            info!("Simulated setup: aggregator notified");
                            break;
                        }
                        None => break,
                    }
                }
                if let Some(start) = state.setup_start.get() {
                    let elapsed = start.elapsed();
                    info!(
                        "Setup complete: {} clients in {:?}",
                        state.num_clients, elapsed
                    );
                }
                info!("Sent {:?}B", bytes_sent());
                info!("Recv {:?}B", bytes_recv());
                reset_byte_counters();
            }
            Message::Error(e) => {
                return Err(anyhow!("Aggregator returned error: {}", e));
            }
            _ => {
                return Err(anyhow!("Unexpected response from aggregator"));
            }
        }

        loop {
            let message = match read_message(&mut socket).await {
                Ok(msg) => msg,
                Err(e) => {
                    return Err(anyhow!("Failed to read message: {e:?}"));
                }
            };

            if let Message::DecryptMaskRequest {
                context,
                dropouts,
                invert,
                length,
            } = message
            {
                let mask_start = std::time::Instant::now();

                // Set current_ctx on first request
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

                // Check that enough clients are online
                let online_clients = match invert {
                    true => dropouts.len(),
                    false => state.num_clients - dropouts.len(),
                };
                if online_clients < state.threshold {
                    return Err(anyhow!("Proceed() predicate failed"));
                }

                // Generate decryption mask
                let secret_key = state
                    .secret_key
                    .get()
                    .ok_or_else(|| anyhow!("Setup incomplete"))?;
                let mask = AggOnlyEnc::decrypt_mask(secret_key, context, &dropouts, invert, length);

                // Send mask to aggregator
                write_message(&mut socket, &Message::DecryptMaskResponse { mask }).await?;

                // Reset for next round so next DecryptMaskRequest can use a new context
                {
                    let mut current_ctx = state.current_ctx.write().await;
                    *current_ctx = None;
                }

                let mask_elapsed = mask_start.elapsed();
                info!(
                    "Decrypt mask for context {}: {} online clients, {:?}",
                    context, online_clients, mask_elapsed
                );
                info!("Sent {:?}B", bytes_sent());
                info!("Recv {:?}B", bytes_recv());
                reset_byte_counters();
            } else {
                error!("Invalid request");
                continue;
            }
        }
    }
}
