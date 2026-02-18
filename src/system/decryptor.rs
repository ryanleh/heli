use crate::{
    agg_only_enc::{EvalKey, SecretKey},
    crypto::{
        G, Scalar,
        app_attest::{verify_app_attest, verify_sig},
        hpke::*,
        prf::{ScalarPRF, KHPRF},
    },
    proofs::Proof,
    system::messages::{Message, *},
};
use rayon::prelude::*;

use anyhow::{Result, anyhow};
use rand_core::{OsRng, RngCore};
use sled::Db;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, OnceCell, RwLock, mpsc, oneshot},
};
use tracing::{error, info};

pub struct Decryptor {
    addr: String,
    pub(crate) state: Arc<DecryptorState>,
}

const KEY_COMMITMENT_BATCH_SIZE: usize = 1024;

pub(crate) struct DecryptorState {
    num_clients: usize,
    threshold: usize,
    hpke_keypair: ServerKeys,
    pub(crate) secret_key: OnceCell<SecretKey>,
    current_ctx: RwLock<Option<u32>>,
    db: Db,
    keygen_prf: RwLock<ScalarPRF>,
    next_client_index: AtomicUsize,
    ek_send: mpsc::UnboundedSender<ClientKey>,
    setup_send: mpsc::UnboundedSender<SetupToAggregator>,
    sk_recv: Mutex<Option<oneshot::Receiver<Scalar>>>,
    setup_start: OnceCell<Instant>,
}

enum ClientKey {
    Simulate,
    Key(u32, Scalar),
}

pub(crate) enum SetupToAggregator {
    KeyCommsBatch(Vec<(u32, G)>),
    Simulate,
}

impl Decryptor {
    pub fn new(
        addr: &str,
        aggregator_addr: &str,
        num_clients: usize,
        threshold: usize,
        hpke_keypair: ServerKeys,
        db: Db,
    ) -> Self {
        let saved_secret_key: Option<SecretKey> = db
            .get(b"secret_key")
            .ok()
            .flatten()
            .and_then(|bytes| bincode::deserialize(&bytes).ok());

        let (ek_send, mut ek_recv) = mpsc::unbounded_channel();
        let (sk_send, sk_recv) = oneshot::channel();
        let (kc_send, kc_recv) = mpsc::unbounded_channel();

        let secret_key_cell = OnceCell::new();
        let keygen_prf = if let Some(ref sk) = saved_secret_key {
            info!("Loaded secret key from database");
            secret_key_cell.set(sk.clone()).ok();
            sk.keygen_prf.clone()
        } else {
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            ScalarPRF::new(&key)
        };

        let state = Arc::new(DecryptorState {
            num_clients,
            threshold,
            hpke_keypair,
            secret_key: secret_key_cell,
            current_ctx: RwLock::new(None),
            db,
            keygen_prf: RwLock::new(keygen_prf),
            next_client_index: AtomicUsize::new(0),
            ek_send,
            setup_send: kc_send,
            sk_recv: Mutex::new(Some(sk_recv)),
            setup_start: OnceCell::new(),
        });

        // If no saved key, spawn task to aggregate evaluation keys
        if saved_secret_key.is_none() {
            let n = num_clients;
            let state_clone = state.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::key_aggregation_task(state_clone, &mut ek_recv, sk_send, n).await {
                    error!("Key aggregation failed: {e:?}");
                }
            });
        }

        // Spawn task to communicate with aggregator
        let agg_addr = aggregator_addr.to_string();
        let state_clone = state.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::aggregator_task(agg_addr, state_clone, kc_recv).await {
                error!("Aggregator connection error: {e:?}");
            }
        });

        Self { addr: addr.to_string(), state }
    }

    async fn key_aggregation_task(
        state: Arc<DecryptorState>,
        ek_recv: &mut mpsc::UnboundedReceiver<ClientKey>,
        sk_send: oneshot::Sender<Scalar>,
        num_clients: usize,
    ) -> Result<()> {
        let Some(first) = ek_recv.recv().await else {
            return Err(anyhow!("Channel closed before receiving any key"));
        };

        let prf_key = match first {
            ClientKey::Simulate => {
                let sk = Self::compute_simulated_secret_key(num_clients).await?;
                state.db.insert(b"secret_key", bincode::serialize(&sk)?)?;
                state.db.flush()?;
                info!("Saved secret key to database (simulated setup)");
                state.secret_key.set(sk.clone()).map_err(|_| anyhow!("Secret key already set"))?;
                state.setup_send.send(SetupToAggregator::Simulate).ok();
                sk.prf_key
            }
            ClientKey::Key(idx, ek) => {
                Self::aggregate_real_keys(&state, ek_recv, idx, ek, num_clients).await?
            }
        };

        sk_send.send(prf_key).map_err(|_| anyhow!("Failed to send secret key"))?;
        Ok(())
    }

    async fn compute_simulated_secret_key(num_clients: usize) -> Result<SecretKey> {
        tokio::task::spawn_blocking(move || {
            let keygen_prf = ScalarPRF::new(&SIMULATE_PRF_KEY);
            let prf_key = (0..num_clients).fold(Scalar::ZERO, |acc, i| acc + keygen_prf.evaluate(i as u64));
            SecretKey { prf_key, keygen_prf }
        }).await.map_err(|e| anyhow!("{e}"))
    }

    async fn aggregate_real_keys(
        state: &DecryptorState,
        ek_recv: &mut mpsc::UnboundedReceiver<ClientKey>,
        first_idx: u32,
        first_ek: Scalar,
        num_clients: usize,
    ) -> Result<Scalar> {
        let g_comm = Proof::get_g_comm();
        let mut prf_key = first_ek;
        let mut key_comms = vec![(first_idx, g_comm * first_ek)];
        let mut received = 1;

        while received < num_clients {
            let ClientKey::Key(idx, ek) = ek_recv.recv().await.ok_or_else(|| anyhow!("Channel closed"))? else {
                return Err(anyhow!("Unexpected simulate message during registration"));
            };

            prf_key += ek;
            key_comms.push((idx, g_comm * ek));
            received += 1;

            if key_comms.len() >= KEY_COMMITMENT_BATCH_SIZE || received == num_clients {
                state.setup_send.send(SetupToAggregator::KeyCommsBatch(std::mem::take(&mut key_comms))).ok();
            }
        }

        Ok(prf_key)
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.addr).await?;
        info!("Decryptor listening on {}", self.addr);

        loop {
            let (mut socket, _) = listener.accept().await?;
            let state = self.state.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_client(&mut socket, state).await {
                    send_error_message(&mut socket, &e.to_string()).await.ok();
                }
            });
        }
    }

    async fn handle_client(socket: &mut TcpStream, state: Arc<DecryptorState>) -> Result<()> {
        let msg = read_message(socket).await?;
        match msg {
            Message::SimulateSetup {} => {
                state.ek_send.send(ClientKey::Simulate)?;
                Self::handle_simulate_setup(socket, state).await
            }
            _ => Self::handle_register_request(socket, state, msg).await,
        }
    }

    async fn handle_simulate_setup(socket: &mut TcpStream, state: Arc<DecryptorState>) -> Result<()> {
        if state.secret_key.initialized() {
            return Err(anyhow!("Setup already complete"));
        }
        state.setup_start.set(Instant::now()).ok();
        write_message(socket, &Message::Success {}).await
    }

    async fn handle_register_request(
        socket: &mut TcpStream,
        state: Arc<DecryptorState>,
        initial_msg: Message,
    ) -> Result<()> {
        if state.secret_key.initialized() {
            return Err(anyhow!("Registration closed"));
        }
        state.setup_start.set(Instant::now()).ok();

        // Decrypt and verify the initial HPKE request
        let hpke_sk = state.hpke_keypair.sk.clone();
        let (mut ctx, request) = tokio::task::spawn_blocking(move || {
            let Message::HpkeRequest { envelope } = initial_msg else {
                return Err(anyhow!("Expected HpkeRequest"));
            };
            let (msg, ctx) = hpke_decrypt(&hpke_sk, &envelope, b"", b"")?;
            Ok::<_, anyhow::Error>((ctx, bincode::deserialize::<Message>(&msg)?))
        }).await??;

        // Verify attestation
        tokio::task::spawn_blocking(move || {
            let Message::RegisterRequest { attestation } = request else {
                return Err(anyhow!("Expected RegisterRequest"));
            };
            verify_app_attest(&attestation)
        }).await??;

        // Challenge-response
        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        write_message(socket, &Message::RegisterChallenge { challenge }).await?;

        let response = read_message(socket).await?;
        let Message::HpkeMessage { message } = response else {
            return Err(anyhow!("Expected HpkeMessage"));
        };
        let decrypted = hpke_decrypt_with_context(&mut ctx, &message, b"")?;
        let response: Message = bincode::deserialize(&decrypted)?;

        tokio::task::spawn_blocking(move || {
            let Message::RegisterResponse { signature } = response else {
                return Err(anyhow!("Expected RegisterResponse"));
            };
            verify_sig(&challenge, &signature)
        }).await??;

        // Assign client ID
        let client_id = state.next_client_index.fetch_add(1, Ordering::SeqCst);
        if client_id >= state.num_clients {
            return Err(anyhow!("Registration closed"));
        }

        // Compute and send evaluation key
        let ek = state.keygen_prf.read().await.evaluate(client_id as u64);
        state.ek_send.send(ClientKey::Key(client_id as u32, ek))?;
        write_message(socket, &Message::RegisterSuccess { id: client_id as u32, eval_key: EvalKey(ek) }).await?;

        // Finalize setup after last client
        if client_id == state.num_clients - 1 {
            let prf_key = state.sk_recv.lock().await.take().unwrap().await?;
            let keygen_prf = state.keygen_prf.read().await.clone();
            let secret_key = SecretKey { prf_key, keygen_prf };

            state.db.insert(b"secret_key", bincode::serialize(&secret_key)?)?;
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
        let mut socket = TcpStream::connect(&aggregator_addr).await?;
        write_message(&mut socket, &Message::DecryptorInit {}).await?;

        match read_message(&mut socket).await? {
            Message::SetupAlreadyComplete {} => {
                info!("Setup already complete, skipping key commitment phase");
                setup_recv.close();
                while setup_recv.recv().await.is_some() {}
            }
            Message::Success {} => {
                Self::send_key_commitments(&mut socket, &state, &mut setup_recv).await?;
            }
            Message::Error(e) => return Err(anyhow!("Aggregator error: {e}")),
            _ => return Err(anyhow!("Unexpected aggregator response")),
        }

        // Process decryption mask requests
        Self::handle_mask_requests(&mut socket, &state).await
    }

    async fn send_key_commitments(
        socket: &mut TcpStream,
        state: &DecryptorState,
        recv: &mut mpsc::UnboundedReceiver<SetupToAggregator>,
    ) -> Result<()> {
        let mut received = 0;
        while received < state.num_clients {
            match recv.recv().await {
                Some(SetupToAggregator::KeyCommsBatch(kc)) => {
                    received += kc.len();
                    make_request(socket, &Message::KeyCommsBatch { key_comms: kc }).await?;
                }
                Some(SetupToAggregator::Simulate) => {
                    make_request(socket, &Message::SimulateSetup {}).await?;
                    info!("Simulated setup: aggregator notified");
                    break;
                }
                None => break,
            }
        }

        if let Some(start) = state.setup_start.get() {
            info!("Setup complete: {} clients in {:?}", state.num_clients, start.elapsed());
        }
        info!("Sent {}B, Recv {}B", bytes_sent(), bytes_recv());
        reset_byte_counters();
        Ok(())
    }

    async fn handle_mask_requests(socket: &mut TcpStream, state: &DecryptorState) -> Result<()> {
        loop {
            let Message::DecryptMaskRequest { context, num_clients, dropout_count, dropouts_packed, invert, length } = read_message(socket).await? else {
                error!("Unexpected message type");
                continue;
            };

            let wall_start = Instant::now();
            
            // Unpack dropout indices
            let unpack_start = Instant::now();
            let dropouts = unpack_indices(&dropouts_packed, dropout_count, num_clients);
            let unpack_time = unpack_start.elapsed();

            // Validate context
            {
                let mut ctx = state.current_ctx.write().await;
                match *ctx {
                    None => *ctx = Some(context),
                    Some(c) if c != context => return Err(anyhow!("Context mismatch: expected {c}, got {context}")),
                    _ => {}
                }
            }

            // Check threshold
            let online = if invert { dropouts.len() } else { state.num_clients - dropouts.len() };
            if online < state.threshold {
                return Err(anyhow!("Threshold not met: {online} < {}", state.threshold));
            }

            // Get secret key
            let sk = state.secret_key.get().ok_or_else(|| anyhow!("Setup incomplete"))?.clone();

            // Compute mask with detailed timing (inlined from AggOnlyEnc::decrypt_mask)
            let (mask, dropout_key_time, mask_compute_time) = tokio::task::spawn_blocking(move || {
                // Phase 1: Compute dropout-adjusted key
                let dropout_key_start = Instant::now();
                let key = match dropouts.len() {
                    0 => sk.prf_key,
                    _ => match invert {
                        false => sk.prf_key - sk.keygen_prf.batch_evaluate(&dropouts),
                        true => sk.keygen_prf.batch_evaluate(&dropouts),
                    },
                };
                let dropout_key_time = dropout_key_start.elapsed();

                // Phase 2: Compute the actual mask (parallel KHPRF evaluations)
                let mask_start = Instant::now();
                let mask: Vec<G> = (0..length)
                    .into_par_iter()
                    .map(|i| KHPRF::evaluate_context(&key, context, i))
                    .collect();
                let mask_compute_time = mask_start.elapsed();

                (mask, dropout_key_time, mask_compute_time)
            }).await?;

            write_message(socket, &Message::DecryptMaskResponse { mask }).await?;

            // Reset for next round
            *state.current_ctx.write().await = None;

            info!(
                "Decrypt mask for context {context}: {online} online clients\n\t\
                 Unpack dropouts: {:?}\n\t\
                 Dropout key: {:?}\n\t\
                 Mask computation: {:?}\n\t\
                 Total: {:?}",
                unpack_time, dropout_key_time, mask_compute_time, wall_start.elapsed()
            );
            info!("Sent {}B, Recv {}B", bytes_sent(), bytes_recv());
            reset_byte_counters();
        }
    }
}
