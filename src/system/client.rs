use crate::{
    agg_only_enc::{AggOnlyEnc, EvalKey},
    crypto::{
        Scalar,
        app_attest::{ATTESTATION, sign_challenge},
        hpke::{ServerKeys, hpke_encrypt, hpke_encrypt_with_context},
        prf::ScalarPRF,
    },
    proofs::{Proof, ProverKey},
    system::{
        ProverType,
        messages::{Message, SIMULATE_PRF_KEY, make_request, read_message, write_message},
    },
};
use anyhow::{Result, anyhow};
use bincode;
use rand_core::OsRng;
use tokio::net::TcpStream;
use tracing::debug;

/// Client for registering and sending ciphertexts.
pub struct Client {
    pub aggregator_addr: String,
    pub aggregator_pk: <hpke::kem::X25519HkdfSha256 as hpke::Kem>::PublicKey,

    pub id: u32,
    pub eval_key: EvalKey,
    pub prover_key: ProverKey,
}

impl Client {
    pub async fn register(
        decryptor_addr: &str,
        aggregator_addr: &str,
        prover: ProverType,
        decryptor_pk: &ServerKeys, // TODO
        aggregator_pk: &ServerKeys,
    ) -> Result<Self> {
        debug!("Registering with decryptor");
        let mut socket = TcpStream::connect(decryptor_addr).await?;

        // Send initial registration request to the decryptor
        let registration = Message::RegisterRequest {
            attestation: ATTESTATION.to_string(),
        };
        let registration_bytes = bincode::serialize(&registration)?;
        let pk_clone = decryptor_pk.clone();
        let (envelope, mut sender_ctx) = tokio::task::spawn_blocking(move || {
            hpke_encrypt(&pk_clone.pk, &registration_bytes, b"", b"")
        })
        .await??;
        write_message(&mut socket, &Message::HpkeRequest { envelope }).await?;

        // Receive challenge
        let challenge = read_message(&mut socket).await?;
        let challenge = match challenge {
            Message::RegisterChallenge { challenge } => challenge,
            Message::Error(e) => return Err(anyhow!("Registration error: {}", e)),
            _ => return Err(anyhow!("Invalid message type")),
        };

        // Send encrypted response
        let encrypted_response = tokio::task::spawn_blocking(move || {
            let sig = sign_challenge(&challenge);
            let response = Message::RegisterResponse {
                signature: sig.as_ref().to_vec(),
            };
            let response_bytes = bincode::serialize(&response)?;
            hpke_encrypt_with_context(&mut sender_ctx, &response_bytes, b"")
        })
        .await??;
        let hpke_message = Message::HpkeMessage {
            message: encrypted_response,
        };
        write_message(&mut socket, &hpke_message).await?;

        // Receive success message
        let success = read_message(&mut socket).await?;
        let Message::RegisterSuccess { id, eval_key } = success else {
            return Err(anyhow!("Expected RegisterSuccess, got {:?}", success));
        };

        // Build proving key
        let g_comm = Proof::get_g_comm();
        let pk = match prover {
            ProverType::Binary => ProverKey::Binary { g_comm },
            ProverType::Range(bitlength) => ProverKey::Range { g_comm, bitlength },
        };

        Ok(Self {
            aggregator_addr: aggregator_addr.to_string(),
            aggregator_pk: aggregator_pk.pk.clone(),
            id,
            eval_key,
            prover_key: pk,
        })
    }

    /// Trigger simulated setup: send SimulateSetup to the decryptor (no attestation).
    /// Call once before creating clients with `new_simulated`. Decryptor and aggregator
    /// will use the hardcoded PRF key to compute keys locally.
    pub async fn trigger_simulate_setup(decryptor_addr: &str) -> Result<()> {
        let mut socket = TcpStream::connect(decryptor_addr).await?;
        write_message(&mut socket, &Message::SimulateSetup {}).await?;
        let response = read_message(&mut socket).await?;
        match response {
            Message::Success {} => Ok(()),
            Message::Error(e) => Err(anyhow!("Simulate setup failed: {}", e)),
            _ => Err(anyhow!("Unexpected response: {:?}", response)),
        }
    }

    /// Create a client for simulated mode: eval key is derived from the hardcoded PRF key.
    /// Use after calling `trigger_simulate_setup`. No registration with decryptor.
    pub fn new_simulated(
        id: u32,
        aggregator_addr: &str,
        aggregator_pk: &ServerKeys,
        prover: ProverType,
    ) -> Self {
        let prf = ScalarPRF::new(&SIMULATE_PRF_KEY);
        let eval_key = EvalKey(prf.evaluate(id as u64));
        let g_comm = Proof::get_g_comm();
        let prover_key = match prover {
            ProverType::Binary => ProverKey::Binary { g_comm },
            ProverType::Range(bitlength) => ProverKey::Range { g_comm, bitlength },
        };
        Self {
            aggregator_addr: aggregator_addr.to_string(),
            aggregator_pk: aggregator_pk.pk.clone(),
            id,
            eval_key,
            prover_key,
        }
    }

    /// Generate a report and store it in pending state.
    pub fn generate_report(&self, context: u32, input: &[u64]) -> Result<Message> {
        // Create aggregation-only ciphertext
        let input_scalars: Vec<Scalar> = input.iter().map(|&x| Scalar::from(x)).collect();
        let ciphertext = AggOnlyEnc::encrypt(&self.eval_key, context, &input_scalars);
        let proof = Proof::prove(
            &self.prover_key,
            &self.eval_key,
            context,
            &input_scalars,
            &ciphertext,
            &mut OsRng,
        )?;

        // Create ClientReport and HPKE encrypt it
        let report = Message::ClientReport { ciphertext, proof };
        let report_bytes = bincode::serialize(&report)?;
        let (envelope, _) = hpke_encrypt(&self.aggregator_pk, &report_bytes, b"", b"")?;

        // Return the prepared report
        Ok(Message::EncryptedClientReport {
            id: self.id,
            context,
            envelope,
        })
    }

    /// Get the aggregator address for this client
    pub fn aggregator_addr(&self) -> &str {
        &self.aggregator_addr
    }

    /// Generate and send a report to the aggregator.
    pub async fn report(&self, context: u32, input: &[u64]) -> Result<()> {
        let report = self.generate_report(context, input)?;

        let mut socket = TcpStream::connect(&self.aggregator_addr).await?;
        match make_request(&mut socket, &report).await {
            Ok(_) => Ok(()),
            Err(e) => Err(anyhow!("Failed to upload encoding: {}", e)),
        }
    }
}
