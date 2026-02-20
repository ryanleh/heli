use crate::{
    agg_only_enc::{AggOnlyEnc, EvalKey},
    crypto::{
        Scalar,
        app_attest::{ATTESTATION, sign_challenge},
        hpke::{ServerKeys, hpke_encrypt, hpke_encrypt_with_context},
        prf::ScalarPRF,
    },
    proofs::{Proof, ProverKey},
    system::{ProverType, messages::*},
};

use anyhow::{Result, anyhow};
use rand_core::OsRng;
use tokio::net::TcpStream;

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
        decryptor_pk: &ServerKeys,
        aggregator_pk: &ServerKeys,
    ) -> Result<Self> {
        let mut socket = TcpStream::connect(decryptor_addr).await?;

        // Send encrypted registration request
        let registration = Message::RegisterRequest {
            attestation: ATTESTATION.to_string(),
        };
        let pk_clone = decryptor_pk.clone();
        let (envelope, mut sender_ctx) = tokio::task::spawn_blocking(move || {
            hpke_encrypt(&pk_clone.pk, &bincode::serialize(&registration)?, b"", b"")
        })
        .await??;
        write_message(&mut socket, &Message::HpkeRequest { envelope }).await?;

        // Receive and respond to challenge
        let Message::RegisterChallenge { challenge } = read_message(&mut socket).await? else {
            return Err(anyhow!("Expected RegisterChallenge"));
        };

        let encrypted_response = tokio::task::spawn_blocking(move || {
            let sig = sign_challenge(&challenge);
            let response = Message::RegisterResponse {
                signature: sig.as_ref().to_vec(),
            };
            hpke_encrypt_with_context(&mut sender_ctx, &bincode::serialize(&response)?, b"")
        })
        .await??;
        write_message(
            &mut socket,
            &Message::HpkeMessage {
                message: encrypted_response,
            },
        )
        .await?;

        // Get registration result
        let Message::RegisterSuccess { id, eval_key } = read_message(&mut socket).await? else {
            return Err(anyhow!("Registration failed"));
        };

        let g_comm = Proof::get_g_comm();
        let prover_key = match prover {
            ProverType::Binary => ProverKey::Binary { g_comm },
            ProverType::Range(bitlength) => ProverKey::Range { g_comm, bitlength },
        };

        Ok(Self {
            aggregator_addr: aggregator_addr.to_string(),
            aggregator_pk: aggregator_pk.pk.clone(),
            id,
            eval_key,
            prover_key,
        })
    }

    /// Trigger simulated setup on the decryptor. Used for benchmarking without attestation.
    pub async fn trigger_sim_setup(decryptor_addr: &str) -> Result<()> {
        let mut socket = TcpStream::connect(decryptor_addr).await?;
        make_request(&mut socket, &Message::SimulateSetup {}).await?;
        Ok(())
    }

    /// Create a simulated client from a hardcoded PRF (no registration required).
    pub fn new_simulated(
        id: u32,
        aggregator_addr: &str,
        aggregator_pk: &ServerKeys,
        prover: ProverType,
    ) -> Self {
        let prf = ScalarPRF::new(&SIMULATE_PRF_KEY);
        let g_comm = Proof::get_g_comm();
        Self {
            aggregator_addr: aggregator_addr.to_string(),
            aggregator_pk: aggregator_pk.pk.clone(),
            id,
            eval_key: EvalKey(prf.evaluate(id as u64)),
            prover_key: Self::build_prover_key(g_comm, prover),
        }
    }

    /// Adapt a stored prover key to a different prover type (e.g. binary -> range).
    pub fn adapt_prover_key_to(pk: ProverKey, prover: ProverType) -> ProverKey {
        let g_comm = match pk {
            ProverKey::Binary { g_comm } | ProverKey::Range { g_comm, .. } => g_comm,
        };
        Self::build_prover_key(g_comm, prover)
    }

    fn build_prover_key(g_comm: crate::crypto::G, prover: ProverType) -> ProverKey {
        match prover {
            ProverType::Binary => ProverKey::Binary { g_comm },
            ProverType::Range(bitlength) => ProverKey::Range { g_comm, bitlength },
        }
    }

    /// Generate an encrypted report for the given context and input.
    pub fn generate_report(&self, context: u32, input: &[u64]) -> Result<Message> {
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

        let report = Message::ClientReport { ciphertext, proof };
        let (envelope, _) =
            hpke_encrypt(&self.aggregator_pk, &bincode::serialize(&report)?, b"", b"")?;

        Ok(Message::EncryptedClientReport {
            id: self.id,
            context,
            envelope,
        })
    }

    pub fn aggregator_addr(&self) -> &str {
        &self.aggregator_addr
    }

    /// Generate and send a report to the aggregator.
    pub async fn report(&self, context: u32, input: &[u64]) -> Result<()> {
        let report = self.generate_report(context, input)?;
        let mut socket = TcpStream::connect(&self.aggregator_addr).await?;
        make_request(&mut socket, &report).await?;
        Ok(())
    }
}
