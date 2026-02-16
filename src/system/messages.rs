use crate::{
    agg_only_enc::{Ciphertext, EvalKey},
    crypto::{G, hpke::HpkeEnvelope},
    proofs::Proof,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Hardcoded PRF key for simulated setup (no attestation). All parties use this to
/// derive eval keys and key commitments locally so setup is instant for large N.
pub const SIMULATE_PRF_KEY: [u8; 32] = [
    0x73, 0x69, 0x6d, 0x75, 0x6c, 0x61, 0x74, 0x65, 0x5f, 0x68, 0x65, 0x6c, 0x69, 0x5f, 0x65, 0x32,
    0x65, 0x5f, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]; // "simulate_heli_e2e_test_key" + zero-pad

// Global byte counters for network traffic
static BYTES_SENT: AtomicU64 = AtomicU64::new(0);
static BYTES_RECV: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize, Deserialize, Debug)]
pub enum Message {
    // Initial HPKE request
    HpkeRequest {
        envelope: HpkeEnvelope,
    },

    // Encrypted message using existing HPKE context
    HpkeMessage {
        message: Vec<u8>,
    },

    RegisterRequest {
        attestation: String,
    },
    RegisterChallenge {
        challenge: [u8; 32],
    },
    RegisterResponse {
        signature: Vec<u8>,
    },
    RegisterSuccess {
        id: u32,
        eval_key: EvalKey,
    },

    ClientReport {
        ciphertext: Ciphertext,
        proof: Proof,
    },

    // HPKE-encrypted ClientReport with plaintext metadata for storage
    EncryptedClientReport {
        id: u32,
        context: u32,
        envelope: HpkeEnvelope,
    },

    // Batch of HPKE-encrypted ClientReports (for efficient bulk upload)
    BatchEncryptedClientReports {
        reports: Vec<(u32, u32, HpkeEnvelope)>, // (id, context, envelope)
    },

    /// Client sends this before submitting batches from sim-generate; aggregator then treats aggregation failure as success (dummy result).
    SimulatedBatchComing {},

    DecryptorInit {},
    /// Sent by aggregator when setup is already complete (key commitments exist)
    SetupAlreadyComplete {},
    /// Trigger simulated setup: no attestation; each party uses SIMULATE_PRF_KEY locally.
    /// Client -> Decryptor, then Decryptor -> Aggregator.
    SimulateSetup {},
    KeyCommsBatch {
        key_comms: Vec<(u32, G)>, // (idx, key_comm)
    },
    DecryptMaskRequest {
        context: u32,
        dropouts: Vec<usize>,
        invert: bool,
        length: usize,
    },
    DecryptMaskResponse {
        mask: Vec<G>,
    },

    AggregationRequest {
        context: u32,
    },
    AggregationResponse {
        result: Vec<u64>,
    },

    Error(String),
    Success(),
}

/// Reads a framed message from a TCP stream.
/// Format: [4-byte length][message data]
pub async fn read_message(socket: &mut TcpStream) -> Result<Message> {
    // Read message length (4 bytes, big-endian)
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await?;
    let message_len = u32::from_be_bytes(len_buf) as usize;

    // Read the actual message
    let mut message_buf = vec![0u8; message_len];
    socket.read_exact(&mut message_buf).await?;

    // Track bytes received (4 byte header + message)
    BYTES_RECV.fetch_add(4 + message_len as u64, Ordering::Relaxed);

    // Deserialize the message
    let message: Message = bincode::deserialize(&message_buf)?;
    Ok(message)
}

/// Writes a framed message to a TCP stream.
/// Format: [4-byte length][message data]
pub async fn write_message(socket: &mut TcpStream, message: &Message) -> Result<()> {
    // Serialize the message
    let message_bytes = bincode::serialize(message)?;
    let message_len = message_bytes.len() as u32;

    // Track bytes sent (4 byte header + message)
    BYTES_SENT.fetch_add(4 + message_bytes.len() as u64, Ordering::Relaxed);

    // Write length prefix (4 bytes, big-endian)
    socket.write_all(&message_len.to_be_bytes()).await?;

    // Write the message
    socket.write_all(&message_bytes).await?;
    socket.flush().await?;

    Ok(())
}

/// Sends a message and waits for a response, handling errors.
pub async fn make_request(socket: &mut TcpStream, message: &Message) -> Result<Message> {
    // Send message
    write_message(socket, message).await?;

    // Wait for response
    match read_message(socket).await {
        Ok(Message::Error(e)) => {
            tracing::error!("Server returned error: {}", e);
            Err(anyhow::anyhow!("Server error: {}", e))
        }
        Ok(response) => Ok(response),
        Err(e) => {
            tracing::error!("Failed to read response: {}", e);
            Err(e)
        }
    }
}

/// Sends an error message to a client.
pub async fn send_error_message(socket: &mut TcpStream, msg: &str) -> Result<()> {
    let error_message = Message::Error(msg.to_string());
    write_message(socket, &error_message).await?;
    Ok(())
}

/// Get total bytes sent across all connections
pub fn bytes_sent() -> u64 {
    BYTES_SENT.load(Ordering::Relaxed)
}

/// Get total bytes received across all connections
pub fn bytes_recv() -> u64 {
    BYTES_RECV.load(Ordering::Relaxed)
}

/// Reset byte counters to zero
pub fn reset_byte_counters() {
    BYTES_SENT.store(0, Ordering::Relaxed);
    BYTES_RECV.store(0, Ordering::Relaxed);
}

/// Get and reset byte counters, returning (sent, recv)
pub fn take_byte_counters() -> (u64, u64) {
    let sent = BYTES_SENT.swap(0, Ordering::Relaxed);
    let recv = BYTES_RECV.swap(0, Ordering::Relaxed);
    (sent, recv)
}
