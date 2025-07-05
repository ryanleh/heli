use crate::protocol::{
    messages::{AggParams, ClientKey, Encoding, PartialOutput},
    proofs::BinarySchnorrProof,
    serialization::serde_derive,
};
use anyhow::Result;
use group::{Group, GroupEncoding};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Serialize, Deserialize, Debug)]
pub enum Message<G: Group + GroupEncoding> {
    RegisterRequest {},
    RegisterResponse {
        id: u32,
        #[serde(with = "serde_derive")]
        key: ClientKey<G>,
    },

    ClientEncoding {
        id: u32,
        #[serde(with = "serde_derive")]
        encoding: Encoding<G>,
        #[serde(with = "serde_derive")]
        proof: BinarySchnorrProof<G>, // TODO: Make this generic over proof type
    },

    AggregationRequest {
        #[serde(with = "serde_derive")]
        params: AggParams<G>,
    },

    AggregationResponse {
        #[serde(with = "serde_derive")]
        aggregate: Encoding<G>,
    },

    PostProcessRequest {
        #[serde(with = "serde_derive")]
        partial_outputs: PartialOutput<G>,
    },

    Error(String),
    Success(),
}

/// Reads a framed message from a TCP stream.
/// Format: [4-byte length][message data]
pub async fn read_message<G: Group + GroupEncoding>(socket: &mut TcpStream) -> Result<Message<G>> {
    // Read message length (4 bytes, big-endian)
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await?;
    let message_len = u32::from_be_bytes(len_buf) as usize;

    // Read the actual message
    let mut message_buf = vec![0u8; message_len];
    socket.read_exact(&mut message_buf).await?;

    // Deserialize the message
    let message: Message<G> = bincode::deserialize(&message_buf)?;
    Ok(message)
}

/// Writes a framed message to a TCP stream.
/// Format: [4-byte length][message data]
pub async fn write_message<G: Group + GroupEncoding>(
    socket: &mut TcpStream,
    message: &Message<G>,
) -> Result<()> {
    // Serialize the message
    let message_bytes = bincode::serialize(message)?;
    let message_len = message_bytes.len() as u32;

    // Write length prefix (4 bytes, big-endian)
    socket.write_all(&message_len.to_be_bytes()).await?;

    // Write the message
    socket.write_all(&message_bytes).await?;
    socket.flush().await?;

    Ok(())
}

/// Sends a message and waits for a response, handling errors.
pub async fn make_request<G: Group + GroupEncoding>(
    socket: &mut TcpStream,
    message: &Message<G>,
) -> Result<Message<G>> {
    // Send message
    write_message(socket, message).await?;

    // Wait for response
    match read_message::<G>(socket).await {
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
pub async fn send_error_message<G: Group + GroupEncoding>(
    socket: &mut TcpStream,
    msg: &str,
) -> Result<()> {
    let error_message = Message::<G>::Error(msg.to_string());
    write_message(socket, &error_message).await?;
    Ok(())
}
