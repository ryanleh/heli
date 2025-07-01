use crate::{protocol::Aggregation, protocol::serialization::serde_derive};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Serialize, Deserialize, Debug)]
pub enum Message<A: Aggregation> {
    RegisterRequest {},
    RegisterResponse {
        id: u32,
        #[serde(with = "serde_derive")]
        key: A::ClientKey,
    },

    ClientEncoding {
        id: u32,
        #[serde(with = "serde_derive")]
        encoding: A::Encoding,
        #[serde(with = "serde_derive")]
        proof: A::Proof,
    },

    AggregationRequest {
        #[serde(with = "serde_derive")]
        params: A::Params,
    },

    AggregationResponse {
        #[serde(with = "serde_derive")]
        aggregate: A::Encoding,
    },

    PostProcessRequest {
        #[serde(with = "serde_derive")]
        partial_outputs: A::PartialOutput,
    },

    Error(String),
    Success(),
}

/// Read a framed message from a TCP stream
/// Format: [4-byte length][message data]
pub async fn read_message<A: Aggregation>(socket: &mut TcpStream) -> Result<Message<A>> {
    // Read message length (4 bytes, big-endian)
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await?;
    let message_len = u32::from_be_bytes(len_buf) as usize;

    // Read the actual message
    let mut message_buf = vec![0u8; message_len];
    socket.read_exact(&mut message_buf).await?;

    // Deserialize the message
    let message: Message<A> = bincode::deserialize(&message_buf)?;
    Ok(message)
}

/// Write a framed message to a TCP stream
/// Format: [4-byte length][message data]
pub async fn write_message<A: Aggregation>(
    socket: &mut TcpStream,
    message: &Message<A>,
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

/// Send a message and wait for a response, handling errors
pub async fn make_request<A: Aggregation>(
    socket: &mut TcpStream,
    message: &Message<A>,
) -> Result<Message<A>> {
    // Send message
    write_message(socket, message).await?;
    
    // Wait for response
    match read_message::<A>(socket).await {
        Ok(Message::Error(e)) => {
            tracing::error!("Server returned error: {}", e);
            Err(anyhow::anyhow!("Server error: {}", e))
        },
        Ok(response) => Ok(response),
        Err(e) => {
            tracing::error!("Failed to read response: {}", e);
            Err(e)
        }
    }
}

/// Send an error message to a client
pub async fn send_error_message<A: Aggregation>(
    socket: &mut TcpStream,
    msg: &str,
) -> Result<()> {
    let error_message = Message::<A>::Error(msg.to_string());
    write_message(socket, &error_message).await?;
    Ok(())
}
