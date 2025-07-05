use crate::{
    net::messages::{Message, make_request},
    protocol::{DiscreteLog, MSM, messages::*, proofs::*},
};
use anyhow::{Result, anyhow};
use group::{Group, GroupEncoding};
use rand_core::OsRng;
use tokio::net::TcpStream;
use tracing::{debug, error, info};

/// Client for registering and sending encodings.
pub struct Client<G: Group + GroupEncoding> {
    decryptor_addr: String,
    aggregator_addr: String,

    pub id: Option<usize>,
    pub key: Option<ClientKey<G>>,
}

impl<G: Group + GroupEncoding> Client<G>
where
    G: MSM<Coeff = G::Scalar, Point = G> + Send + Sync,
{
    pub fn new(decryptor_addr: &str, aggregator_addr: &str) -> Self {
        Self {
            decryptor_addr: decryptor_addr.to_string(),
            aggregator_addr: aggregator_addr.to_string(),
            id: None,
            key: None,
        }
    }

    /// Register the client with the decryptor.
    pub async fn register(&mut self) -> Result<()> {
        debug!("Registering with decryptor");
        let mut socket = TcpStream::connect(&self.decryptor_addr).await?;
        let registration = Message::<G>::RegisterRequest {};
        let response = make_request::<G>(&mut socket, &registration)
            .await
            .inspect_err(|e| error!("Registration failed: {}", e))?;

        match response {
            Message::RegisterResponse { id, key } => {
                self.id = Some(id as usize);
                self.key = Some(key);
                info!("Successfully registered with ID {}", id);
            }
            _ => unreachable!(),
        };
        Ok(())
    }

    /// Sends an encoding and proof to the aggregator.
    pub async fn send_encoding(&self, input: &[u32]) -> Result<()> {
        let id = self.id.unwrap();
        let key = self.key.as_ref().unwrap();

        debug!("Sending encoding to aggregator");
        let mut socket = TcpStream::connect(&self.aggregator_addr).await?;

        // Encode input and send to aggregator
        let (prover_key, _) = BinarySchnorr::<G>::setup();
        let (encoding, proof) =
            DiscreteLog::<G, BinarySchnorr<G>>::encode(key, &prover_key, input, &mut OsRng)?;
        let encoding_message = Message::<G>::ClientEncoding {
            id: id as u32,
            encoding,
            proof,
        };

        // Send message and handle potential error responses
        match make_request::<G>(&mut socket, &encoding_message).await {
            Ok(_) => info!("Client {} successfully sent encoding to aggregator", id),
            Err(e) => return Err(anyhow!("Failed to send encoding: {}", e)),
        }
        Ok(())
    }
}
