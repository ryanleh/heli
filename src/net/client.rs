use crate::{
    net::messages::{Message, read_message, write_message, make_request},
    protocol::Aggregation,
};
use anyhow::{anyhow, Result};
use rand_core::OsRng;
use tokio::net::TcpStream;
use tracing::{debug, error, info};

pub struct Client<A: Aggregation> {
    decryptor_addr: String,
    aggregator_addr: String,

    pub id: Option<usize>,
    pub key: Option<A::ClientKey>,
}

impl<A: Aggregation> Client<A> {
    pub fn new(decryptor_addr: &str, aggregator_addr: &str) -> Self {
        Self {
            decryptor_addr: decryptor_addr.to_string(),
            aggregator_addr: aggregator_addr.to_string(),
            id: None,
            key: None,
        }
    }

    pub async fn register(&mut self) -> Result<()> {
        debug!("Registering with decryptor");
        let mut socket = TcpStream::connect(&self.decryptor_addr).await?;

        // Register with decryptor
        let registration = Message::<A>::RegisterRequest {};
        let response = make_request::<A>(&mut socket, &registration)
            .await
            .inspect_err(|e| error!("Registration failed: {}", e))?;
        
        match response {
            Message::RegisterResponse { id, key } => {
                self.id = Some(id as usize);
                self.key = Some(key);
                info!("Successfully registered with ID {}", id);
            },
            _ => unreachable!(),
        };
        Ok(())
    }

    pub async fn send_encoding(&self, input: &[u32]) -> Result<()> {
        let id = self.id.unwrap();
        let key = self.key.as_ref().unwrap();

        debug!("Sending encoding to aggregator");
        let mut socket = TcpStream::connect(&self.aggregator_addr).await?;

        // Encode input and send to aggregator
        let (encoding, proof) = A::encode(key, input, &mut OsRng)?;
        let encoding_message = Message::<A>::ClientEncoding {
            id: id as u32,
            encoding,
            proof,
        };
        
        // Send message and handle potential error responses
        match make_request::<A>(&mut socket, &encoding_message).await {
            Ok(_) => info!("Client {} successfully sent encoding to aggregator", id),
            Err(e) => return Err(anyhow!("Failed to send encoding: {}", e)),
        }
        Ok(())
    }
}
