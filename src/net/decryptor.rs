use crate::{
    net::messages::{Message, make_request, read_message, send_error_message, write_message},
    protocol::{DiscreteLog, MSM, messages::*, proofs::*},
};

use anyhow::{Result, anyhow};
use group::{Group, GroupEncoding};
use rand_core::OsRng;
use std::sync::Arc;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tracing::{debug, error, info};

pub struct Decryptor<G: Group + GroupEncoding> {
    addr: String,
    state: Arc<DecryptorState<G>>,
}

struct DecryptorState<G: Group + GroupEncoding> {
    aggregator_addr: String,
    params: Mutex<Option<AggParams<G>>>,
    key: DecKey<G>,
    last_client_id: Mutex<u32>,
    registered_clients: Mutex<Vec<ClientKey<G>>>,
}

impl<G: Group + GroupEncoding> Decryptor<G>
where
    G: MSM<Coeff = G::Scalar, Point = G> + Send + Sync,
{
    pub fn new(addr: &str, aggregator_addr: &str, num_clients: usize, length: usize) -> Self {
        let (params, key, client_keys) =
            DiscreteLog::<G, BinarySchnorr<G>>::setup(num_clients, length, &mut OsRng);
        let state = DecryptorState {
            aggregator_addr: aggregator_addr.to_string(),
            params: Mutex::new(Some(params)),
            key,
            last_client_id: Mutex::new(client_keys.len() as u32),
            registered_clients: Mutex::new(client_keys),
        };

        Self {
            addr: addr.to_string(),
            state: Arc::new(state),
        }
    }

    pub async fn run(&self) -> Result<()> {
        debug!("Starting decryptor on {}", self.addr);
        let listener = TcpListener::bind(&self.addr).await?;
        info!("Decryptor listening on {}", self.addr);

        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    debug!("New connection from {}", addr);
                    tokio::spawn(Self::handle_connection(socket, self.state.clone()));
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    async fn handle_connection(mut socket: TcpStream, state: Arc<DecryptorState<G>>) {
        let message = match read_message::<G>(&mut socket).await {
            Ok(msg) => msg,
            Err(e) => {
                let _ =
                    send_error_message::<G>(&mut socket, &format!("Failed to read message: {}", e))
                        .await;
                return;
            }
        };

        let response = match message {
            Message::<G>::RegisterRequest {} => Self::handle_register_request(state).await,
            Message::<G>::AggregationResponse { aggregate } => {
                Self::handle_aggregation_response(&mut socket, state, aggregate).await
            }
            _ => Err(anyhow!("Invalid message type")),
        };

        // Inform caller of success or error
        match response {
            Ok(msg) => {
                let _ = write_message(&mut socket, &msg).await;
            }
            Err(e) => {
                let _ =
                    send_error_message::<G>(&mut socket, &format!("Request failed: {}", e)).await;
            }
        }
    }

    /// Register a client
    async fn handle_register_request(state: Arc<DecryptorState<G>>) -> Result<Message<G>> {
        let mut client_guard = state.registered_clients.lock().await;
        let key = client_guard
            .pop()
            .ok_or(anyhow!("Too many clients attempted to register"))?;

        let mut id_guard = state.last_client_id.lock().await;
        let id = *id_guard;
        *id_guard -= 1;

        if *id_guard == 0 {
            let params = state.params.lock().await.take().unwrap();

            // Send initialization information to the aggregator
            let mut agg_conn = TcpStream::connect(&state.aggregator_addr).await?;
            let message = Message::<G>::AggregationRequest { params };
            if let Ok(_) = make_request::<G>(&mut agg_conn, &message).await {
                info!("Sent aggregation request to aggregator");
            } else {
                error!("Aggregation request failed");
            }
        }

        debug!("Client {} registered", id);
        Ok(Message::<G>::RegisterResponse { id, key })
    }

    /// Decode the aggregate result and send to aggregator for post-processing
    async fn handle_aggregation_response(
        socket: &mut TcpStream,
        state: Arc<DecryptorState<G>>,
        aggregate: Encoding<G>,
    ) -> Result<Message<G>> {
        debug!("Processing aggregation response");

        // Decode the aggregate result
        let partial_outputs = DiscreteLog::<G, BinarySchnorr<G>>::decode(&state.key, aggregate)?;

        // Give the partial output to the aggregator for post-processing
        if let Err(e) = make_request::<G>(
            socket,
            &Message::<G>::PostProcessRequest { partial_outputs },
        )
        .await
        {
            error!("Post-processing request failed: {}", e);
        };

        Ok(Message::<G>::Success {})
    }
}
