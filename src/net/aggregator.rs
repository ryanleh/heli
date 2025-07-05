use crate::{
    net::messages::{Message, make_request, read_message, send_error_message, write_message},
    protocol::{DiscreteLog, MSM, messages::*, proofs::*},
};

use anyhow::{Result, anyhow};
use group::{Group, GroupEncoding};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, OnceCell, mpsc},
};
use tracing::{debug, error, info};

pub struct Aggregator<G: Group + GroupEncoding> {
    addr: String,
    state: Arc<AggregatorState<G>>,
}

pub struct AggregatorState<G: Group + GroupEncoding> {
    decryptor_addr: String,
    params: OnceCell<AggParams<G>>,
    seen_clients: Mutex<HashSet<u32>>,
    encodings: Mutex<Vec<(u32, Encoding<G>, BinarySchnorrProof<G>)>>,
    results_channel: mpsc::Sender<Vec<u32>>,
}

impl<G: Group + GroupEncoding> Aggregator<G>
where
    G: MSM<Coeff = G::Scalar, Point = G> + Send + Sync,
{
    pub fn new(addr: &str, decryptor_addr: &str, results_channel: mpsc::Sender<Vec<u32>>) -> Self {
        let state = Arc::new(AggregatorState {
            decryptor_addr: decryptor_addr.to_string(),
            params: OnceCell::new(),
            seen_clients: Mutex::new(HashSet::new()),
            encodings: Mutex::new(Vec::new()),
            results_channel,
        });

        Self {
            addr: addr.to_string(),
            state,
        }
    }

    pub async fn run(&self) -> Result<()> {
        debug!("Starting aggregator on {}", self.addr);
        let listener = TcpListener::bind(&self.addr).await?;
        info!("Aggregator listening on {}", self.addr);

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

    async fn handle_connection(mut socket: TcpStream, state: Arc<AggregatorState<G>>) {
        let message = match read_message::<G>(&mut socket).await {
            Ok(msg) => msg,
            Err(e) => {
                let _ =
                    send_error_message::<G>(&mut socket, &format!("Failed to read message: {}", e))
                        .await;
                return;
            }
        };

        // Handle request
        let result = match message {
            Message::<G>::AggregationRequest { params } => {
                Self::handle_aggregation_request(state, params).await
            }
            Message::<G>::ClientEncoding {
                id,
                encoding,
                proof,
            } => Self::handle_client_encoding(state, id, encoding, proof).await,
            _ => Err(anyhow!("Invalid message type")),
        };

        // Inform caller of success or error
        match result {
            Ok(()) => {
                let _ = write_message(&mut socket, &Message::<G>::Success {}).await;
            }
            Err(e) => {
                let _ =
                    send_error_message::<G>(&mut socket, &format!("Request failed: {}", e)).await;
            }
        }
    }

    async fn handle_aggregation_request(
        state: Arc<AggregatorState<G>>,
        params: AggParams<G>,
    ) -> Result<()> {
        // TODO: If want to allow a full reset, need to clear things here
        Ok(state.params.set(params)?)
    }

    async fn handle_client_encoding(
        state: Arc<AggregatorState<G>>,
        id: u32,
        encoding: Encoding<G>,
        proof: BinarySchnorrProof<G>,
    ) -> Result<()> {
        // Check if parameters are set
        if state.params.get().is_none() {
            return Err(anyhow!("Decryptor setup incomplete"));
        }

        // Check if this client has already contributed
        {
            let mut received_clients = state.seen_clients.lock().await;
            if received_clients.contains(&id) {
                return Err(anyhow!("Already received contribution from client {}", id));
            }
            received_clients.insert(id);
        }

        {
            // Store client encoding
            let mut encodings = state.encodings.lock().await;
            encodings.push((id, encoding, proof));
            debug!("Received contribution from client {}", id);

            // If we have all of the encodings, verify and aggregate them
            //
            // TODO: Have a separate thread that handles this in a streaming fashion
            if encodings.len()
                == DiscreteLog::<G, BinarySchnorr<G>>::num_clients(state.params.get().unwrap())
            {
                // Sort encodings and proofs by client ID
                encodings.sort_by_key(|(id, _, _)| *id);
                let (encodings, proofs): (Vec<Encoding<G>>, Vec<BinarySchnorrProof<G>>) =
                    encodings.drain(..).map(|(_, e, p)| (e, p)).unzip();

                // Verify encodings
                let params = state.params.get().unwrap();
                let (_, verifier_key) = BinarySchnorr::<G>::setup();
                if let Err(e) = DiscreteLog::<G, BinarySchnorr<G>>::verify_encodings(
                    params,
                    &verifier_key,
                    None,
                    &encodings,
                    &proofs,
                ) {
                    // TODO: Actually do something here
                    error!("Failed to verify encodings: {}", e);
                    return Ok(());
                }

                let aggregate =
                    match DiscreteLog::<G, BinarySchnorr<G>>::aggregate(params, &encodings) {
                        Ok(a) => a,
                        Err(e) => {
                            error!("Failed to aggregate encodings: {}", e);
                            return Ok(());
                        }
                    };

                // Send aggregate to decryptor
                tokio::spawn(Self::send_aggregation_response(state.clone(), aggregate));
            }
        }
        Ok(())
    }

    async fn send_aggregation_response(state: Arc<AggregatorState<G>>, aggregate: Encoding<G>) {
        // Send aggregate to decryptor
        let mut socket = match TcpStream::connect(&state.decryptor_addr).await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to connect to decryptor: {}", e);
                return;
            }
        };
        let message = Message::<G>::AggregationResponse { aggregate };
        let response = make_request::<G>(&mut socket, &message).await;

        // Decryptor sends back a partial output
        if let Ok(partial_outputs) = response {
            match partial_outputs {
                Message::<G>::PostProcessRequest { partial_outputs } => {
                    // Perform post-processing
                    //
                    // TODO: Spawn in separate task
                    let params = state.params.get().unwrap();
                    match DiscreteLog::<G, BinarySchnorr<G>>::post_process(params, partial_outputs)
                    {
                        Ok(results) => {
                            // Send result to channel
                            state.results_channel.send(results).await.unwrap();
                            let _ = write_message(&mut socket, &Message::<G>::Success {}).await;
                        }
                        Err(e) => {
                            error!("Failed to post-process: {}", e);
                            let _ = send_error_message::<G>(&mut socket, "Post-processing failed")
                                .await;
                        }
                    }
                }
                _ => {
                    let _ = send_error_message::<G>(&mut socket, "Invalid message type").await;
                }
            }
        } else {
            error!("Failed to send aggregation response to decryptor");
        }
    }
}
