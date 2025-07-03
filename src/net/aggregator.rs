use crate::{
    net::messages::{Message, make_request, read_message, send_error_message, write_message},
    protocol::*,
};

use anyhow::{Result, anyhow};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, OnceCell, mpsc},
};
use tracing::{debug, error, info};

pub struct Aggregator<A: Aggregation> {
    addr: String,
    state: Arc<AggregatorState<A>>,
}

pub struct AggregatorState<A: Aggregation> {
    decryptor_addr: String,
    params: OnceCell<A::Params>,
    seen_clients: Mutex<HashSet<u32>>,
    encodings: Mutex<Vec<(u32, A::Encoding, A::Proof)>>,
    results_channel: mpsc::Sender<Vec<u32>>,
}

impl<A: Aggregation> Aggregator<A> {
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

    async fn handle_connection(mut socket: TcpStream, state: Arc<AggregatorState<A>>) {
        let message = match read_message::<A>(&mut socket).await {
            Ok(msg) => msg,
            Err(e) => {
                let _ =
                    send_error_message::<A>(&mut socket, &format!("Failed to read message: {}", e))
                        .await;
                return;
            }
        };

        // Handle request
        let result = match message {
            Message::<A>::AggregationRequest { params } => {
                Self::handle_aggregation_request(state, params).await
            }
            Message::<A>::ClientEncoding {
                id,
                encoding,
                proof,
            } => Self::handle_client_encoding(state, id, encoding, proof).await,
            _ => Err(anyhow!("Invalid message type")),
        };

        // Inform caller of success or error
        match result {
            Ok(()) => {
                let _ = write_message(&mut socket, &Message::<A>::Success {}).await;
            }
            Err(e) => {
                let _ =
                    send_error_message::<A>(&mut socket, &format!("Request failed: {}", e)).await;
            }
        }
    }

    async fn handle_aggregation_request(
        state: Arc<AggregatorState<A>>,
        params: A::Params,
    ) -> Result<()> {
        // TODO: If want to allow a full reset, need to clear things here
        Ok(state.params.set(params)?)
    }

    async fn handle_client_encoding(
        state: Arc<AggregatorState<A>>,
        id: u32,
        encoding: A::Encoding,
        proof: A::Proof,
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
            if encodings.len() == A::num_clients(state.params.get().unwrap()) {
                // Sort encodings and proofs by client ID
                encodings.sort_by_key(|(id, _, _)| *id);
                let (encodings, proofs): (Vec<A::Encoding>, Vec<A::Proof>) =
                    encodings.drain(..).map(|(_, e, p)| (e, p)).unzip();

                // Verify encodings
                let params = state.params.get().unwrap();
                if let Err(e) = A::verify_encodings(params, None, &encodings, &proofs) {
                    // TODO: Actually do something here
                    error!("Failed to verify encodings: {}", e);
                    return Ok(());
                }

                let aggregate = match A::aggregate(params, &encodings) {
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

    async fn send_aggregation_response(state: Arc<AggregatorState<A>>, aggregate: A::Encoding) {
        // Send aggregate to decryptor
        let mut socket = match TcpStream::connect(&state.decryptor_addr).await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to connect to decryptor: {}", e);
                return;
            }
        };
        let message = Message::<A>::AggregationResponse { aggregate };
        let response = make_request::<A>(&mut socket, &message).await;

        // Decryptor sends back a partial output
        if let Ok(partial_outputs) = response {
            match partial_outputs {
                Message::<A>::PostProcessRequest { partial_outputs } => {
                    // Perform post-processing
                    //
                    // TODO: Spawn in separate task
                    let params = state.params.get().unwrap();
                    match A::post_process(params, partial_outputs) {
                        Ok(results) => {
                            // Send result to channel
                            state.results_channel.send(results).await.unwrap();
                            let _ = write_message(&mut socket, &Message::<A>::Success {}).await;
                        }
                        Err(e) => {
                            error!("Failed to post-process: {}", e);
                            let _ = send_error_message::<A>(&mut socket, "Post-processing failed")
                                .await;
                        }
                    }
                }
                _ => {
                    let _ = send_error_message::<A>(&mut socket, "Invalid message type").await;
                }
            }
        } else {
            error!("Failed to retrieve partial outputs");
        }
    }
}
