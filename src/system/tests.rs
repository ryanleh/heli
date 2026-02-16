use crate::{
    crypto::{Scalar, hpke::ServerKeys},
    system::{
        ProverType,
        aggregator::Aggregator,
        client::Client,
        decryptor::Decryptor,
        messages::{Message, read_message, write_message},
    },
};

use anyhow::{Result, anyhow};
use rand::{Rng, rngs::OsRng};
use std::time::Duration;
use tokio::{net::TcpStream, time::sleep};
use tracing_subscriber::EnvFilter;

struct TestConfig {
    num_clients: usize,
    threshold: usize,
    length: usize,
    bitlength: usize,
    decryptor_addr: String,
    aggregator_addr: String,
    prover: ProverType,
}

impl TestConfig {
    fn binary(num_clients: usize, length: usize) -> Self {
        Self {
            num_clients,
            threshold: num_clients,
            length,
            bitlength: 1,
            decryptor_addr: format!("127.0.0.1:{}", 18000 + rand::random::<u16>() % 1000),
            aggregator_addr: format!("127.0.0.1:{}", 19000 + rand::random::<u16>() % 1000),
            prover: ProverType::Binary,
        }
    }

    fn range(num_clients: usize, length: usize, bitlength: usize) -> Self {
        Self {
            num_clients,
            threshold: num_clients,
            length,
            bitlength,
            decryptor_addr: format!("127.0.0.1:{}", 20000 + rand::random::<u16>() % 1000),
            aggregator_addr: format!("127.0.0.1:{}", 21000 + rand::random::<u16>() % 1000),
            prover: ProverType::Range(bitlength),
        }
    }
}

fn init_tracing() {
    // Sled logging is a bit verbose so disable it
    let filter = EnvFilter::from_default_env().add_directive("sled=off".parse().unwrap());

    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stdout)
        .with_env_filter(filter)
        .with_test_writer()
        .try_init();
}

#[tokio::test]
async fn test_decryptor_setup() -> Result<()> {
    init_tracing();

    let config = TestConfig::binary(5, 1);
    let db = sled::Config::default().temporary(true).open()?;

    // Generate HPKE keypairs
    let decryptor_keys = ServerKeys::generate();
    let aggregator_keys = ServerKeys::generate();

    // Start the aggregator
    let aggregator = Aggregator::new(
        &config.aggregator_addr,
        config.num_clients,
        config.threshold,
        config.prover,
        db,
        aggregator_keys.clone(),
    );
    let aggregator_handle = tokio::spawn(async move {
        if let Err(e) = aggregator.run().await {
            panic!("Aggregator error: {}", e);
        }
    });

    // Give the server time to start up
    sleep(Duration::from_millis(100)).await;

    // Start the decryptor
    let decryptor_db = sled::Config::default().temporary(true).open()?;
    let decryptor = Decryptor::new(
        &config.decryptor_addr,
        &config.aggregator_addr,
        config.num_clients,
        config.threshold,
        decryptor_keys.clone(),
        decryptor_db,
    );
    let decryptor_state = decryptor.state.clone();
    let decryptor_handle = tokio::spawn(async move {
        if let Err(e) = decryptor.run().await {
            panic!("Decryptor error: {}", e);
        }
    });

    // Give the server time to start up
    sleep(Duration::from_millis(100)).await;

    // Register all clients and collect their evaluation keys
    let mut expected_key = Scalar::ZERO;
    for _ in 0..config.num_clients {
        let client = Client::register(
            &config.decryptor_addr,
            &config.aggregator_addr,
            ProverType::Binary,
            &decryptor_keys,
            &aggregator_keys,
        )
        .await?;
        expected_key += *client.eval_key;
    }

    // Give the decryptor time to process the last registration and set up the secret key
    sleep(Duration::from_millis(500)).await;

    // Try to register one more client - should fail
    let result = Client::register(
        &config.decryptor_addr,
        &config.aggregator_addr,
        ProverType::Binary,
        &decryptor_keys,
        &aggregator_keys,
    )
    .await;
    assert!(
        result.is_err(),
        "Should not be able to register after max clients"
    );

    // Check that the sum of client keys matches the decryptor's secret key
    let secret_key = decryptor_state.secret_key.get().unwrap();
    assert_eq!(secret_key.prf_key, expected_key);

    // Clean up
    decryptor_handle.abort();
    aggregator_handle.abort();

    Ok(())
}

// End-to-end test
async fn test_end_to_end_impl(
    config: TestConfig,
    num_rounds: u32,
    num_dropouts: usize,
) -> Result<()> {
    let db = sled::Config::default().temporary(true).open()?;

    // Generate HPKE keypairs
    let decryptor_keys = ServerKeys::generate();
    let aggregator_keys = ServerKeys::generate();

    // Start the aggregator
    let aggregator = Aggregator::new(
        &config.aggregator_addr,
        config.num_clients,
        config.threshold,
        config.prover,
        db,
        aggregator_keys.clone(),
    );
    let aggregator_handle = tokio::spawn(async move {
        if let Err(e) = aggregator.run().await {
            panic!("Aggregator error: {}", e);
        }
    });

    // Give the aggregator time to start
    sleep(Duration::from_millis(100)).await;

    // Start the decryptor
    let decryptor_db = sled::Config::default().temporary(true).open()?;
    let decryptor = Decryptor::new(
        &config.decryptor_addr,
        &config.aggregator_addr,
        config.num_clients,
        config.threshold,
        decryptor_keys.clone(),
        decryptor_db,
    );
    let decryptor_handle = tokio::spawn(async move {
        if let Err(e) = decryptor.run().await {
            panic!("Decryptor error: {}", e);
        }
    });

    // Give the decryptor time to start and connect to aggregator
    sleep(Duration::from_millis(100)).await;

    // Register all clients
    let mut clients = Vec::new();
    for _ in 0..config.num_clients {
        let client = Client::register(
            &config.decryptor_addr,
            &config.aggregator_addr,
            config.prover,
            &decryptor_keys,
            &aggregator_keys,
        )
        .await?;
        clients.push(client);
    }

    // Wait for key commitments to propagate to aggregator
    sleep(Duration::from_millis(100)).await;

    // Generate random inputs based on prover type
    let mut rng = OsRng;
    let max_val = match config.prover {
        ProverType::Binary => 2,
        ProverType::Range(bitlength) => 1u64 << bitlength,
    };

    // Run multiple rounds
    for round in 0..num_rounds {
        let mut expected_sums = vec![0u64; config.length];
        let mut client_inputs: Vec<Vec<u64>> = Vec::new();

        // Generate inputs for all clients
        for _ in 0..config.num_clients {
            let inputs: Vec<u64> = (0..config.length)
                .map(|_| rng.gen_range(0..max_val))
                .collect();
            client_inputs.push(inputs);
        }

        // Determine which clients will submit (all except dropouts)
        let num_submitting = config.num_clients - num_dropouts;
        for i in 0..num_submitting {
            for (j, &val) in client_inputs[i].iter().enumerate() {
                expected_sums[j] += val;
            }
        }

        // Clients submit reports for this round
        for i in 0..num_submitting {
            clients[i].report(round, &client_inputs[i]).await?;
        }

        // Request aggregation
        let mut socket = TcpStream::connect(&config.aggregator_addr).await?;
        write_message(&mut socket, &Message::AggregationRequest { context: round }).await?;
        let response = read_message(&mut socket).await?;

        let result = match response {
            Message::AggregationResponse { result } => result,
            Message::Error(e) => return Err(anyhow!("Round {} aggregation failed: {}", round, e)),
            _ => return Err(anyhow!("Unexpected response")),
        };

        assert_eq!(
            result, expected_sums,
            "Round {} results don't match expected sums",
            round
        );
    }

    // Clean up
    decryptor_handle.abort();
    aggregator_handle.abort();

    Ok(())
}

#[tokio::test]
async fn test_end_to_end_binary() -> Result<()> {
    init_tracing();
    test_end_to_end_impl(TestConfig::binary(10, 4), 1, 0).await
}

#[tokio::test]
async fn test_end_to_end_range() -> Result<()> {
    init_tracing();
    test_end_to_end_impl(TestConfig::range(8, 4, 8), 1, 0).await
}

/// Test multiple rounds of aggregation
#[tokio::test]
async fn test_multiple_rounds() -> Result<()> {
    init_tracing();
    test_end_to_end_impl(TestConfig::binary(6, 2), 3, 0).await
}

/// Test with many clients to ensure multi-chunk batch verification
#[tokio::test]
async fn test_multi_chunk_verification() -> Result<()> {
    init_tracing();
    test_end_to_end_impl(TestConfig::binary(200, 1), 1, 0).await
}

#[tokio::test]
async fn test_with_dropouts() -> Result<()> {
    init_tracing();
    let num_clients = 200;
    let num_dropouts = 50;
    let mut config = TestConfig::binary(num_clients, 1);
    config.threshold = num_clients - num_dropouts;
    test_end_to_end_impl(config, 1, num_dropouts).await
}

/// End-to-end test using simulated setup: no attestation, hardcoded PRF key.
/// Client triggers SimulateSetup once; decryptor and aggregator compute keys locally.
#[tokio::test]
async fn test_end_to_end_simulated_setup() -> Result<()> {
    init_tracing();

    let config = TestConfig::binary(20, 4);
    let db = sled::Config::default().temporary(true).open()?;

    let decryptor_keys = ServerKeys::generate();
    let aggregator_keys = ServerKeys::generate();

    let aggregator = Aggregator::new(
        &config.aggregator_addr,
        config.num_clients,
        config.threshold,
        config.prover,
        db,
        aggregator_keys.clone(),
    );
    let aggregator_handle = tokio::spawn(async move {
        if let Err(e) = aggregator.run().await {
            panic!("Aggregator error: {}", e);
        }
    });

    sleep(Duration::from_millis(100)).await;

    let decryptor_db = sled::Config::default().temporary(true).open()?;
    let decryptor = Decryptor::new(
        &config.decryptor_addr,
        &config.aggregator_addr,
        config.num_clients,
        config.threshold,
        decryptor_keys.clone(),
        decryptor_db,
    );
    let decryptor_handle = tokio::spawn(async move {
        if let Err(e) = decryptor.run().await {
            panic!("Decryptor error: {}", e);
        }
    });

    sleep(Duration::from_millis(100)).await;

    // Simulated setup: one RPC to decryptor, decryptor and aggregator do local setup
    Client::trigger_simulate_setup(&config.decryptor_addr).await?;

    // Wait for decryptor→aggregator SimulateSetup to complete
    sleep(Duration::from_millis(200)).await;

    // Create clients from hardcoded key (no registration)
    let clients: Vec<Client> = (0..config.num_clients)
        .map(|id| {
            Client::new_simulated(
                id as u32,
                &config.aggregator_addr,
                &aggregator_keys,
                config.prover,
            )
        })
        .collect();

    // One round: submit reports and aggregate
    let mut rng = OsRng;
    let mut expected_sums = vec![0u64; config.length];
    let mut client_inputs: Vec<Vec<u64>> = Vec::new();
    for _ in 0..config.num_clients {
        let inputs: Vec<u64> = (0..config.length).map(|_| rng.gen_range(0..2)).collect();
        for (j, &val) in inputs.iter().enumerate() {
            expected_sums[j] += val;
        }
        client_inputs.push(inputs);
    }

    for (i, client) in clients.iter().enumerate() {
        client.report(0, &client_inputs[i]).await?;
    }

    let mut socket = TcpStream::connect(&config.aggregator_addr).await?;
    write_message(&mut socket, &Message::AggregationRequest { context: 0 }).await?;
    let response = read_message(&mut socket).await?;

    let result = match response {
        Message::AggregationResponse { result } => result,
        Message::Error(e) => return Err(anyhow!("Aggregation failed: {}", e)),
        _ => return Err(anyhow!("Unexpected response")),
    };

    assert_eq!(result, expected_sums, "Simulated setup e2e: results don't match");

    decryptor_handle.abort();
    aggregator_handle.abort();

    Ok(())
}
