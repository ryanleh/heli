use crate::{
    net::{aggregator::Aggregator, client::Client, decryptor::Decryptor},
    protocol::{DiscreteLog, Ristretto, proofs::BinarySchnorr},
};

use anyhow::{Result, anyhow};
use rand::{Rng, rngs::OsRng};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{Level, info};
use tracing_subscriber;

type G = Ristretto;
type Agg = DiscreteLog<G, BinarySchnorr<G>>;

struct TestConfig {
    num_clients: usize,
    length: usize,
    decryptor_addr: String,
    aggregator_addr: String,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            num_clients: 5,
            length: 1,
            decryptor_addr: "127.0.0.1:8096".to_string(),
            aggregator_addr: "127.0.0.1:8097".to_string(),
        }
    }
}

fn init_tracing() {
    // Use stdout, so output suppressed by default
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stdout)
        .with_max_level(Level::DEBUG)
        .with_test_writer()
        .try_init();
}

async fn run_protocol(config: TestConfig) -> Result<()> {
    init_tracing();

    // Start the decryptor
    let decryptor = Decryptor::<G>::new(
        &config.decryptor_addr,
        &config.aggregator_addr,
        config.num_clients,
        config.length,
    );
    let decryptor_handle = tokio::spawn(async move {
        if let Err(e) = decryptor.run().await {
            panic!("Decryptor error: {}", e);
        }
    });

    // Start the aggregator first (without decryptor)
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    let aggregator = Aggregator::<G>::new(&config.aggregator_addr, &config.decryptor_addr, sender);

    let aggregator_handle = tokio::spawn(async move {
        if let Err(e) = aggregator.run().await {
            panic!("Aggregator error: {}", e);
        }
    });

    // Give the servers time to start up
    sleep(Duration::from_millis(100)).await;

    let mut clients = Vec::new();
    let mut expected_sums = vec![0u32; config.length];
    let mut client_inputs = Vec::new();
    for _ in 0..config.num_clients {
        // Register client
        let mut client = Client::<G>::new(&config.decryptor_addr, &config.aggregator_addr);
        client.register().await?;

        assert!(client.id.is_some());
        assert!(client.key.is_some());

        // Generate random input for client
        let mut inputs = Vec::with_capacity(config.length);
        for i in 0..config.length {
            let val = OsRng.gen_bool(0.5);
            expected_sums[i] += val as u32;
            inputs.push(val as u32);
        }
        clients.push(client);
        client_inputs.push(inputs);
    }
    info!("{} clients registered successfully", config.num_clients);

    // Send encodings from all clients
    for (i, client) in clients.iter().enumerate() {
        client.send_encoding(&client_inputs[i]).await?;
    }
    info!("Clients sent encodings");

    // Wait for the final result from aggregator
    let final_results = receiver.recv().await.ok_or(anyhow!("No result received"))?;
    assert_eq!(final_results, expected_sums);

    // Clean up
    decryptor_handle.abort();
    aggregator_handle.abort();

    info!("Protocol test completed successfully");
    Ok(())
}

#[tokio::test]
async fn test_protocol() -> Result<()> {
    let config = TestConfig::default();
    run_protocol(config).await
}

#[tokio::test]
async fn test_aggregator_waits_for_params() -> Result<()> {
    init_tracing();

    // Make sure ports are different from above test
    let mut config = TestConfig::default();
    config.decryptor_addr = "127.0.0.1:8098".to_string();
    config.aggregator_addr = "127.0.0.1:8099".to_string();

    // Start the aggregator first (without decryptor)
    let (sender, _receiver) = tokio::sync::mpsc::channel(1);
    let aggregator = Aggregator::<G>::new(&config.aggregator_addr, &config.decryptor_addr, sender);
    let aggregator_handle = tokio::spawn(async move {
        if let Err(e) = aggregator.run().await {
            panic!("Aggregator error: {}", e);
        }
    });

    // Give the aggregator time to start
    sleep(Duration::from_millis(50)).await;

    // Try to send an encoding before the aggregator has parameters
    let mut client = Client::<G>::new(&config.decryptor_addr, &config.aggregator_addr);

    // Manually set client ID and key (simulating registration)
    client.id = Some(1);
    client.key = Some(Agg::setup(1, 1, &mut OsRng).2[0].clone());

    // This should fail with an error message
    let result = client.send_encoding(&[1]).await;
    assert!(
        result.is_err(),
        "Expected error when sending encoding before parameters"
    );

    aggregator_handle.abort();
    Ok(())
}
