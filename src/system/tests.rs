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

const TEST_BATCH_SIZE: usize = 64;

struct TestConfig {
    num_clients: usize,
    threshold: usize,
    length: usize,
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
            decryptor_addr: format!("127.0.0.1:{}", 20000 + rand::random::<u16>() % 1000),
            aggregator_addr: format!("127.0.0.1:{}", 21000 + rand::random::<u16>() % 1000),
            prover: ProverType::Range(bitlength),
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::from_default_env().add_directive("sled=off".parse().unwrap());

    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stdout)
        .with_env_filter(filter)
        .with_test_writer()
        .try_init();
}

/// Stream reports to the aggregator using AggregateStreamStart and return the result.
async fn stream_aggregate(
    aggregator_addr: &str,
    context: u32,
    reports: Vec<(u32, Vec<u8>)>,
    binary: bool,
    bitlength: Option<usize>,
) -> Result<Vec<u64>> {
    let batches: Vec<Vec<(u32, Vec<u8>)>> = reports
        .chunks(TEST_BATCH_SIZE)
        .map(|c| c.to_vec())
        .collect();
    let num_batches = batches.len();

    let mut socket = TcpStream::connect(aggregator_addr).await?;
    write_message(&mut socket, &Message::AggregateStreamStart {
        context,
        num_batches,
        binary,
        bitlength,
        simulated: false,
        sim_dropouts: vec![],
    }).await?;

    for batch in batches {
        write_message(&mut socket, &Message::BatchEncryptedClientReports {
            context,
            reports: batch,
        }).await?;
    }

    match read_message(&mut socket).await? {
        Message::AggregationResponse { result } => Ok(result),
        Message::Error(e) => Err(anyhow!("Aggregation failed: {e}")),
        _ => Err(anyhow!("Unexpected response")),
    }
}

#[tokio::test]
async fn test_decryptor_setup() -> Result<()> {
    init_tracing();

    let config = TestConfig::binary(5, 1);
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
        4,
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
    let decryptor_state = decryptor.state.clone();
    let decryptor_handle = tokio::spawn(async move {
        if let Err(e) = decryptor.run().await {
            panic!("Decryptor error: {}", e);
        }
    });

    sleep(Duration::from_millis(100)).await;

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

    sleep(Duration::from_millis(500)).await;

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

    let secret_key = decryptor_state.secret_key.get().unwrap();
    assert_eq!(secret_key.prf_key, expected_key);

    decryptor_handle.abort();
    aggregator_handle.abort();

    Ok(())
}

async fn test_end_to_end_impl(
    config: TestConfig,
    num_rounds: u32,
    num_dropouts: usize,
) -> Result<()> {
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
        4,
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

    sleep(Duration::from_millis(100)).await;

    let mut rng = OsRng;
    let max_val = match config.prover {
        ProverType::Binary => 2,
        ProverType::Range(bitlength) => 1u64 << bitlength,
    };
    let (binary, bitlength) = match config.prover {
        ProverType::Binary => (true, None),
        ProverType::Range(bl) => (false, Some(bl)),
    };

    for round in 0..num_rounds {
        let mut expected_sums = vec![0u64; config.length];
        let mut client_inputs: Vec<Vec<u64>> = Vec::new();

        for _ in 0..config.num_clients {
            let inputs: Vec<u64> = (0..config.length)
                .map(|_| rng.gen_range(0..max_val))
                .collect();
            client_inputs.push(inputs);
        }

        let num_submitting = config.num_clients - num_dropouts;
        for i in 0..num_submitting {
            for (j, &val) in client_inputs[i].iter().enumerate() {
                expected_sums[j] += val;
            }
        }

        // Generate reports and serialize envelopes into batched format
        let mut reports: Vec<(u32, Vec<u8>)> = Vec::new();
        for i in 0..num_submitting {
            let report = clients[i].generate_report(round, &client_inputs[i])?;
            if let Message::EncryptedClientReport { id, envelope, .. } = report {
                reports.push((id, bincode::serialize(&envelope)?));
            }
        }

        let result = stream_aggregate(
            &config.aggregator_addr,
            round,
            reports,
            binary,
            bitlength,
        ).await?;

        assert_eq!(
            result, expected_sums,
            "Round {} results don't match expected sums",
            round
        );
    }

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

#[tokio::test]
async fn test_multiple_rounds() -> Result<()> {
    init_tracing();
    test_end_to_end_impl(TestConfig::binary(6, 2), 3, 0).await
}

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
        4,
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

    Client::trigger_sim_setup(&config.decryptor_addr).await?;
    sleep(Duration::from_millis(200)).await;

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

    let mut reports: Vec<(u32, Vec<u8>)> = Vec::new();
    for (i, client) in clients.iter().enumerate() {
        let report = client.generate_report(0, &client_inputs[i])?;
        if let Message::EncryptedClientReport { id, envelope, .. } = report {
            reports.push((id, bincode::serialize(&envelope)?));
        }
    }

    let result = stream_aggregate(
        &config.aggregator_addr,
        0,
        reports,
        true,
        None,
    ).await?;

    assert_eq!(result, expected_sums, "Simulated setup e2e: results don't match");

    decryptor_handle.abort();
    aggregator_handle.abort();

    Ok(())
}
