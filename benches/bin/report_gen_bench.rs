mod common;
use common::{TimeStats, print_results};

use clap::Parser;
use heli::{
    agg_only_enc::AggOnlyEnc,
    crypto::{Scalar, hpke::ServerKeys},
    proofs::Proof,
    system::ProverType,
};
use rand::Rng;
use rand_core::OsRng;
use std::hint::black_box;
use std::time::Instant;

#[derive(Parser)]
struct Config {
    /// Number of measurement iterations to run
    #[arg(short, long, default_value_t = 10)]
    iterations: usize,

    /// Number of warmup iterations before measurement
    #[arg(short, long, default_value_t = 5)]
    warmup: usize,

    /// Number of clients to benchmark (space-separated list)
    #[arg(short, long, num_args = 1.., value_delimiter = ' ', default_value = "100")]
    clients: Vec<usize>,

    /// Length of input vectors
    #[arg(short, long, default_value_t = 1)]
    length: usize,

    /// Bit length of input values
    #[arg(short, long, default_value_t = 1)]
    bitlength: usize,
}

const CONTEXT: u32 = 42;

/// Run client report generation benchmarks
fn bench_report_generation(config: &Config) -> Vec<(usize, TimeStats)> {
    // Find the maximum number of clients to set up for
    let max_clients = config.clients.iter().max().unwrap_or(&100);

    // Determine the actual proof system type being used
    let prover_type = if config.bitlength == 1 && config.length < 8 {
        ProverType::Binary
    } else {
        ProverType::Range(config.bitlength)
    };

    let prover_type_str = match prover_type {
        ProverType::Binary => "Binary",
        ProverType::Range(_) => "Range",
    };
    println!(
        "Setting up report generation benchmark for up to {} clients using {} proof system (bitlength={}, length={})...",
        max_clients, prover_type_str, config.bitlength, config.length
    );

    // Setup - generate keys for clients
    let aggregator_keys = ServerKeys::generate();
    let (_sk, eval_keys) = AggOnlyEnc::setup(*max_clients, &mut OsRng);
    let (prover_keys, _verifier_key) = Proof::setup(&eval_keys, config.bitlength, config.length);

    // Create clients (simulating registration) - use prover keys from setup
    let clients: Vec<_> = (0..*max_clients)
        .map(|i| (prover_keys[i].clone(), eval_keys[i].clone(), i as u32))
        .collect();

    // Generate test inputs
    let mut rng = OsRng;
    let inputs: Vec<Vec<u64>> = (0..*max_clients)
        .map(|_| {
            (0..config.length)
                .map(|_| rng.gen_range(0u64..(1u64 << config.bitlength)))
                .collect()
        })
        .collect();

    let mut results = Vec::new();

    // Benchmark each client count
    for &client_count in &config.clients {
        println!("Benchmarking {} clients...", client_count);

        // Warmup runs
        for i in 0..config.warmup.min(client_count) {
            let (prover_key, eval_key, _id) = &clients[i];
            let input = &inputs[i];
            let input_scalars: Vec<Scalar> = input.iter().map(|&x| Scalar::from(x)).collect();

            // Generate ciphertext
            let ciphertext = AggOnlyEnc::encrypt(eval_key, CONTEXT, &input_scalars);
            // Generate proof
            let _proof = black_box(
                Proof::prove(
                    prover_key,
                    eval_key,
                    CONTEXT,
                    &input_scalars,
                    &ciphertext,
                    &mut OsRng,
                )
                .unwrap(),
            );
            // Create report and HPKE encrypt
            let report = heli::system::messages::Message::ClientReport {
                ciphertext,
                proof: _proof,
            };
            let report_bytes = bincode::serialize(&report).unwrap();
            let _envelope = black_box(
                heli::crypto::hpke::hpke_encrypt(&aggregator_keys.pk, &report_bytes, b"", b"")
                    .unwrap()
                    .0,
            );
        }

        // Measurement runs
        let mut times = Vec::with_capacity(config.iterations);
        for _iteration in 0..config.iterations {
            let start = Instant::now();

            // Generate reports for all clients in this iteration
            for i in 0..client_count {
                let (prover_key, eval_key, _id) = &clients[i];
                let input = &inputs[i];
                let input_scalars: Vec<Scalar> = input.iter().map(|&x| Scalar::from(x)).collect();

                // Generate ciphertext
                let ciphertext = AggOnlyEnc::encrypt(eval_key, CONTEXT, &input_scalars);
                // Generate proof
                let proof = black_box(
                    Proof::prove(
                        prover_key,
                        eval_key,
                        CONTEXT,
                        &input_scalars,
                        &ciphertext,
                        &mut OsRng,
                    )
                    .unwrap(),
                );
                // Create report and HPKE encrypt
                let report = heli::system::messages::Message::ClientReport { ciphertext, proof };
                let report_bytes = bincode::serialize(&report).unwrap();
                let _envelope = black_box(
                    heli::crypto::hpke::hpke_encrypt(&aggregator_keys.pk, &report_bytes, b"", b"")
                        .unwrap()
                        .0,
                );
            }

            let duration = start.elapsed();
            times.push(duration);
        }

        results.push((client_count, TimeStats::from_times(&times)));
    }

    results
}

fn main() {
    let config = Config::parse();

    println!("Running client report generation benchmark...");

    // Determine proof system type from config
    let proof_system_type = if config.bitlength == 1 && config.length < 8 {
        "BINARY"
    } else {
        "RANGE"
    };

    println!("\n{}", "=".repeat(80));
    println!("{} PROOF SYSTEM", proof_system_type);
    println!("{}", "=".repeat(80));

    let results = bench_report_generation(&config);
    print_results(
        &results,
        proof_system_type,
        &config.clients,
        config.length,
        config.bitlength,
        config.iterations,
        config.warmup,
        "Report Generation Results",
        "Total (ms)",
        "Per-Client (ms)",
    );

    println!("\n{}", "=".repeat(80));
}
