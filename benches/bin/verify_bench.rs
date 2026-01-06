mod common;
use common::{TimeStats, print_results};

use clap::Parser;
use heli::{agg_only_enc::AggOnlyEnc, crypto::Scalar, proofs::Proof};
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

/// Run batch proof verification benchmarks for different client counts
fn bench_verification(config: &Config) -> Vec<(usize, TimeStats)> {
    // Find the maximum number of clients to set up for
    let max_clients = config.clients.iter().max().unwrap_or(&100);

    // Determine the actual proof system type being used
    let actual_proof_system = if config.bitlength == 1 && config.length < 8 {
        "Binary"
    } else {
        "Range"
    };

    println!(
        "Setting up verification benchmark for up to {} clients using {} proof system (bitlength={}, length={})...",
        max_clients, actual_proof_system, config.bitlength, config.length
    );

    // Setup - use the same inputs for all benchmarks
    let input: Vec<Scalar> = (0..config.length)
        .map(|_| Scalar::from(OsRng.gen_range(0u64..(1u64 << config.bitlength))))
        .collect();
    let (_sk, eval_keys) = AggOnlyEnc::setup(*max_clients, &mut OsRng);
    let (prover_keys, verifier_key) = Proof::setup(&eval_keys, config.bitlength, config.length);

    // Create ciphertexts and proofs for maximum number of clients
    let (ciphertexts, proofs): (Vec<_>, Vec<_>) = (0..*max_clients)
        .map(|i| {
            let ciphertext = AggOnlyEnc::encrypt(&eval_keys[i], CONTEXT, &input);
            let proof = Proof::prove(
                &prover_keys[i],
                &eval_keys[i],
                CONTEXT,
                &input,
                &ciphertext,
                &mut OsRng,
            )
            .unwrap();
            (ciphertext, proof)
        })
        .unzip();

    let mut results = Vec::new();
    let mut rng = OsRng;

    // Benchmark each client count
    for &client_count in &config.clients {
        println!("Benchmarking {} clients...", client_count);

        // Create indices for this client count
        let indices = (0u32..client_count as u32).collect::<Vec<_>>();
        let client_ciphertexts = &ciphertexts[..client_count];
        let client_proofs = &proofs[..client_count];

        // Warmup runs
        for _ in 0..config.warmup {
            black_box(
                Proof::batch_verify(
                    &verifier_key,
                    client_ciphertexts,
                    CONTEXT,
                    client_proofs,
                    &indices,
                    &mut rng,
                )
                .unwrap(),
            );
        }

        // Measurement runs
        let mut times = Vec::with_capacity(config.iterations);
        for _ in 0..config.iterations {
            let start = Instant::now();
            black_box(
                Proof::batch_verify(
                    &verifier_key,
                    client_ciphertexts,
                    CONTEXT,
                    client_proofs,
                    &indices,
                    &mut rng,
                )
                .unwrap(),
            );
            let duration = start.elapsed();
            times.push(duration);
        }

        results.push((client_count, TimeStats::from_times(&times)));
    }

    results
}

fn main() {
    let config = Config::parse();

    println!("Running proof verification benchmark...");

    // Determine proof system type from config
    let proof_system_type = if config.bitlength == 1 && config.length < 8 {
        "BINARY"
    } else {
        "RANGE"
    };

    println!("\n{}", "=".repeat(80));
    println!("{} PROOF SYSTEM", proof_system_type);
    println!("{}", "=".repeat(80));

    let results = bench_verification(&config);
    print_results(
        &results,
        proof_system_type,
        &config.clients,
        config.length,
        config.bitlength,
        config.iterations,
        config.warmup,
        "Verification Results",
        "Mean (ms)",
        "Per-User (ms)",
    );

    println!("\n{}", "=".repeat(80));
}
