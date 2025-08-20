use clap::Parser;
use hlagg::protocol::{
    ElGamal,
    provers::{Binary, Prover, Range},
};
use rand::Rng;
use rand_core::OsRng;
use std::hint::black_box;
use std::time::{Duration, Instant};

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

#[derive(Debug)]
pub struct TimeStats {
    pub mean: Duration,
    pub min: Duration,
    pub max: Duration,
    pub median: Duration,
    pub std_dev: Duration,
}

impl TimeStats {
    fn from_times(times: &[Duration]) -> Self {
        if times.is_empty() {
            return Self {
                mean: Duration::ZERO,
                min: Duration::ZERO,
                max: Duration::ZERO,
                median: Duration::ZERO,
                std_dev: Duration::ZERO,
            };
        }

        // Sort times to find min, max, median
        let mut sorted_times = times.to_vec();
        sorted_times.sort();

        let mean_nanos =
            times.iter().map(|d| d.as_nanos() as f64).sum::<f64>() / times.len() as f64;
        let mean = Duration::from_nanos(mean_nanos as u64);
        let min = sorted_times[0];
        let max = sorted_times[times.len() - 1];
        let median = sorted_times[times.len() / 2];

        // Calculate standard deviation
        let variance = times
            .iter()
            .map(|d| {
                let diff = d.as_nanos() as f64 - mean_nanos;
                diff * diff
            })
            .sum::<f64>()
            / times.len() as f64;
        let std_dev = Duration::from_nanos(variance.sqrt() as u64);

        Self {
            mean,
            min,
            max,
            median,
            std_dev,
        }
    }
}

/// Run batch proof verification benchmarks for different client counts
fn bench_verification<P: Prover>(
    config: &Config,
    proof_system_name: &str,
) -> Vec<(usize, TimeStats)> {
    // Find the maximum number of clients to set up for
    let max_clients = config.clients.iter().max().unwrap_or(&100);

    println!(
        "Setting up verification benchmark for up to {} clients using {} proof system...",
        max_clients, proof_system_name
    );

    // Setup - use the same inputs for all benchmarks
    let input: Vec<u64> = (0..config.length)
        .map(|_| OsRng.gen_range(0..(1 << config.bitlength)))
        .collect();
    let (params, _sk, cks) = ElGamal::setup(*max_clients, config.length, &mut OsRng);
    let (prover_key, verifier_key) = P::setup(config.length, config.bitlength);

    // Create encodings and proofs for maximum number of clients
    let (encodings, proofs): (Vec<_>, Vec<_>) = (0..*max_clients)
        .map(|i| {
            let (encoding, r) = ElGamal::encode(&cks[i], &input, &mut OsRng).unwrap();
            let proof = P::prove(&prover_key, &cks[i], &input, r, &encoding, &mut OsRng).unwrap();
            (encoding, proof)
        })
        .unzip();

    let mut results = Vec::new();

    // Benchmark each client count
    for &client_count in &config.clients {
        println!("Benchmarking {} clients...", client_count);

        // Create indices for this client count
        let indices = (0..client_count).collect::<Vec<_>>();
        let client_encodings = &encodings[..client_count];
        let client_proofs = &proofs[..client_count];

        // Warmup runs
        for _ in 0..config.warmup {
            black_box(
                P::batch_verify(
                    &verifier_key,
                    &params,
                    &indices,
                    client_encodings,
                    client_proofs,
                    &mut OsRng,
                )
                .unwrap(),
            );
        }

        // Measurement runs
        let mut times = Vec::with_capacity(config.iterations);
        for _ in 0..config.iterations {
            let start = Instant::now();
            black_box(
                P::batch_verify(
                    &verifier_key,
                    &params,
                    &indices,
                    client_encodings,
                    client_proofs,
                    &mut OsRng,
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

/// Run batch proof verification benchmarks for untagged proofs
fn bench_verification_untagged<P: Prover>(
    config: &Config,
    proof_system_name: &str,
) -> Vec<(usize, TimeStats)> {
    // Find the maximum number of clients to set up for
    let max_clients = config.clients.iter().max().unwrap_or(&100);

    println!(
        "Setting up untagged verification benchmark for up to {} clients using {} proof system...",
        max_clients, proof_system_name
    );

    // Setup - use the same inputs for all benchmarks
    let input: Vec<u64> = (0..config.length)
        .map(|_| OsRng.gen_range(0..(1 << config.bitlength)))
        .collect();
    let (params, _sk, cks) = ElGamal::setup(*max_clients, config.length, &mut OsRng);
    let (prover_key, verifier_key) = P::setup(config.length, config.bitlength);

    // Create encodings and untagged proofs for maximum number of clients
    let (encodings, proofs): (Vec<_>, Vec<_>) = (0..*max_clients)
        .map(|i| {
            let (encoding, r) = ElGamal::encode(&cks[i], &input, &mut OsRng).unwrap();
            let proof =
                P::prove_untagged(&prover_key, &cks[i], &input, r, &encoding, &mut OsRng).unwrap();
            (encoding, proof)
        })
        .unzip();

    let mut results = Vec::new();

    // Benchmark each client count
    for &client_count in &config.clients {
        println!("Benchmarking {} clients (untagged)...", client_count);

        // Create indices for this client count
        let indices = (0..client_count).collect::<Vec<_>>();
        let client_encodings = &encodings[..client_count];
        let client_proofs = &proofs[..client_count];

        // Warmup runs
        for _ in 0..config.warmup {
            black_box(
                P::batch_verify_untagged(
                    &verifier_key,
                    &params,
                    &indices,
                    client_encodings,
                    client_proofs,
                    &mut OsRng,
                )
                .unwrap(),
            );
        }

        // Measurement runs
        let mut times = Vec::with_capacity(config.iterations);
        for _ in 0..config.iterations {
            let start = Instant::now();
            black_box(
                P::batch_verify_untagged(
                    &verifier_key,
                    &params,
                    &indices,
                    client_encodings,
                    client_proofs,
                    &mut OsRng,
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

    if config.bitlength == 1 {
        // For bitlength 1, run both Binary and Range proof systems
        println!("\n{}", "=".repeat(80));
        println!("BINARY PROOF SYSTEM");
        println!("{}", "=".repeat(80));

        let binary_results = bench_verification::<Binary>(&config, "Binary");
        print_results(&binary_results, &config, "Binary");

        println!("\n{}", "=".repeat(80));
        println!("BINARY PROOF SYSTEM (UNTAGGED)");
        println!("{}", "=".repeat(80));

        let binary_untagged_results = bench_verification_untagged::<Binary>(&config, "Binary");
        print_results(&binary_untagged_results, &config, "Binary (Untagged)");

        println!("\n{}", "=".repeat(80));
        println!("RANGE PROOF SYSTEM");
        println!("{}", "=".repeat(80));

        let range_results = bench_verification::<Range>(&config, "Range");
        print_results(&range_results, &config, "Range");

        println!("\n{}", "=".repeat(80));
        println!("RANGE PROOF SYSTEM (UNTAGGED)");
        println!("{}", "=".repeat(80));

        let range_untagged_results = bench_verification_untagged::<Range>(&config, "Range");
        print_results(&range_untagged_results, &config, "Range (Untagged)");
    } else {
        let results = bench_verification::<Range>(&config, "Range");
        print_results(&results, &config, "Range");

        println!("\n{}", "=".repeat(80));
        println!("RANGE PROOF SYSTEM (UNTAGGED)");
        println!("{}", "=".repeat(80));

        let range_untagged_results = bench_verification_untagged::<Range>(&config, "Range");
        print_results(&range_untagged_results, &config, "Range (Untagged)");
    }

    println!("\n{}", "=".repeat(80));
}

fn print_results(results: &[(usize, TimeStats)], config: &Config, proof_system_name: &str) {
    println!("Configuration:");
    println!("  Proof System: {}", proof_system_name);
    println!("  Client Counts: {:?}", config.clients);
    println!("  Input Length: {}", config.length);
    println!("  Bitlength: {}", config.bitlength);
    println!(
        "  Iterations: {} (warmup: {})",
        config.iterations, config.warmup
    );

    // Helper function to format duration with 2 decimal places
    let format_duration = |duration: Duration| {
        let millis = duration.as_micros() as f64 / 1000.0;
        format!("{:.2}ms", millis)
    };

    println!("\nVerification Results:");
    println!(
        "  Clients | Mean (ms) | Per-User (ms) | Relative | Median (ms) | Min (ms) | Max (ms) | Std Dev (ms)"
    );
    println!(
        "  --------|-----------|---------------|----------|-------------|----------|----------|-------------"
    );

    // Calculate baseline per-user cost (from first result)
    let baseline_per_user = if let Some((_, first_stats)) = results.first() {
        first_stats.mean / results[0].0 as u32
    } else {
        Duration::ZERO
    };

    for (client_count, stats) in results {
        let per_user = stats.mean / *client_count as u32;

        // Calculate speedup (baseline / current)
        let relative = if baseline_per_user > Duration::ZERO {
            let speedup = baseline_per_user.as_nanos() as f64 / per_user.as_nanos() as f64;
            format!("{:.1}x", speedup)
        } else {
            "1.0x".to_string()
        };

        println!(
            "  {:6} | {:9} | {:13} | {:8} | {:11} | {:8} | {:8} | {:11}",
            client_count,
            format_duration(stats.mean),
            format_duration(per_user),
            relative,
            format_duration(stats.median),
            format_duration(stats.min),
            format_duration(stats.max),
            format_duration(stats.std_dev)
        );
    }
}
