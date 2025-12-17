use bytesize::ByteSize;
use clap::Parser;
use heli::{
    agg_only_enc::{AggOnlyEnc, EvalKey},
    crypto::Scalar,
    proofs::Proof,
};
use rand::Rng;
use rand_core::OsRng;

#[derive(Parser)]
#[command(name = "size-bench")]
#[command(about = "Measure proof and encoding sizes for different configurations")]
struct Config {
    /// Length of input vectors (space-separated list)
    #[arg(short, long, value_delimiter = ' ', num_args = 1.., default_value = "1")]
    length: Vec<usize>,

    /// Bit length of input values (space-separated list)
    #[arg(short, long, value_delimiter = ' ', num_args = 1.., default_value = "1")]
    bitlength: Vec<usize>,
}

fn random_input(length: usize, bitlength: usize) -> Vec<u64> {
    (0..length)
        .map(|_| OsRng.gen_range(0..1u128 << bitlength) as u64)
        .collect()
}

fn measure_sizes(length: usize, bitlength: usize, proof_system_name: &str) {
    const CONTEXT: u32 = 42;
    let mut rng = OsRng;
    let (_, eval_keys) = AggOnlyEnc::setup(1, &mut rng);
    let (prover_keys, _) = Proof::setup(&eval_keys, bitlength, length);

    let input: Vec<Scalar> = random_input(length, bitlength)
        .into_iter()
        .map(|x| Scalar::from(x))
        .collect();
    let ciphertext = AggOnlyEnc::encrypt(&eval_keys[0], CONTEXT, &input);
    let proof = Proof::prove(
        &prover_keys[0],
        &eval_keys[0],
        CONTEXT,
        &input,
        &ciphertext,
        &mut OsRng,
    )
    .unwrap();

    // Serialize using bincode
    let encoding_size = bincode::serialized_size(&ciphertext).unwrap() as usize;
    let proof_size = bincode::serialized_size(&proof).unwrap() as usize;
    let total_size = encoding_size + proof_size;

    println!(
        "({:>3}, {:>3}) [{}] -> {:>8} + {:>8} = {:>8}",
        length,
        bitlength,
        proof_system_name,
        ByteSize::b(encoding_size as u64),
        ByteSize::b(proof_size as u64),
        format!("{:.2}KB", total_size as f64 / 1024.0)
    );
}

fn main() {
    let config = Config::parse();

    println!("Running size measurements...");
    println!("Configuration:");
    println!("  Input Lengths: {:?}", config.length);
    println!("  Bitlengths: {:?}", config.bitlength);

    println!("\n=== Size Measurements (Serde/Bincode) ===");
    println!(
        "Format: (input_length, bitlength) [proof_system] -> encoding_size + proof_size = total_size\n"
    );

    for &length in &config.length {
        for &bitlength in &config.bitlength {
            // Note: Binary proofs are not yet implemented, so we only measure Range
            measure_sizes(length, bitlength, "Range");
        }
    }

    println!("\n{}", "=".repeat(80));
}
