use bytesize::ByteSize;
use clap::Parser;
use heli::protocol::{
    ElGamal,
    provers::{Binary, Prover, Range},
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

fn measure_sizes<P: Prover>(length: usize, bitlength: usize, proof_system_name: &str) {
    let (_params, _sk, cks) = ElGamal::setup(1, length, &mut OsRng);
    let (prover_key, _) = P::setup(length, bitlength);

    let (encoding, r) =
        ElGamal::encode(&cks[0], &random_input(length, bitlength), &mut OsRng).unwrap();
    let proof = P::prove(
        &prover_key,
        &cks[0],
        &random_input(length, bitlength),
        r,
        &encoding,
        &mut OsRng,
    )
    .unwrap();

    // Serialize using bincode
    let encoding_size = bincode::serialized_size(&encoding).unwrap() as usize;
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
            if bitlength == 1 {
                // For bitlength 1, run both Binary and Range proof systems
                measure_sizes::<Binary>(length, bitlength, "Binary");
                measure_sizes::<Range>(length, bitlength, "Range");
            } else {
                measure_sizes::<Range>(length, bitlength, "Range");
            }
        }
    }

    println!("\n{}", "=".repeat(80));
}
