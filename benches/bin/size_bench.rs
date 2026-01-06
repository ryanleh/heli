use bytesize::ByteSize;
use clap::Parser;
use heli::{agg_only_enc::AggOnlyEnc, crypto::Scalar, proofs::Proof};
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

pub fn random_inputs(len: usize, bitlength: usize) -> Vec<u64> {
    let mut rng = OsRng;
    (0..len)
        .map(|_| rng.gen_range(0..(1 << bitlength)))
        .collect()
}

fn measure_sizes(length: usize, bitlength: usize) {
    const CONTEXT: u32 = 42;
    let mut rng = OsRng;
    let (_, eval_keys) = AggOnlyEnc::setup(1, &mut rng);
    let (prover_keys, _) = Proof::setup(&eval_keys, bitlength, length);

    // Determine the actual proof system type being used
    let proof_system_name = if bitlength == 1 && length < 8 {
        "Binary"
    } else {
        "Range"
    };

    let input: Vec<Scalar> = random_inputs(length, bitlength)
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
            measure_sizes(length, bitlength);
        }
    }

    println!("\n{}", "=".repeat(80));
}
