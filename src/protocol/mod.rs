/// Hardcoded group
pub type G = curve25519_dalek::RistrettoPoint;
pub type Scalar = curve25519_dalek::Scalar;

pub mod elgamal;
pub mod messages;
pub mod provers;

// Re-export commonly used types
pub use elgamal::ElGamal;
pub use messages::*;
pub use provers::*;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, rngs::OsRng};

    fn random_input(length: usize, bitlength: usize) -> Vec<u64> {
        (0..length)
            .map(|_| OsRng.gen_range(0..(1 << bitlength)))
            .collect()
    }

    fn aggregation<P: Prover>(num_clients: usize, length: usize, bitlength: usize) {
        // Setup scheme
        let (params, sk, cks) = ElGamal::setup(num_clients, length, &mut OsRng);
        let (prover_key, verifier_key) = P::setup(length, bitlength);

        // Generate encodings and proofs
        let mut encodings = Vec::new();
        let mut proofs = Vec::new();
        let mut expected_sums = vec![0u64; length];
        for i in 0..num_clients {
            let inputs = random_input(length, bitlength);

            // Track expected sums
            for (j, &val) in inputs.iter().enumerate() {
                expected_sums[j] += val;
            }

            let (encoding, r) = ElGamal::encode(&cks[i], &inputs, &mut OsRng).unwrap();
            let proof = P::prove(&prover_key, &cks[i], &inputs, r, &encoding, &mut OsRng).unwrap();

            encodings.push(encoding);
            proofs.push(proof);
        }

        // Verify all proofs individually
        for (i, (encoding, proof)) in encodings.iter().zip(proofs.iter()).enumerate() {
            P::verify(&verifier_key, &params, i, encoding, proof).unwrap();
        }

        // Verify all proofs in a batch
        P::batch_verify(
            &verifier_key,
            &params,
            &(0..num_clients).collect::<Vec<_>>(),
            &encodings,
            &proofs,
            &mut OsRng,
        )
        .unwrap();

        // Aggregate and decode
        let aggregate = ElGamal::aggregate(&params, &encodings).unwrap();
        let partial_output = ElGamal::decode(&sk, aggregate).unwrap();

        let result = ElGamal::post_process(&params, bitlength, partial_output).unwrap();

        // Verify the result matches expected sums
        assert_eq!(result, expected_sums);
    }

    #[test]
    fn binary_aggregation() {
        let num_clients = vec![1, 10];
        let lengths = vec![1, 16];
        for (n, l) in num_clients.into_iter().zip(lengths) {
            aggregation::<Binary>(n, l, 1);
        }
    }

    #[test]
    fn small_int_aggregation() {
        let num_clients = vec![1, 10];
        let lengths = vec![1, 16];
        let bitlengths = vec![8, 16];
        for ((n, l), b) in num_clients.into_iter().zip(lengths).zip(bitlengths) {
            aggregation::<Range>(n, l, b);
        }
    }

    fn measure_sizes<P: Prover>(length: usize, bitlength: usize) {
        use bytesize::ByteSize;

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
            "({:>3}, {:>3}) -> {:>8} + {:>8} = {:>8}",
            length,
            bitlength,
            ByteSize::b(encoding_size as u64),
            ByteSize::b(proof_size as u64),
            ByteSize::b(total_size as u64)
        );
        println!("\n========================\n");
    }

    #[test]
    fn print_sizes() {
        println!("\n=== Size Measurements (Serde/Bincode) ===");
        println!(
            "Format: (input_length, bitlength) -> encoding_size + proof_size = comm_per_client\n"
        );
        measure_sizes::<Binary>(1, 1);
        measure_sizes::<Range>(1, 8);
        measure_sizes::<Binary>(8, 1);
        measure_sizes::<Range>(8, 8);
    }
}
