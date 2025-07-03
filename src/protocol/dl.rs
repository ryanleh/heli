use crate::net::client::Client;

use super::{Aggregation, messages::*, serialization::*};

use anyhow::{Result, anyhow};
use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};
use rand_core::{CryptoRng, RngCore};
use std::marker::PhantomData;

pub struct DiscreteLog<G: Group + GroupEncoding> {
    _g: PhantomData<G>,
}

impl<G: Group + GroupEncoding> DiscreteLog<G> {
    /// We prove the following relation (informally stated) for secrets r and s:
    ///  1) c_0 = g^r and
    ///  2) c_1 = pk_0^r * g^s and
    ///  3) ck = h^s and
    ///  4) c_i = DLEQ(c_0, pk_i^r) or DLEQ(c_0, pk_i^r / g) for i > 1
    ///
    /// This enforces that the ElGamal ciphertext is well-formed, that the secret
    /// key is embedded correctly, and that each input is either 0 or 1.
    fn create_proof<R: RngCore + CryptoRng>(
        key: &ClientKey<G>,
        r: G::Scalar,
        input: &[u32],
        encoding: &Encoding<G>,
        rng: &mut R,
    ) -> Proof<G> {
        // Generate commitments (and simulated transcripts) for claim 4
        let mut r_x_rand = Vec::with_capacity(input.len()); // Randomness for real branch
        let mut comm_g_x0 = Vec::with_capacity(input.len());
        let mut comm_pk_x0 = Vec::with_capacity(input.len());
        let mut comm_g_x1 = Vec::with_capacity(input.len());
        let mut comm_pk_x1 = Vec::with_capacity(input.len());

        let mut sim_challenges = Vec::with_capacity(input.len());
        let mut sim_responses = Vec::with_capacity(input.len());

        for i in 0..input.len() {
            // Generate simulated transcripts for false paths in claim 4
            let challenge = G::Scalar::random(&mut *rng);
            let response = G::Scalar::random(&mut *rng);
            sim_challenges.push(challenge);
            sim_responses.push(response);

            // Generate commitments
            let r_rand = G::Scalar::random(&mut *rng);
            r_x_rand.push(r_rand);
            match input[i] {
                0 => {
                    // Real
                    comm_g_x0.push(key.g * r_rand);
                    comm_pk_x0.push(key.pks[i + 1] * r_rand);

                    // Simulated
                    comm_g_x1.push(key.g * response - encoding.rand * challenge);
                    comm_pk_x1
                        .push(key.pks[i + 1] * response - (encoding.vals[i] - key.g) * challenge);
                }
                1 => {
                    // Simulated
                    comm_g_x0.push(key.g * response - encoding.rand * challenge);
                    comm_pk_x0.push(key.pks[i + 1] * response - encoding.vals[i] * challenge);

                    // Real
                    comm_g_x1.push(key.g * r_rand);
                    comm_pk_x1.push(key.pks[i + 1] * r_rand);
                }
                _ => panic!("Input should be 0 or 1"),
            }
        }

        // Generate commitments for claims 1-3
        let r_rand = G::Scalar::random(&mut *rng);
        let s_rand = G::Scalar::random(&mut *rng);
        let comm_g_r_rand = key.g * r_rand;
        let comm_pk0_r_rand = key.pks[0] * r_rand;
        let comm_g_s_rand = key.g * s_rand;
        let comm_h_s_rand = key.h * s_rand;

        // Collect Fiat-Shamir inputs as owned Vec<u8>
        //
        // TODO: This doesn't include full transcript atm
        let challenge = Self::fiat_shamir_challenge(&[
            key.g.to_bytes().as_ref(),
            encoding.rand.to_bytes().as_ref(),
        ]);

        // Generate responses for claim 4
        let mut challenges_x = Vec::with_capacity(input.len());
        let mut responses_x0 = Vec::with_capacity(input.len());
        let mut responses_x1 = Vec::with_capacity(input.len());
        for i in 0..input.len() {
            let challenge_real = challenge - sim_challenges[i];
            // Always send the challenge for the zero branch
            match input[i] {
                0 => {
                    challenges_x.push(challenge_real);
                    responses_x0.push(r_x_rand[i] + challenge_real * r);
                    responses_x1.push(sim_responses[i]);
                }
                1 => {
                    // Always send the challenge for the zero branch
                    challenges_x.push(sim_challenges[i]);
                    responses_x0.push(sim_responses[i]);
                    responses_x1.push(r_x_rand[i] + challenge_real * r);
                }
                _ => unreachable!(),
            }
        }

        Proof {
            comm_g_r: comm_g_r_rand,
            comm_pk_r: comm_pk0_r_rand,
            comm_g_s: comm_g_s_rand,
            comm_h_s: comm_h_s_rand,
            comm_g_x0,
            comm_pk_x0,
            comm_g_x1,
            comm_pk_x1,
            challenge_x: challenges_x,
            response_r: r_rand + challenge * r,
            response_s: s_rand + challenge * key.secret,
            response_x0: responses_x0,
            response_x1: responses_x1,
        }
    }

    // TODO: Double check that this is correct
    fn fiat_shamir_challenge(inputs: &[&[u8]]) -> G::Scalar {
        use ff::PrimeField;
        use num_bigint::BigUint;
        use num_traits::One;
        use sha3::{Digest, Sha3_256};

        // Compute the hash
        let mut hasher = Sha3_256::new();
        for input in inputs {
            hasher.update(input);
        }
        let bytes = hasher.finalize();

        // Compute the BigUint representation of the modulus
        let modulus_bytes = (G::Scalar::ZERO - G::Scalar::ONE).to_repr();
        let modulus = BigUint::from_bytes_le(modulus_bytes.as_ref()) + BigUint::one();

        // Map the hash value to a scalar value
        let scalar = BigUint::from_bytes_be(&bytes) % modulus;

        // Map the BigUint to a scalar value
        let scalar_byte_length = (G::Scalar::NUM_BITS as usize + 7) / 8;
        let mut bytes = vec![0u8; scalar_byte_length];
        let scalar_bytes = scalar.to_bytes_be();
        let start = bytes.len() - scalar_bytes.len();
        bytes[start..].copy_from_slice(&scalar_bytes);
        bytes.reverse();
        let mut repr = <<G as Group>::Scalar as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&bytes);
        <<G as Group>::Scalar as PrimeField>::from_repr(repr).expect("Error mapping hash to scalar")
    }

    pub fn verify_proof(
        params: &Params<G>,
        client_index: u32,
        encoding: &Encoding<G>,
        proof: &Proof<G>,
    ) -> bool {
        // Recompute Fiat-Shamir challenge
        //
        // TODO: Add public keys in hash
        let challenge = Self::fiat_shamir_challenge(&[
            params.g.to_bytes().as_ref(),
            encoding.rand.to_bytes().as_ref(),
        ]);

        // Check 1) c_0 = g^r
        if params.g * proof.response_r != proof.comm_g_r + encoding.rand * challenge {
            return false;
        }

        // Check 2) c_1 = pk_0^r * g^s
        if params.pks[0] * proof.response_r + params.g * proof.response_s
            != proof.comm_pk_r + proof.comm_g_s + encoding.secret * challenge
        {
            return false;
        }

        // Check 3) ck = h^s
        if params.h * proof.response_s
            != proof.comm_h_s + params.client_key_comms[client_index as usize] * challenge
        {
            return false;
        }

        // Check 4) c_i = DLEQ(c_0, pk_i^r) or DLEQ(c_0, pk_i^r / g) for i > 1
        for i in 0..encoding.vals.len() {
            let challenge_0 = proof.challenge_x[i];
            let challenge_1 = challenge - challenge_0;

            // X=0, check DLEQ(c_0, pk_i^r)
            if params.g * proof.response_x0[i] != proof.comm_g_x0[i] + encoding.rand * challenge_0 {
                return false;
            }
            if params.pks[i + 1] * proof.response_x0[i]
                != proof.comm_pk_x0[i] + encoding.vals[i] * challenge_0
            {
                return false;
            }

            // X=1, check DLEQ(c_0, pk_i^r / g)
            if params.g * proof.response_x1[i] != proof.comm_g_x1[i] + encoding.rand * challenge_1 {
                return false;
            }
            if params.pks[i + 1] * proof.response_x1[i]
                != proof.comm_pk_x1[i] + (encoding.vals[i] - params.g) * challenge_1
            {
                return false;
            }
        }

        true
    }
}

// TODO: Consider abstracting out the encryption scheme
impl<G: Group + GroupEncoding> Aggregation for DiscreteLog<G> {
    type Params = Params<G>;
    type DecryptorKey = (Vec<G::Scalar>, G::Scalar);
    type ClientKey = ClientKey<G>;
    type Encoding = Encoding<G>;
    type Proof = Proof<G>;
    type PartialOutput = PartialOutput<G>;

    fn setup<R: RngCore + CryptoRng>(
        num_clients: usize,
        length: usize,
        rng: &mut R,
    ) -> (Self::Params, Self::DecryptorKey, Vec<Self::ClientKey>) {
        let g = G::generator();
        let h = G::random(&mut *rng); // TODO: generate correctly
        let secret_keys: Vec<_> = (0..=length).map(|_| G::Scalar::random(&mut *rng)).collect();
        let pks: Vec<_> = secret_keys.iter().map(|ski| g * ski).collect();

        let mut client_keys = Vec::with_capacity(num_clients);
        let mut share = G::Scalar::ZERO;
        for _ in 0..num_clients {
            let c_share = G::Scalar::random(&mut *rng);
            share += c_share;
            client_keys.push(ClientKey {
                g,
                h,
                pks: pks.clone(),
                secret: c_share,
            });
        }

        let params = Params {
            g,
            h,
            pks,
            client_key_comms: client_keys
                .iter()
                .map(|ck| h * ck.secret)
                .collect::<Vec<G>>(),
        };

        (params, (secret_keys, share), client_keys)
    }

    fn encode<R: RngCore + CryptoRng>(
        key: &Self::ClientKey,
        val: &[u32],
        rng: &mut R,
    ) -> Result<(Self::Encoding, Self::Proof)> {
        assert!(
            val.iter().all(|v| *v == 0 || *v == 1),
            "Only support inputs of 0 or 1"
        );
        assert!(val.len() == 1, "TODO: support multiple inputs");
        assert_eq!(key.pks.len() - 1, val.len());
        let g = G::generator();

        // Compute input encoding (ElGamal ciphertext)
        let r = G::Scalar::random(&mut *rng);
        let encoding = Encoding {
            rand: g * r,
            secret: key.pks[0] * r + g * key.secret,
            vals: val
                .iter()
                .enumerate()
                .map(|(i, v)| key.pks[i + 1] * r + g * G::Scalar::from(*v as u64))
                .collect::<Vec<_>>(),
        };

        // Prove ciphertext is well-formed using the new proof system
        let proof = Self::create_proof(key, r, val, &encoding, rng);
        Ok((encoding, proof))
    }

    fn verify_encodings(
        params: &Self::Params,
        client_indices: Option<&[u32]>,
        encodings: &[Self::Encoding],
        proofs: &[Self::Proof],
    ) -> Result<()> {
        assert!(encodings.len() == proofs.len());
        match client_indices {
            Some(indices) => {
                // TODO: Batch verification
                assert!(indices.len() == encodings.len());
                for ((encoding, proof), &client_index) in
                    encodings.iter().zip(proofs.iter()).zip(indices.iter())
                {
                    if !Self::verify_proof(params, client_index, encoding, &proof) {
                        return Err(anyhow!(
                            "Proof verification failed for client {}",
                            client_index
                        ));
                    }
                }
            }
            None => {
                // If `client_indices` is `None`, we assume that the encodings are in the same order
                // as the client keys
                for (i, (encoding, proof)) in encodings.iter().zip(proofs.iter()).enumerate() {
                    if !Self::verify_proof(params, i as u32, encoding, &proof) {
                        return Err(anyhow!("Proof verification failed for client {}", i));
                    }
                }
            }
        }
        Ok(())
    }

    fn aggregate(_params: &Self::Params, encodings: &[Self::Encoding]) -> Result<Self::Encoding> {
        let one = G::identity();
        let mut agg = Encoding {
            rand: one,
            secret: one,
            vals: vec![one; encodings[0].vals.len()],
        };

        for enc in encodings {
            agg.rand += enc.rand;
            agg.secret += enc.secret;
            agg.vals
                .iter_mut()
                .zip(enc.vals.iter())
                .for_each(|(a, e)| *a += e);
        }
        Ok(agg)
    }

    fn decode(key: &Self::DecryptorKey, aggregate: Self::Encoding) -> Result<Self::PartialOutput> {
        let g = G::generator();
        let c_lifted_share = aggregate.secret - aggregate.rand * key.0[0];
        if c_lifted_share == g * key.1 {
            Ok(PartialOutput {
                vals: aggregate
                    .vals
                    .into_iter()
                    .enumerate()
                    .map(|(i, x)| x - aggregate.rand * key.0[i + 1])
                    .collect::<Vec<_>>(),
            })
        } else {
            Err(anyhow!("Verification failure"))
        }
    }

    fn post_process(
        params: &Self::Params,
        partial_outputs: Self::PartialOutput,
    ) -> Result<Vec<u32>> {
        let g = G::generator();
        let mut results = Vec::with_capacity(partial_outputs.vals.len());

        for output in partial_outputs.vals {
            // Bruteforce discrete log
            // TODO: use a more efficient method
            let mut guess = G::Scalar::ZERO;
            for _ in 0..=Self::num_clients(params) {
                if g * guess == output {
                    results.push(u32::from_le_bytes(
                        guess.to_repr().as_ref()[0..4].try_into().unwrap(),
                    ));
                    break;
                }
                guess += G::Scalar::ONE;
            }
        }

        Ok(results)
    }

    fn num_clients(params: &Self::Params) -> usize {
        params.client_key_comms.len()
    }

    fn length(params: &Self::Params) -> usize {
        params.pks.len() - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use curve25519_dalek::RistrettoPoint;
    use rand::rngs::OsRng;

    type G = RistrettoPoint;
    type Agg = DiscreteLog<G>;

    #[test]
    fn basic_serialization() {
        let num_clients = 1;
        let length = 1;
        let (params, sk, cks) = Agg::setup(num_clients, length, &mut OsRng);

        let params_bytes = params.to_bytes();
        let new_params = <Agg as Aggregation>::Params::from_bytes(&params_bytes).unwrap();
        assert_eq!(params, new_params);

        let ck_bytes = cks[0].to_bytes();
        let new_ck = <Agg as Aggregation>::ClientKey::from_bytes(&ck_bytes).unwrap();
        assert_eq!(cks[0], new_ck);

        let (encoding, proof) = Agg::encode(&cks[0], &[1], &mut OsRng).unwrap();

        let enc_bytes = encoding.to_bytes();
        let new_enc = <Agg as Aggregation>::Encoding::from_bytes(&enc_bytes).unwrap();
        assert_eq!(encoding, new_enc);

        let proof_bytes = proof.to_bytes();
        let new_proof = <Agg as Aggregation>::Proof::from_bytes(&proof_bytes).unwrap();
        assert_eq!(proof, new_proof);

        let enc = &[encoding];
        Agg::verify_encodings(&params, None, enc, &[proof]).unwrap();
        let agg = Agg::aggregate(&params, enc).unwrap();
        let partial_results = Agg::decode(&sk, agg).unwrap();

        let partial_result_bytes = partial_results.to_bytes();
        let new_partial_results =
            <Agg as Aggregation>::PartialOutput::from_bytes(&partial_result_bytes).unwrap();
        assert_eq!(partial_results, new_partial_results);

        let results = Agg::post_process(&params, partial_results).unwrap();
        assert_eq!(results[0], 1);
    }

    #[test]
    fn proof_3correctness() {
        // Test with multiple clients and random inputs
        let num_clients = 5;
        let length = 1;
        let (params, _sk, cks) = Agg::setup(num_clients, length, &mut OsRng);

        // Test both 0 and 1 inputs
        let test_inputs = vec![0u32, 1u32];

        for input in test_inputs {
            for client_idx in 0..num_clients {
                let r = <G as Group>::Scalar::random(&mut OsRng);
                let encoding = Encoding {
                    rand: params.g * r,
                    secret: params.pks[0] * r + params.g * cks[client_idx].secret,
                    vals: vec![
                        params.pks[1] * r + params.g * <G as Group>::Scalar::from(input as u64),
                    ],
                };
                let proof = Agg::create_proof(&cks[client_idx], r, &[input], &encoding, &mut OsRng);

                // Verify valid proof
                assert!(
                    Agg::verify_proof(&params, client_idx as u32, &encoding, &proof),
                    "Valid proof should pass verification for input {} from client {}",
                    input,
                    client_idx
                );
            }
        }
    }

    #[test]
    fn proof_soundness_rejects_tampered_data() {
        let num_clients = 3;
        let length = 1;
        let (params, _sk, cks) = Agg::setup(num_clients, length, &mut OsRng);

        // Create a valid proof first
        let input = vec![1u32];
        let r = <G as Group>::Scalar::random(&mut OsRng);
        let encoding = Encoding {
            rand: params.g * r,
            secret: params.pks[0] * r + params.g * cks[0].secret,
            vals: input
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    params.pks[i + 1] * r + params.g * <G as Group>::Scalar::from(*v as u64)
                })
                .collect(),
        };
        let proof = Agg::create_proof(&cks[0], r, &input, &encoding, &mut OsRng);

        // Verify the original proof is valid
        assert!(
            Agg::verify_proof(&params, 0, &encoding, &proof),
            "Original proof should be valid"
        );

        // Test 1: Tamper with encoding.rand
        let mut bad_encoding = encoding.clone();
        bad_encoding.rand = params.g * <G as Group>::Scalar::random(&mut OsRng);
        assert!(
            !Agg::verify_proof(&params, 0, &bad_encoding, &proof),
            "Proof should be rejected when encoding.rand is tampered"
        );

        // Test 2: Tamper with encoding.secret
        let mut bad_encoding = encoding.clone();
        bad_encoding.secret = params.g * <G as Group>::Scalar::random(&mut OsRng);
        assert!(
            !Agg::verify_proof(&params, 0, &bad_encoding, &proof),
            "Proof should be rejected when encoding.secret is tampered"
        );

        // Test 3: Tamper with encoding.vals
        let mut bad_encoding = encoding.clone();
        bad_encoding.vals[0] = params.g * <G as Group>::Scalar::random(&mut OsRng);
        assert!(
            !Agg::verify_proof(&params, 0, &bad_encoding, &proof),
            "Proof should be rejected when encoding.vals is tampered"
        );

        // Test 4: Tamper with proof.response_r
        let mut bad_proof = proof.clone();
        bad_proof.response_r = <G as Group>::Scalar::random(&mut OsRng);
        assert!(
            !Agg::verify_proof(&params, 0, &encoding, &bad_proof),
            "Proof should be rejected when response_r is tampered"
        );

        // Test 5: Tamper with proof.response_s
        let mut bad_proof = proof.clone();
        bad_proof.response_s = <G as Group>::Scalar::random(&mut OsRng);
        assert!(
            !Agg::verify_proof(&params, 0, &encoding, &bad_proof),
            "Proof should be rejected when response_s is tampered"
        );

        // Test 6: Tamper with proof.response_x0
        let mut bad_proof = proof.clone();
        bad_proof.response_x0[0] = <G as Group>::Scalar::random(&mut OsRng);
        assert!(
            !Agg::verify_proof(&params, 0, &encoding, &bad_proof),
            "Proof should be rejected when response_x0 is tampered"
        );

        // Test 7: Tamper with proof.response_x1
        let mut bad_proof = proof.clone();
        bad_proof.response_x1[0] = <G as Group>::Scalar::random(&mut OsRng);
        assert!(
            !Agg::verify_proof(&params, 0, &encoding, &bad_proof),
            "Proof should be rejected when response_x1 is tampered"
        );

        // Test 8: Tamper with proof.challenge_x
        let mut bad_proof = proof.clone();
        bad_proof.challenge_x[0] = <G as Group>::Scalar::random(&mut OsRng);
        assert!(
            !Agg::verify_proof(&params, 0, &encoding, &bad_proof),
            "Proof should be rejected when challenge_x is tampered"
        );

        // Test 9: Tamper with proof commitments
        let mut bad_proof = proof.clone();
        bad_proof.comm_g_r = params.g * <G as Group>::Scalar::random(&mut OsRng);
        assert!(
            !Agg::verify_proof(&params, 0, &encoding, &bad_proof),
            "Proof should be rejected when comm_g_r is tampered"
        );

        // Test 10: Tamper with proof.comm_g_x0
        let mut bad_proof = proof.clone();
        bad_proof.comm_g_x0[0] = params.g * <G as Group>::Scalar::random(&mut OsRng);
        assert!(
            !Agg::verify_proof(&params, 0, &encoding, &bad_proof),
            "Proof should be rejected when comm_g_x0 is tampered"
        );

        // Test 11: Tamper with proof.comm_g_x1
        let mut bad_proof = proof.clone();
        bad_proof.comm_g_x1[0] = params.g * <G as Group>::Scalar::random(&mut OsRng);
        assert!(
            !Agg::verify_proof(&params, 0, &encoding, &bad_proof),
            "Proof should be rejected when comm_g_x1 is tampered"
        );
    }

    #[test]
    fn proof_soundness_rejects_wrong_client_index() {
        let num_clients = 3;
        let length = 1;
        let (params, _sk, cks) = Agg::setup(num_clients, length, &mut OsRng);

        // Create proof for client 0
        let input = vec![0u32];
        let r = <G as Group>::Scalar::random(&mut OsRng);
        let encoding = Encoding {
            rand: params.g * r,
            secret: params.pks[0] * r + params.g * cks[0].secret,
            vals: input
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    params.pks[i + 1] * r + params.g * <G as Group>::Scalar::from(*v as u64)
                })
                .collect(),
        };
        let proof = Agg::create_proof(&cks[0], r, &input, &encoding, &mut OsRng);

        // Verify with correct client index
        assert!(
            Agg::verify_proof(&params, 0, &encoding, &proof),
            "Proof should be valid with correct client index"
        );

        // Verify with wrong client index
        assert!(
            !Agg::verify_proof(&params, 1, &encoding, &proof),
            "Proof should be rejected with wrong client index"
        );
        assert!(
            !Agg::verify_proof(&params, 2, &encoding, &proof),
            "Proof should be rejected with wrong client index"
        );
    }

    #[test]
    fn proof_correctness_with_multiple_inputs() {
        // Test with multiple input bits (when supported)
        let num_clients = 2;
        let length = 2; // Multiple inputs
        let (params, _sk, cks) = Agg::setup(num_clients, length, &mut OsRng);

        // Test different input combinations
        let test_inputs = vec![
            vec![0u32, 0u32],
            vec![0u32, 1u32],
            vec![1u32, 0u32],
            vec![1u32, 1u32],
        ];

        for input in test_inputs {
            for client_idx in 0..num_clients {
                let r = <G as Group>::Scalar::random(&mut OsRng);
                let encoding = Encoding {
                    rand: params.g * r,
                    secret: params.pks[0] * r + params.g * cks[client_idx].secret,
                    vals: input
                        .iter()
                        .enumerate()
                        .map(|(i, v)| {
                            params.pks[i + 1] * r + params.g * <G as Group>::Scalar::from(*v as u64)
                        })
                        .collect(),
                };
                let proof = Agg::create_proof(&cks[client_idx], r, &input, &encoding, &mut OsRng);

                // Verify valid proof
                assert!(
                    Agg::verify_proof(&params, client_idx as u32, &encoding, &proof),
                    "Valid proof should pass verification for input {:?} from client {}",
                    input,
                    client_idx
                );
            }
        }
    }

    #[test]
    fn proof_size_scales_with_length() {
        // Expected proof sizes in terms of group elements
        // Each group element is 32 bytes, each scalar is 32 bytes
        let expected_group_elements = vec![
            (1, 13),
            (2, 20),
            (4, 34),
            (8, 62),
            (16, 118),
        ];

        let num_clients = 1;
        let group_element_size = 32; // RistrettoPoint is 32 bytes

        for (length, expected_elements) in expected_group_elements {
            let (params, _sk, cks) = Agg::setup(num_clients, length, &mut OsRng);
            
            // Create a test input with all zeros
            let input = vec![0u32; length];
            let r = <G as Group>::Scalar::random(&mut OsRng);
            let encoding = Encoding {
                rand: params.g * r,
                secret: params.pks[0] * r + params.g * cks[0].secret,
                vals: input
                    .iter()
                    .enumerate()
                    .map(|(i, v)| {
                        params.pks[i + 1] * r + params.g * <G as Group>::Scalar::from(*v as u64)
                    })
                    .collect(),
            };
            let proof = Agg::create_proof(&cks[0], r, &input, &encoding, &mut OsRng);
            
            // Serialize the proof and check its size
            let proof_bytes = proof.to_bytes();
            let actual_size = proof_bytes.len();
            let actual_elements = actual_size / group_element_size;
            
            assert_eq!(
                actual_elements, expected_elements,
                "Proof size for length {} should be {} group elements ({} bytes), got {} group elements ({} bytes)",
                length, expected_elements, expected_elements * group_element_size, actual_elements, actual_size
            );
            
            // Verify the proof is valid
            assert!(
                Agg::verify_proof(&params, 0, &encoding, &proof),
                "Proof should be valid for length {}",
                length
            );
        }
    }
}
