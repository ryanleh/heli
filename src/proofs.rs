use crate::{
    agg_only_enc::{Ciphertext, EvalKey},
    crypto::{G, KHPRF, Scalar},
};

use anyhow::Result;
use curve25519_dalek::traits::MultiscalarMul;
use group::Group;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use tari_bulletproofs_plus::{
    commitment_opening::CommitmentOpening,
    generators::pedersen_gens::{ExtensionDegree, PedersenGens},
    protocols::scalar_protocol::ScalarProtocol,
    range_parameters::RangeParameters,
    range_proof::VerifyAction,
    range_statement::RangeStatement,
    range_witness::RangeWitness,
    ristretto::RistrettoRangeProof,
};

// TODO: Stuff will need to change for the range proof

/// Prover and verifier keys
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProverKey {
    Binary { g_comm: G },                  // Schnorr proof
    Range { g_comm: G, bitlength: usize }, // Bulletproof proof
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum VerifierKey {
    Binary {
        g_comm: G,
        key_commitments: Vec<G>,
    },
    Range {
        g_comm: G,
        key_commitments: Vec<G>,
        bitlength: usize,
    },
}

/// Sigma protocol for proving ciphertext well-formedness with binary inputs.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BinaryProof {
    /// Commitments for inputs on both branches.
    pub(super) g_x0: Vec<G>,
    pub(super) g_x1: Vec<G>,
    /// Commitments for DLEQ claim
    pub(super) hash_k: Vec<G>,
    pub(super) g_comm_k: G,

    /// Challenges for x=0 branch
    pub(crate) challenges_x0: Vec<Scalar>, // x=0 branch

    /// Responses for proving knowledge of x=0 branch.
    pub(super) x0: Vec<Scalar>,
    /// Responses for proving knowledge of x=1 branch.
    pub(super) x1: Vec<Scalar>,
    /// Response for proving knowledge of k.
    pub(super) k: Scalar,
}

/// Sigma protocol + Bulletproof for proving ciphertext well-formedness
/// with b-bounded inputs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RangeProof { 
    /// Commitments for DLEQ claim
    pub(super) g_comm_k: G,
    // Bulletproof commitments
    pub(super) range_comms: Vec<G>,
    // Commitments to bind the ciphertext to the bulletproof proof
    pub(super) g_x: Vec<G>,
    pub(super) g_bp_x: Vec<G>,
    // Responses
    k: Scalar,
    range_proof: RistrettoRangeProof,
    xs: Vec<Scalar>,
    bp_rs: Vec<Scalar>,
}

#[derive(Clone)]
pub enum Proof {
    Binary(BinaryProof),
    Range(RangeProof),
}

impl RangeProof {
    fn get_bp_params(bitlength: usize, h: G, num_inputs: usize) -> Result<RangeParameters<G>> {
        // Initialize generators. This library denotes the generator `g` as `h` and vv.
        let generators = PedersenGens::<G> {
            h_base: G::generator(),
            h_base_compressed: G::generator().compress(),
            g_base_vec: vec![h; 1],
            g_base_compressed_vec: vec![h.compress(); 1],
            extension_degree: ExtensionDegree::DefaultPedersen,
        };
        RangeParameters::init(bitlength, num_inputs, generators)
            .map_err(|e| anyhow::anyhow!("Failed to generate proof parameters: {}", e))
    }

    fn prove_bulletproof<R: RngCore + CryptoRng>(
        bitlength: usize,
        h: G,
        input: &[Scalar],
        rng: &mut R,
    ) -> Result<(Vec<G>, Vec<Scalar>, RistrettoRangeProof)> {
        let params = Self::get_bp_params(bitlength, h, input.len())?;

        // Create witness data
        let mut commitments = Vec::with_capacity(input.len());
        let mut rands = Vec::with_capacity(input.len());
        let mut openings = Vec::with_capacity(input.len());
        for i in 0..input.len() {
            let rand = Scalar::random_not_zero(rng);
            commitments.push(params.pc_gens().commit(&input[i], &[rand]).unwrap());
            openings.push(CommitmentOpening::new(
                u64::from_le_bytes(input[i].to_bytes()[..8].try_into().unwrap()),
                vec![rand],
            ));
            rands.push(rand);
        }
        let witness = RangeWitness::init(openings).unwrap();

        // Generate statement
        let statement =
            RangeStatement::init(params, commitments.clone(), vec![None; input.len()], None)
                .map_err(|e| anyhow::anyhow!("Failed to generate proof statement: {}", e))?;
        let mut transcript = Transcript::new(b"range_proof");

        // Create the proof
        let proof = RistrettoRangeProof::prove(&mut transcript, &statement, &witness)
            .map_err(|e| anyhow::anyhow!("Failed to generate proof: {}", e))?;

        Ok((commitments, rands, proof))
    }
}

impl Proof {
    pub fn setup(
        eval_keys: &[EvalKey],
        bitlength: usize,
        length: usize,
    ) -> (Vec<ProverKey>, VerifierKey) {
        // TODO: Generate this correctly
        let g_comm = G::from_hash(Sha3_512::new().chain_update(b"h"));
        let key_commitments = eval_keys.iter().map(|ek| g_comm * (**ek)).collect();

        // For short binary inputs (l < 8 in our experiments), the Schnorr
        // proof is slightly more efficient.
        if bitlength == 1 && length < 8 {
            unimplemented!()
            //let prover_keys = vec![ProverKey::Binary { g_comm }; eval_keys.len()];
            //let verifier_key = VerifierKey::Binary { g_comm, key_commitments };
            //(prover_keys, verifier_key)
        } else {
            let prover_keys = vec![ProverKey::Range { g_comm, bitlength }; eval_keys.len()];
            let verifier_key = VerifierKey::Range {
                g_comm,
                key_commitments,
                bitlength,
            };
            (prover_keys, verifier_key)
        }
    }

    /// Prove the following relation (informally stated) for secrets x_i and k:
    ///  1) c_0 = g^x_i * H(context || i)^k, 
    ///  2) DLEQ(g_comm^k, H(context || i)^k) 
    ///  3) x_i < bitlength
    /// 
    /// This enforces that the client's aggregation-only ciphertext is well-formed.
    pub fn prove<R: RngCore + CryptoRng>(
        pk: &ProverKey,
        ek: &EvalKey,
        context: u32,
        input: &[Scalar],
        rng: &mut R,
    ) -> Result<Proof> {
        let g = G::generator();
        
        // Claims (1) and (2) are done using standard Schnorr proofs. Claim (3) is done
        // using either OR composition for x=0 and x=1, or bulletproofs
        match pk {
            ProverKey::Binary { g_comm } => {
                // Commitments for claims (1) and (2)
                let k_rand = Scalar::random(&mut *rng);
                let hash_k = (0..input.len())
                    .map(|i| KHPRF::evaluate_context(&k_rand, context, i))
                    .collect::<Vec<_>>();
                let g_comm_k = g_comm * k_rand;

                // Commitments for claim (3)
                let mut x_rand = Vec::with_capacity(input.len()); // Randomness for real branch
                let mut g_x0 = Vec::with_capacity(input.len());
                let mut g_x1 = Vec::with_capacity(input.len());
                let mut sim_challenges = Vec::with_capacity(input.len());
                let mut sim_responses = Vec::with_capacity(input.len());

                for i in 0..input.len() {
                    // Simulated transcripts for false paths
                    let sim_challenge = Scalar::random(&mut *rng);
                    let sim_response = Scalar::random(&mut *rng);
                    sim_challenges.push(sim_challenge);
                    sim_responses.push(sim_response);

                    // Randomness for real branch
                    let rand = Scalar::random(&mut *rng);
                    x_rand.push(rand);

                    // OR composition for x=0 and x=1
                    if input[i] == Scalar::ZERO {
                        g_x0.push(g * rand); // Real
                        g_x1.push(g * sim_response - hash_k[i] * sim_challenge); // Simulated
                    } else if input[i] == Scalar::ONE {
                        g_x0.push(g * sim_response - hash_k[i] * sim_challenge); // Simulated
                        g_x1.push(g * rand); // Real
                    } else {
                        return Err(anyhow::anyhow!("Expected binary input"));
                    }
                }

                // Generate challenge
                //
                // TODO: Can probably do this without cloning
                let challenge = fiat_shamir(
                    [g, *g_comm, g_comm_k]
                        .into_iter()
                        .chain(g_x0.clone().into_iter())
                        .chain(g_x1.clone().into_iter())
                        .chain(hash_k.clone().into_iter())
                        .collect::<Vec<_>>()
                        .as_slice(),
                    [k_rand]
                        .into_iter()
                        .chain(x_rand.clone().into_iter())
                        .collect::<Vec<_>>()
                        .as_slice(),
                );

                // Generate responses
                let mut challenges_x0 = Vec::with_capacity(input.len());
                let mut responses_x0 = Vec::with_capacity(input.len());
                let mut responses_x1 = Vec::with_capacity(input.len());

                // TODO: This is not right lol 
                for i in 0..input.len() {
                    let challenge_real = challenge - sim_challenges[i];
                    if input[i] == Scalar::ZERO {
                        challenges_x0.push(challenge_real);
                        responses_x0.push(x_rand[i]);
                        responses_x1.push(sim_responses[i]);
                    } else if input[i] == Scalar::ONE {
                        // Always send the challenge for the zero branch
                        challenges_x0.push(sim_challenges[i]);
                        responses_x0.push(sim_responses[i]);
                        responses_x1.push(x_rand[i] + challenge_real);
                    } else {
                        unreachable!()
                    }
                }

                unimplemented!() // Binary proof not yet implemented
            }
            ProverKey::Range { g_comm, bitlength } => {
                // First, generate the bulletproof proof
                let (range_comms, range_rands, range_proof) =
                    RangeProof::prove_bulletproof(*bitlength, *g_comm, &input, rng)?;

                // Generate commitments for claims (1) and (2)
                let k_rand = Scalar::random(&mut *rng);
                let g_comm_k = *g_comm * k_rand;


                let hash_bases = (0..input.len())
                    .map(|i| KHPRF::compute_generator(context, i))
                    .collect::<Vec<_>>();

                // Generate commitments to bind the ciphertext to the bulletproof proof
                let x_rands = vec![Scalar::random(&mut *rng); input.len()];
                let bp_r_rands = vec![Scalar::random(&mut *rng); input.len()];
                let mut g_x = Vec::with_capacity(input.len());
                let mut g_bp_x = Vec::with_capacity(input.len());
                for i in 0..input.len() {
                    g_x.push(hash_bases[i] * k_rand + g * x_rands[i]);
                    g_bp_x.push(*g_comm * bp_r_rands[i] + g * x_rands[i]);
                }

                // Apply fiat-shamir to non-interactively generate challenge
                let challenge = fiat_shamir(
                    &[g, *g_comm, g_comm_k],
                        //.iter()
                        //.chain(hash_k.iter())
                        //.chain(g_x.iter())
                        //.chain(g_bp_x.iter())
                        //.chain(range_comms.iter())
                        //.cloned()
                        //.collect::<Vec<_>>(),
                    &[],
                );

                Ok(Proof::Range(RangeProof {
                    g_comm_k,
                    range_comms,
                    g_x,
                    g_bp_x,
                    range_proof,
                    k: k_rand + challenge * (**ek),
                    xs: x_rands
                        .iter()
                        .zip(input)
                        .map(|(r, x)| r + challenge * x)
                        .collect(),
                    bp_rs: bp_r_rands
                        .iter()
                        .zip(range_rands)
                        .map(|(r, bp_r)| r + challenge * bp_r)
                        .collect(),
                }))
            }
        }
    }

    pub fn verify(
        &self,
        vk: &VerifierKey,
        ciphertext: &Ciphertext,
        context: u32,
        proof_index: usize,
    ) -> Result<()> {
        let g = G::generator();

        // Verify the following claims:
        //  1) c_i = g^x_i * H(context || i)^k,
        //  2) DLEQ(g_comm^k, H(context || i)^k)
        //  3) x_i < bitlength
        match (self, vk) {
            (
                Proof::Binary(_proof),
                VerifierKey::Binary {
                    g_comm: _,
                    key_commitments: _,
                },
            ) => {
                unimplemented!();
            }
            (
                Proof::Range(proof),
                VerifierKey::Range {
                    g_comm,
                    key_commitments,
                    bitlength,
                },
            ) => {
                // Apply fiat-shamir to generate challenge (same as in prove)
                let challenge = fiat_shamir(
                    &[g, *g_comm, proof.g_comm_k],
                        //.iter()
                        //.chain(proof.hash_k.iter())
                        //.chain(proof.g_x.iter())
                        //.chain(proof.g_bp_x.iter())
                        //.chain(proof.range_comms.iter())
                        //.cloned()
                        //.collect::<Vec<_>>(),
                    &[],
                );

                // TODO: There's a few repeated group operations here
                for i in 0..ciphertext.len() {
                    // Check claim 1
                    let g_hash = KHPRF::compute_generator(context, i);
                    crate::check_claim!(
                        g * proof.xs[i] + g_hash * proof.k,
                        ciphertext[i] * challenge + proof.g_x[i],
                        format!("Claim 1 failed (ciphertext consistency) for slot {}", i)
                    );

                    // Check that the ciphertext is consistent with the bulletproof commitment (claim 3)
                    crate::check_claim!(
                        *g_comm * proof.bp_rs[i] + g * proof.xs[i],
                        proof.range_comms[i] * challenge + proof.g_bp_x[i],
                        format!("Claim 3 failed (bulletproof consistency) for slot {}", i)
                    );
                }

                // Check claim 2
                crate::check_claim!(
                    *g_comm * proof.k,
                    key_commitments[proof_index] * challenge + proof.g_comm_k,
                    "Claim 2 failed (DLEQ)"
                );

                // Verify bulletproof (claim 3)
                let range_params =
                    RangeProof::get_bp_params(*bitlength, *g_comm, ciphertext.len())?;
                let statement = RangeStatement::init(
                    range_params,
                    proof.range_comms.clone(),
                    vec![None; ciphertext.len()],
                    None,
                )
                .map_err(|e| anyhow::anyhow!("Failed to generate bulletproof statement: {}", e))?;
                RistrettoRangeProof::verify_batch(
                    &mut [Transcript::new(b"range_proof")],
                    &[statement],
                    &[proof.range_proof.clone()],
                    VerifyAction::VerifyOnly,
                )
                .map_err(|e| anyhow::anyhow!("Failed to verify bulletproof: {}", e))?;
                Ok(())
            }
            _ => Err(anyhow::anyhow!("Proof and key type mismatch")),
        }
    }

    pub fn batch_verify<R: RngCore + CryptoRng>(
        vk: &VerifierKey,
        ciphertexts: &[Ciphertext],
        context: u32,
        proofs: &[Proof],
        proof_indices: &[usize],
        rng: &mut R,
    ) -> Result<()> {
        let g = G::generator();

        match vk {
            VerifierKey::Binary {
                g_comm: _,
                key_commitments: _,
            } => {
                unimplemented!();
            }
            VerifierKey::Range {
                g_comm,
                key_commitments,
                bitlength,
            } => {
                // We batch by taking a random linear combination over all Schnorr claims.
                // (The range proofs are done separately.)
                //
                // Here we generate all the necessary randomness upfront.
                let num_inputs = ciphertexts[0].len();
                let num_proof_claims = 1 + 2 * num_inputs; // Claim 2 (DLEQ) + 2 claims per input (claims 1 and 3)
                let total_claims = proof_indices.len() * num_proof_claims;
                let rands: Vec<_> = (0..total_claims)
                    .map(|_| Scalar::random(&mut *rng))
                    .collect();

                // Many terms share the g, g_comm, and g_hash bases
                let mut g_scalar = Scalar::ZERO;
                let mut g_comm_scalar = Scalar::ZERO;
                let mut g_hash_scalars = vec![Scalar::ZERO; num_inputs];
                let mut scalars = Vec::new();
                let mut bases = Vec::new();

                // Helper closure to add terms to the MSM vectors
                let mut add_term = |scalar: Scalar, base: G| {
                    scalars.push(scalar);
                    bases.push(base);
                };

                let mut r_idx = 0;
                let range_params = RangeProof::get_bp_params(*bitlength, *g_comm, num_inputs)?;

                // For each proof, add the relevant terms to the final MSM computation
                for i in 0..proof_indices.len() {
                    let proof_idx = proof_indices[i];
                    let ciphertext = &ciphertexts[i];
                    let Proof::Range(proof) = &proofs[i] else {
                        return Err(anyhow::anyhow!("Proof type mismatch"));
                    };

                    // Verify the bulletproof separately
                    let statement = RangeStatement::init(
                        range_params.clone(),
                        proof.range_comms.clone(),
                        vec![None; num_inputs],
                        None,
                    )
                    .map_err(|e| anyhow::anyhow!("Failed to generate proof statement: {}", e))?;
                    RistrettoRangeProof::verify_batch(
                        &mut [Transcript::new(b"range_proof")],
                        &[statement],
                        &[proof.range_proof.clone()],
                        VerifyAction::VerifyOnly,
                    )
                    .map_err(|e| {
                        anyhow::anyhow!("Batch verification failed (range proof): {}", e)
                    })?;

                    // Apply fiat-shamir to non-interactively generate challenge
                    //
                    // TODO: Update
                    let challenge = fiat_shamir(
                        &[g, *g_comm, proof.g_comm_k],
                            //.iter()
                            //.chain(proof.hash_k.iter())
                            //.chain(proof.g_x.iter())
                            //.chain(proof.g_bp_x.iter())
                            //.chain(proof.range_comms.iter())
                            //.cloned()
                            //.collect::<Vec<_>>(),
                        &[],
                    );

                    // Check claim 2: DLEQ(g_comm^k, H(context || i)^k)
                    // g_comm * k = key_commitments[proof_index] * challenge + g_comm_k
                    g_comm_scalar += proof.k * rands[r_idx];
                    add_term(-rands[r_idx], proof.g_comm_k);
                    add_term(-challenge * rands[r_idx], key_commitments[proof_idx]);
                    r_idx += 1;

                    // Check claims 1 and 3 for each input slot
                    for j in 0..num_inputs {
                        // Check claim 1: ciphertext consistency
                        // g * xs[j] + g_hash * k = ciphertext[j] * challenge + g_x[j] + hash_k[j]
                        g_scalar += proof.xs[j] * rands[r_idx];
                        g_hash_scalars[j] += proof.k * rands[r_idx];
                        add_term(-rands[r_idx], proof.g_x[j]);
                        //add_term(-rands[r_idx], proof.hash_k[j]);
                        add_term(-challenge * rands[r_idx], ciphertext[j]);
                        r_idx += 1;

                        // Check claim 3: bulletproof consistency
                        // g_comm * bp_rs[j] + g * xs[j] = range_comms[j] * challenge + g_bp_x[j]
                        g_comm_scalar += proof.bp_rs[j] * rands[r_idx];
                        g_scalar += proof.xs[j] * rands[r_idx];
                        add_term(-rands[r_idx], proof.g_bp_x[j]);
                        add_term(-challenge * rands[r_idx], proof.range_comms[j]);
                        r_idx += 1;
                    }
                }

                // Add the shared basis terms
                scalars.push(g_scalar);
                scalars.push(g_comm_scalar);
                scalars.extend(g_hash_scalars);
                bases.push(g);
                bases.push(*g_comm);
                bases.extend((0..num_inputs).map(|i| KHPRF::compute_generator(context, i)));

                // If all proofs are valid, the MSM should equal the identity
                if G::multiscalar_mul(&scalars, &bases) == G::identity() {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(
                        "Batch verification failed (ciphertext consistency)"
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agg_only_enc::AggOnlyEnc;
    use rand::Rng;
    use rand::rngs::OsRng;

    #[test]
    fn proof_correctness() {
        let mut rng = OsRng;
        const CONTEXT: u32 = 42;

        // Test configurations: (bitlength, length)
        let configs = vec![
            (8, 4),
            (4, 2),
            // (1, 4), // Binary not yet implemented
        ];

        for (config_idx, (bitlength, length)) in configs.iter().enumerate() {
            // Setup
            let (_, eval_keys) = AggOnlyEnc::setup(*length, &mut rng);
            let (prover_keys, verifier_key) = Proof::setup(&eval_keys, *bitlength, *length);

            // Generate a ciphertext and proof
            let input: Vec<Scalar> = (0..*length)
                .map(|_| Scalar::from(rng.gen_range(0u64..(1u64 << bitlength))))
                .collect();
            let ciphertext = AggOnlyEnc::encrypt(&eval_keys[0], CONTEXT, &input);
            let proof =
                Proof::prove(&prover_keys[0], &eval_keys[0], CONTEXT, &input, &mut rng).unwrap();

            // Test individual verification
            assert!(
                proof.verify(&verifier_key, &ciphertext, CONTEXT, 0).is_ok(),
                "Individual proof verification failed for config {}",
                config_idx
            );

            // Test batch verification
            assert!(
                Proof::batch_verify(
                    &verifier_key,
                    &[ciphertext.clone()],
                    CONTEXT,
                    &[proof.clone()],
                    &[0],
                    &mut rng
                )
                .is_ok(),
                "Batch proof verification failed for config {}",
                config_idx
            );
        }
    }

    #[test]
    fn proof_soundness_tampering() {
        let mut rng = OsRng;
        const CONTEXT: u32 = 42;

        // Test configurations: (bitlength, length)
        let configs = vec![
            (8, 4),
            // (1, 4), // Binary not yet implemented
        ];

        for (config_idx, (bitlength, length)) in configs.iter().enumerate() {
            // Setup
            let (_, eval_keys) = AggOnlyEnc::setup(*length, &mut rng);
            let (prover_keys, verifier_key) = Proof::setup(&eval_keys, *bitlength, *length);

            // Generate a valid ciphertext and proof
            let input: Vec<Scalar> = (0..*length)
                .map(|_| Scalar::from(rng.gen_range(0u64..(1u64 << bitlength))))
                .collect();
            let ciphertext = AggOnlyEnc::encrypt(&eval_keys[0], CONTEXT, &input);
            let proof =
                Proof::prove(&prover_keys[0], &eval_keys[0], CONTEXT, &input, &mut rng).unwrap();

            // Verify the original proof is valid with both methods
            assert!(proof.verify(&verifier_key, &ciphertext, CONTEXT, 0).is_ok());
            assert!(
                Proof::batch_verify(
                    &verifier_key,
                    &[ciphertext.clone()],
                    CONTEXT,
                    &[proof.clone()],
                    &[0],
                    &mut rng
                )
                .is_ok()
            );

            // Try tampering the ciphertext by encrypting with wrong input
            // This tests that the proof correctly verifies ciphertext matches the proven input
            let mut bad_input = input.clone();
            bad_input[0] =
                Scalar::from(rng.gen_range((1u64 << bitlength)..(1u64 << (bitlength + 1))));
            let bad_ciphertext = AggOnlyEnc::encrypt(&eval_keys[0], CONTEXT, &bad_input);
            assert!(
                proof
                    .verify(&verifier_key, &bad_ciphertext, CONTEXT, 0)
                    .is_err(),
                "Tampered ciphertext accepted for config {}",
                config_idx
            );
            assert!(
                Proof::batch_verify(
                    &verifier_key,
                    &[bad_ciphertext.clone()],
                    CONTEXT,
                    &[proof.clone()],
                    &[0],
                    &mut rng
                )
                .is_err(),
                "Tampered ciphertext accepted in batch for config {}",
                config_idx
            );

            // Tampering any slot should be detected
            for i in 0..*length {
                let mut bad_input = input.clone();
                bad_input[i] =
                    Scalar::from(rng.gen_range((1u64 << bitlength)..(1u64 << (bitlength + 1))));
                let bad_ciphertext = AggOnlyEnc::encrypt(&eval_keys[0], CONTEXT, &bad_input);
                assert!(
                    proof
                        .verify(&verifier_key, &bad_ciphertext, CONTEXT, 0)
                        .is_err(),
                    "Tampered ciphertext slot {} accepted for config {}",
                    i,
                    config_idx
                );
                assert!(
                    Proof::batch_verify(
                        &verifier_key,
                        &[bad_ciphertext.clone()],
                        CONTEXT,
                        &[proof.clone()],
                        &[0],
                        &mut rng
                    )
                    .is_err(),
                    "Tampered ciphertext slot {} accepted in batch for config {}",
                    i,
                    config_idx
                );
            }

            // Try tampering the proof (only public fields)
            if let Proof::Range(_) = &proof {
                let mut bad_proof = proof.clone();
                if let Proof::Range(bad_range_proof) = &mut bad_proof {
                    // Tamper with g_comm_k
                    bad_range_proof.g_comm_k = G::generator() * Scalar::random(&mut rng);
                    assert!(
                        bad_proof
                            .verify(&verifier_key, &ciphertext, CONTEXT, 0)
                            .is_err(),
                        "Tampered g_comm_k accepted for config {}",
                        config_idx
                    );
                    assert!(
                        Proof::batch_verify(
                            &verifier_key,
                            &[ciphertext.clone()],
                            CONTEXT,
                            &[bad_proof.clone()],
                            &[0],
                            &mut rng
                        )
                        .is_err(),
                        "Tampered g_comm_k accepted in batch for config {}",
                        config_idx
                    );
                }

//                // Tamper with hash_k
//                let mut bad_proof = proof.clone();
//                if let Proof::Range(bad_range_proof) = &mut bad_proof {
//                    bad_range_proof.hash_k[0] = G::generator() * Scalar::random(&mut rng);
//                    assert!(
//                        bad_proof
//                            .verify(&verifier_key, &ciphertext, CONTEXT, 0)
//                            .is_err(),
//                        "Tampered hash_k accepted for config {}",
//                        config_idx
//                    );
//                    assert!(
//                        Proof::batch_verify(
//                            &verifier_key,
//                            &[ciphertext.clone()],
//                            CONTEXT,
//                            &[bad_proof.clone()],
//                            &[0],
//                            &mut rng
//                        )
//                        .is_err(),
//                        "Tampered hash_k accepted in batch for config {}",
//                        config_idx
//                    );
//                }

                // Tamper with g_x
                let mut bad_proof = proof.clone();
                if let Proof::Range(bad_range_proof) = &mut bad_proof {
                    bad_range_proof.g_x[0] = G::generator() * Scalar::random(&mut rng);
                    assert!(
                        bad_proof
                            .verify(&verifier_key, &ciphertext, CONTEXT, 0)
                            .is_err(),
                        "Tampered g_x accepted for config {}",
                        config_idx
                    );
                    assert!(
                        Proof::batch_verify(
                            &verifier_key,
                            &[ciphertext.clone()],
                            CONTEXT,
                            &[bad_proof.clone()],
                            &[0],
                            &mut rng
                        )
                        .is_err(),
                        "Tampered g_x accepted in batch for config {}",
                        config_idx
                    );
                }

                // Tamper with g_bp_x
                let mut bad_proof = proof.clone();
                if let Proof::Range(bad_range_proof) = &mut bad_proof {
                    bad_range_proof.g_bp_x[0] = G::generator() * Scalar::random(&mut rng);
                    assert!(
                        bad_proof
                            .verify(&verifier_key, &ciphertext, CONTEXT, 0)
                            .is_err(),
                        "Tampered g_bp_x accepted for config {}",
                        config_idx
                    );
                    assert!(
                        Proof::batch_verify(
                            &verifier_key,
                            &[ciphertext.clone()],
                            CONTEXT,
                            &[bad_proof.clone()],
                            &[0],
                            &mut rng
                        )
                        .is_err(),
                        "Tampered g_bp_x accepted in batch for config {}",
                        config_idx
                    );
                }

                // Tamper with range_comms
                let mut bad_proof = proof.clone();
                if let Proof::Range(bad_range_proof) = &mut bad_proof {
                    bad_range_proof.range_comms[0] = G::generator() * Scalar::random(&mut rng);
                    assert!(
                        bad_proof
                            .verify(&verifier_key, &ciphertext, CONTEXT, 0)
                            .is_err(),
                        "Tampered range_comms accepted for config {}",
                        config_idx
                    );
                    assert!(
                        Proof::batch_verify(
                            &verifier_key,
                            &[ciphertext.clone()],
                            CONTEXT,
                            &[bad_proof.clone()],
                            &[0],
                            &mut rng
                        )
                        .is_err(),
                        "Tampered range_comms accepted in batch for config {}",
                        config_idx
                    );
                }
            }
        }
    }

    #[test]
    fn proof_soundness_wrong_client() {
        let mut rng = OsRng;
        const CONTEXT: u32 = 42;

        // Test configurations: (bitlength, length)
        let configs = vec![
            (8, 4),
            // (1, 4), // Binary not yet implemented
        ];

        for (config_idx, (bitlength, length)) in configs.iter().enumerate() {
            // Setup with multiple clients
            let num_clients = 3;
            let (_, eval_keys) = AggOnlyEnc::setup(*length, &mut rng);
            let (prover_keys, verifier_key) = Proof::setup(&eval_keys, *bitlength, *length);

            // Generate a valid ciphertext and proof for client 0
            let input: Vec<Scalar> = (0..*length)
                .map(|_| Scalar::from(rng.gen_range(0u64..(1u64 << bitlength))))
                .collect();
            let ciphertext = AggOnlyEnc::encrypt(&eval_keys[0], CONTEXT, &input);
            let proof =
                Proof::prove(&prover_keys[0], &eval_keys[0], CONTEXT, &input, &mut rng).unwrap();

            // Verify with correct client index using both methods
            assert!(proof.verify(&verifier_key, &ciphertext, CONTEXT, 0).is_ok());
            assert!(
                Proof::batch_verify(
                    &verifier_key,
                    &[ciphertext.clone()],
                    CONTEXT,
                    &[proof.clone()],
                    &[0],
                    &mut rng
                )
                .is_ok()
            );

            // Verify with wrong client index using both methods
            for wrong_idx in 1..num_clients {
                assert!(
                    proof
                        .verify(&verifier_key, &ciphertext, CONTEXT, wrong_idx)
                        .is_err(),
                    "Wrong client index {} accepted for config {}",
                    wrong_idx,
                    config_idx
                );
                assert!(
                    Proof::batch_verify(
                        &verifier_key,
                        &[ciphertext.clone()],
                        CONTEXT,
                        &[proof.clone()],
                        &[wrong_idx],
                        &mut rng
                    )
                    .is_err(),
                    "Wrong client index {} accepted in batch for config {}",
                    wrong_idx,
                    config_idx
                );
            }
        }
    }
}

/// Apply fiat-shamir to a list of group and scalarelements
fn fiat_shamir(elements: &[G], scalars: &[Scalar]) -> Scalar {
    let mut hasher = Sha3_512::new();
    for g in elements {
        hasher.update(g.compress().to_bytes().as_ref());
    }
    for s in scalars {
        hasher.update(s.to_bytes().as_ref());
    }
    Scalar::from_hash(hasher)
}

// Helper macro for verifying claims
#[macro_export]
macro_rules! check_claim {
    ($left:expr, $right:expr, $msg:expr) => {
        if $left != $right {
            return Err(anyhow::anyhow!($msg));
        }
    };
}
