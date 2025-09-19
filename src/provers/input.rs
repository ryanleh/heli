use crate::{
    check_claim,
    agg_only_enc::EvalKey,
    crypto::{G, Scalar, ElGamalPublicKey, ElGamalCiphertext},
};
use super::{Prover, fiat_shamir};

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

/// Prover and verifier key for proving well-formedness of inputs.
/// * Binary = Schnorr,
/// * Range = Bulletproof.
/// 
/// For short binary inputs (l < 8 in our experiments), the Schnorr
/// proof is slightly more efficient.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputProofKey {
    Binary { enc_pk: ElGamalPublicKey }, // Schnorr proof
    Range { bitlength: usize, enc_pk: ElGamalPublicKey, g_comm: G, } // Bulletproof proof
}

/// Schnorr proof proving knowledge of x = 0 OR x = 1 for the given ElGamal
/// ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryProof {
    /// Commitments for inputs on x=0 branch.
    pub(super) g_x0: Vec<G>,
    pub(super) pk_x0: Vec<G>,
    /// Commitments for inputs on x=1 branch.
    pub(super) g_x1: Vec<G>,
    pub(super) pk_x1: Vec<G>,
    /// Challenges for x = 0 branch.
    pub(crate) challenges_x: Vec<Scalar>,
    /// Responses for proving knowledge of x=0 branch.
    pub(super) x0: Vec<Scalar>,
    /// Responses for proving knowledge of x=1 branch.
    pub(super) x1: Vec<Scalar>,
}

/// Bulletproof proof proving knowledge of x in [0, 2^bitlength) for the given
/// ElGamal ciphertext.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeProof { 
    // Bulletproof commitment
    range_comms: Vec<G>,
    // Commitments to bind the ciphertext to the bulletproof proof
    comm_r: G,
    comm_x: Vec<G>,
    comm_bp_x: Vec<G>,
    // Responses
    range_proof: RistrettoRangeProof,
    r: Scalar,
    xs: Vec<Scalar>,
    bp_rs: Vec<Scalar>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum InputProof {
    Binary(BinaryProof),
    Range(RangeProof),
}

impl InputProof {
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
            commitments.push(
                params
                    .pc_gens()
                    .commit(&input[i], &[rand])
                    .unwrap(),
            );
            openings.push(CommitmentOpening::new(
                u64::from_le_bytes(input[i].to_bytes()[..8].try_into().unwrap()),
                vec![rand]
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

impl Prover for InputProof {
    type ProverKey = InputProofKey;
    type VerifierKey = InputProofKey;
    type Proof = InputProof;

    // TODO: Not sure if we want this
    fn setup(eval_keys: &[EvalKey], bitlength: usize) -> (Vec<Self::ProverKey>, Self::VerifierKey) {
        let g_comm = G::from_hash(Sha3_512::new().chain_update(b"h"));
        
        // These ranges tested impirically–might differ from machine to machine
        let key = match bitlength == 1 && eval_keys[0].enc_pk.len() < 8 {
            true => InputProofKey::Binary { enc_pk: eval_keys[0].enc_pk.clone() },
            false => InputProofKey::Range { bitlength, enc_pk: eval_keys[0].enc_pk.clone(), g_comm },
        };
        (vec![key.clone(); eval_keys.len()], key)
    }

    /// Prove that inputs are bounded integers
    fn prove<R: RngCore + CryptoRng>(
        pk: &Self::ProverKey,
        _ek: &EvalKey,
        _context: u64,
        r: Scalar,
        input: &[Scalar],
        rng: &mut R,
    ) -> Result<Self::Proof> {
        let g = G::generator();

        match pk {
            // TODO: Naming conventions here need to be improved
            InputProofKey::Binary { enc_pk } => {
                // Generate commitments (and simulated transcripts) for claim 4
                let mut r_x_rand = Vec::with_capacity(input.len()); // Randomness for real branch
                let mut comm_g_x0 = Vec::with_capacity(input.len());
                let mut comm_pk_x0 = Vec::with_capacity(input.len());
                let mut comm_g_x1 = Vec::with_capacity(input.len());
                let mut comm_pk_x1 = Vec::with_capacity(input.len());
                let mut sim_challenges = Vec::with_capacity(input.len());
                let mut sim_responses = Vec::with_capacity(input.len());

                for i in 0..input.len() {
                    // Generate simulated transcripts for false paths
                    let challenge = Scalar::random(&mut *rng);
                    let response = Scalar::random(&mut *rng);
                    sim_challenges.push(challenge);
                    sim_responses.push(response);

                    // Generate commitments
                    let rand = Scalar::random(&mut *rng);
                    r_x_rand.push(rand);
                    
                    // TODO: Write why this is correct
                    if input[i] == Scalar::ZERO {
                        // Real
                        comm_g_x0.push(g * rand);
                        comm_pk_x0.push(enc_pk[i] * rand);

                        // Simulated
                        comm_g_x1.push(g * (response - r * challenge));
                        comm_pk_x1
                            .push(enc_pk[i] * (response - r * challenge) + g * challenge);
                    } else if input[i] == Scalar::ONE {
                        // Simulated
                        comm_g_x0.push(g * (response - r * challenge));
                        comm_pk_x0.push(enc_pk[i] * (response - r * challenge) - g * challenge);

                        // Real
                        comm_g_x1.push(g * rand);
                        comm_pk_x1.push(enc_pk[i] * rand);
                    } else {
                        panic!("Input should be 0 or 1")
                    }
                }

                // TODO: Can probably do this without cloning
                let challenge = fiat_shamir(
                    comm_g_x0.clone()
                        .into_iter()
                        .chain(comm_pk_x0.clone().into_iter())
                        .chain(comm_g_x1.clone().into_iter())
                        .chain(comm_pk_x1.clone().into_iter())
                        .collect::<Vec<_>>().as_slice(),
                    &[]
                );

                // Generate responses for claim 4
                let mut challenges_x = Vec::with_capacity(input.len());
                let mut responses_x0 = Vec::with_capacity(input.len());
                let mut responses_x1 = Vec::with_capacity(input.len());
                for i in 0..input.len() {
                    let challenge_real = challenge - sim_challenges[i];
                    // Always send the challenge for the zero branch
                    if input[i] == Scalar::ZERO {
                        challenges_x.push(challenge_real);
                        responses_x0.push(r_x_rand[i] + challenge_real * r);
                        responses_x1.push(sim_responses[i]);
                    } else if input[i] == Scalar::ONE {
                        // Always send the challenge for the zero branch
                        challenges_x.push(sim_challenges[i]);
                        responses_x0.push(sim_responses[i]);
                        responses_x1.push(r_x_rand[i] + challenge_real * r);
                    } else {
                        unreachable!()
                    }
                }

                Ok(InputProof::Binary(BinaryProof {
                    g_x0: comm_g_x0,
                    pk_x0: comm_pk_x0,
                    g_x1: comm_g_x1,
                    pk_x1: comm_pk_x1,
                    challenges_x,
                    x0: responses_x0,
                    x1: responses_x1,
                }))
            },
            InputProofKey::Range { bitlength, enc_pk, g_comm } => {
                // First, generate the bulletproof proof
                let (range_comms, range_rands, range_proof) = Self::prove_bulletproof(*bitlength, *g_comm, &input, rng)?;

                // Generate commitments to bind the ciphertext to the bulletproof proof
                let r_rand = Scalar::random(&mut *rng);
                let x_rands = vec![Scalar::random(&mut *rng); input.len()];
                let bp_r_rands = vec![Scalar::random(&mut *rng); input.len()];
                let comm_r = g * r_rand;
                let mut comm_x = Vec::with_capacity(input.len());
                let mut comm_bp_x = Vec::with_capacity(input.len());
                for i in 0..input.len() {
                    comm_x.push(enc_pk[i] * r_rand + g * x_rands[i]);
                    comm_bp_x.push(*g_comm * bp_r_rands[i] + g * x_rands[i]);
                }

                // Apply fiat-shamir to non-interactively generate challenge
                // Include the ciphertext rand in the challenge generation (like the old implementation)
                let ciphertext_rand = g * r; // This is what will be in the ciphertext
                let challenge = fiat_shamir(
                    &[g, *g_comm, ciphertext_rand]
                        .iter()
                        .chain([comm_r].iter())
                        .chain(comm_x.iter())
                        .chain(comm_bp_x.iter())
                        .chain(range_comms.iter())
                        .cloned()
                        .collect::<Vec<_>>(),
                    &[]
                );

                Ok(InputProof::Range(RangeProof {
                    range_comms,
                    comm_r,
                    comm_x,
                    comm_bp_x,
                    r: r_rand + challenge * r,
                    range_proof,
                    xs: x_rands
                        .iter()
                        .zip(input)
                        .map(|(r, x)| r + challenge * x)
                        .collect(),
                    bp_rs: bp_r_rands
                        .iter()
                        .zip(range_rands)
                        .map(|(r, x)| r + challenge * x)
                        .collect(),
                }))
            }
        }

    }

    fn verify(
        vk: &Self::VerifierKey,
        ciphertext: &ElGamalCiphertext,
        _context: u64,
        proof: &Self::Proof,
        _proof_index: usize,
    ) -> Result<()> {
        match (vk, proof) {
            (InputProofKey::Binary { enc_pk }, InputProof::Binary(binary_proof)) => {
                let g = G::generator();
                
                // Apply fiat-shamir to generate challenge
                let challenge = fiat_shamir(
                    &binary_proof.g_x0.iter()
                        .chain(binary_proof.pk_x0.iter())
                        .chain(binary_proof.g_x1.iter())
                        .chain(binary_proof.pk_x1.iter())
                        .cloned()
                        .collect::<Vec<_>>(),
                    &[]
                );

                // Check that each input slot is either 0 or 1
                // For binary inputs, we need to verify that each slot in the ciphertext
                // corresponds to either 0 or 1
                for i in 0..binary_proof.challenges_x.len() {
                    let challenge_0 = binary_proof.challenges_x[i];
                    let challenge_1 = challenge - challenge_0;

                    // X=0, check DLEQ(c_0, pk_i^r)
                    check_claim!(
                                g * binary_proof.x0[i],
                                binary_proof.g_x0[i] + ciphertext.rand * challenge_0,
                                format!("Claim failed: DLEQ(c_0, pk_{}^r) for x=0", i)
                    );
                    check_claim!(
                                enc_pk[i] * binary_proof.x0[i],
                                binary_proof.pk_x0[i] + ciphertext.slots[i] * challenge_0,
                                format!("Claim failed: DLEQ(c_0, pk_{}^r) for x=0", i)
                    );

                    // X=1, check DLEQ(c_0, pk_i^r / g)
                    check_claim!(
                                g * binary_proof.x1[i],
                                binary_proof.g_x1[i] + ciphertext.rand * challenge_1,
                                format!("Claim failed: DLEQ(c_0, pk_{}^r / g) for x=1", i)
                    );
                    check_claim!(
                                enc_pk[i] * binary_proof.x1[i],
                                binary_proof.pk_x1[i] + (ciphertext.slots[i] - g) * challenge_1,
                                format!("Claim failed: DLEQ(c_0, pk_{}^r / g) for x=1", i)
                    );
                }
                Ok(())
            },
            (InputProofKey::Range { bitlength, enc_pk, g_comm }, InputProof::Range(range_proof)) => {
                let g = G::generator();

                // Apply fiat-shamir to generate challenge (same as in prove)
                let challenge = fiat_shamir(
                    &[g, *g_comm, ciphertext.rand]
                        .iter()
                        .chain([range_proof.comm_r].iter())
                        .chain(range_proof.comm_x.iter())
                        .chain(range_proof.comm_bp_x.iter())
                        .chain(range_proof.range_comms.iter())
                        .cloned()
                        .collect::<Vec<_>>(),
                    &[]
                );

                // Check 1) c_0 = g^r
                check_claim!(
                    g * range_proof.r,
                    range_proof.comm_r + ciphertext.rand * challenge,
                    "Claim failed: c_0 = g^r"
                );

                // Verify bulletproof
                let range_params = Self::get_bp_params(*bitlength, *g_comm, ciphertext.slots.len() - 1)?;
                let statement = RangeStatement::init(
                    range_params,
                    range_proof.range_comms.clone(),
                    vec![None; ciphertext.slots.len() - 1],
                    None,
                )
                .map_err(|e| anyhow::anyhow!("Failed to generate proof statement: {}", e))?;
                RistrettoRangeProof::verify_batch(
                    &mut [Transcript::new(b"range_proof")],
                    &[statement],
                    &[range_proof.range_proof.clone()],
                    VerifyAction::VerifyOnly,
                )
                .map_err(|e| anyhow::anyhow!("Failed to verify proof: {}", e))?;

                // Check that each commitment from the range proof is consistent with the ciphertext
                for i in 0..(ciphertext.slots.len() - 1) {
                    check_claim!(
                        enc_pk[i] * range_proof.r + g * range_proof.xs[i],
                        range_proof.comm_x[i] + ciphertext.slots[i] * challenge,
                        format!("Claim failed: ciphertext consistency for slot {}", i)
                    );

                    check_claim!(
                        *g_comm * range_proof.bp_rs[i] + g * range_proof.xs[i],
                        range_proof.comm_bp_x[i] + range_proof.range_comms[i] * challenge,
                        format!("Claim failed: bulletproof consistency for slot {}", i)
                    );
                }

                Ok(())
            },
            _ => Err(anyhow::anyhow!("Proof type mismatch with verifier key"))
        }
    }

    fn batch_verify<R: RngCore + CryptoRng>(
        vk: &Self::VerifierKey,
        ciphertexts: &[ElGamalCiphertext],
        _context: u64,
        proofs: &[Self::Proof],
        proof_indices: &[usize],
        rng: &mut R,
    ) -> Result<()> {
        match vk {
            InputProofKey::Binary { enc_pk } => {
                // We batch by taking a random linear combination over all claims
                let num_inputs = ciphertexts[0].slots.len() - 1;
                let num_proof_claims = 4 * num_inputs; // 4 claims per input
                let total_claims = proof_indices.len() * num_proof_claims;
                let rands: Vec<_> = (0..total_claims)
                    .map(|_| Scalar::random(&mut *rng))
                    .collect();

                // Many terms share the g and pk bases
                let mut g_scalar = Scalar::ZERO;
                let mut pk_scalars = vec![Scalar::ZERO; enc_pk.len()];
                let mut scalars = Vec::new();
                let mut bases = Vec::new();

                // Helper closure to add terms to the MSM vectors
                let mut add_term = |scalar: Scalar, base: G| {
                    scalars.push(scalar);
                    bases.push(base);
                };

                let mut r_idx = 0;
                let g = G::generator();

                // For each proof, add the relevant terms to the final MSM computation
                for i in 0..proof_indices.len() {
                    let ciphertext = &ciphertexts[i];
                    let InputProof::Binary(proof) = &proofs[i] else {
                        return Err(anyhow::anyhow!("Proof type mismatch"));
                    };

                    let challenge = fiat_shamir(
                        &proof.g_x0.iter()
                            .chain(proof.pk_x0.iter())
                            .chain(proof.g_x1.iter())
                            .chain(proof.pk_x1.iter())
                            .cloned()
                            .collect::<Vec<_>>(),
                        &[]
                    );

                    // Check DLEQ claims for each input
                    for j in 0..num_inputs {
                        let challenge_0 = proof.challenges_x[j];
                        let challenge_1 = challenge - challenge_0;

                        // X=0, check DLEQ(c_0, pk_i^r)
                        g_scalar += proof.x0[j] * rands[r_idx];
                        add_term(-rands[r_idx], proof.g_x0[j]);
                        add_term(-challenge_0 * rands[r_idx], ciphertext.rand);
                        r_idx += 1;

                        pk_scalars[j] += proof.x0[j] * rands[r_idx];
                        add_term(-rands[r_idx], proof.pk_x0[j]);
                        add_term(-challenge_0 * rands[r_idx], ciphertext.slots[j]);
                        r_idx += 1;

                        // X=1, check DLEQ(c_0, pk_i^r / g)
                        g_scalar += proof.x1[j] * rands[r_idx];
                        add_term(-rands[r_idx], proof.g_x1[j]);
                        add_term(-challenge_1 * rands[r_idx], ciphertext.rand);
                        r_idx += 1;

                        pk_scalars[j] += proof.x1[j] * rands[r_idx];
                        add_term(-rands[r_idx], proof.pk_x1[j]);
                        add_term(-challenge_1 * rands[r_idx], ciphertext.slots[j] - g);
                        r_idx += 1;
                    }
                }
                
                // Add the shared basis terms
                scalars.push(g_scalar);
                scalars.extend(pk_scalars);
                bases.push(g);
                bases.extend_from_slice(enc_pk);

                // If all proofs are valid, the MSM should equal the identity
                if G::multiscalar_mul(&scalars, &bases) == G::identity() {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Batch verification failed"))
                }
            },
            InputProofKey::Range { bitlength, enc_pk, g_comm } => {
                // We batch by taking a random linear combination over all Schnorr claims.
                // (The range proofs are done separately.)
                //
                // Here we generate all the necessary randomnesss upfront.
                let num_inputs = ciphertexts[0].slots.len() - 1; // -1 to exclude attestation slot
                let num_proof_claims = 1 + 2 * num_inputs; // Only claim 1 + range consistency
                let total_claims = proof_indices.len() * num_proof_claims;
                let rands: Vec<_> = (0..total_claims)
                    .map(|_| Scalar::random(&mut *rng))
                    .collect();

                // Many terms share the g, h, and pk bases
                let mut g_scalar = Scalar::ZERO;
                let mut h_scalar = Scalar::ZERO;
                let mut pk_scalars = vec![Scalar::ZERO; enc_pk.len()];
                let mut scalars = Vec::new();
                let mut bases = Vec::new();

                // Helper closure to add terms to the MSM vectors
                let mut add_term = |scalar: Scalar, base: G| {
                    scalars.push(scalar);
                    bases.push(base);
                };

                let mut r_idx = 0;
                let g = G::generator();
                let range_params = Self::get_bp_params(*bitlength, *g_comm, num_inputs)?;

                // For each proof, add the relevant terms to the final MSM computation
                for i in 0..proof_indices.len() {
                    let ciphertext = &ciphertexts[i];
                    let InputProof::Range(proof) = &proofs[i] else {
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
                    .map_err(|e| anyhow::anyhow!("Batch verification failed (range proof): {}", e))?;

                    // Apply fiat-shamir to non-interactively generate challenge
                    let challenge = fiat_shamir(
                        &[g, *g_comm, ciphertext.rand]
                            .iter()
                            .chain([proof.comm_r].iter())
                            .chain(proof.comm_x.iter())
                            .chain(proof.comm_bp_x.iter())
                            .chain(proof.range_comms.iter())
                            .cloned()
                            .collect::<Vec<_>>(),
                        &[]
                    );

                    // Check 1) c_0 = g^r
                    g_scalar += proof.r * rands[r_idx];
                    add_term(-rands[r_idx], proof.comm_r);
                    add_term(-challenge * rands[r_idx], ciphertext.rand);
                    r_idx += 1;

                    // Check 4) Pederson commitments are consistent with the ciphertext
                    for j in 0..num_inputs {
                        g_scalar += proof.xs[j] * rands[r_idx];
                        h_scalar += proof.bp_rs[j] * rands[r_idx];
                        add_term(-rands[r_idx], proof.comm_bp_x[j]);
                        add_term(-challenge * rands[r_idx], proof.range_comms[j]);
                        r_idx += 1;

                        g_scalar += proof.xs[j] * rands[r_idx];
                        pk_scalars[j] += proof.r * rands[r_idx];
                        add_term(-rands[r_idx], proof.comm_x[j]);
                        add_term(-challenge * rands[r_idx], ciphertext.slots[j]);
                        r_idx += 1;
                    }
                }

                // Add the shared basis terms
                scalars.push(g_scalar);
                scalars.push(h_scalar);
                scalars.extend(pk_scalars);
                bases.push(g);
                bases.push(*g_comm);
                bases.extend_from_slice(enc_pk);

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
    use rand::{Rng, rngs::OsRng};

    type P = InputProof;
    type Agg = AggOnlyEnc;

    fn random_inputs(length: usize, max_val: u64) -> Vec<Scalar> {
        let mut rng = OsRng;
        (0..length)
            .map(|_| Scalar::from(rng.gen_range(0..max_val)))
            .collect()
    }

    #[test]
    fn input_proof_correctness() {
        let mut rng = OsRng;
        let length = 4;
        let (_secret_key, eval_keys) = Agg::setup(1, length, &mut rng);

        for bitwidth in [1, 8] {
            let (prover_keys, verifier_key) = P::setup(&eval_keys, bitwidth);

            let r = Scalar::random(&mut rng);
            let input = random_inputs(length, 1 << bitwidth);
            let context = rng.next_u64();
            let ciphertext = Agg::encrypt(&eval_keys[0], context, r, &input);
            let proof = P::prove(&prover_keys[0], &eval_keys[0], context, r, &input, &mut rng).unwrap();
                
            assert!(P::verify(&verifier_key, &ciphertext, context, &proof, 0).is_ok());
            assert!(P::batch_verify(&verifier_key, &[ciphertext], context, &[proof], &[0], &mut rng).is_ok());
        }
    }

    #[test]
     // Do some dumb tampering as a sanity check
    fn binary_proof_soundness_tampering() {
        let mut rng = OsRng;
        
        // Setup
        let length = 4;
        let (_secret_key, eval_keys) = Agg::setup(1, length, &mut rng);
        let (prover_keys, verifier_key) = P::setup(&eval_keys, 1);
        
        // Generate a valid ciphertext and proof
        let r = Scalar::random(&mut rng);
        let input: Vec<Scalar> = (0..length)
            .map(|_| if rng.gen_bool(0.5) { Scalar::ONE } else { Scalar::ZERO })
            .collect();
        let context = rng.next_u64();
        let ciphertext = Agg::encrypt(&eval_keys[0], context, r, &input);
        let proof = P::prove(
            &prover_keys[0],
            &eval_keys[0],
            context,
            r,
            &input,
            &mut rng
        ).unwrap();

        // Verify the original proof is valid with both methods
        assert!(P::verify(&verifier_key, &ciphertext, context, &proof, 0).is_ok());
        assert!(P::batch_verify(&verifier_key, &[ciphertext.clone()], context, &[proof.clone()], &[0], &mut rng).is_ok());

        // Try tampering the ciphertext and assert that it is rejected by both methods
        let mut bad_ciphertext = ciphertext.clone();
        bad_ciphertext.rand = G::generator() * Scalar::random(&mut rng);
        assert!(P::verify(&verifier_key, &bad_ciphertext, context, &proof, 0).is_err());
        assert!(P::batch_verify(&verifier_key, &[bad_ciphertext], context, &[proof.clone()], &[0], &mut rng).is_err());

        // Tampering any input slot should be detected by both methods
        // Only tamper input slots, not the attestation slot
        for i in 0..(ciphertext.slots.len() - 1) {
            let mut bad_ciphertext = ciphertext.clone();
            bad_ciphertext.slots[i] = G::generator() * Scalar::random(&mut rng);
            assert!(P::verify(&verifier_key, &bad_ciphertext, context, &proof, 0).is_err());
            assert!(P::batch_verify(&verifier_key, &[bad_ciphertext], context, &[proof.clone()], &[0], &mut rng).is_err());
        }

        // Try tampering the proof and assert that it is rejected by both methods
        if let InputProof::Binary(_binary_proof) = &proof {
            let mut bad_proof = proof.clone();
            if let InputProof::Binary(bad_binary_proof) = &mut bad_proof {
                bad_binary_proof.x0[0] = Scalar::random(&mut rng);
                assert!(P::verify(&verifier_key, &ciphertext, context, &bad_proof, 0).is_err());
                assert!(P::batch_verify(&verifier_key, &[ciphertext.clone()], context, &[bad_proof], &[0], &mut rng).is_err());
            }

            let mut bad_proof = proof.clone();
            if let InputProof::Binary(bad_binary_proof) = &mut bad_proof {
                bad_binary_proof.x1[0] = Scalar::random(&mut rng);
                assert!(P::verify(&verifier_key, &ciphertext, context, &bad_proof, 0).is_err());
                assert!(P::batch_verify(&verifier_key, &[ciphertext.clone()], context, &[bad_proof], &[0], &mut rng).is_err());
            }

            let mut bad_proof = proof.clone();
            if let InputProof::Binary(bad_binary_proof) = &mut bad_proof {
                bad_binary_proof.challenges_x[0] = Scalar::random(&mut rng);
                assert!(P::verify(&verifier_key, &ciphertext, context, &bad_proof, 0).is_err());
                assert!(P::batch_verify(&verifier_key, &[ciphertext.clone()], context, &[bad_proof], &[0], &mut rng).is_err());
            }

            let mut bad_proof = proof.clone();
            if let InputProof::Binary(bad_binary_proof) = &mut bad_proof {
                bad_binary_proof.g_x0[0] = G::generator() * Scalar::random(&mut rng);
                assert!(P::verify(&verifier_key, &ciphertext, context, &bad_proof, 0).is_err());
                assert!(P::batch_verify(&verifier_key, &[ciphertext.clone()], context, &[bad_proof], &[0], &mut rng).is_err());
            }

            let mut bad_proof = proof.clone();
            if let InputProof::Binary(bad_binary_proof) = &mut bad_proof {
                bad_binary_proof.g_x1[0] = G::generator() * Scalar::random(&mut rng);
                assert!(P::verify(&verifier_key, &ciphertext, context, &bad_proof, 0).is_err());
                assert!(P::batch_verify(&verifier_key, &[ciphertext.clone()], context, &[bad_proof], &[0], &mut rng).is_err());
            }

            let mut bad_proof = proof.clone();
            if let InputProof::Binary(bad_binary_proof) = &mut bad_proof {
                bad_binary_proof.pk_x0[0] = G::generator() * Scalar::random(&mut rng);
                assert!(P::verify(&verifier_key, &ciphertext, context, &bad_proof, 0).is_err());
                assert!(P::batch_verify(&verifier_key, &[ciphertext.clone()], context, &[bad_proof], &[0], &mut rng).is_err());
            }

            let mut bad_proof = proof.clone();
            if let InputProof::Binary(bad_binary_proof) = &mut bad_proof {
                bad_binary_proof.pk_x1[0] = G::generator() * Scalar::random(&mut rng);
                assert!(P::verify(&verifier_key, &ciphertext, context, &bad_proof, 0).is_err());
                assert!(P::batch_verify(&verifier_key, &[ciphertext.clone()], context, &[bad_proof], &[0], &mut rng).is_err());
            }
        }
    }

    #[test]
    fn range_proof_soundness_tampering() {
        let mut rng = OsRng;
        
        // Setup for range proofs
        let length = 4;
        let (_secret_key, eval_keys) = Agg::setup(1, length, &mut rng);
        let (prover_keys, verifier_key) = P::setup(&eval_keys, 4);
        
        // Generate a valid ciphertext and proof
        let r = Scalar::random(&mut rng);
        let input: Vec<Scalar> = (0..length)
            .map(|_| Scalar::from(rng.gen_range(0u64..16)))
            .collect();
        let context = rng.next_u64();
        let ciphertext = Agg::encrypt(&eval_keys[0], context, r, &input);
        let proof = P::prove(&prover_keys[0], &eval_keys[0], context, r, &input, &mut rng).unwrap();

        // Verify the original proof is valid
        assert!(P::verify(&verifier_key, &ciphertext, context, &proof, 0).is_ok());
        assert!(P::batch_verify(&verifier_key, &[ciphertext.clone()], context, &[proof.clone()], &[0], &mut rng).is_ok());

        // Test that tampering the ciphertext randomness is detected
        let mut bad_ciphertext = ciphertext.clone();
        bad_ciphertext.rand = G::generator() * Scalar::random(&mut rng);
        assert!(P::verify(&verifier_key, &bad_ciphertext, context, &proof, 0).is_err());
        assert!(P::batch_verify(&verifier_key, &[bad_ciphertext], context, &[proof.clone()], &[0], &mut rng).is_err());
    }

    /// Tests that range inputs outside the valid range are rejected during proof generation
    #[test]
    fn range_proof_soundness_out_of_range() {
        let mut rng = OsRng;
        
        // Setup for range proofs with 4-bit range [0, 16)
        let length = 2;
        let (_secret_key, eval_keys) = Agg::setup(1, length, &mut rng);
        let (prover_keys, _verifier_key) = P::setup(&eval_keys, 4);
        
        // Test with values outside the range
        let bad_inputs = vec![
            vec![Scalar::from(16u64), Scalar::from(5u64)],  // 16 is outside [0, 16)
            vec![Scalar::from(5u64), Scalar::from(20u64)],  // 20 is outside [0, 16)
            vec![Scalar::from(100u64), Scalar::from(3u64)], // 100 is outside [0, 16)
        ];

        for bad_input in bad_inputs {
            let r = Scalar::random(&mut rng);
            let context = rng.next_u64();
            let _ciphertext = Agg::encrypt(&eval_keys[0], context, r, &bad_input);
            
            // This should fail because the inputs are outside the range
            let result = P::prove(&prover_keys[0], &eval_keys[0], context, r, &bad_input, &mut rng);
            assert!(
                result.is_err(),
                "Should fail for out-of-range input {:?}",
                bad_input
            );
        }
    }

    // Tests that bulletproof-ciphertext consistency checks prevent attacks where
    // a client proves a bulletproof over different values than what's in the ciphertext
    #[test]
    fn range_proof_soundness_bulletproof_ciphertext_inconsistency() {
        let mut rng = OsRng;
        
        // Setup for range proofs
        let length = 2;
        let (_secret_key, eval_keys) = Agg::setup(1, length, &mut rng);
        let (prover_keys, verifier_key) = P::setup(&eval_keys, 4);
        
        // Create valid input for the ciphertext
        let input: Vec<Scalar> = (0..length)
            .map(|_| Scalar::from(rng.gen_range(0u64..16)))
            .collect();

        let r = Scalar::random(&mut rng);
        let context = rng.next_u64();
        let ciphertext = Agg::encrypt(&eval_keys[0], context, r, &input);

        // Create a valid proof first
        let mut proof = P::prove(&prover_keys[0], &eval_keys[0], context, r, &input, &mut rng).unwrap();

        // Attack 1: Tamper with the bulletproof commitments to use different values
        // This simulates proving a bulletproof over different values than the ciphertext
        let fake_input: Vec<Scalar> = (0..length)
            .map(|_| Scalar::from(rng.gen_range(0u64..16)))
            .collect();

        // Use the same g_comm that's in the proof key
        let g_comm = G::from_hash(Sha3_512::new().chain_update(b"h"));
        let (fake_range_comms, _fake_range_rands, fake_range_proof) =
            P::prove_bulletproof(4, g_comm, &fake_input, &mut rng).unwrap();

        // Replace the bulletproof components with fake ones
        if let InputProof::Range(range_proof) = &mut proof {
            range_proof.range_comms = fake_range_comms;
            range_proof.range_proof = fake_range_proof;
        }

        // The proof should now fail because the bulletproof commitments don't match
        // the ciphertext values in the consistency check
        assert!(P::verify(&verifier_key, &ciphertext, context, &proof, 0).is_err());
        assert!(P::batch_verify(&verifier_key, &[ciphertext.clone()], context, &[proof.clone()], &[0], &mut rng).is_err());

        // Attack 1.5: Change only the xs values to break consistency
        // This should trigger the consistency checks specifically
        let mut proof = P::prove(&prover_keys[0], &eval_keys[0], context, r, &input, &mut rng).unwrap();

        if let InputProof::Range(range_proof) = &mut proof {
            // Change the xs values to random values
            // This breaks the consistency between ciphertext and bulletproof
            for i in 0..range_proof.xs.len() {
                range_proof.xs[i] = Scalar::random(&mut rng);
            }
        }

        // This should fail on the consistency checks since xs no longer match
        assert!(P::verify(&verifier_key, &ciphertext, context, &proof, 0).is_err());
        assert!(P::batch_verify(&verifier_key, &[ciphertext.clone()], context, &[proof.clone()], &[0], &mut rng).is_err());

        // Attack 2: Tamper with the binding commitments (comm_x, comm_bp_x) to break
        // the consistency between bulletproof and ciphertext
        let mut proof = P::prove(&prover_keys[0], &eval_keys[0], context, r, &input, &mut rng).unwrap();

        // Replace comm_x with random commitments
        if let InputProof::Range(range_proof) = &mut proof {
            for i in 0..range_proof.comm_x.len() {
                range_proof.comm_x[i] = G::generator() * Scalar::random(&mut rng);
            }
        }

        // The proof should fail because comm_x no longer binds the ciphertext to the bulletproof
        assert!(P::verify(&verifier_key, &ciphertext, context, &proof, 0).is_err());
        assert!(P::batch_verify(&verifier_key, &[ciphertext.clone()], context, &[proof.clone()], &[0], &mut rng).is_err());

        // Attack 3: Tamper with comm_bp_x to break bulletproof consistency
        let mut proof = P::prove(&prover_keys[0], &eval_keys[0], context, r, &input, &mut rng).unwrap();

        // Replace comm_bp_x with random commitments
        if let InputProof::Range(range_proof) = &mut proof {
            for i in 0..range_proof.comm_bp_x.len() {
                range_proof.comm_bp_x[i] = G::generator() * Scalar::random(&mut rng);
            }
        }

        // The proof should fail because comm_bp_x no longer binds the bulletproof commitments
        assert!(P::verify(&verifier_key, &ciphertext, context, &proof, 0).is_err());
        assert!(P::batch_verify(&verifier_key, &[ciphertext.clone()], context, &[proof.clone()], &[0], &mut rng).is_err());
    }
}