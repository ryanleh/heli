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
use std::borrow::Borrow;
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
    /// Commitments for inputs on x=0 branch.
    pub(super) g_comm_x0: Vec<G>,
    pub(super) hash_x0: Vec<G>,
    /// Commitments for inputs on x=1 branch.
    pub(super) g_comm_x1: Vec<G>,
    pub(super) hash_x1: Vec<G>,

    /// Challenges for x=0 branch
    pub(crate) challenges_x: Vec<Scalar>,

    /// Responses for proving knowledge of x=0 branch.
    pub(super) x0: Vec<Scalar>,
    /// Responses for proving knowledge of x=1 branch.
    pub(super) x1: Vec<Scalar>,
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
            let prover_keys = vec![ProverKey::Binary { g_comm }; eval_keys.len()];
            let verifier_key = VerifierKey::Binary { g_comm, key_commitments };
            (prover_keys, verifier_key)
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
    ///  1) c_i = g^x_i * H(context || i)^k, 
    ///  2) C_i = g_comm^k
    ///  3) x_i < bitlength
    /// 
    /// This enforces that the client's aggregation-only ciphertext is well-formed.
    pub fn prove<R: RngCore + CryptoRng>(
        pk: &ProverKey,
        ek: &EvalKey,
        context: u32,
        input: &[Scalar],
        ciphertext: &Ciphertext,
        rng: &mut R,
    ) -> Result<Proof> {
        let g = G::generator();

        // Generators for the key-homomorphic PRF
        let hash_bases = (0..input.len())
            .map(|i| KHPRF::compute_generator(context, i))
            .collect::<Vec<_>>();
        
        // Claims (1) and (2) are done using standard Schnorr proofs. Claim (3) is done
        // using either OR composition for x=0 and x=1, or bulletproofs
        match pk {
            ProverKey::Binary { g_comm } => {
                // Generate commitments
                let mut k_rand = Vec::with_capacity(input.len()); // Randomness for real branch
                let mut g_comm_x0 = Vec::with_capacity(input.len());
                let mut hash_x0 = Vec::with_capacity(input.len());
                let mut g_comm_x1 = Vec::with_capacity(input.len());
                let mut hash_x1 = Vec::with_capacity(input.len());
                let mut sim_challenges = Vec::with_capacity(input.len());
                let mut sim_responses = Vec::with_capacity(input.len());

                for i in 0..input.len() {
                    // Generate simulated transcripts for false paths
                    let challenge = Scalar::random(&mut *rng);
                    let response = Scalar::random(&mut *rng);
                    sim_challenges.push(challenge);
                    sim_responses.push(response);

                    // Generate randomness for real branch
                    let rand = Scalar::random(&mut *rng);
                    k_rand.push(rand);

                    // OR composition for x=0 and x=1
                    // For x=0: ciphertext[i] = H(context || i)^k
                    // For x=1: ciphertext[i] = g + H(context || i)^k
                    let hash_base = hash_bases[i];
                    if input[i] == Scalar::ZERO {
                        // Real branch for x=0
                        g_comm_x0.push(g_comm * rand);
                        hash_x0.push(hash_base * rand);

                        // Simulated branch for x=1
                        g_comm_x1.push(g_comm * (response - (**ek) * challenge));
                        hash_x1.push(hash_base * (response - (**ek) * challenge) + g * challenge);
                    } else if input[i] == Scalar::ONE {
                        // Simulated branch for x=0
                        g_comm_x0.push(g_comm * (response - (**ek) * challenge));
                        hash_x0.push(hash_base * (response - (**ek) * challenge) - g * challenge);

                        // Real branch for x=1
                        g_comm_x1.push(g_comm * rand);
                        hash_x1.push(hash_base * rand);
                    } else {
                        return Err(anyhow::anyhow!("Expected binary input"));
                    }
                }

                // Generate challenge via fiat-shamir
                let challenge = fiat_shamir(
                    [g, *g_comm]
                        .iter()
                        .chain(g_comm_x0.iter())
                        .chain(hash_x0.iter())
                        .chain(g_comm_x1.iter())
                        .chain(hash_x1.iter())
                        .chain(ciphertext.iter()),
                    std::iter::empty::<&Scalar>(),
                );

                // Generate responses for claim 3
                let mut challenges_x = Vec::with_capacity(input.len());
                let mut responses_x0 = Vec::with_capacity(input.len());
                let mut responses_x1 = Vec::with_capacity(input.len());
                for i in 0..input.len() {
                    let challenge_real = challenge - sim_challenges[i];
                    // Always send the challenge for the zero branch
                    if input[i] == Scalar::ZERO {
                        challenges_x.push(challenge_real);
                        responses_x0.push(k_rand[i] + challenge_real * (**ek));
                        responses_x1.push(sim_responses[i]);
                    } else if input[i] == Scalar::ONE {
                        challenges_x.push(sim_challenges[i]);
                        responses_x0.push(sim_responses[i]);
                        responses_x1.push(k_rand[i] + challenge_real * (**ek));
                    } else {
                        unreachable!()
                    }
                }

                Ok(Proof::Binary(BinaryProof {
                    g_comm_x0,
                    hash_x0,
                    g_comm_x1,
                    hash_x1,
                    challenges_x,
                    x0: responses_x0,
                    x1: responses_x1,
                }))
            }
            ProverKey::Range { g_comm, bitlength } => {
                // First, generate the bulletproof proof
                let (range_comms, range_rands, range_proof) =
                    RangeProof::prove_bulletproof(*bitlength, *g_comm, &input, rng)?;

                // Generate commitments for claims (1) and (2)
                let k_rand = Scalar::random(&mut *rng);
                let g_comm_k = *g_comm * k_rand;
                
                // Generate commitments to for claim (1) and to bind the ciphertext
                // to the bulletproof proof
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
                    [g, *g_comm, g_comm_k]
                        .iter()
                        .chain(g_x.iter())
                        .chain(g_bp_x.iter())
                        .chain(range_comms.iter())
                        .chain(ciphertext.iter()),
                    std::iter::empty::<&Scalar>(),
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
                Proof::Binary(proof),
                VerifierKey::Binary {
                    g_comm,
                    key_commitments,
                },
            ) => {
                // Apply fiat-shamir to generate challenge (same as in prove)
                let challenge = fiat_shamir(
                    [g, *g_comm]
                        .iter()
                        .chain(proof.g_comm_x0.iter())
                        .chain(proof.hash_x0.iter())
                        .chain(proof.g_comm_x1.iter())
                        .chain(proof.hash_x1.iter())
                        .chain(ciphertext.iter()),
                    std::iter::empty::<&Scalar>(),
                );

                // Check that each input slot is either 0 or 1 and uses the correct key
                for i in 0..proof.challenges_x.len() {
                    let challenge_0 = proof.challenges_x[i];
                    let challenge_1 = challenge - challenge_0;
                    let g_hash = KHPRF::compute_generator(context, i);

                    // X=0
                    crate::check_claim!(
                        g_comm * proof.x0[i],
                        key_commitments[proof_index] * challenge_0 + proof.g_comm_x0[i],
                        format!("Claim (2) failed for x=0, slot {}", i)
                    );
                    crate::check_claim!(
                        g_hash * proof.x0[i],
                        ciphertext[i] * challenge_0 + proof.hash_x0[i],
                        format!("Claim (1/3) failed for x=0, slot {}", i)
                    );

                    // X=1
                    crate::check_claim!(
                        g_comm * proof.x1[i],
                        key_commitments[proof_index] * challenge_1 + proof.g_comm_x1[i],
                        format!("Claim (2) failed for x=1, slot {}", i)
                    );
                    crate::check_claim!(
                        g_hash * proof.x1[i],
                        (ciphertext[i] - g) * challenge_1 + proof.hash_x1[i],
                        format!("Claim (1/3) failed for x=1, slot {}", i)
                    );
                }
                Ok(())
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
                    [g, *g_comm, proof.g_comm_k]
                        .iter()
                        .chain(proof.g_x.iter())
                        .chain(proof.g_bp_x.iter())
                        .chain(proof.range_comms.iter())
                        .chain(ciphertext.iter()),
                    std::iter::empty::<&Scalar>(),
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
                g_comm,
                key_commitments,
            } => {
                // We batch by taking a random linear combination over all claims
                let num_inputs = ciphertexts[0].len();
                let num_proof_claims = 4 * num_inputs; // 4 claims per input (2 for x=0, 2 for x=1)
                let total_claims = proof_indices.len() * num_proof_claims;
                let rands: Vec<_> = (0..total_claims)
                    .map(|_| Scalar::random(&mut *rng))
                    .collect();

                // Many terms share the g_comm, g_hash, and key_commitments bases
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

                // For each proof, add the relevant terms to the final MSM computation
                for i in 0..proof_indices.len() {
                    let proof_idx = proof_indices[i];
                    let ciphertext = &ciphertexts[i];
                    let Proof::Binary(proof) = &proofs[i] else {
                        return Err(anyhow::anyhow!("Proof type mismatch"));
                    };

                    // Apply fiat-shamir to generate challenge (same as in verify)
                    let challenge = fiat_shamir(
                        [g, *g_comm]
                            .iter()
                            .chain(proof.g_comm_x0.iter())
                            .chain(proof.hash_x0.iter())
                            .chain(proof.g_comm_x1.iter())
                            .chain(proof.hash_x1.iter())
                            .chain(ciphertext.iter()),
                        std::iter::empty::<&Scalar>(),
                    );

                    // Check DLEQ claims for each input
                    for j in 0..num_inputs {
                        let challenge_0 = proof.challenges_x[j];
                        let challenge_1 = challenge - challenge_0;
                        let _g_hash = KHPRF::compute_generator(context, j);

                        // X=0
                        g_comm_scalar += proof.x0[j] * rands[r_idx];
                        add_term(-rands[r_idx], proof.g_comm_x0[j]);
                        add_term(-challenge_0 * rands[r_idx], key_commitments[proof_idx]);
                        r_idx += 1;

                        g_hash_scalars[j] += proof.x0[j] * rands[r_idx];
                        add_term(-rands[r_idx], proof.hash_x0[j]);
                        add_term(-challenge_0 * rands[r_idx], ciphertext[j]);
                        r_idx += 1;

                        // X=1
                        g_comm_scalar += proof.x1[j] * rands[r_idx];
                        add_term(-rands[r_idx], proof.g_comm_x1[j]);
                        add_term(-challenge_1 * rands[r_idx], key_commitments[proof_idx]);
                        r_idx += 1;

                        g_hash_scalars[j] += proof.x1[j] * rands[r_idx];
                        add_term(-rands[r_idx], proof.hash_x1[j]);
                        add_term(-challenge_1 * rands[r_idx], ciphertext[j]-g);
                        r_idx += 1;
                    }
                }

                // Add the shared basis terms
                scalars.push(g_comm_scalar);
                scalars.extend(g_hash_scalars);
                // Add unique bases for key_commitments and ciphertext terms (already added via add_term)
                bases.push(*g_comm);
                bases.extend((0..num_inputs).map(|i| KHPRF::compute_generator(context, i)));

                // If all proofs are valid, the MSM should equal the identity
                if G::multiscalar_mul(&scalars, &bases) == G::identity() {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Batch verification failed"))
                }
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
                    let challenge = fiat_shamir(
                        [g, *g_comm, proof.g_comm_k]
                            .iter()
                            .chain(proof.g_x.iter())
                            .chain(proof.g_bp_x.iter())
                            .chain(proof.range_comms.iter())
                            .chain(ciphertext.iter()),
                        std::iter::empty::<&Scalar>(),
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


/// Apply fiat-shamir to a list of group and scalar elements
fn fiat_shamir<I, J>(elements: I, scalars: J) -> Scalar
where
    I: IntoIterator,
    I::Item: Borrow<G>,
    J: IntoIterator,
    J::Item: Borrow<Scalar>,
{
    let mut hasher = Sha3_512::new();
    for g in elements {
        hasher.update(g.borrow().compress().as_bytes());
    }
    for s in scalars {
        hasher.update(s.borrow().as_bytes());
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
            (1, 4),
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
                Proof::prove(&prover_keys[0], &eval_keys[0], CONTEXT, &input, &ciphertext, &mut rng).unwrap();

            // Test individual verification
            if let Err(e) = proof.verify(&verifier_key, &ciphertext, CONTEXT, 0) {
                panic!(
                    "Individual proof verification failed for config {}: {}",
                    config_idx, e
                );
            }

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
            (1, 4), // Binary proof
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
                Proof::prove(&prover_keys[0], &eval_keys[0], CONTEXT, &input, &ciphertext, &mut rng).unwrap();

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
            match &proof {
                Proof::Range(_) => {
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
                Proof::Binary(_) => {
                    // Tamper with g_comm_x0
                    let mut bad_proof = proof.clone();
                    if let Proof::Binary(bad_binary_proof) = &mut bad_proof {
                        bad_binary_proof.g_comm_x0[0] = G::generator() * Scalar::random(&mut rng);
                        assert!(
                            bad_proof
                                .verify(&verifier_key, &ciphertext, CONTEXT, 0)
                                .is_err(),
                            "Tampered g_comm_x0 accepted for config {}",
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
                            "Tampered g_comm_x0 accepted in batch for config {}",
                            config_idx
                        );
                    }

                    // Tamper with hash_x0
                    let mut bad_proof = proof.clone();
                    if let Proof::Binary(bad_binary_proof) = &mut bad_proof {
                        bad_binary_proof.hash_x0[0] = G::generator() * Scalar::random(&mut rng);
                        assert!(
                            bad_proof
                                .verify(&verifier_key, &ciphertext, CONTEXT, 0)
                                .is_err(),
                            "Tampered hash_x0 accepted for config {}",
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
                            "Tampered hash_x0 accepted in batch for config {}",
                            config_idx
                        );
                    }

                    // Tamper with g_comm_x1
                    let mut bad_proof = proof.clone();
                    if let Proof::Binary(bad_binary_proof) = &mut bad_proof {
                        bad_binary_proof.g_comm_x1[0] = G::generator() * Scalar::random(&mut rng);
                        assert!(
                            bad_proof
                                .verify(&verifier_key, &ciphertext, CONTEXT, 0)
                                .is_err(),
                            "Tampered g_comm_x1 accepted for config {}",
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
                            "Tampered g_comm_x1 accepted in batch for config {}",
                            config_idx
                        );
                    }

                    // Tamper with hash_x1
                    let mut bad_proof = proof.clone();
                    if let Proof::Binary(bad_binary_proof) = &mut bad_proof {
                        bad_binary_proof.hash_x1[0] = G::generator() * Scalar::random(&mut rng);
                        assert!(
                            bad_proof
                                .verify(&verifier_key, &ciphertext, CONTEXT, 0)
                                .is_err(),
                            "Tampered hash_x1 accepted for config {}",
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
                            "Tampered hash_x1 accepted in batch for config {}",
                            config_idx
                        );
                    }
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
            (1, 4), // Binary proof
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
                Proof::prove(&prover_keys[0], &eval_keys[0], CONTEXT, &input, &ciphertext, &mut rng).unwrap();

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