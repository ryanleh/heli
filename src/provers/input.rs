use crate::{
    check_claim,
    agg_only_enc::EvalKey,
    crypto::{G, Scalar, ElGamalPublicKey, ElGamalCiphertext},
};
use super::{Prover, fiat_shamir};

use anyhow::Result;
use curve25519_dalek::traits::MultiscalarMul;
use group::Group;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tari_bulletproofs_plus::ristretto::RistrettoRangeProof;

/// Prover and verifier key for proving well-formedness of inputs.
/// * Binary = Schnorr,
/// * Range = Bulletproof.
/// 
/// For short binary inputs (l < 8 in our experiments), the Schnorr
/// proof is slightly more efficient.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputProofKey {
    Binary { enc_pk: ElGamalPublicKey }, // Schnorr proof
    Range { bitlength: usize, enc_pk: ElGamalPublicKey }, // Bulletproof proof
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
    // TODO
    range_comms: Vec<G>,
    comm_x: Vec<G>,
    comm_bp_x: Vec<G>,
    range_proof: RistrettoRangeProof,
    xs: Vec<Scalar>,
    bp_rs: Vec<Scalar>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum InputProof {
    Binary(BinaryProof),
    Range(RangeProof),
}

impl Prover for InputProof {
    type ProverKey = InputProofKey;
    type VerifierKey = InputProofKey;
    type Proof = InputProof;

    // TODO: Not sure if we want this
    fn setup(eval_keys: &[EvalKey], bitlength: usize) -> (Vec<Self::ProverKey>, Self::VerifierKey) {
        // These were tested impirically–might differ from machine to machine
        let key = match bitlength == 1 && eval_keys[0].enc_pk.len() < 8 {
            true => InputProofKey::Binary { enc_pk: eval_keys[0].enc_pk.clone() },
            false => InputProofKey::Range { bitlength, enc_pk: eval_keys[0].enc_pk.clone() },
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
            InputProofKey::Range { bitlength: _bitlength, enc_pk: _enc_pk } => {
                unimplemented!("")
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
            (InputProofKey::Range { .. }, InputProof::Range(_)) => {
                unimplemented!("Range proof verification not yet implemented")
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
                    let proof = &proofs[i];

                    if let InputProof::Binary(binary_proof) = proof {
                        let challenge = fiat_shamir(
                            &binary_proof.g_x0.iter()
                                .chain(binary_proof.pk_x0.iter())
                                .chain(binary_proof.g_x1.iter())
                                .chain(binary_proof.pk_x1.iter())
                                .cloned()
                                .collect::<Vec<_>>(),
                            &[]
                        );

                        // Check DLEQ claims for each input
                        for j in 0..num_inputs {
                            let challenge_0 = binary_proof.challenges_x[j];
                            let challenge_1 = challenge - challenge_0;

                            // X=0, check DLEQ(c_0, pk_i^r)
                            g_scalar += binary_proof.x0[j] * rands[r_idx];
                            add_term(-rands[r_idx], binary_proof.g_x0[j]);
                            add_term(-challenge_0 * rands[r_idx], ciphertext.rand);
                            r_idx += 1;

                            pk_scalars[j] += binary_proof.x0[j] * rands[r_idx];
                            add_term(-rands[r_idx], binary_proof.pk_x0[j]);
                            add_term(-challenge_0 * rands[r_idx], ciphertext.slots[j]);
                            r_idx += 1;

                            // X=1, check DLEQ(c_0, pk_i^r / g)
                            g_scalar += binary_proof.x1[j] * rands[r_idx];
                            add_term(-rands[r_idx], binary_proof.g_x1[j]);
                            add_term(-challenge_1 * rands[r_idx], ciphertext.rand);
                            r_idx += 1;

                            pk_scalars[j] += binary_proof.x1[j] * rands[r_idx];
                            add_term(-rands[r_idx], binary_proof.pk_x1[j]);
                            add_term(-challenge_1 * rands[r_idx], ciphertext.slots[j] - g);
                            r_idx += 1;
                        }
                    } else {
                        return Err(anyhow::anyhow!("Proof type mismatch: expected Binary proof"));
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
            InputProofKey::Range { .. } => {
                unimplemented!("Range proof batch verification not yet implemented")
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

    #[test]
    fn base_proof_correctness() {
        let mut rng = OsRng;
        
        // Setup
        let length = 5;
        let (_secret_key, eval_keys) = Agg::setup(1, length, &mut rng);
        let (prover_keys, verifier_key) = P::setup(&eval_keys, 1);

        // Generate a ciphertext and proof
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
            
        // Test individual verification
        let verify_result = P::verify(&verifier_key, &ciphertext, context, &proof, 0);
        if let Err(ref e) = verify_result {
            println!("Verification error: {:?}", e);
        }
        assert!(
            verify_result.is_ok(),
            "Individual proof verification failed for input {:?}",
            input
        );

        // Test batch verification
        assert!(
            P::batch_verify(
                &verifier_key,
                &[ciphertext],
                context,
                &[proof],
                &[0],
                &mut rng
            ).is_ok(),
            "Batch proof verification failed for input {:?}",
            input
        );
    }

    #[test]
     // Do some dumb tampering as a sanity check
    fn base_proof_soundness_tampering() {
        let mut rng = OsRng;
        
        // Setup
        let length = 5;
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
    fn base_proof_batch_correctness() {
        let mut rng = OsRng;
        let num_clients = 3;
        let length = 2;
        
        // Setup with multiple clients
        let (_secret_key, eval_keys) = Agg::setup(num_clients, length, &mut rng);
        let (prover_keys, verifier_key) = P::setup(&eval_keys, 1);

        let mut ciphertexts = Vec::with_capacity(num_clients);
        let mut proofs = Vec::with_capacity(num_clients);
        let mut proof_indices = Vec::with_capacity(num_clients);
        let context = rng.next_u64(); // Use same context for all clients
        
        for i in 0..num_clients {
            let r = Scalar::random(&mut rng);
            let input: Vec<Scalar> = (0..length)
                .map(|_| if rng.gen_bool(0.5) { Scalar::ONE } else { Scalar::ZERO })
                .collect();
            
            let ciphertext = Agg::encrypt(&eval_keys[i], context, r, &input);
            let proof = P::prove(
                &prover_keys[i],
                &eval_keys[i],
                context,
                r,
                &input,
                &mut rng
            ).unwrap();
            
            ciphertexts.push(ciphertext);
            proofs.push(proof);
            proof_indices.push(i);
        }

        // Test individual verification for each proof
        for i in 0..num_clients {
            assert!(
                P::verify(&verifier_key, &ciphertexts[i], context, &proofs[i], i).is_ok(),
                "Individual proof verification failed for client {}",
                i
            );
        }

        // Test batch verification
        assert!(
            P::batch_verify(
                &verifier_key,
                &ciphertexts,
                context,
                &proofs,
                &proof_indices,
                &mut rng
            ).is_ok(),
            "Batch proof verification failed"
        );
    }
}