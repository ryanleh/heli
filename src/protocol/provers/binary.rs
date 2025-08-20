use crate::{
    check_claim,
    protocol::{G, Scalar, messages::*, provers::Prover},
};

use anyhow::Result;
use curve25519_dalek::traits::MultiscalarMul;
use group::Group;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};

pub struct Binary {}

/// Proof of well-formedness for binary encodings.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BinaryProof {
    /// Commitments
    pub(crate) commitments: Commiments,
    /// Challenges for x = 0 branch.
    pub(crate) challenges_x: Vec<Scalar>,
    /// Responses
    pub(crate) responses: Responses,
}

impl Prover for Binary {
    type ProverKey = ();
    type VerifierKey = ();
    type Proof = BinaryProof;

    // TODO: Not sure if we want this
    fn setup(_num_inputs: usize, _bitlength: usize) -> (Self::ProverKey, Self::VerifierKey) {
        ((), ())
    }

    /// We prove the following relation (informally stated) for secrets r and s:
    ///  1) c_0 = g^r and
    ///  2) c_1 = pk_0^r * g^s and
    ///  3) ck = h^s and
    ///  4) c_i = DLEQ(c_0, pk_i^r) or DLEQ(c_0, pk_i^r / g) for i > 1
    ///
    /// This enforces that the ElGamal ciphertext is well-formed, that the secret
    /// key is embedded correctly, and that each input is either 0 or 1.
    ///
    /// TODO: Currently this isn't correct for multi-round
    fn prove<R: RngCore + CryptoRng>(
        _pk: &Self::ProverKey,
        ck: &ClientKey,
        input: &[u64],
        r: Scalar,
        encoding: &Encoding,
        rng: &mut R,
    ) -> Result<Self::Proof> {
        // TODO: Check that input is well-formed

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
            let challenge = Scalar::random(&mut *rng);
            let response = Scalar::random(&mut *rng);
            sim_challenges.push(challenge);
            sim_responses.push(response);

            // Generate commitments
            let rand = Scalar::random(&mut *rng);
            r_x_rand.push(rand);
            match input[i] {
                0 => {
                    // Real
                    comm_g_x0.push(ck.g * rand);
                    comm_pk_x0.push(ck.pks[i + 1] * rand);

                    // Simulated
                    comm_g_x1.push(ck.g * response - encoding.rand * challenge);
                    comm_pk_x1
                        .push(ck.pks[i + 1] * response - (encoding.vals[i] - ck.g) * challenge);
                }
                1 => {
                    // Simulated
                    comm_g_x0.push(ck.g * response - encoding.rand * challenge);
                    comm_pk_x0.push(ck.pks[i + 1] * response - encoding.vals[i] * challenge);

                    // Real
                    comm_g_x1.push(ck.g * rand);
                    comm_pk_x1.push(ck.pks[i + 1] * rand);
                }
                _ => panic!("Input should be 0 or 1"),
            }
        }

        // Generate commitments for claims 1-3
        let r_rand = Scalar::random(&mut *rng);
        let s_rand = Scalar::random(&mut *rng);
        let comm_g_r_rand = ck.g * r_rand;
        let comm_g_s_rand = ck.pks[0] * r_rand + ck.g * s_rand;
        let comm_h_s_rand = ck.h * s_rand;

        // Apply fiat-shamir to non-interactively generate challenge
        let commitments = Commiments {
            g_r: comm_g_r_rand,
            g_s: comm_g_s_rand,
            h_s: comm_h_s_rand,
            g_x0: comm_g_x0,
            pk_x0: comm_pk_x0,
            g_x1: comm_g_x1,
            pk_x1: comm_pk_x1,
        };
        let challenge = commitments.get_challenge(ck.g, ck.h, &ck.pks, ck.h * ck.secret, encoding);

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

        Ok(BinaryProof {
            commitments,
            challenges_x,
            responses: Responses {
                r: r_rand + challenge * r,
                s: s_rand + challenge * ck.secret,
                x0: responses_x0,
                x1: responses_x1,
            },
        })
    }

    fn prove_untagged<R: RngCore + CryptoRng>(
        _pk: &Self::ProverKey,
        ck: &ClientKey,
        input: &[u64],
        r: Scalar,
        encoding: &Encoding,
        rng: &mut R,
    ) -> Result<Self::Proof> {
        // TODO: Check that input is well-formed

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
            let challenge = Scalar::random(&mut *rng);
            let response = Scalar::random(&mut *rng);
            sim_challenges.push(challenge);
            sim_responses.push(response);

            // Generate commitments
            let rand = Scalar::random(&mut *rng);
            r_x_rand.push(rand);
            match input[i] {
                0 => {
                    // Real
                    comm_g_x0.push(ck.g * rand);
                    comm_pk_x0.push(ck.pks[i + 1] * rand);

                    // Simulated
                    comm_g_x1.push(ck.g * response - encoding.rand * challenge);
                    comm_pk_x1
                        .push(ck.pks[i + 1] * response - (encoding.vals[i] - ck.g) * challenge);
                }
                1 => {
                    // Simulated
                    comm_g_x0.push(ck.g * response - encoding.rand * challenge);
                    comm_pk_x0.push(ck.pks[i + 1] * response - encoding.vals[i] * challenge);

                    // Real
                    comm_g_x1.push(ck.g * rand);
                    comm_pk_x1.push(ck.pks[i + 1] * rand);
                }
                _ => panic!("Input should be 0 or 1"),
            }
        }

        // Generate commitments for claims 1-3
        let r_rand = Scalar::random(&mut *rng);
        let comm_g_r_rand = ck.g * r_rand;

        // Apply fiat-shamir to non-interactively generate challenge
        let commitments = Commiments {
            g_r: comm_g_r_rand,
            g_s: G::identity(), // TODO: hacky
            h_s: G::identity(),
            g_x0: comm_g_x0,
            pk_x0: comm_pk_x0,
            g_x1: comm_g_x1,
            pk_x1: comm_pk_x1,
        };
        let challenge = commitments.get_challenge(ck.g, ck.h, &ck.pks, ck.h * ck.secret, encoding);

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

        Ok(BinaryProof {
            commitments,
            challenges_x,
            responses: Responses {
                r: r_rand + challenge * r,
                s: Scalar::ZERO,
                x0: responses_x0,
                x1: responses_x1,
            },
        })
    }

    fn verify(
        _vk: &Self::VerifierKey,
        params: &AggParams,
        proof_index: usize,
        encoding: &Encoding,
        proof: &Self::Proof,
    ) -> Result<()> {
        // Apply fiat-shamir to generate challenge
        //
        // TODO: This doesn't include full transcript atm
        let challenge = proof.commitments.get_challenge(
            params.g,
            params.h,
            &params.pks,
            params.client_key_comms[proof_index],
            encoding,
        );

        // Check 1) c_0 = g^r
        check_claim!(
            params.g * proof.responses.r,
            proof.commitments.g_r + encoding.rand * challenge,
            "Claim failed: c_0 = g^r"
        );

        // Check 2) c_1 = pk_0^r * g^s
        check_claim!(
            params.pks[0] * proof.responses.r + params.g * proof.responses.s,
            proof.commitments.g_s + encoding.secret * challenge,
            "Claim failed: c_1 = pk_0^r * g^s"
        );

        // Check 3) ck = h^s
        //
        // TODO: This is wrong for multi-round
        check_claim!(
            params.h * proof.responses.s,
            proof.commitments.h_s + params.client_key_comms[proof_index] * challenge,
            "Claim failed: ck = h^s"
        );

        // Check 4) c_i = DLEQ(c_0, pk_i^r) or DLEQ(c_0, pk_i^r / g) for i > 1
        for i in 0..encoding.vals.len() {
            let challenge_0 = proof.challenges_x[i];
            let challenge_1 = challenge - challenge_0;

            // X=0, check DLEQ(c_0, pk_i^r)
            check_claim!(
                params.g * proof.responses.x0[i],
                proof.commitments.g_x0[i] + encoding.rand * challenge_0,
                format!("Claim 4 failed: DLEQ(c_0, pk_{}^r) for x=0", i + 1)
            );
            check_claim!(
                params.pks[i + 1] * proof.responses.x0[i],
                proof.commitments.pk_x0[i] + encoding.vals[i] * challenge_0,
                format!("Claim 4 failed: DLEQ(c_0, pk_{}^r) for x=0", i + 1)
            );

            // X=1, check DLEQ(c_0, pk_i^r / g)
            check_claim!(
                params.g * proof.responses.x1[i],
                proof.commitments.g_x1[i] + encoding.rand * challenge_1,
                format!("Claim 4 failed: DLEQ(c_0, pk_{}^r / g) for x=1", i + 1)
            );
            check_claim!(
                params.pks[i + 1] * proof.responses.x1[i],
                proof.commitments.pk_x1[i] + (encoding.vals[i] - params.g) * challenge_1,
                format!("Claim 4 failed: DLEQ(c_0, pk_{}^r / g) for x=1", i + 1)
            );
        }
        Ok(())
    }

    fn batch_verify<R: RngCore + CryptoRng>(
        _vk: &Self::VerifierKey,
        params: &AggParams,
        proof_indices: &[usize],
        encodings: &[Encoding],
        proofs: &[Self::Proof],
        rng: &mut R,
    ) -> Result<()> {
        // We batch by taking a random linear combination over all claims.  Here we
        // generate all the necessary randomnesss upfront.
        let num_proof_claims = 3 + 4 * encodings[0].vals.len();
        let total_claims = proof_indices.len() * num_proof_claims;
        let rands: Vec<_> = (0..total_claims)
            .map(|_| Scalar::random(&mut *rng))
            .collect();

        // Many terms share the g, h, and pk bases
        let mut g_scalar = Scalar::ZERO;
        let mut h_scalar = Scalar::ZERO;
        let mut pk_scalars = vec![Scalar::ZERO; params.pks.len()];
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
            let encoding = &encodings[i];
            let proof = &proofs[i];

            let challenge = proof.commitments.get_challenge(
                params.g,
                params.h,
                &params.pks,
                params.client_key_comms[proof_idx],
                encoding,
            );

            // Check 1) c_0 = g^r
            g_scalar += proof.responses.r * rands[r_idx];
            add_term(-rands[r_idx], proof.commitments.g_r);
            add_term(-challenge * rands[r_idx], encoding.rand);
            r_idx += 1;

            // Check 2) c_1 = pk_0^r * g^s
            pk_scalars[0] += proof.responses.r * rands[r_idx];
            g_scalar += proof.responses.s * rands[r_idx];
            add_term(-rands[r_idx], proof.commitments.g_s);
            add_term(-challenge * rands[r_idx], encoding.secret);
            r_idx += 1;

            // Check 3) c_2 = h^s
            h_scalar += proof.responses.s * rands[r_idx];
            add_term(-rands[r_idx], proof.commitments.h_s);
            add_term(
                -challenge * rands[r_idx],
                params.client_key_comms[proof_idx],
            );
            r_idx += 1;

            // Check 4) DLEQ claims for each input
            for j in 0..encoding.vals.len() {
                let challenge_0 = proof.challenges_x[j];
                let challenge_1 = challenge - challenge_0;

                // X=0, check DLEQ(c_0, pk_i^r)
                g_scalar += proof.responses.x0[j] * rands[r_idx];
                add_term(-rands[r_idx], proof.commitments.g_x0[j]);
                add_term(-challenge_0 * rands[r_idx], encoding.rand);
                r_idx += 1;

                pk_scalars[j + 1] += proof.responses.x0[j] * rands[r_idx];
                add_term(-rands[r_idx], proof.commitments.pk_x0[j]);
                add_term(-challenge_0 * rands[r_idx], encoding.vals[j]);
                r_idx += 1;

                // X=1, check DLEQ(c_0, pk_i^r / g)
                g_scalar += proof.responses.x1[j] * rands[r_idx];
                add_term(-rands[r_idx], proof.commitments.g_x1[j]);
                add_term(-challenge_1 * rands[r_idx], encoding.rand);
                r_idx += 1;

                pk_scalars[j + 1] += proof.responses.x1[j] * rands[r_idx];
                add_term(-rands[r_idx], proof.commitments.pk_x1[j]);
                add_term(-challenge_1 * rands[r_idx], encoding.vals[j] - params.g);
                r_idx += 1;
            }
        }

        // Add the shared basis terms
        scalars.push(g_scalar);
        scalars.push(h_scalar);
        scalars.extend(pk_scalars);
        bases.push(params.g);
        bases.push(params.h);
        bases.extend_from_slice(&params.pks);

        // If all proofs are valid, the MSM should equal the identity
        if G::multiscalar_mul(&scalars, &bases) == G::identity() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Batch verification failed"))
        }
    }

    fn batch_verify_untagged<R: RngCore + CryptoRng>(
        _vk: &Self::VerifierKey,
        params: &AggParams,
        proof_indices: &[usize],
        encodings: &[Encoding],
        proofs: &[Self::Proof],
        rng: &mut R,
    ) -> Result<()> {
        // We batch by taking a random linear combination over all claims.  Here we
        // generate all the necessary randomnesss upfront.
        let num_proof_claims = 1 + 4 * encodings[0].vals.len();
        let total_claims = proof_indices.len() * num_proof_claims;
        let rands: Vec<_> = (0..total_claims)
            .map(|_| Scalar::random(&mut *rng))
            .collect();

        // Many terms share the g, h, and pk bases
        let mut g_scalar = Scalar::ZERO;
        let mut pk_scalars = vec![Scalar::ZERO; params.pks.len()];
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
            let encoding = &encodings[i];
            let proof = &proofs[i];

            let challenge = proof.commitments.get_challenge(
                params.g,
                params.h,
                &params.pks,
                params.client_key_comms[proof_idx],
                encoding,
            );

            // Check 1) c_0 = g^r
            g_scalar += proof.responses.r * rands[r_idx];
            add_term(-rands[r_idx], proof.commitments.g_r);
            add_term(-challenge * rands[r_idx], encoding.rand);
            r_idx += 1;

            // Check 4) DLEQ claims for each input
            for j in 0..encoding.vals.len() {
                let challenge_0 = proof.challenges_x[j];
                let challenge_1 = challenge - challenge_0;

                // X=0, check DLEQ(c_0, pk_i^r)
                g_scalar += proof.responses.x0[j] * rands[r_idx];
                add_term(-rands[r_idx], proof.commitments.g_x0[j]);
                add_term(-challenge_0 * rands[r_idx], encoding.rand);
                r_idx += 1;

                pk_scalars[j + 1] += proof.responses.x0[j] * rands[r_idx];
                add_term(-rands[r_idx], proof.commitments.pk_x0[j]);
                add_term(-challenge_0 * rands[r_idx], encoding.vals[j]);
                r_idx += 1;

                // X=1, check DLEQ(c_0, pk_i^r / g)
                g_scalar += proof.responses.x1[j] * rands[r_idx];
                add_term(-rands[r_idx], proof.commitments.g_x1[j]);
                add_term(-challenge_1 * rands[r_idx], encoding.rand);
                r_idx += 1;

                pk_scalars[j + 1] += proof.responses.x1[j] * rands[r_idx];
                add_term(-rands[r_idx], proof.commitments.pk_x1[j]);
                add_term(-challenge_1 * rands[r_idx], encoding.vals[j] - params.g);
                r_idx += 1;
            }
        }

        // Add the shared basis terms
        scalars.push(g_scalar);
        scalars.extend(pk_scalars);
        bases.push(params.g);
        bases.extend_from_slice(&params.pks);

        // If all proofs are valid, the MSM should equal the identity
        if G::multiscalar_mul(&scalars, &bases) == G::identity() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Batch verification failed"))
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Commiments {
    /// Commitment for for claim 1) c_0 = g^r.
    pub(super) g_r: G,
    /// Commitment for for claim 2) c_1 = pk_0^r * g^s.
    pub(super) g_s: G,
    /// Commitment for for claim 3) ck = h^s.
    pub(super) h_s: G,
    /// Commitments for inputs on x=0 branch.
    pub(super) g_x0: Vec<G>,
    pub(super) pk_x0: Vec<G>,
    /// Commitments for inputs on x=1 branch.
    pub(super) g_x1: Vec<G>,
    pub(super) pk_x1: Vec<G>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Responses {
    /// Response for proving knowledge of r.
    pub(super) r: Scalar,
    /// Response for proving knowledge of s.
    pub(super) s: Scalar,
    /// Responses for proving knowledge of x=0 branch.
    pub(super) x0: Vec<Scalar>,
    /// Responses for proving knowledge of x=1 branch.
    pub(super) x1: Vec<Scalar>,
}

impl Commiments {
    /// Apply fiat-shamir to generate challenge
    fn get_challenge(&self, g: G, h: G, _pks: &[G], ck: G, encoding: &Encoding) -> Scalar {
        // Compute the hash
        //
        // TODO: This doesn't include full transcript atm
        let mut hasher = Sha3_512::new();
        hasher.update(g.compress().to_bytes().as_ref());
        hasher.update(h.compress().to_bytes().as_ref());
        hasher.update(ck.compress().to_bytes().as_ref());
        hasher.update(encoding.rand.compress().to_bytes().as_ref());
        Scalar::from_hash(hasher)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ElGamal, Scalar, messages::Encoding};

    use rand::{Rng, rngs::OsRng};

    type P = Binary;
    type Agg = ElGamal;

    #[test]
    fn proof_correctness() {
        let length = 5;
        let (params, _sk, cks) = Agg::setup(1, length, &mut OsRng);
        let (prover_key, verifier_key) = P::setup(length, 1);
        let mut rng = rand::thread_rng();

        for _ in 0..10 {
            let input: Vec<u64> = (0..length)
                .map(|_| if rng.gen_bool(0.5) { 1 } else { 0 })
                .collect();
            let r = Scalar::random(&mut OsRng);
            let encoding = Encoding {
                rand: params.g * r,
                secret: params.pks[0] * r + params.g * cks[0].secret,
                vals: input
                    .iter()
                    .enumerate()
                    .map(|(i, v)| params.pks[i + 1] * r + params.g * Scalar::from(*v))
                    .collect(),
            };
            let proof = P::prove(&prover_key, &cks[0], &input, r, &encoding, &mut OsRng).unwrap();
            assert!(
                P::verify(&verifier_key, &params, 0, &encoding, &proof).is_ok(),
                "Proof verification failed for input {:?}",
                input
            );
        }
    }

    /// Tests that tampered data is rejected by proof verification.
    #[test]
    fn proof_soundness_tampering() {
        let length = 5;
        let (params, _sk, cks) = Agg::setup(1, length, &mut OsRng);
        let (prover_key, verifier_key) = P::setup(length, 1);
        let mut rng = rand::thread_rng();
        let input: Vec<u64> = (0..length)
            .map(|_| if rng.gen_bool(0.5) { 1 } else { 0 })
            .collect();
        let r = Scalar::random(&mut OsRng);
        let encoding = Encoding {
            rand: params.g * r,
            secret: params.pks[0] * r + params.g * cks[0].secret,
            vals: input
                .iter()
                .enumerate()
                .map(|(i, v)| params.pks[i + 1] * r + params.g * Scalar::from(*v))
                .collect(),
        };
        let proof = P::prove(&prover_key, &cks[0], &input, r, &encoding, &mut OsRng).unwrap();

        // Verify the original proof is valid
        assert!(P::verify(&verifier_key, &params, 0, &encoding, &proof).is_ok());

        // Try tampering each location of the proof and assert that it is rejected
        let mut bad_encoding = encoding.clone();
        bad_encoding.rand = params.g * Scalar::random(&mut OsRng);
        assert!(P::verify(&verifier_key, &params, 0, &bad_encoding, &proof).is_err());

        let mut bad_encoding = encoding.clone();
        bad_encoding.secret = params.g * Scalar::random(&mut OsRng);
        assert!(P::verify(&verifier_key, &params, 0, &bad_encoding, &proof).is_err());

        for i in 0..encoding.vals.len() {
            let mut bad_encoding = encoding.clone();
            bad_encoding.vals[i] = params.g * Scalar::random(&mut OsRng);
            assert!(P::verify(&verifier_key, &params, 0, &bad_encoding, &proof).is_err());
        }

        let mut bad_proof = proof.clone();
        bad_proof.responses.r = Scalar::random(&mut OsRng);
        assert!(P::verify(&verifier_key, &params, 0, &encoding, &bad_proof).is_err());

        let mut bad_proof = proof.clone();
        bad_proof.responses.s = Scalar::random(&mut OsRng);
        assert!(P::verify(&verifier_key, &params, 0, &encoding, &bad_proof).is_err());

        for i in 0..proof.responses.x0.len() {
            let mut bad_proof = proof.clone();
            bad_proof.responses.x0[i] = Scalar::random(&mut OsRng);
            assert!(P::verify(&verifier_key, &params, 0, &encoding, &bad_proof).is_err());
        }

        for i in 0..proof.responses.x1.len() {
            let mut bad_proof = proof.clone();
            bad_proof.responses.x1[i] = Scalar::random(&mut OsRng);
            assert!(P::verify(&verifier_key, &params, 0, &encoding, &bad_proof).is_err());
        }

        for i in 0..proof.challenges_x.len() {
            let mut bad_proof = proof.clone();
            bad_proof.challenges_x[i] = Scalar::random(&mut OsRng);
            assert!(P::verify(&verifier_key, &params, 0, &encoding, &bad_proof).is_err());
        }

        let mut bad_proof = proof.clone();
        bad_proof.commitments.g_r = params.g * Scalar::random(&mut OsRng);
        assert!(P::verify(&verifier_key, &params, 0, &encoding, &bad_proof).is_err());

        for i in 0..proof.commitments.g_x0.len() {
            let mut bad_proof = proof.clone();
            bad_proof.commitments.g_x0[i] = params.g * Scalar::random(&mut OsRng);
            assert!(P::verify(&verifier_key, &params, 0, &encoding, &bad_proof).is_err());
        }

        for i in 0..proof.commitments.g_x1.len() {
            let mut bad_proof = proof.clone();
            bad_proof.commitments.g_x1[i] = params.g * Scalar::random(&mut OsRng);
            assert!(P::verify(&verifier_key, &params, 0, &encoding, &bad_proof).is_err());
        }
    }

    /// Tests that wrong client indices are rejected by proof verification.
    #[test]
    fn proof_soundness_wrong_client() {
        let num_clients = 3;
        let length = 5;
        let (params, _sk, cks) = Agg::setup(num_clients, length, &mut OsRng);
        let (prover_key, verifier_key) = P::setup(length, 1);
        let mut rng = rand::thread_rng();
        let input: Vec<u64> = (0..length)
            .map(|_| if rng.gen_bool(0.5) { 1 } else { 0 })
            .collect();
        let r = Scalar::random(&mut OsRng);
        let encoding = Encoding {
            rand: params.g * r,
            secret: params.pks[0] * r + params.g * cks[0].secret,
            vals: input
                .iter()
                .enumerate()
                .map(|(i, v)| params.pks[i + 1] * r + params.g * Scalar::from(*v))
                .collect(),
        };
        let proof = P::prove(&prover_key, &cks[0], &input, r, &encoding, &mut OsRng).unwrap();

        // Verify with correct client index
        assert!(P::verify(&verifier_key, &params, 0, &encoding, &proof).is_ok());

        // Verify with wrong client index
        assert!(P::verify(&verifier_key, &params, 1, &encoding, &proof).is_err());
        assert!(P::verify(&verifier_key, &params, 2, &encoding, &proof).is_err());
    }

    /// Tests batch verification
    #[test]
    fn batch_proof_correctness() {
        let num_clients = 3;
        let length = 1;
        let (params, _sk, cks) = Agg::setup(num_clients, length, &mut OsRng);
        let (prover_key, verifier_key) = P::setup(length, 1);
        let mut rng = rand::thread_rng();

        let mut encodings = Vec::with_capacity(num_clients);
        let mut proofs = Vec::with_capacity(num_clients);
        for i in 0..num_clients {
            let input = (0..length)
                .map(|_| if rng.gen_bool(0.5) { 1 } else { 0 })
                .collect::<Vec<_>>();
            let r = Scalar::random(&mut OsRng);

            let encoding = Encoding {
                rand: params.g * r,
                secret: params.pks[0] * r + params.g * cks[i].secret,
                vals: input
                    .iter()
                    .enumerate()
                    .map(|(i, v)| params.pks[i + 1] * r + params.g * Scalar::from(*v))
                    .collect(),
            };
            let proof = P::prove(&prover_key, &cks[i], &input, r, &encoding, &mut OsRng).unwrap();
            encodings.push(encoding);
            proofs.push(proof);
        }

        // First verify each proof individually
        for i in 0..num_clients {
            assert!(
                P::verify(&verifier_key, &params, i, &encodings[i], &proofs[i]).is_ok(),
                "Individual proof verification failed for client {}",
                i
            );
        }

        assert!(
            P::batch_verify(
                &verifier_key,
                &params,
                &[0, 1, 2],
                &encodings,
                &proofs,
                &mut OsRng
            )
            .is_ok()
        );
    }

    /// Tests basic untagged proof correctness with batch verification
    #[test]
    fn untagged_proof_correctness() {
        let num_clients = 3;
        let length = 2;
        let (params, _sk, cks) = Agg::setup(num_clients, length, &mut OsRng);
        let (prover_key, verifier_key) = P::setup(length, 1);
        let mut rng = rand::thread_rng();

        let mut encodings = Vec::with_capacity(num_clients);
        let mut proofs = Vec::with_capacity(num_clients);
        for i in 0..num_clients {
            let input = (0..length)
                .map(|_| if rng.gen_bool(0.5) { 1 } else { 0 })
                .collect::<Vec<_>>();
            let r = Scalar::random(&mut OsRng);

            let encoding = Encoding {
                rand: params.g * r,
                secret: params.pks[0] * r + params.g * cks[i].secret,
                vals: input
                    .iter()
                    .enumerate()
                    .map(|(i, v)| params.pks[i + 1] * r + params.g * Scalar::from(*v))
                    .collect(),
            };
            let proof =
                P::prove_untagged(&prover_key, &cks[i], &input, r, &encoding, &mut OsRng).unwrap();
            encodings.push(encoding);
            proofs.push(proof);
        }

        assert!(
            P::batch_verify_untagged(
                &verifier_key,
                &params,
                &[0, 1, 2],
                &encodings,
                &proofs,
                &mut OsRng
            )
            .is_ok()
        );
    }
}
