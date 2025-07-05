use crate::protocol::{FromBytes, MSM, ToBytes, messages::*};

use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};
use num_bigint::BigUint;
use num_traits::One;
use rand_core::{CryptoRng, RngCore};
use sha3::{Digest, Sha3_256};

pub trait Prover<G: Group + GroupEncoding>: 'static {
    type ProverKey: Send + Sync + ToBytes + FromBytes;
    type VerifierKey: Send + Sync + ToBytes + FromBytes;
    type Proof: Send + Sync + ToBytes + FromBytes;

    fn setup() -> (Self::ProverKey, Self::VerifierKey);

    fn prove<R: RngCore + CryptoRng>(
        pk: &Self::ProverKey,
        ck: &ClientKey<G>,
        input: &[u32],
        r: G::Scalar,
        encoding: &Encoding<G>,
        rng: &mut R,
    ) -> Self::Proof;

    fn verify(
        vk: &Self::VerifierKey,
        params: &AggParams<G>,
        proof_index: u32,
        encoding: &Encoding<G>,
        proof: &Self::Proof,
    ) -> bool;

    fn batch_verify<R: RngCore + CryptoRng>(
        vk: &Self::VerifierKey,
        params: &AggParams<G>,
        proof_indices: &[u32],
        encodings: &[Encoding<G>],
        proofs: &[Self::Proof],
        rng: &mut R,
    ) -> bool
    where
        G: MSM<Coeff = <G as Group>::Scalar, Point = G>;
}

pub struct BinarySchnorr<G: Group + GroupEncoding> {
    _g: std::marker::PhantomData<G>,
}

/// Proof of well-formedness for binary encodings.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BinarySchnorrProof<G: Group + GroupEncoding> {
    /// Commitments
    pub(crate) commitments: Commiments<G>,
    /// Challenges for x = 0 branch.
    pub(crate) challenges_x: Vec<G::Scalar>,
    /// Responses
    pub(crate) responses: Responses<G>,
}

// Helper macro for verifying claims
macro_rules! check_claim {
    ($left:expr, $right:expr) => {
        if $left != $right {
            return false;
        }
    };
}

impl<G: Group + GroupEncoding> Prover<G> for BinarySchnorr<G> {
    type ProverKey = ();
    type VerifierKey = ();
    type Proof = BinarySchnorrProof<G>;

    // TODO: Not sure if we want this
    fn setup() -> (Self::ProverKey, Self::VerifierKey) {
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
    fn prove<R: RngCore + CryptoRng>(
        _pk: &Self::ProverKey,
        ck: &ClientKey<G>,
        input: &[u32],
        r: G::Scalar,
        encoding: &Encoding<G>,
        rng: &mut R,
    ) -> Self::Proof {
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
            let rand = <G as Group>::Scalar::random(&mut *rng);
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
        let r_rand = <G as Group>::Scalar::random(&mut *rng);
        let s_rand = <G as Group>::Scalar::random(&mut *rng);
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

        BinarySchnorrProof {
            commitments,
            challenges_x,
            responses: Responses {
                r: r_rand + challenge * r,
                s: s_rand + challenge * ck.secret,
                x0: responses_x0,
                x1: responses_x1,
            },
        }
    }

    fn verify(
        _vk: &Self::VerifierKey,
        params: &AggParams<G>,
        client_index: u32,
        encoding: &Encoding<G>,
        proof: &Self::Proof,
    ) -> bool {
        // Apply fiat-shamir to generate challenge
        //
        // TODO: This doesn't include full transcript atm
        let challenge = proof.commitments.get_challenge(
            params.g,
            params.h,
            &params.pks,
            params.client_key_comms[client_index as usize],
            encoding,
        );

        // Check 1) c_0 = g^r
        check_claim!(
            params.g * proof.responses.r,
            proof.commitments.g_r + encoding.rand * challenge
        );

        // Check 2) c_1 = pk_0^r * g^s
        check_claim!(
            params.pks[0] * proof.responses.r + params.g * proof.responses.s,
            proof.commitments.g_s + encoding.secret * challenge
        );

        // Check 3) ck = h^s
        check_claim!(
            params.h * proof.responses.s,
            proof.commitments.h_s + params.client_key_comms[client_index as usize] * challenge
        );

        // Check 4) c_i = DLEQ(c_0, pk_i^r) or DLEQ(c_0, pk_i^r / g) for i > 1
        for i in 0..encoding.vals.len() {
            let challenge_0 = proof.challenges_x[i];
            let challenge_1 = challenge - challenge_0;

            // X=0, check DLEQ(c_0, pk_i^r)
            check_claim!(
                params.g * proof.responses.x0[i],
                proof.commitments.g_x0[i] + encoding.rand * challenge_0
            );
            check_claim!(
                params.pks[i + 1] * proof.responses.x0[i],
                proof.commitments.pk_x0[i] + encoding.vals[i] * challenge_0
            );

            // X=1, check DLEQ(c_0, pk_i^r / g)
            check_claim!(
                params.g * proof.responses.x1[i],
                proof.commitments.g_x1[i] + encoding.rand * challenge_1
            );
            check_claim!(
                params.pks[i + 1] * proof.responses.x1[i],
                proof.commitments.pk_x1[i] + (encoding.vals[i] - params.g) * challenge_1
            );
        }
        true
    }

    fn batch_verify<R: RngCore + CryptoRng>(
        _vk: &Self::VerifierKey,
        params: &AggParams<G>,
        client_indices: &[u32],
        encodings: &[Encoding<G>],
        proofs: &[Self::Proof],
        rng: &mut R,
    ) -> bool
    where
        G: MSM<Coeff = <G as Group>::Scalar, Point = G>,
    {
        // We batch by taking a random linear combination over all claims.  Here we
        // generate all the necessary randomnesss upfront.
        let num_proof_claims = 3 + 4 * encodings[0].vals.len();
        let total_claims = client_indices.len() * num_proof_claims;
        let rands: Vec<_> = (0..total_claims)
            .map(|_| <G as Group>::Scalar::random(&mut *rng))
            .collect();

        // Many terms share the g, h, and pk bases
        let mut g_scalar = <G as Group>::Scalar::ZERO;
        let mut h_scalar = <G as Group>::Scalar::ZERO;
        let mut pk_scalars = vec![<G as Group>::Scalar::ZERO; params.pks.len()];
        let mut scalars = Vec::new();
        let mut bases = Vec::new();

        // Helper closure to add terms to the MSM vectors
        let mut add_term = |scalar: <G as Group>::Scalar, base: G| {
            scalars.push(scalar);
            bases.push(base);
        };

        let mut r_idx = 0;

        // For each proof, add the relevant terms to the final MSM computation
        for i in 0..client_indices.len() {
            let client_idx = client_indices[i];
            let encoding = &encodings[i];
            let proof = &proofs[i];

            let challenge = proof.commitments.get_challenge(
                params.g,
                params.h,
                &params.pks,
                params.client_key_comms[client_idx as usize],
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
                params.client_key_comms[client_idx as usize],
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
        let result = <G as MSM>::msm(&scalars, &bases);
        result == G::identity()
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Commiments<G: Group + GroupEncoding> {
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

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Responses<G: Group + GroupEncoding> {
    /// Response for proving knowledge of r.
    pub(super) r: G::Scalar,
    /// Response for proving knowledge of s.
    pub(super) s: G::Scalar,
    /// Responses for proving knowledge of x=0 branch.
    pub(super) x0: Vec<G::Scalar>,
    /// Responses for proving knowledge of x=1 branch.
    pub(super) x1: Vec<G::Scalar>,
}

impl<G: Group + GroupEncoding> Commiments<G> {
    /// Apply fiat-shamir to generate challenge
    fn get_challenge(&self, g: G, h: G, _pks: &[G], ck: G, encoding: &Encoding<G>) -> G::Scalar {
        // Compute the hash
        let mut hasher = Sha3_256::new();
        // TODO: This doesn't include full transcript atm
        hasher.update(g.to_bytes().as_ref());
        hasher.update(h.to_bytes().as_ref());
        hasher.update(ck.to_bytes().as_ref());
        hasher.update(encoding.rand.to_bytes().as_ref());
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{DiscreteLog, Ristretto, messages::Encoding};

    use rand::{Rng, rngs::OsRng};

    type G = Ristretto;
    type P = BinarySchnorr<G>;
    type Agg = DiscreteLog<G, P>;

    #[test]
    fn proof_correctness() {
        let length = 5;
        let (params, _sk, cks) = Agg::setup(1, length, &mut OsRng);
        let (prover_key, verifier_key) = P::setup();
        let mut rng = rand::thread_rng();

        for _ in 0..10 {
            let input: Vec<u32> = (0..length)
                .map(|_| if rng.gen_bool(0.5) { 1 } else { 0 })
                .collect();
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
            let proof = P::prove(&prover_key, &cks[0], &input, r, &encoding, &mut OsRng);
            assert!(
                P::verify(&verifier_key, &params, 0, &encoding, &proof),
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
        let (prover_key, verifier_key) = P::setup();
        let mut rng = rand::thread_rng();
        let input: Vec<u32> = (0..length)
            .map(|_| if rng.gen_bool(0.5) { 1 } else { 0 })
            .collect();
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
        let proof = P::prove(&prover_key, &cks[0], &input, r, &encoding, &mut OsRng);

        // Verify the original proof is valid
        assert!(P::verify(&verifier_key, &params, 0, &encoding, &proof));

        // Try tampering each location of the proof and assert that it is rejected
        let mut bad_encoding = encoding.clone();
        bad_encoding.rand = params.g * <G as Group>::Scalar::random(&mut OsRng);
        assert!(!P::verify(&verifier_key, &params, 0, &bad_encoding, &proof));

        let mut bad_encoding = encoding.clone();
        bad_encoding.secret = params.g * <G as Group>::Scalar::random(&mut OsRng);
        assert!(!P::verify(&verifier_key, &params, 0, &bad_encoding, &proof));

        for i in 0..encoding.vals.len() {
            let mut bad_encoding = encoding.clone();
            bad_encoding.vals[i] = params.g * <G as Group>::Scalar::random(&mut OsRng);
            assert!(!P::verify(&verifier_key, &params, 0, &bad_encoding, &proof));
        }

        let mut bad_proof = proof.clone();
        bad_proof.responses.r = <G as Group>::Scalar::random(&mut OsRng);
        assert!(!P::verify(&verifier_key, &params, 0, &encoding, &bad_proof));

        let mut bad_proof = proof.clone();
        bad_proof.responses.s = <G as Group>::Scalar::random(&mut OsRng);
        assert!(!P::verify(&verifier_key, &params, 0, &encoding, &bad_proof));

        for i in 0..proof.responses.x0.len() {
            let mut bad_proof = proof.clone();
            bad_proof.responses.x0[i] = <G as Group>::Scalar::random(&mut OsRng);
            assert!(!P::verify(&verifier_key, &params, 0, &encoding, &bad_proof));
        }

        for i in 0..proof.responses.x1.len() {
            let mut bad_proof = proof.clone();
            bad_proof.responses.x1[i] = <G as Group>::Scalar::random(&mut OsRng);
            assert!(!P::verify(&verifier_key, &params, 0, &encoding, &bad_proof));
        }

        for i in 0..proof.challenges_x.len() {
            let mut bad_proof = proof.clone();
            bad_proof.challenges_x[i] = <G as Group>::Scalar::random(&mut OsRng);
            assert!(!P::verify(&verifier_key, &params, 0, &encoding, &bad_proof));
        }

        let mut bad_proof = proof.clone();
        bad_proof.commitments.g_r = params.g * <G as Group>::Scalar::random(&mut OsRng);
        assert!(!P::verify(&verifier_key, &params, 0, &encoding, &bad_proof));

        for i in 0..proof.commitments.g_x0.len() {
            let mut bad_proof = proof.clone();
            bad_proof.commitments.g_x0[i] = params.g * <G as Group>::Scalar::random(&mut OsRng);
            assert!(!P::verify(&verifier_key, &params, 0, &encoding, &bad_proof));
        }

        for i in 0..proof.commitments.g_x1.len() {
            let mut bad_proof = proof.clone();
            bad_proof.commitments.g_x1[i] = params.g * <G as Group>::Scalar::random(&mut OsRng);
            assert!(!P::verify(&verifier_key, &params, 0, &encoding, &bad_proof));
        }
    }

    /// Tests that wrong client indices are rejected by proof verification.
    #[test]
    fn proof_soundness_wrong_client() {
        let num_clients = 3;
        let length = 5;
        let (params, _sk, cks) = Agg::setup(num_clients, length, &mut OsRng);
        let (prover_key, verifier_key) = P::setup();
        let mut rng = rand::thread_rng();
        let input: Vec<u32> = (0..length)
            .map(|_| if rng.gen_bool(0.5) { 1 } else { 0 })
            .collect();
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
        let proof = P::prove(&prover_key, &cks[0], &input, r, &encoding, &mut OsRng);

        // Verify with correct client index
        assert!(P::verify(&verifier_key, &params, 0, &encoding, &proof));

        // Verify with wrong client index
        assert!(!P::verify(&verifier_key, &params, 1, &encoding, &proof));
        assert!(!P::verify(&verifier_key, &params, 2, &encoding, &proof));
    }

    /// Tests batch verification
    #[test]
    fn batch_proof_correctness() {
        let num_clients = 3;
        let length = 1;
        let (params, _sk, cks) = Agg::setup(num_clients, length, &mut OsRng);
        let (prover_key, verifier_key) = P::setup();
        let mut rng = rand::thread_rng();

        let mut encodings = Vec::with_capacity(num_clients);
        let mut proofs = Vec::with_capacity(num_clients);
        for i in 0..num_clients {
            let input = (0..length)
                .map(|_| if rng.gen_bool(0.5) { 1 } else { 0 })
                .collect::<Vec<_>>();
            let r = <G as Group>::Scalar::random(&mut OsRng);

            let encoding = Encoding {
                rand: params.g * r,
                secret: params.pks[0] * r + params.g * cks[i].secret,
                vals: input
                    .iter()
                    .enumerate()
                    .map(|(i, v)| {
                        params.pks[i + 1] * r + params.g * <G as Group>::Scalar::from(*v as u64)
                    })
                    .collect(),
            };
            let proof = P::prove(&prover_key, &cks[i], &input, r, &encoding, &mut OsRng);
            encodings.push(encoding);
            proofs.push(proof);
        }

        // First verify each proof individually
        for i in 0..num_clients {
            assert!(
                P::verify(&verifier_key, &params, i as u32, &encodings[i], &proofs[i]),
                "Individual proof verification failed for client {}",
                i
            );
        }

        assert!(P::batch_verify(
            &verifier_key,
            &params,
            &[0, 1, 2],
            &encodings,
            &proofs,
            &mut OsRng
        ));

        //// Verify with correct client index
        //assert!(verify_proof_binary(&params, 0, &encoding, &proof));

        //// Verify with wrong client index
        //assert!(!verify_proof_binary(&params, 1, &encoding, &proof));
        //assert!(!verify_proof_binary(&params, 2, &encoding, &proof));
    }
}
