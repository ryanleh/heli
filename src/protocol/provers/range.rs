use crate::{
    check_claim,
    protocol::{G, Scalar, messages::*, provers::Prover},
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

pub struct Range {}

/// Proof of well-formedness for bounded inputs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeProof {
    // Commitments
    comm_r: G,
    comm_s: G,
    comm_ck: G,
    range_comms: Vec<G>,
    comm_x: Vec<G>,
    comm_bp_x: Vec<G>,

    // Responses
    r: Scalar,
    s: Scalar,
    range_proof: RistrettoRangeProof,
    xs: Vec<Scalar>,
    bp_rs: Vec<Scalar>,
}

impl Range {
    fn get_bp_params(bitlength: usize, h: G, num_inputs: usize) -> Result<RangeParameters<G>> {
        // Initialize generators.  This library denotes the generator `g` as `h` and vv.
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
        bitlength: usize, // bitlength
        ck: &ClientKey,
        input: &[u64],
        rng: &mut R,
    ) -> Result<(Vec<G>, Vec<Scalar>, RistrettoRangeProof)> {
        let params = Self::get_bp_params(bitlength, ck.h, input.len())?;

        // Create witness data
        let mut commitments = Vec::with_capacity(input.len());
        let mut rands = Vec::with_capacity(input.len());
        let mut openings = Vec::with_capacity(input.len());
        for i in 0..input.len() {
            let rand = Scalar::random_not_zero(rng);
            commitments.push(
                params
                    .pc_gens()
                    .commit(&Scalar::from(input[i]), &[rand])
                    .unwrap(),
            );
            openings.push(CommitmentOpening::new(input[i], vec![rand]));
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

impl Prover for Range {
    type ProverKey = usize;
    type VerifierKey = usize;
    type Proof = RangeProof;

    // TODO: Not sure if we want this
    fn setup(_num_inputs: usize, bitlength: usize) -> (Self::ProverKey, Self::VerifierKey) {
        (bitlength, bitlength)
    }



    fn prove<R: RngCore + CryptoRng>(
        pk: &Self::ProverKey, // bitlength
        ck: &ClientKey,
        input: &[u64],
        r: Scalar,
        encoding: &Encoding,
        rng: &mut R,
    ) -> Result<Self::Proof> {
        // First, generate the bulletproof proof
        let (range_comms, range_rands, range_proof) = Self::prove_bulletproof(*pk, ck, input, rng)?;

        // Generate commitments for claims 1-3
        let r_rand = Scalar::random(&mut *rng);
        let s_rand = Scalar::random(&mut *rng);
        let comm_r = ck.g * r_rand;
        let comm_s = ck.pks[0] * r_rand + ck.g * s_rand;
        let comm_ck = ck.h * s_rand;

        // Generate commitments to bind the ciphertext to the bulletproof proof
        let x_rands = vec![Scalar::random(&mut *rng); input.len()];
        let bp_r_rands = vec![Scalar::random(&mut *rng); input.len()];
        let mut comm_x = Vec::with_capacity(input.len());
        let mut comm_bp_x = Vec::with_capacity(input.len());
        for i in 0..input.len() {
            comm_x.push(ck.pks[i + 1] * r_rand + ck.g * x_rands[i]);
            comm_bp_x.push(ck.h * bp_r_rands[i] + ck.g * x_rands[i]);
        }

        // Apply fiat-shamir to non-interactively generate challenge
        //
        // TODO: Actually include the full transcript here
        let hasher = Sha3_512::new()
            .chain_update(ck.g.compress().to_bytes().as_ref())
            .chain_update(ck.h.compress().to_bytes().as_ref())
            .chain_update(encoding.rand.compress().to_bytes().as_ref());
        let challenge = Scalar::from_hash(hasher);

        Ok(RangeProof {
            comm_r,
            comm_s,
            comm_ck,
            comm_x,
            comm_bp_x,
            range_comms,
            r: r_rand + challenge * r,
            s: s_rand + challenge * ck.secret,
            range_proof,
            xs: x_rands
                .iter()
                .zip(input)
                .map(|(r, x)| r + challenge * Scalar::from(*x))
                .collect(),
            bp_rs: bp_r_rands
                .iter()
                .zip(range_rands)
                .map(|(r, x)| r + challenge * x)
                .collect(),
        })
    }

    fn verify(
        vk: &Self::VerifierKey,
        params: &AggParams,
        proof_index: usize,
        encoding: &Encoding,
        proof: &Self::Proof, // TODO: Remove clones
    ) -> Result<()> {
        // Apply fiat-shamir to non-interactively generate challenge
        //
        // TODO: Actually include the full transcript here
        let mut hasher = Sha3_512::new();
        hasher.update(params.g.compress().to_bytes().as_ref());
        hasher.update(params.h.compress().to_bytes().as_ref());
        hasher.update(encoding.rand.compress().to_bytes().as_ref());
        let challenge = Scalar::from_hash(hasher);

        // Check 1) c_0 = g^r
        check_claim!(
            params.g * proof.r,
            proof.comm_r + encoding.rand * challenge,
            "Claim failed: c_0 = g^r"
        );

        // Check 2) c_1 = pk_0^r * g^s
        check_claim!(
            params.pks[0] * proof.r + params.g * proof.s,
            proof.comm_s + encoding.secret * challenge,
            "Claim failed: c_1 = pk_0^r * g^s"
        );

        // Check 3) ck = h^s
        check_claim!(
            params.h * proof.s,
            proof.comm_ck + params.client_key_comms[proof_index] * challenge,
            "Claim failed: ck = h^s"
        );

        // Verify range proof
        let range_params = Self::get_bp_params(*vk, params.h, encoding.vals.len())?;
        let statement = RangeStatement::init(
            range_params,
            proof.range_comms.clone(),
            vec![None; encoding.vals.len()],
            None,
        )
        .map_err(|e| anyhow::anyhow!("Failed to generate proof statement: {}", e))?;
        RistrettoRangeProof::verify_batch(
            &mut [Transcript::new(b"range_proof")],
            &[statement],
            &[proof.range_proof.clone()],
            VerifyAction::VerifyOnly,
        )
        .map_err(|e| anyhow::anyhow!("Failed to verify proof: {}", e))?;

        // Check that each commiment from the range proof is consistent with the ciphertext
        for i in 0..encoding.vals.len() {
            check_claim!(
                params.pks[i + 1] * proof.r + params.g * proof.xs[i],
                proof.comm_x[i] + encoding.vals[i] * challenge,
                "Claim failed: ciphertext consistency"
            );

            check_claim!(
                params.h * proof.bp_rs[i] + params.g * proof.xs[i],
                proof.comm_bp_x[i] + proof.range_comms[i] * challenge,
                "Claim failed: bulletproof consistency"
            );
        }

        Ok(())
    }



    fn batch_verify<R: RngCore + CryptoRng>(
        vk: &Self::VerifierKey,
        params: &AggParams,
        proof_indices: &[usize],
        encodings: &[Encoding],
        proofs: &[Self::Proof],
        rng: &mut R,
    ) -> Result<()> {
        // We batch by taking a random linear combination over all Schnorr claims.
        // (The range proofs are done separately.)
        //
        // Here we generate all the necessary randomnesss upfront.
        let num_proof_claims = 3 + 2 * encodings[0].vals.len();
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
        let range_params = Self::get_bp_params(*vk, params.h, encodings[0].vals.len())?;

        // For each proof, add the relevant terms to the final MSM computation
        for ((proof_idx, encoding), proof) in proof_indices.iter().zip(encodings).zip(proofs) {
            let statement = RangeStatement::init(
                range_params.clone(),
                proof.range_comms.clone(),
                vec![None; encoding.vals.len()],
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
            //
            // TODO: Actually include the full transcript here
            //
            // TODO: Precompute hash for public parts and clone when computing separate
            let mut hasher = Sha3_512::new();
            hasher.update(params.g.compress().to_bytes().as_ref());
            hasher.update(params.h.compress().to_bytes().as_ref());
            hasher.update(encoding.rand.compress().to_bytes().as_ref());
            let challenge = Scalar::from_hash(hasher);

            // Check 1) c_0 = g^r
            g_scalar += proof.r * rands[r_idx];
            add_term(-rands[r_idx], proof.comm_r);
            add_term(-challenge * rands[r_idx], encoding.rand);
            r_idx += 1;

            // Check 2) c_1 = pk_0^r * g^s
            pk_scalars[0] += proof.r * rands[r_idx];
            g_scalar += proof.s * rands[r_idx];
            add_term(-rands[r_idx], proof.comm_s);
            add_term(-challenge * rands[r_idx], encoding.secret);
            r_idx += 1;

            // Check 3) c_2 = h^s
            h_scalar += proof.s * rands[r_idx];
            add_term(-rands[r_idx], proof.comm_ck);
            add_term(
                -challenge * rands[r_idx],
                params.client_key_comms[*proof_idx],
            );
            r_idx += 1;

            // Check 4) Pederson commitments are consistent with the ciphertext
            for i in 0..encoding.vals.len() {
                g_scalar += proof.xs[i] * rands[r_idx];
                h_scalar += proof.bp_rs[i] * rands[r_idx];
                add_term(-rands[r_idx], proof.comm_bp_x[i]);
                add_term(-challenge * rands[r_idx], proof.range_comms[i]);
                r_idx += 1;

                g_scalar += proof.xs[i] * rands[r_idx];
                pk_scalars[i + 1] += proof.r * rands[r_idx];
                add_term(-rands[r_idx], proof.comm_x[i]);
                add_term(-challenge * rands[r_idx], encoding.vals[i]);
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
            Err(anyhow::anyhow!(
                "Batch verification failed (ciphertext consistency)"
            ))
        }
    }

    fn prove_untagged<R: RngCore + CryptoRng>(
        pk: &Self::ProverKey, // bitlength
        ck: &ClientKey,
        input: &[u64],
        r: Scalar,
        encoding: &Encoding,
        rng: &mut R,
    ) -> Result<Self::Proof> {
        // First, generate the bulletproof proof
        let (range_comms, range_rands, range_proof) = Self::prove_bulletproof(*pk, ck, input, rng)?;

        // Generate commitments for claim 1 only (skip claims 2-3 related to secret key)
        let r_rand = Scalar::random(&mut *rng);
        let comm_r = ck.g * r_rand;

        // Generate commitments to bind the ciphertext to the bulletproof proof
        let x_rands = vec![Scalar::random(&mut *rng); input.len()];
        let bp_r_rands = vec![Scalar::random(&mut *rng); input.len()];
        let mut comm_x = Vec::with_capacity(input.len());
        let mut comm_bp_x = Vec::with_capacity(input.len());
        for i in 0..input.len() {
            comm_x.push(ck.pks[i + 1] * r_rand + ck.g * x_rands[i]);
            comm_bp_x.push(ck.h * bp_r_rands[i] + ck.g * x_rands[i]);
        }

        // Apply fiat-shamir to non-interactively generate challenge
        //
        // TODO: Actually include the full transcript here
        let hasher = Sha3_512::new()
            .chain_update(ck.g.compress().to_bytes().as_ref())
            .chain_update(ck.h.compress().to_bytes().as_ref())
            .chain_update(encoding.rand.compress().to_bytes().as_ref());
        let challenge = Scalar::from_hash(hasher);

        Ok(RangeProof {
            comm_r,
            comm_s: G::identity(), // TODO: hacky
            comm_ck: G::identity(),
            comm_x,
            comm_bp_x,
            range_comms,
            r: r_rand + challenge * r,
            s: Scalar::ZERO, // Skip secret key claim
            range_proof,
            xs: x_rands
                .iter()
                .zip(input)
                .map(|(r, x)| r + challenge * Scalar::from(*x))
                .collect(),
            bp_rs: bp_r_rands
                .iter()
                .zip(range_rands)
                .map(|(r, x)| r + challenge * x)
                .collect(),
        })
    }

    fn batch_verify_untagged<R: RngCore + CryptoRng>(
        vk: &Self::VerifierKey,
        params: &AggParams,
        proof_indices: &[usize],
        encodings: &[Encoding],
        proofs: &[Self::Proof],
        rng: &mut R,
    ) -> Result<()> {
        // We batch by taking a random linear combination over all Schnorr claims.
        // (The range proofs are done separately.)
        //
        // Here we generate all the necessary randomnesss upfront.
        let num_proof_claims = 1 + 2 * encodings[0].vals.len(); // Only claim 1 + range consistency
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
        let range_params = Self::get_bp_params(*vk, params.h, encodings[0].vals.len())?;

        // For each proof, add the relevant terms to the final MSM computation
        for ((_proof_idx, encoding), proof) in proof_indices.iter().zip(encodings).zip(proofs) {
            let statement = RangeStatement::init(
                range_params.clone(),
                proof.range_comms.clone(),
                vec![None; encoding.vals.len()],
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
            //
            // TODO: Actually include the full transcript here
            //
            // TODO: Precompute hash for public parts and clone when computing separate
            let mut hasher = Sha3_512::new();
            hasher.update(params.g.compress().to_bytes().as_ref());
            hasher.update(params.h.compress().to_bytes().as_ref());
            hasher.update(encoding.rand.compress().to_bytes().as_ref());
            let challenge = Scalar::from_hash(hasher);

            // Check 1) c_0 = g^r
            g_scalar += proof.r * rands[r_idx];
            add_term(-rands[r_idx], proof.comm_r);
            add_term(-challenge * rands[r_idx], encoding.rand);
            r_idx += 1;

            // Check 4) Pederson commitments are consistent with the ciphertext
            for i in 0..encoding.vals.len() {
                g_scalar += proof.xs[i] * rands[r_idx];
                h_scalar += proof.bp_rs[i] * rands[r_idx];
                add_term(-rands[r_idx], proof.comm_bp_x[i]);
                add_term(-challenge * rands[r_idx], proof.range_comms[i]);
                r_idx += 1;

                g_scalar += proof.xs[i] * rands[r_idx];
                pk_scalars[i + 1] += proof.r * rands[r_idx];
                add_term(-rands[r_idx], proof.comm_x[i]);
                add_term(-challenge * rands[r_idx], encoding.vals[i]);
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
            Err(anyhow::anyhow!(
                "Batch verification failed (ciphertext consistency)"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ElGamal, Scalar, messages::Encoding};

    use rand::{Rng, rngs::OsRng};

    type P = Range;
    type Agg = ElGamal;

    #[test]
    fn proof_correctness() {
        let num_clients = 5;
        let length = 4;
        let bitlength = 8; // 8-bit range [0, 256)
        let (params, _sk, cks) = Agg::setup(num_clients, length, &mut OsRng);
        let (prover_key, verifier_key) = P::setup(length, bitlength);
        let mut rng = rand::thread_rng();

        let mut encodings = Vec::with_capacity(num_clients);
        let mut proofs = Vec::with_capacity(num_clients);
        for i in 0..num_clients {
            // Generate random inputs within the range [0, 2^bitlength)
            let input: Vec<u64> = (0..length)
                .map(|_| rng.gen_range(0..(1 << bitlength)))
                .collect();

            let r = Scalar::random(&mut OsRng);
            let encoding = Encoding {
                rand: params.g * r,
                secret: params.pks[0] * r + params.g * cks[i].secret,
                vals: input
                    .iter()
                    .enumerate()
                    .map(|(j, v)| params.pks[j + 1] * r + params.g * Scalar::from(*v))
                    .collect(),
            };

            let proof = P::prove(&prover_key, &cks[i], &input, r, &encoding, &mut OsRng).unwrap();

            if let Err(err) = P::verify(&verifier_key, &params, i, &encoding, &proof) {
                panic!("Verification error: {:?}", err);
            }

            // Save for batch verification
            encodings.push(encoding);
            proofs.push(proof);
        }

        // Check batch verification
        if let Err(err) = P::batch_verify(
            &verifier_key,
            &params,
            &(0..num_clients).collect::<Vec<_>>(),
            &encodings,
            &proofs,
            &mut OsRng,
        ) {
            panic!("Batch verification error: {:?}", err);
        };
    }

    /// Tests that inputs outside the range are rejected
    #[test]
    fn proof_soundness_out_of_range() {
        let length = 2;
        let bitlength = 4; // 4-bit range [0, 16)
        let (params, _sk, cks) = Agg::setup(1, length, &mut OsRng);
        let (prover_key, _verifier_key) = P::setup(length, bitlength);

        // Test with values outside the range
        let bad_inputs = vec![
            vec![16, 5],  // 16 is outside [0, 16)
            vec![5, 20],  // 20 is outside [0, 16)
            vec![100, 3], // 100 is outside [0, 16)
        ];

        for bad_input in bad_inputs {
            let r = Scalar::random(&mut OsRng);
            let encoding = Encoding {
                rand: params.g * r,
                secret: params.pks[0] * r + params.g * cks[0].secret,
                vals: bad_input
                    .iter()
                    .enumerate()
                    .map(|(i, v)| params.pks[i + 1] * r + params.g * Scalar::from(*v))
                    .collect(),
            };

            // This should fail because the inputs are outside the range
            let result = P::prove(&prover_key, &cks[0], &bad_input, r, &encoding, &mut OsRng);
            assert!(
                result.is_err(),
                "Should fail for out-of-range input {:?}",
                bad_input
            );
        }
    }

    /// Tests that tampered data is rejected by proof verification
    #[test]
    fn proof_soundness_tampering() {
        let num_clients = 2;
        let length = 2;
        let bitlength = 8;
        let (params, _sk, cks) = Agg::setup(num_clients, length, &mut OsRng);
        let (prover_key, verifier_key) = P::setup(length, bitlength);
        let mut rng = rand::thread_rng();

        let input: Vec<u64> = (0..length)
            .map(|_| rng.gen_range(0..(1 << bitlength)))
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

        // Try tampering with the encoding and assert that it is rejected
        let mut bad_encoding = encoding.clone();
        bad_encoding.rand = params.g * Scalar::random(&mut OsRng);
        assert!(P::verify(&verifier_key, &params, 0, &bad_encoding, &proof).is_err());
        assert!(
            P::batch_verify(
                &verifier_key,
                &params,
                &[0, 1],
                &[bad_encoding.clone(), encoding.clone()],
                &[proof.clone(), proof.clone()],
                &mut OsRng
            )
            .is_err()
        );

        let mut bad_encoding = encoding.clone();
        bad_encoding.secret = params.g * Scalar::random(&mut OsRng);
        assert!(P::verify(&verifier_key, &params, 0, &bad_encoding, &proof).is_err());
        assert!(
            P::batch_verify(
                &verifier_key,
                &params,
                &[0, 1],
                &[bad_encoding.clone(), encoding.clone()],
                &[proof.clone(), proof.clone()],
                &mut OsRng
            )
            .is_err()
        );

        for i in 0..encoding.vals.len() {
            let mut bad_encoding = encoding.clone();
            bad_encoding.vals[i] = params.g * Scalar::random(&mut OsRng);
            println!(
                "bad_encoding: {:?}",
                P::verify(&verifier_key, &params, 0, &bad_encoding, &proof)
            );
            assert!(P::verify(&verifier_key, &params, 0, &bad_encoding, &proof).is_err());
            assert!(
                P::batch_verify(
                    &verifier_key,
                    &params,
                    &[0, 1],
                    &[bad_encoding.clone(), encoding.clone()],
                    &[proof.clone(), proof.clone()],
                    &mut OsRng
                )
                .is_err()
            );
        }
    }

    /// Tests that wrong client indices are rejected by proof verification
    #[test]
    fn proof_soundness_wrong_client() {
        let num_clients = 3;
        let length = 2;
        let bitlength = 8;
        let (params, _sk, cks) = Agg::setup(num_clients, length, &mut OsRng);
        let (prover_key, verifier_key) = P::setup(length, bitlength);
        let mut rng = rand::thread_rng();

        let input: Vec<u64> = (0..length)
            .map(|_| rng.gen_range(0..(1 << bitlength)))
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

        // Batch verification should also fail with wrong client indices
        assert!(
            P::batch_verify(
                &verifier_key,
                &params,
                &[1, 0],
                &[encoding.clone(), encoding.clone()],
                &[proof.clone(), proof.clone()],
                &mut OsRng
            )
            .is_err()
        );
        assert!(
            P::batch_verify(
                &verifier_key,
                &params,
                &[2, 0],
                &[encoding.clone(), encoding.clone()],
                &[proof.clone(), proof.clone()],
                &mut OsRng
            )
            .is_err()
        );
    }

    /// Tests that bulletproof-ciphertext consistency checks prevent attacks where
    /// a client proves a bulletproof over different values than what's in the ciphertext
    #[test]
    fn proof_soundness_bulletproof_ciphertext_inconsistency() {
        let num_clients = 2;
        let length = 2;
        let bitlength = 8;
        let (params, _sk, cks) = Agg::setup(num_clients, length, &mut OsRng);
        let (prover_key, verifier_key) = P::setup(length, bitlength);
        let mut rng = rand::thread_rng();

        // Create valid input for the ciphertext
        let input: Vec<u64> = (0..length)
            .map(|_| rng.gen_range(0..(1 << bitlength)))
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

        // Create a valid proof first
        let mut proof = P::prove(&prover_key, &cks[0], &input, r, &encoding, &mut OsRng).unwrap();

        // Verify the original proof is valid
        assert!(P::verify(&verifier_key, &params, 0, &encoding, &proof).is_ok());

        // Attack 1: Tamper with the bulletproof commitments to use different values
        // This simulates proving a bulletproof over different values than the ciphertext
        let fake_input: Vec<u64> = (0..length)
            .map(|_| rng.gen_range(0..(1 << bitlength)))
            .collect();

        // Generate new bulletproof commitments for the fake input
        let (fake_range_comms, _fake_range_rands, fake_range_proof) =
            Range::prove_bulletproof(bitlength, &cks[0], &fake_input, &mut OsRng).unwrap();

        // Replace the bulletproof components with fake ones
        proof.range_comms = fake_range_comms;
        proof.range_proof = fake_range_proof;

        // The proof should now fail because the bulletproof commitments don't match
        // the ciphertext values in the consistency check
        assert!(P::verify(&verifier_key, &params, 0, &encoding, &proof).is_err());
        assert!(
            P::batch_verify(
                &verifier_key,
                &params,
                &[0, 1],
                &[encoding.clone(), encoding.clone()],
                &[proof.clone(), proof.clone()],
                &mut OsRng
            )
            .is_err()
        );

        // Attack 2: Tamper with the binding commitments (comm_x, comm_bp_x) to break
        // the consistency between bulletproof and ciphertext
        let mut proof = P::prove(&prover_key, &cks[0], &input, r, &encoding, &mut OsRng).unwrap();

        // Replace comm_x with random commitments
        for i in 0..proof.comm_x.len() {
            proof.comm_x[i] = params.g * Scalar::random(&mut OsRng);
        }

        // The proof should fail because comm_x no longer binds the ciphertext to the bulletproof
        assert!(P::verify(&verifier_key, &params, 0, &encoding, &proof).is_err());
        assert!(
            P::batch_verify(
                &verifier_key,
                &params,
                &[0, 1],
                &[encoding.clone(), encoding.clone()],
                &[proof.clone(), proof.clone()],
                &mut OsRng
            )
            .is_err()
        );

        // Attack 3: Tamper with comm_bp_x to break bulletproof consistency
        let mut proof = P::prove(&prover_key, &cks[0], &input, r, &encoding, &mut OsRng).unwrap();

        // Replace comm_bp_x with random commitments
        for i in 0..proof.comm_bp_x.len() {
            proof.comm_bp_x[i] = params.g * Scalar::random(&mut OsRng);
        }

        // The proof should fail because comm_bp_x no longer binds the bulletproof commitments
        assert!(P::verify(&verifier_key, &params, 0, &encoding, &proof).is_err());
        assert!(
            P::batch_verify(
                &verifier_key,
                &params,
                &[0, 1],
                &[encoding.clone(), encoding.clone()],
                &[proof.clone(), proof.clone()],
                &mut OsRng
            )
            .is_err()
        );

        // Attack 4: Tamper with the response values (xs, bp_rs) to break the consistency
        let mut proof = P::prove(&prover_key, &cks[0], &input, r, &encoding, &mut OsRng).unwrap();

        // Replace xs with random values
        for i in 0..proof.xs.len() {
            proof.xs[i] = Scalar::random(&mut OsRng);
        }

        // The proof should fail because xs no longer satisfy the consistency equations
        assert!(P::verify(&verifier_key, &params, 0, &encoding, &proof).is_err());
        assert!(
            P::batch_verify(
                &verifier_key,
                &params,
                &[0, 1],
                &[encoding.clone(), encoding.clone()],
                &[proof.clone(), proof.clone()],
                &mut OsRng
            )
            .is_err()
        );
    }

    /// Tests basic untagged proof correctness with batch verification  
    #[test]
    fn untagged_proof_correctness() {
        let num_clients = 3;
        let length = 2;
        let bitlength = 8; // 8-bit range [0, 256)
        let (params, _sk, cks) = Agg::setup(num_clients, length, &mut OsRng);
        let (prover_key, verifier_key) = P::setup(length, bitlength);
        let mut rng = rand::thread_rng();

        let mut encodings = Vec::with_capacity(num_clients);
        let mut proofs = Vec::with_capacity(num_clients);
        for i in 0..num_clients {
            // Generate random inputs within the range [0, 2^bitlength)
            let input: Vec<u64> = (0..length)
                .map(|_| rng.gen_range(0..(1 << bitlength)))
                .collect();

            let r = Scalar::random(&mut OsRng);
            let encoding = Encoding {
                rand: params.g * r,
                secret: params.pks[0] * r + params.g * cks[i].secret,
                vals: input
                    .iter()
                    .enumerate()
                    .map(|(j, v)| params.pks[j + 1] * r + params.g * Scalar::from(*v))
                    .collect(),
            };
            let proof = P::prove_untagged(&prover_key, &cks[i], &input, r, &encoding, &mut OsRng).unwrap();
            encodings.push(encoding);
            proofs.push(proof);
        }

        assert!(
            P::batch_verify_untagged(
                &verifier_key,
                &params,
                &(0..num_clients).collect::<Vec<_>>(),
                &encodings,
                &proofs,
                &mut OsRng
            )
            .is_ok()
        );
    }
}
