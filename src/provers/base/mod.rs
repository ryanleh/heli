use crate::{
    check_claim,
    agg_only_enc::EvalKey,
    crypto::{G, Scalar, ElGamalPublicKey, ElGamalCiphertext, KHPRF},
};
use super::{Prover, fiat_shamir};

use anyhow::Result;
use curve25519_dalek::traits::MultiscalarMul;
use group::Group;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BaseProverKey {
    /// Generator for key commitments
    g_comm: G,
    /// Commitment to an evaluation key
    key_commitment: G,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BaseVerifierKey {
    /// ElGamal public-key
    enc_pk: ElGamalPublicKey,
    /// Generator for key commitments
    g_comm: G,
    /// Commitments to the evaluation keys
    key_commitments: Vec<G>,
}

/// Schnorr proof of well-formedness for aggregation-only ciphertext.
/// Does not prove anything about the inputs.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BaseProof {
    /// Commitments
    pub(crate) commitments: BaseCommiments,
    /// Responses
    pub(crate) responses: BaseResponses,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BaseCommiments {
    /// Commitment for for claim 1) c_0 = g^r.
    pub(super) g_r: G,
    /// Commitment for for claim 2) c_1 = pk_0^r * H(context)^k.
    pub(super) g_k: G,
    /// Commitments for for claim 3) DLEQ(g_comm^k, H(context)^k)
    pub(super) g_comm_k: G,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BaseResponses {
    /// Response for proving knowledge of r.
    pub(super) r: Scalar,
    /// Response for proving knowledge of k.
    pub(super) k: Scalar,
}

impl Prover for BaseProof {
    type ProverKey = BaseProverKey;
    type VerifierKey = BaseVerifierKey;
    type Proof = BaseProof;

    fn setup(eval_keys: &[EvalKey], _: usize) -> (Vec<Self::ProverKey>, Self::VerifierKey) {
        // TODO: Generate this differently
        let g_comm = G::from_hash(Sha3_512::new().chain_update(b"h"));

        // Compute commitments to each evaluation key
        let (prover_keys, key_commitments) = eval_keys.iter().map(|ek| {
            let key_commitment = g_comm * ek.prf_key_share;
            (BaseProverKey { g_comm, key_commitment }, key_commitment)
        }).unzip();

        let enc_pk = eval_keys[0].enc_pk.clone();
        (prover_keys, BaseVerifierKey { enc_pk, g_comm, key_commitments })
    }

    /// Prove the following relation (informally stated) for secrets r and k:
    ///  1) c_0 = g^r, 
    ///  2) c_1 = pk_0^r * H(context)^k, and
    ///  3) DLEQ(g_comm^k, H(context)^k) 
    ///
    /// This enforces that the client's aggregation-only ciphertext is well-formed.
    fn prove<R: RngCore + CryptoRng>(
        pk: &Self::ProverKey,
        ek: &EvalKey,
        context: u64,
        r: Scalar,
        _input: &[Scalar],
        rng: &mut R,
    ) -> Result<Self::Proof> {
        let g = G::generator();

        // Generate commitments
        let r_rand = Scalar::random(&mut *rng);
        let k_rand = Scalar::random(&mut *rng);
        let g_r = g * r_rand;
        let g_k = ek.enc_pk[1] * r_rand + KHPRF::evaluate(&k_rand, context);
        let g_comm_k = pk.g_comm * k_rand;

        // Generate challenge via fiat-shamir
        // 
        // TODO: This doesn't include full transcript atm
        let commitments = BaseCommiments { g_r, g_k, g_comm_k };
        let challenge = fiat_shamir(&[g, pk.g_comm, g_r, g_k, g_comm_k], &[]);

        Ok(BaseProof {
            commitments,
            responses: BaseResponses {
                r: r_rand + challenge * r,
                k: k_rand + challenge * ek.prf_key_share,
            },
        })
    }

    fn verify(
        vk: &Self::VerifierKey,
        ciphertext: &ElGamalCiphertext,
        context: u64,
        proof: &Self::Proof,
        proof_index: usize,
    ) -> Result<()> {
        let g = G::generator();

        // Comptue challenge via fiat-shamir
        //
        // TODO: This doesn't include full transcript atm
        let challenge = fiat_shamir(&[
            g,
            vk.g_comm,
            proof.commitments.g_r,
            proof.commitments.g_k,
            proof.commitments.g_comm_k,
        ], &[]);

        // Check 1) c_0 = g^r
        check_claim!(
            g * proof.responses.r,
            proof.commitments.g_r + ciphertext.rand * challenge,
            "Claim failed: c_0 = g^r"
        );

        // Check 2) c_1 = pk_1^r * H(context)^k
        check_claim!(
            vk.enc_pk[1] * proof.responses.r + KHPRF::evaluate(&proof.responses.k, context),
            proof.commitments.g_k + ciphertext.slots[ciphertext.slots.len() - 1] * challenge,
            "Claim failed: c_1 = pk_1^r * H(context)^k"
        );

        // Check 3) DLEQ(g_comm^k, H(context)^k)
        //
        // (Note that we've already shown knowledge of H(context)^k in the previous claim)
        check_claim!(
            vk.g_comm * proof.responses.k,
            proof.commitments.g_comm_k + vk.key_commitments[proof_index] * challenge,
            "Claim failed: ck = h^s"
        );
        Ok(())
    }

    fn batch_verify<R: RngCore + CryptoRng>(
        vk: &Self::VerifierKey,
        ciphertexts: &[ElGamalCiphertext],
        context: u64,
        proofs: &[Self::Proof],
        proof_indices: &[usize],
        rng: &mut R,
    ) -> Result<()> {
        let g = G::generator();
        
        // We batch by taking a random linear combination over all claims.
        // Each proof has 3 claims, so we need 3 random scalars per proof.
        let num_proofs = proof_indices.len();
        let total_claims = num_proofs * 3;
        let rands: Vec<_> = (0..total_claims)
            .map(|_| Scalar::random(&mut *rng))
            .collect();

        // Accumulate scalars for shared bases
        let mut g_scalar = Scalar::ZERO;
        let mut pk_scalar = Scalar::ZERO;
        let mut prf_scalar = Scalar::ZERO;
        let mut g_comm_scalar = Scalar::ZERO;
        
        // Individual terms for MSM
        let mut scalars = Vec::new();
        let mut bases = Vec::new();

        // Helper closure to add terms to the MSM vectors
        let mut add_term = |scalar: Scalar, base: G| {
            scalars.push(scalar);
            bases.push(base);
        };

        let mut r_idx = 0;

        // For each proof, add the relevant terms to the final MSM computation
        for i in 0..num_proofs {
            let proof_idx = proof_indices[i];
            let ciphertext = &ciphertexts[i];
            let proof = &proofs[i];

            // Compute challenge via fiat-shamir (same as in verify)
            let challenge = fiat_shamir(&[
                g,
                vk.g_comm,
                proof.commitments.g_r,
                proof.commitments.g_k,
                proof.commitments.g_comm_k,
            ], &[]);

            // Check 1) c_0 = g^r
            g_scalar += proof.responses.r * rands[r_idx];
            add_term(-rands[r_idx], proof.commitments.g_r);
            add_term(-challenge * rands[r_idx], ciphertext.rand);
            r_idx += 1;

            // Check 2) c_1 = pk_0^r * H(context)^k
            pk_scalar += proof.responses.r * rands[r_idx];
            prf_scalar += proof.responses.k * rands[r_idx];
            add_term(-rands[r_idx], proof.commitments.g_k);
            add_term(-challenge * rands[r_idx], ciphertext.slots[ciphertext.slots.len() - 1]);
            r_idx += 1;

            // Check 3) DLEQ(g_comm^k, H(context)^k)
            g_comm_scalar += proof.responses.k * rands[r_idx];
            add_term(-rands[r_idx], proof.commitments.g_comm_k);
            add_term(-challenge * rands[r_idx], vk.key_commitments[proof_idx]);
            r_idx += 1;
        }

        // Add the shared basis terms
        scalars.push(g_scalar);
        scalars.push(pk_scalar);
        scalars.push(prf_scalar);
        scalars.push(g_comm_scalar);
        bases.push(g);
        bases.push(vk.enc_pk[vk.enc_pk.len() - 1]);
        bases.push(KHPRF::evaluate(&Scalar::ONE, context));
        bases.push(vk.g_comm);

        // If all proofs are valid, the MSM should equal the identity
        if G::multiscalar_mul(&scalars, &bases) == G::identity() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Batch verification failed"))
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::agg_only_enc::AggOnlyEnc;
    use rand::rngs::OsRng;

     #[test]
     fn base_proof_correctness() {
         let mut rng = OsRng;
         
         // Setup
         let (_secret_key, eval_keys) = AggOnlyEnc::setup(1, 1, &mut rng);
         let (prover_keys, verifier_key) = BaseProof::setup(&eval_keys, 1);

         // Generate a ciphertext and proof
         let r = Scalar::random(&mut rng);
         let input = vec![Scalar::from(rng.next_u64())];
         let ciphertext = AggOnlyEnc::encrypt(&eval_keys[0], 0, r, &input);
         let proof = BaseProof::prove(
             &prover_keys[0],
             &eval_keys[0],
             0,
             r,
             &input,
             &mut rng
         ).unwrap();
            
         // Test individual verification
         assert!(
             BaseProof::verify(&verifier_key, &ciphertext, 0, &proof, 0).is_ok(),
             "Individual proof verification failed for input {:?}",
             input
         );

         // Test batch verification
         assert!(
             BaseProof::batch_verify(
                 &verifier_key,
                 &[ciphertext],
                 0,
                 &[proof],
                 &[0],
                 &mut rng
             ).is_ok(),
             "Batch proof verification failed for input {:?}",
             input
         );
     }

     #[test]
     fn base_proof_soundness_tampering() {
         let mut rng = OsRng;
         
         // Setup
         let (_secret_key, eval_keys) = AggOnlyEnc::setup(1, 1, &mut rng);
         let (prover_keys, verifier_key) = BaseProof::setup(&eval_keys, 1);
         
         // Generate a valid ciphertext and proof
         let r = Scalar::random(&mut rng);
         let input = vec![Scalar::from(rng.next_u64())];
         let context = rng.next_u64();
         let ciphertext = AggOnlyEnc::encrypt(&eval_keys[0], context, r, &input);
         let proof = BaseProof::prove(
             &prover_keys[0],
             &eval_keys[0],
             context,
             r,
             &input,
             &mut rng
         ).unwrap();

         // Verify the original proof is valid with both methods
         assert!(BaseProof::verify(&verifier_key, &ciphertext, context, &proof, 0).is_ok());
         assert!(BaseProof::batch_verify(&verifier_key, &[ciphertext.clone()], context, &[proof.clone()], &[0], &mut rng).is_ok());

         // Try tampering the ciphertext and assert that it is rejected by both methods
         let mut bad_ciphertext = ciphertext.clone();
         bad_ciphertext.rand = G::generator() * Scalar::random(&mut rng);
         assert!(BaseProof::verify(&verifier_key, &bad_ciphertext, context, &proof, 0).is_err());
         assert!(BaseProof::batch_verify(&verifier_key, &[bad_ciphertext], context, &[proof.clone()], &[0], &mut rng).is_err());

         // Tampering the attestation slot (slots[1]) should be detected by both methods
         let mut bad_ciphertext = ciphertext.clone();
         bad_ciphertext.slots[ciphertext.slots.len() - 1] = G::generator() * Scalar::random(&mut rng);
         assert!(BaseProof::verify(&verifier_key, &bad_ciphertext, context, &proof, 0).is_err());
         assert!(BaseProof::batch_verify(&verifier_key, &[bad_ciphertext], context, &[proof.clone()], &[0], &mut rng).is_err());

         // Try tampering the proof and assert that it is rejected by both methods
         let mut bad_proof = proof.clone();
         bad_proof.responses.r = Scalar::random(&mut rng);
         assert!(BaseProof::verify(&verifier_key, &ciphertext, context, &bad_proof, 0).is_err());
         assert!(BaseProof::batch_verify(&verifier_key, &[ciphertext.clone()], context, &[bad_proof], &[0], &mut rng).is_err());

         let mut bad_proof = proof.clone();
         bad_proof.responses.k = Scalar::random(&mut rng);
         assert!(BaseProof::verify(&verifier_key, &ciphertext, context, &bad_proof, 0).is_err());
         assert!(BaseProof::batch_verify(&verifier_key, &[ciphertext.clone()], context, &[bad_proof], &[0], &mut rng).is_err());

         let mut bad_proof = proof.clone();
         bad_proof.commitments.g_r = G::generator() * Scalar::random(&mut rng);
         assert!(BaseProof::verify(&verifier_key, &ciphertext, context, &bad_proof, 0).is_err());
         assert!(BaseProof::batch_verify(&verifier_key, &[ciphertext.clone()], context, &[bad_proof], &[0], &mut rng).is_err());

         let mut bad_proof = proof.clone();
         bad_proof.commitments.g_k = G::generator() * Scalar::random(&mut rng);
         assert!(BaseProof::verify(&verifier_key, &ciphertext, context, &bad_proof, 0).is_err());
         assert!(BaseProof::batch_verify(&verifier_key, &[ciphertext.clone()], context, &[bad_proof], &[0], &mut rng).is_err());

         let mut bad_proof = proof.clone();
         bad_proof.commitments.g_comm_k = G::generator() * Scalar::random(&mut rng);
         assert!(BaseProof::verify(&verifier_key, &ciphertext, context, &bad_proof, 0).is_err());
         assert!(BaseProof::batch_verify(&verifier_key, &[ciphertext.clone()], context, &[bad_proof], &[0], &mut rng).is_err());
     }

     #[test]
     fn base_proof_soundness_wrong_client() {
         let mut rng = OsRng;
         
         // Setup with multiple clients
         let (_secret_key, eval_keys) = AggOnlyEnc::setup(3, 1, &mut rng);
         let (prover_keys, verifier_key) = BaseProof::setup(&eval_keys, 1);
         
         // Generate a valid ciphertext and proof for client 0
         let r = Scalar::random(&mut rng);
         let input = vec![Scalar::from(rng.next_u64())];
         let context = rng.next_u64();
         let ciphertext = AggOnlyEnc::encrypt(&eval_keys[0], context, r, &input);
         let proof = BaseProof::prove(
             &prover_keys[0],
             &eval_keys[0],
             context,
             r,
             &input,
             &mut rng
         ).unwrap();

         // Verify with correct client index using both methods
         assert!(BaseProof::verify(&verifier_key, &ciphertext, context, &proof, 0).is_ok());
         assert!(BaseProof::batch_verify(&verifier_key, &[ciphertext.clone()], context, &[proof.clone()], &[0], &mut rng).is_ok());

         // Verify with wrong client index using both methods
         assert!(BaseProof::verify(&verifier_key, &ciphertext, context, &proof, 1).is_err());
         assert!(BaseProof::batch_verify(&verifier_key, &[ciphertext.clone()], context, &[proof.clone()], &[1], &mut rng).is_err());
         
         assert!(BaseProof::verify(&verifier_key, &ciphertext, context, &proof, 2).is_err());
         assert!(BaseProof::batch_verify(&verifier_key, &[ciphertext.clone()], context, &[proof.clone()], &[2], &mut rng).is_err());
     }

     #[test]
     fn base_proof_batch_correctness() {
         let mut rng = OsRng;
         let num_clients = 3;
         
         // Setup with multiple clients
         let (_secret_key, eval_keys) = AggOnlyEnc::setup(num_clients, 1, &mut rng);
         let (prover_keys, verifier_key) = BaseProof::setup(&eval_keys, 1);

         let mut ciphertexts = Vec::with_capacity(num_clients);
         let mut proofs = Vec::with_capacity(num_clients);
         let mut proof_indices = Vec::with_capacity(num_clients);
         let context = rng.next_u64(); // Use same context for all clients
         
         for i in 0..num_clients {
             let r = Scalar::random(&mut rng);
             let input = vec![Scalar::from(rng.next_u64())];
             
             let ciphertext = AggOnlyEnc::encrypt(&eval_keys[i], context, r, &input);
             let proof = BaseProof::prove(
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
                 BaseProof::verify(&verifier_key, &ciphertexts[i], context, &proofs[i], i).is_ok(),
                 "Individual proof verification failed for client {}",
                 i
             );
         }

         // Test batch verification
         assert!(
             BaseProof::batch_verify(
                 &verifier_key,
                 &ciphertexts,
                 context,
                 &proofs,
                 &proof_indices,
                 &mut rng
             ).is_ok(),
             "Batch proof verification failed"
         );

         // Test mixed verification: some individual, some batch
         // Verify first two individually, then batch verify all three
         assert!(BaseProof::verify(&verifier_key, &ciphertexts[0], context, &proofs[0], 0).is_ok());
         assert!(BaseProof::verify(&verifier_key, &ciphertexts[1], context, &proofs[1], 1).is_ok());
         assert!(
             BaseProof::batch_verify(
                 &verifier_key,
                 &ciphertexts,
                 context,
                 &proofs,
                 &proof_indices,
                 &mut rng
             ).is_ok(),
             "Mixed individual and batch verification failed"
         );
     }
}