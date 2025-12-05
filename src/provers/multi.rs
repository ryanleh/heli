use crate::{
    agg_only_enc::EvalKey,
    crypto::{Scalar, ElGamalCiphertext},
    provers::{ciphertext, input, Prover},
};

use anyhow::Result;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Combined prover key that can handle both ciphertext and input proofs
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum MultiProverKey {
    Ciphertext(ciphertext::CiphertextProverKey),
    Input(input::InputProofKey),
}

/// Combined verifier key that can handle both ciphertext and input proofs
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum MultiVerifierKey {
    Ciphertext(ciphertext::CiphertextVerifierKey),
    Input(input::InputProofKey),
}

/// Combined proof that can be either a ciphertext proof or an input proof
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum MultiProof {
    Ciphertext(ciphertext::CiphertextProof),
    Input(input::InputProof),
}

/// Multi-prover that combines ciphertext and input provers
pub struct MultiProver;

impl Prover for MultiProver {
    type ProverKey = MultiProverKey;
    type VerifierKey = MultiVerifierKey;
    type Proof = MultiProof;

    /// Setup prover and verifier keys for the specified proof type
    fn setup(eval_keys: &[EvalKey], bitlength: usize) -> (Vec<Self::ProverKey>, Self::VerifierKey) {
        // For now, default to input proofs
        // In a real implementation, this could be configurable
        let (input_prover_keys, input_verifier_key) = input::InputProof::setup(eval_keys, bitlength);
        
        let prover_keys = input_prover_keys
            .into_iter()
            .map(MultiProverKey::Input)
            .collect();
        
        let verifier_key = MultiVerifierKey::Input(input_verifier_key);
        
        (prover_keys, verifier_key)
    }

    /// Prove well-formedness based on the prover key type
    fn prove<R: RngCore + CryptoRng>(
        pk: &Self::ProverKey,
        ek: &EvalKey,
        context: u64,
        r: Scalar,
        input: &[Scalar],
        rng: &mut R,
    ) -> Result<Self::Proof> {
        match pk {
            MultiProverKey::Ciphertext(ciphertext_pk) => {
                let proof = ciphertext::CiphertextProof::prove(ciphertext_pk, ek, context, r, input, rng)?;
                Ok(MultiProof::Ciphertext(proof))
            }
            MultiProverKey::Input(input_pk) => {
                let proof = input::InputProof::prove(input_pk, ek, context, r, input, rng)?;
                Ok(MultiProof::Input(proof))
            }
        }
    }

    /// Verify a proof based on the verifier key type
    fn verify(
        vk: &Self::VerifierKey,
        ciphertext: &ElGamalCiphertext,
        context: u64,
        proof: &Self::Proof,
        proof_index: usize,
    ) -> Result<()> {
        match (vk, proof) {
            (MultiVerifierKey::Ciphertext(ciphertext_vk), MultiProof::Ciphertext(ciphertext_proof)) => {
                ciphertext::CiphertextProof::verify(ciphertext_vk, ciphertext, context, ciphertext_proof, proof_index)
            }
            (MultiVerifierKey::Input(input_vk), MultiProof::Input(input_proof)) => {
                input::InputProof::verify(input_vk, ciphertext, context, input_proof, proof_index)
            }
            _ => Err(anyhow::anyhow!("Proof type mismatch with verifier key"))
        }
    }

    /// Batch verify proofs based on the verifier key type
    fn batch_verify<R: RngCore + CryptoRng>(
        vk: &Self::VerifierKey,
        ciphertexts: &[ElGamalCiphertext],
        context: u64,
        proofs: &[Self::Proof],
        proof_indices: &[usize],
        rng: &mut R,
    ) -> Result<()> {
        match vk {
            MultiVerifierKey::Ciphertext(ciphertext_vk) => {
                // Extract ciphertext proofs
                let ciphertext_proofs: Result<Vec<_>> = proofs
                    .iter()
                    .map(|proof| match proof {
                        MultiProof::Ciphertext(cp) => Ok(cp.clone()),
                        _ => Err(anyhow::anyhow!("Expected ciphertext proof")),
                    })
                    .collect();
                let ciphertext_proofs = ciphertext_proofs?;
                
                ciphertext::CiphertextProof::batch_verify(
                    ciphertext_vk, 
                    ciphertexts, 
                    context, 
                    &ciphertext_proofs, 
                    proof_indices, 
                    rng
                )
            }
            MultiVerifierKey::Input(input_vk) => {
                // Extract input proofs
                let input_proofs: Result<Vec<_>> = proofs
                    .iter()
                    .map(|proof| match proof {
                        MultiProof::Input(ip) => Ok(ip.clone()),
                        _ => Err(anyhow::anyhow!("Expected input proof")),
                    })
                    .collect();
                let input_proofs = input_proofs?;
                
                input::InputProof::batch_verify(
                    input_vk, 
                    ciphertexts, 
                    context, 
                    &input_proofs, 
                    proof_indices, 
                    rng
                )
            }
        }
    }
}

/// Helper functions for creating specific prover types
impl MultiProver {
    /// Create a ciphertext-only prover setup
    pub fn setup_ciphertext(eval_keys: &[EvalKey]) -> (Vec<MultiProverKey>, MultiVerifierKey) {
        let (ciphertext_prover_keys, ciphertext_verifier_key) = ciphertext::CiphertextProof::setup(eval_keys, 1);
        
        let prover_keys = ciphertext_prover_keys
            .into_iter()
            .map(MultiProverKey::Ciphertext)
            .collect();
        
        let verifier_key = MultiVerifierKey::Ciphertext(ciphertext_verifier_key);
        
        (prover_keys, verifier_key)
    }

    /// Create an input-only prover setup
    pub fn setup_input(eval_keys: &[EvalKey], bitlength: usize) -> (Vec<MultiProverKey>, MultiVerifierKey) {
        let (input_prover_keys, input_verifier_key) = input::InputProof::setup(eval_keys, bitlength);
        
        let prover_keys = input_prover_keys
            .into_iter()
            .map(MultiProverKey::Input)
            .collect();
        
        let verifier_key = MultiVerifierKey::Input(input_verifier_key);
        
        (prover_keys, verifier_key)
    }

    /// Create a mixed setup with both ciphertext and input provers
    pub fn setup_mixed(
        eval_keys: &[EvalKey], 
        bitlength: usize,
        ciphertext_count: usize,
        input_count: usize,
    ) -> (Vec<MultiProverKey>, MultiVerifierKey) {
        let mut prover_keys = Vec::new();
        
        // Add ciphertext prover keys
        let (ciphertext_prover_keys, _) = ciphertext::CiphertextProof::setup(eval_keys, 1);
        for i in 0..ciphertext_count {
            prover_keys.push(MultiProverKey::Ciphertext(ciphertext_prover_keys[i].clone()));
        }
        
        // Add input prover keys
        let (input_prover_keys, input_verifier_key) = input::InputProof::setup(eval_keys, bitlength);
        for i in 0..input_count {
            prover_keys.push(MultiProverKey::Input(input_prover_keys[i].clone()));
        }
        
        // For mixed setup, we'll use the input verifier key as the primary one
        // In a real implementation, you might want a more sophisticated approach
        let verifier_key = MultiVerifierKey::Input(input_verifier_key);
        
        (prover_keys, verifier_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_ciphertext_only_setup() {
        let mut rng = OsRng;
        let (_secret_key, eval_keys) = crate::agg_only_enc::AggOnlyEnc::setup(2, 3, &mut rng);
        
        let (prover_keys, verifier_key) = MultiProver::setup_ciphertext(&eval_keys);
        
        assert_eq!(prover_keys.len(), 2);
        assert!(matches!(verifier_key, MultiVerifierKey::Ciphertext(_)));
        
        for pk in &prover_keys {
            assert!(matches!(pk, MultiProverKey::Ciphertext(_)));
        }
    }

    #[test]
    fn test_input_only_setup() {
        let mut rng = OsRng;
        let (_secret_key, eval_keys) = crate::agg_only_enc::AggOnlyEnc::setup(2, 3, &mut rng);
        
        let (prover_keys, verifier_key) = MultiProver::setup_input(&eval_keys, 4);
        
        assert_eq!(prover_keys.len(), 2);
        assert!(matches!(verifier_key, MultiVerifierKey::Input(_)));
        
        for pk in &prover_keys {
            assert!(matches!(pk, MultiProverKey::Input(_)));
        }
    }

    #[test]
    fn test_mixed_setup() {
        let mut rng = OsRng;
        let (_secret_key, eval_keys) = crate::agg_only_enc::AggOnlyEnc::setup(3, 2, &mut rng);
        
        let (prover_keys, verifier_key) = MultiProver::setup_mixed(&eval_keys, 4, 1, 2);
        
        assert_eq!(prover_keys.len(), 3);
        assert!(matches!(verifier_key, MultiVerifierKey::Input(_)));
        
        // Check that we have the right mix
        let mut ciphertext_count = 0;
        let mut input_count = 0;
        
        for pk in &prover_keys {
            match pk {
                MultiProverKey::Ciphertext(_) => ciphertext_count += 1,
                MultiProverKey::Input(_) => input_count += 1,
            }
        }
        
        assert_eq!(ciphertext_count, 1);
        assert_eq!(input_count, 2);
    }

    #[test]
    fn test_prove_and_verify_ciphertext() {
        let mut rng = OsRng;
        let (_secret_key, eval_keys) = crate::agg_only_enc::AggOnlyEnc::setup(1, 1, &mut rng);
        
        let (prover_keys, verifier_key) = MultiProver::setup_ciphertext(&eval_keys);
        
        let r = Scalar::random(&mut rng);
        let input = vec![Scalar::from(1u64)];
        let context = rng.next_u64();
        let ciphertext = crate::agg_only_enc::AggOnlyEnc::encrypt(&eval_keys[0], context, r, &input);
        
        let proof = MultiProver::prove(&prover_keys[0], &eval_keys[0], context, r, &input, &mut rng).unwrap();
        
        assert!(matches!(proof, MultiProof::Ciphertext(_)));
        
        let verify_result = MultiProver::verify(&verifier_key, &ciphertext, context, &proof, 0);
        assert!(verify_result.is_ok());
    }

    #[test]
    fn test_prove_and_verify_input() {
        let mut rng = OsRng;
        let (_secret_key, eval_keys) = crate::agg_only_enc::AggOnlyEnc::setup(1, 2, &mut rng);
        
        let (prover_keys, verifier_key) = MultiProver::setup_input(&eval_keys, 1);
        
        let r = Scalar::random(&mut rng);
        let input = vec![Scalar::from(1u64), Scalar::from(0u64)];
        let context = rng.next_u64();
        let ciphertext = crate::agg_only_enc::AggOnlyEnc::encrypt(&eval_keys[0], context, r, &input);
        
        let proof = MultiProver::prove(&prover_keys[0], &eval_keys[0], context, r, &input, &mut rng).unwrap();
        
        assert!(matches!(proof, MultiProof::Input(_)));
        
        let verify_result = MultiProver::verify(&verifier_key, &ciphertext, context, &proof, 0);
        assert!(verify_result.is_ok());
    }
}
