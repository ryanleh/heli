use crate::{
    agg_only_enc::EvalKey,
    crypto::{Scalar, ElGamalCiphertext, G},
};

use anyhow::Result;
use sha3::{Digest, Sha3_512};
use rand_core::{CryptoRng, RngCore};
use serde::{Serialize, de::DeserializeOwned};

// Prove that a ciphertext is well-formed
pub mod ciphertext;

// Prove that input is well-formed
pub mod input;

// Combine both ciphertext and input proofs via enums
pub mod multi;

/// Trait for proving well-formedness of a ciphertext 
pub trait Prover: 'static {
    type ProverKey: Send + Sync + Serialize + DeserializeOwned;
    type VerifierKey: Send + Sync + Serialize + DeserializeOwned;
    type Proof: Send + Sync + Serialize + DeserializeOwned;

    /// Given a set of aggregation-only evaluation keys and a max input
    /// bitlength, setup prover and verifier keys. 
    fn setup(eval_keys: &[EvalKey], bitlength: usize) -> (Vec<Self::ProverKey>, Self::VerifierKey);

    /// Prove well-formedness of given ciphertext
    fn prove<R: RngCore + CryptoRng>(
        pk: &Self::ProverKey,
        ek: &EvalKey,
        context: u64,
        r: Scalar,
        input: &[Scalar],
        rng: &mut R,
    ) -> Result<Self::Proof>;

    /// Verify a proof 
    fn verify(
        vk: &Self::VerifierKey,
        ciphertext: &ElGamalCiphertext,
        context: u64,
        proof: &Self::Proof,
        proof_index: usize,
    ) -> Result<()>;

    /// Batch verify a set of proofs
    fn batch_verify<R: RngCore + CryptoRng>(
        vk: &Self::VerifierKey,
        ciphertexts: &[ElGamalCiphertext],
        context: u64,
        proofs: &[Self::Proof],
        proof_indices: &[usize],
        rng: &mut R,
    ) -> Result<()>;
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
