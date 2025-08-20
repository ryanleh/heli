use crate::protocol::{Scalar, messages::*};

use anyhow::Result;
use rand_core::{CryptoRng, RngCore};
use serde::{Serialize, de::DeserializeOwned};

pub mod binary;
pub use binary::*;

pub mod range;
pub use range::*;

// Helper macro for verifying claims - can be used by all provers
#[macro_export]
macro_rules! check_claim {
    ($left:expr, $right:expr, $msg:expr) => {
        if $left != $right {
            return Err(anyhow::anyhow!($msg));
        }
    };
}

pub trait Prover: 'static {
    type ProverKey: Send + Sync + Serialize + DeserializeOwned;
    type VerifierKey: Send + Sync + Serialize + DeserializeOwned;
    type Proof: Send + Sync + Serialize + DeserializeOwned;

    fn setup(num_inputs: usize, bitlength: usize) -> (Self::ProverKey, Self::VerifierKey);

    fn prove<R: RngCore + CryptoRng>(
        pk: &Self::ProverKey,
        ck: &ClientKey,
        input: &[u64],
        r: Scalar,
        encoding: &Encoding,
        rng: &mut R,
    ) -> Result<Self::Proof>;

    /// Temporary trait function, move somewhere else
    ///
    /// prove _without_ verification tag, just input claims
    fn prove_untagged<R: RngCore + CryptoRng>(
        pk: &Self::ProverKey,
        ck: &ClientKey,
        input: &[u64],
        r: Scalar,
        encoding: &Encoding,
        rng: &mut R,
    ) -> Result<Self::Proof>;

    fn verify(
        vk: &Self::VerifierKey,
        params: &AggParams,
        proof_index: usize,
        encoding: &Encoding,
        proof: &Self::Proof,
    ) -> Result<()>;

    fn batch_verify<R: RngCore + CryptoRng>(
        vk: &Self::VerifierKey,
        params: &AggParams,
        proof_indices: &[usize],
        encodings: &[Encoding],
        proofs: &[Self::Proof],
        rng: &mut R,
    ) -> Result<()>;

    /// Temporary trait function, move somewhere else
    ///
    /// batch_verify _without_ verification tag, just input claims
    fn batch_verify_untagged<R: RngCore + CryptoRng>(
        vk: &Self::VerifierKey,
        params: &AggParams,
        proof_indices: &[usize],
        encodings: &[Encoding],
        proofs: &[Self::Proof],
        rng: &mut R,
    ) -> Result<()>;
}
