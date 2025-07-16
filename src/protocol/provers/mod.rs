use crate::protocol::{Scalar, messages::*};

use rand_core::{CryptoRng, RngCore};
use serde::{Serialize, de::DeserializeOwned};

pub mod binary;
pub use binary::*;

//pub mod range;
//pub use range::*;

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
    ) -> Self::Proof;

    fn verify(
        vk: &Self::VerifierKey,
        params: &AggParams,
        proof_index: u32,
        encoding: &Encoding,
        proof: &Self::Proof,
    ) -> bool;

    fn batch_verify<R: RngCore + CryptoRng>(
        vk: &Self::VerifierKey,
        params: &AggParams,
        proof_indices: &[u32],
        encodings: &[Encoding],
        proofs: &[Self::Proof],
        rng: &mut R,
    ) -> bool;
}
