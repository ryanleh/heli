use anyhow::Result;
use rand_core::{CryptoRng, RngCore};
use std::fmt::Debug;

pub mod dl;
pub use dl::DiscreteLog;

#[macro_use]
pub mod serialization;
pub use serialization::{FromBytes, ToBytes};

pub(crate) use crate::impl_serialization;

pub mod messages;

#[cfg(test)]
mod tests;

pub trait Aggregation: Send + Sync + 'static {
    type Params: Send + Sync + ToBytes + FromBytes + Debug;
    type DecryptorKey: Send + Sync;
    type ClientKey: Send + Sync + ToBytes + FromBytes;
    type Encoding: Send + Sync + ToBytes + FromBytes + Clone + Debug + Sized;
    type Proof: Send + Sync + ToBytes + FromBytes;
    type PartialOutput: Send + Sync + ToBytes + FromBytes + Debug;

    fn setup<R: RngCore + CryptoRng>(
        num_clients: usize,
        length: usize,
        rng: &mut R,
    ) -> (Self::Params, Self::DecryptorKey, Vec<Self::ClientKey>);

    fn encode<R: RngCore + CryptoRng>(
        key: &Self::ClientKey,
        val: &[u32],
        rng: &mut R,
    ) -> Result<(Self::Encoding, Self::Proof)>;

    fn verify_encodings(
        params: &Self::Params,
        client_indices: Option<&[u32]>,
        encoding: &[Self::Encoding],
        proof: &[Self::Proof],
    ) -> Result<()>;

    fn aggregate(params: &Self::Params, encodings: &[Self::Encoding]) -> Result<Self::Encoding>;

    fn decode(key: &Self::DecryptorKey, aggregate: Self::Encoding) -> Result<Self::PartialOutput>;

    fn post_process(
        params: &Self::Params,
        partial_outputs: Self::PartialOutput,
    ) -> Result<Vec<u32>>;

    // Helper functions
    fn num_clients(params: &Self::Params) -> usize;
    fn length(params: &Self::Params) -> usize;
}
