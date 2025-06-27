use anyhow::Result;
use rand_core::{CryptoRng, RngCore};

pub mod dl;
pub use dl::DiscreteLog;

pub mod serialization;
pub use serialization::{FromBytes, ToBytes};
//
//#[cfg(test)]
//mod tests;

// todo: Rename
pub trait Aggregation {
    type Params: ToBytes + FromBytes;
    type DecryptorKey;
    type ClientKey: ToBytes + FromBytes;
    type Input;
    type Output;
    type Encoding: ToBytes + FromBytes;
    type Proof: ToBytes + FromBytes;

    fn setup<R: RngCore + CryptoRng>(
        num_clients: usize,
        length: usize,
        rng: &mut R,
    ) -> (Self::Params, Self::DecryptorKey, Vec<Self::ClientKey>);

    fn encode<R: RngCore + CryptoRng>(
        key: &Self::ClientKey,
        val: &[Self::Input],
        rng: &mut R,
    ) -> Result<(Self::Encoding, Self::Proof)>;

    fn aggregate(
        params: &Self::Params,
        encodings: Vec<Self::Encoding>,
        proofs: Vec<Self::Proof>,
    ) -> Result<Self::Encoding>;

    fn decode(key: &Self::DecryptorKey, aggregate: Self::Encoding)
    -> Result<Vec<Self::Output>>;
}
