use anyhow::Result;
use rand_core::{CryptoRng, RngCore};
use std::fmt::Debug;

pub mod dl;
pub mod messages;
pub mod proofs;
pub use dl::DiscreteLog;

#[macro_use]
pub mod serialization;
pub(crate) use crate::impl_serialization;
use serialization::{FromBytes, ToBytes};

pub trait Aggregation: Send + Sync + 'static {
    /// Public parameters given to aggregator.
    type Params: Send + Sync + ToBytes + FromBytes + Debug;
    /// Decryptor key.
    type DecryptorKey: Send + Sync;
    /// Client key.
    type ClientKey: Send + Sync + ToBytes + FromBytes;
    /// Client encoding (ciphertext).
    type Encoding: Send + Sync + ToBytes + FromBytes + Clone + Debug + Sized;
    /// Proof of encoding well-formedness.
    type Proof: Send + Sync + ToBytes + FromBytes;
    /// Partial decryption/aggregation output.
    type PartialOutput: Send + Sync + ToBytes + FromBytes + Debug;

    /// Generate protocol parameters and keys.
    fn setup<R: RngCore + CryptoRng>(
        num_clients: usize,
        length: usize,
        rng: &mut R,
    ) -> (Self::Params, Self::DecryptorKey, Vec<Self::ClientKey>);

    /// Encode a client's input for aggregation.
    fn encode<R: RngCore + CryptoRng>(
        key: &Self::ClientKey,
        val: &[u32],
        rng: &mut R,
    ) -> Result<(Self::Encoding, Self::Proof)>;

    /// Verify encodings.
    fn verify_encodings(
        params: &Self::Params,
        client_indices: Option<&[u32]>,
        encoding: &[Self::Encoding],
        proof: &[Self::Proof],
    ) -> Result<()>;

    /// Aggregate encodings.
    fn aggregate(params: &Self::Params, encodings: &[Self::Encoding]) -> Result<Self::Encoding>;

    /// Decrypt the aggregate encoding.
    fn decode(key: &Self::DecryptorKey, aggregate: Self::Encoding) -> Result<Self::PartialOutput>;

    /// Compute the final output from decrypted aggregation result.
    fn post_process(
        params: &Self::Params,
        partial_outputs: Self::PartialOutput,
    ) -> Result<Vec<u32>>;

    /// Returns the number of clients.
    fn num_clients(params: &Self::Params) -> usize;
    /// Returns the input length.
    fn length(params: &Self::Params) -> usize;
}
