pub mod dl;
pub use dl::DiscreteLog;
pub mod dlog;
pub mod messages;
mod msm;
pub mod proofs;
pub use msm::*;

#[macro_use]
pub mod serialization;
pub(crate) use crate::impl_serialization;
use serialization::{FromBytes, ToBytes};

// TODO: In the future this should be generic over an encoding scheme and proof system
//pub trait Aggregation: Send + Sync + 'static {
//    /// Public parameters given to aggregator.
//    type AggParams: Send + Sync + ToBytes + FromBytes + Debug;
//    /// Decryptor key.
//    type DecKey: Send + Sync;
//    /// Client key.
//    type ClientKey: Send + Sync + ToBytes + FromBytes;
//    /// Client encoding (ciphertext).
//    type Encoding: Send + Sync + ToBytes + FromBytes + Clone + Debug + Sized;
//    /// Proof of encoding well-formedness.
//    type Proof: Send + Sync + ToBytes + FromBytes;
//    /// Partial decryption/aggregation output.
//    type PartialOutput: Send + Sync + ToBytes + FromBytes + Debug;
//
//    /// Generate protocol parameters and keys.
//    fn setup<R: RngCore + CryptoRng>(
//        num_clients: usize,
//        length: usize,
//        rng: &mut R,
//    ) -> (Self::AggParams, Self::DecKey, Vec<Self::ClientKey>);
//
//    /// Encode a client's input for aggregation.
//    fn encode<R: RngCore + CryptoRng>(
//        key: &Self::ClientKey,
//        val: &[u32],
//        rng: &mut R,
//    ) -> Result<(Self::Encoding, Self::Proof)>;
//
//    /// Verify encodings.
//    fn verify_encodings(
//        params: &Self::AggParams,
//        verifier_key: &Proof::VerifierKey,
//        client_indices: Option<&[u32]>,
//        encodings: &[Self::Encoding],
//        proofs: &[Self::Proof],
//    ) -> Result<()>;
//
//    /// Batch verify encodings
//    fn batch_verify_encodings<R: RngCore + CryptoRng>(
//        params: &Self::AggParams,
//        client_indices: Option<&[u32]>,
//        encodings: &[Self::Encoding],
//        proofs: &[Self::Proof],
//        rng: &mut R,
//    ) -> Result<()>;
//
//    /// Aggregate encodings.
//    fn aggregate(params: &Self::AggParams, encodings: &[Self::Encoding]) -> Result<Self::Encoding>;
//
//    /// Decrypt the aggregate encoding.
//    fn decode(key: &Self::DecKey, aggregate: Self::Encoding) -> Result<Self::PartialOutput>;
//
//    /// Compute the final output from decrypted aggregation result.
//    fn post_process(
//        params: &Self::AggParams,
//        partial_outputs: Self::PartialOutput,
//    ) -> Result<Vec<u32>>;
//
//    /// Returns the number of clients.
//    fn num_clients(params: &Self::AggParams) -> usize;
//    /// Returns the input length.
//    fn length(params: &Self::AggParams) -> usize;
//}
//
