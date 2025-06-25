use rand_core::RngCore; // TODO: Eventually go over RNGs

pub mod dl;
pub use dl::DiscreteLog;

// todo: Rename
pub trait Aggregation {
    type Params;
    type DecryptorKey;
    type ClientKey;
    type Input;
    type Output;
    type Encoding;

    fn setup<R: RngCore>(
        num_clients: usize,
        length: usize,
        rng: &mut R,
    ) -> (Self::Params, Self::DecryptorKey, Vec<Self::ClientKey>);

    fn encode<R: RngCore>(
        params: &Self::Params,
        key: &Self::ClientKey,
        val: &[Self::Input],
        rng: &mut R,
    ) -> Self::Encoding;

    fn aggregate(encodings: Vec<Self::Encoding>) -> Self::Encoding;

    fn decode(key: &Self::DecryptorKey, aggregate: Self::Encoding) -> Result<Vec<Self::Output>, ()>;
}
