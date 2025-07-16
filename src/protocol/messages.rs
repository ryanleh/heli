use crate::protocol::{G, Scalar};
use serde::{Deserialize, Serialize};

/// Public parameters given to the aggregator.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AggParams {
    // Generators
    pub(crate) g: G,
    pub(crate) h: G,
    /// Public keys for each ciphertext slot.
    pub(crate) pks: Vec<G>,
    /// Commitments to client secret key shares.
    pub(crate) client_key_comms: Vec<G>,
}

/// Secret key material given to the client.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ClientKey {
    /// Generators
    pub(crate) g: G,
    pub(crate) h: G,
    /// Public keys for each ciphertext slot.
    pub(crate) pks: Vec<G>,
    /// Client's secret key share.
    pub(crate) secret: Scalar,
}

pub struct DecKey {
    pub(crate) secret_keys: Vec<Scalar>,
    pub(crate) share: Scalar,
}

/// Encoding of a client's input (an ElGamal ciphertext).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Encoding {
    /// g^r
    pub(crate) rand: G,
    /// pk_0^r * g^s
    pub(crate) secret: G,
    /// pk_i^r * g^x_i
    pub(crate) vals: Vec<G>,
}

/// Result of decrypting the aggregate encoding. For some schemes (e.g., DiscreteLog),
/// this value needs to be post-processed (solve discrete log) to get the final result.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PartialOutput {
    /// Aggregated values.
    pub(crate) vals: Vec<G>,
}
