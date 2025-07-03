use crate::protocol::{FromBytes, ToBytes, serialization::*};
use anyhow::Result;
use ff::PrimeField;
use group::{Group, GroupEncoding};

/// Public parameters given to the aggregator.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Params<G: Group + GroupEncoding> {
    // Generators
    pub(crate) g: G,
    pub(crate) h: G,
    /// Public keys for each ciphertext slot.
    pub(crate) pks: Vec<G>,
    /// Commitments to client secret key shares.
    pub(crate) client_key_comms: Vec<G>,
}

/// Secret key material given to the client.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ClientKey<G: Group + GroupEncoding> {
    /// Generators
    pub(crate) g: G,
    pub(crate) h: G,
    /// Public keys for each ciphertext slot.
    pub(crate) pks: Vec<G>,
    /// Client's secret key share.
    pub(crate) secret: G::Scalar,
}

/// Encoding of a client's input (an ElGamal ciphertext).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Encoding<G: Group + GroupEncoding> {
    /// g^r
    pub(crate) rand: G,
    /// pk_0^r * g^s
    pub(crate) secret: G,
    /// pk_i^r * g^x_i
    pub(crate) vals: Vec<G>,
}

/// Proof of well-formedness for binary encodings.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Proof<G: Group + GroupEncoding> {
    /// Commitment for for claim 1) c_0 = g^r.
    pub(crate) comm_g_r: G,
    /// Commitments for for claim 2) c_1 = pk_0^r * g^s.
    pub(crate) comm_pk_r: G,
    pub(crate) comm_g_s: G,
    /// Commitment for for claim 3) ck = h^s.
    pub(crate) comm_h_s: G,
    /// Commitments for inputs on x=0 branch.
    pub(crate) comm_g_x0: Vec<G>,
    pub(crate) comm_pk_x0: Vec<G>,
    /// Commitments for inputs on x=1 branch.
    pub(crate) comm_g_x1: Vec<G>,
    pub(crate) comm_pk_x1: Vec<G>,

    /// Challenges for x = 0 branch.
    pub(crate) challenge_x: Vec<G::Scalar>,

    /// Response for proving knowledge of r.
    pub(crate) response_r: G::Scalar,
    /// Response for proving knowledge of s.
    pub(crate) response_s: G::Scalar,
    /// Responses for proving knowledge of x=0 branch.
    pub(crate) response_x0: Vec<G::Scalar>,
    /// Responses for proving knowledge of x=1 branch.
    pub(crate) response_x1: Vec<G::Scalar>,
}

/// Result of decrypting the aggregate encoding. For some schemes (e.g., DiscreteLog),
/// this value needs to be post-processed (solve discrete log) to get the final result.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PartialOutput<G: Group + GroupEncoding> {
    /// Aggregated values.
    pub(crate) vals: Vec<G>,
}

// Serialization impls
crate::protocol::impl_serialization! {
    Params<G> {
        g: group,
        h: group,
        pks: group_vec,
        client_key_comms: group_vec
    }
}

crate::protocol::impl_serialization! {
    ClientKey<G> {
        g: group,
        h: group,
        pks: group_vec,
        secret: scalar
    }
}

crate::protocol::impl_serialization! {
    Encoding<G> {
        rand: group,
        secret: group,
        vals: group_vec
    }
}

crate::protocol::impl_serialization! {
    Proof<G> {
        comm_g_r: group,
        comm_pk_r: group,
        comm_g_s: group,
        comm_h_s: group,
        comm_g_x0: group_vec,
        comm_pk_x0: group_vec,
        comm_g_x1: group_vec,
        comm_pk_x1: group_vec,
        challenge_x: scalar_vec,
        response_r: scalar,
        response_s: scalar,
        response_x0: scalar_vec,
        response_x1: scalar_vec,
    }
}

crate::protocol::impl_serialization! {
    PartialOutput<G> {
        vals: group_vec
    }
}
