use crate::protocol::{
    FromBytes, ToBytes,
    proofs::{BinarySchnorrProof, Commiments, Responses},
    serialization::*,
};
use anyhow::Result;
use ff::PrimeField;
use group::{Group, GroupEncoding};

/// Public parameters given to the aggregator.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AggParams<G: Group + GroupEncoding> {
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

pub struct DecKey<G: Group + GroupEncoding> {
    pub(crate) secret_keys: Vec<G::Scalar>,
    pub(crate) share: G::Scalar,
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

/// Result of decrypting the aggregate encoding. For some schemes (e.g., DiscreteLog),
/// this value needs to be post-processed (solve discrete log) to get the final result.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PartialOutput<G: Group + GroupEncoding> {
    /// Aggregated values.
    pub(crate) vals: Vec<G>,
}

// Serialization impls
crate::protocol::impl_serialization! {
    AggParams<G> {
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
    Commiments<G> {
        g_r: group,
        g_s: group,
        h_s: group,
        g_x0: group_vec,
        pk_x0: group_vec,
        g_x1: group_vec,
        pk_x1: group_vec,
    }
}

crate::protocol::impl_serialization! {
    Responses<G> {
        r: scalar,
        s: scalar,
        x0: scalar_vec,
        x1: scalar_vec,
    }
}

// TODO: Manually implementing to avoid changing the macro
impl<G: Group + GroupEncoding> ToBytes for BinarySchnorrProof<G> {
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let comm_bytes = self.commitments.to_bytes();
        out.extend_from_slice(&(comm_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&comm_bytes);

        serialize_scalars(&mut out, &self.challenges_x);

        out.extend_from_slice(&self.responses.to_bytes());
        out
    }
}

// TODO: Manually implementing to avoid changing the macro
impl<G: Group + GroupEncoding> FromBytes for BinarySchnorrProof<G> {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut pos = 0;

        // Deserialize commitments
        let commitment_length = deserialize_len(&bytes[pos..]);
        pos += 4;
        let commitment = Commiments::from_bytes(&bytes[pos..pos + commitment_length])?;
        pos += commitment_length;

        // Deserialize challenges_x (serialized with serialize_scalars which includes length)
        let challenge_length = deserialize_len(&bytes[pos..]);
        pos += 4;
        let scalar_len = scalar_len::<G::Scalar>();
        let challenges_x = deserialize_scalars(
            &bytes[pos..pos + challenge_length * scalar_len],
            challenge_length,
        )?;
        pos += challenge_length * scalar_len;

        // Deserialize responses
        let responses = Responses::from_bytes(&bytes[pos..])?;

        Ok(BinarySchnorrProof {
            commitments: commitment,
            challenges_x: challenges_x,
            responses: responses,
        })
    }
}

crate::protocol::impl_serialization! {
    PartialOutput<G> {
        vals: group_vec
    }
}
