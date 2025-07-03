use crate::protocol::{FromBytes, ToBytes, serialization::*};
use anyhow::{Result, anyhow};
use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Params<G: Group + GroupEncoding> {
    pub(crate) g: G,
    pub(crate) h: G,
    pub(crate) pks: Vec<G>,
    pub(crate) client_key_comms: Vec<G>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ClientKey<G: Group + GroupEncoding> {
    pub(crate) g: G,
    pub(crate) h: G,
    pub(crate) pks: Vec<G>,
    pub(crate) secret: G::Scalar,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Encoding<G: Group + GroupEncoding> {
    pub(crate) rand: G,
    pub(crate) secret: G,
    pub(crate) vals: Vec<G>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Proof<G: Group + GroupEncoding> {
    // Commitments
    pub(crate) comm_g_r: G,
    pub(crate) comm_pk_r: G,
    pub(crate) comm_g_s: G,
    pub(crate) comm_h_s: G,
    pub(crate) comm_g_x0: Vec<G>,
    pub(crate) comm_pk_x0: Vec<G>,
    pub(crate) comm_g_x1: Vec<G>,
    pub(crate) comm_pk_x1: Vec<G>,

    // Challenges for the OR compositions
    pub(crate) challenge_x: Vec<G::Scalar>,

    // Responses
    pub(crate) response_r: G::Scalar,
    pub(crate) response_s: G::Scalar,
    pub(crate) response_x0: Vec<G::Scalar>,
    pub(crate) response_x1: Vec<G::Scalar>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PartialOutput<G: Group + GroupEncoding> {
    pub(crate) vals: Vec<G>,
}

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
