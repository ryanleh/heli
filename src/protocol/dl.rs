use super::{Aggregation, serialization::*};
use ff::Field;
use group::{Group, GroupEncoding};
use rand_core::{CryptoRng, RngCore};
use sigma_rs::{
    LinearRelation, NISigmaProtocol,
    codec::ShakeCodec,
    composition::{Protocol, ProtocolWitness},
};
use std::marker::PhantomData;

pub struct DiscreteLog<G: Group + GroupEncoding> {
    _g: PhantomData<G>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Params<G: Group + GroupEncoding> {
    g: G,
    h: G,
    pks: Vec<G>,
    client_key_comms: Vec<G>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ClientKey<G: Group + GroupEncoding> {
    g: G,
    h: G,
    pks: Vec<G>,
    secret: G::Scalar,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Encoding<G: Group + GroupEncoding> {
    rand: G,
    secret: G,
    vals: Vec<G>,
}

impl<G: Group + GroupEncoding> DiscreteLog<G> {
    /// Prove that the encoding is well-formed with inputs either 0 or 1.
    fn create_relation(g: G, h: G, pks: &[G], ck: G, encoding: &Encoding<G>) -> Protocol<G> {
        assert!(
            encoding.vals.len() == 1,
            "Currently only support proofs with a single input (need witness scoping)"
        );

        // Build two relations: one for x = 0 and x = 1. We take the OR of these two.
        //
        // TODO: update sigma-rs library so that we can make this more efficient
        let mut relations = vec![LinearRelation::new(); 2];
        for i in 0..2 {
            let relation = &mut relations[i];
            let r = relation.allocate_scalar();
            let s = relation.allocate_scalar();

            let g_elem = relation.allocate_element();
            let h_elem = relation.allocate_element();
            let pk1 = relation.allocate_element();
            let pk2 = relation.allocate_element();
            relation.set_element(g_elem, g);
            relation.set_element(h_elem, h);
            relation.set_element(pk1, pks[0]);
            relation.set_element(pk2, pks[1]);

            // Relation 0: c_0 = g * r
            let r_0 = relation.allocate_eq(g_elem * r);
            relation.set_element(r_0, encoding.rand);

            // Relation 1: c_1 = pk1 * r + g * s
            let r_1 = relation.allocate_eq(pk1 * r + g_elem * s);
            relation.set_element(r_1, encoding.secret);

            // Relation 2: ck = h^s
            let r_2 = relation.allocate_eq(h_elem * s);
            relation.set_element(r_2, ck);

            // Relation 3: c_2 = pk2 * r + g * x for x = 0 or x = 1
            let r_3 = relation.allocate_eq(pk2 * r);
            match i {
                0 => relation.set_element(r_3, encoding.vals[0]),
                1 => relation.set_element(r_3, encoding.vals[0] - g),
                _ => unreachable!(),
            };
        }

        Protocol::Or(
            relations
                .into_iter()
                .map(|r| Protocol::from(r))
                .collect::<Vec<_>>(),
        )
    }
}

// todo: Eventually abstract out the encryption scheme
impl<G: Group + GroupEncoding> Aggregation for DiscreteLog<G> {
    type Params = Params<G>;
    type DecryptorKey = (Vec<G::Scalar>, G::Scalar);
    type ClientKey = ClientKey<G>;
    type Input = G::Scalar;
    type Output = G; // protocol outputs `g^X` where X is the aggregated sum. 
    type Encoding = Encoding<G>;
    type Proof = Vec<u8>;

    fn setup<R: RngCore + CryptoRng>(
        num_clients: usize,
        length: usize,
        rng: &mut R,
    ) -> (Self::Params, Self::DecryptorKey, Vec<Self::ClientKey>) {
        let g = G::generator();
        let h = G::random(&mut *rng); // todo: generate correctly
        let secret_keys: Vec<_> = (0..=length).map(|_| G::Scalar::random(&mut *rng)).collect();
        let pks: Vec<_> = secret_keys.iter().map(|ski| g * ski).collect();

        let mut client_keys = Vec::with_capacity(num_clients);
        let mut share = G::Scalar::ZERO;
        for _ in 0..num_clients {
            let c_share = G::Scalar::random(&mut *rng);
            share += c_share;
            client_keys.push(ClientKey {
                g,
                h,
                pks: pks.clone(),
                secret: c_share,
            });
        }

        let params = Params {
            g,
            h,
            pks,
            client_key_comms: client_keys
                .iter()
                .map(|ck| h * ck.secret)
                .collect::<Vec<G>>(),
        };

        (params, (secret_keys, share), client_keys)
    }

    fn encode<R: RngCore + CryptoRng>(
        key: &Self::ClientKey,
        val: &[Self::Input],
        rng: &mut R,
    ) -> Result<(Self::Encoding, Self::Proof), ()> {
        assert_eq!(key.pks.len() - 1, val.len());
        let g = G::generator();

        // Compute input encoding (ElGamal ciphertext)
        let r = G::Scalar::random(&mut *rng);
        let encoding = Encoding {
            rand: g * r,
            secret: key.pks[0] * r + g * key.secret,
            vals: val
                .iter()
                .enumerate()
                .map(|(i, v)| key.pks[i + 1] * r + g * v)
                .collect::<Vec<_>>(),
        };

        // Prove ciphertext is well-formed
        let relation = Self::create_relation(key.g, key.h, &key.pks, key.h * key.secret, &encoding);
        let witness = match val[0] == G::Scalar::ZERO {
            true => ProtocolWitness::Or(0, vec![ProtocolWitness::Simple(vec![r, key.secret])]),
            false => ProtocolWitness::Or(1, vec![ProtocolWitness::Simple(vec![r, key.secret])]),
        };
        let nizk = NISigmaProtocol::<_, ShakeCodec<G>>::new(b"dl_agg_enc", relation);
        let proof = nizk.prove_batchable(&witness, rng).unwrap(); // TODO
        Ok((encoding, proof))
    }

    fn aggregate(
        params: &Self::Params,
        encodings: Vec<Self::Encoding>,
        proofs: Vec<Self::Proof>,
    ) -> Result<Self::Encoding, ()> {
        let one = G::identity();
        let mut agg = Encoding {
            rand: one,
            secret: one,
            vals: vec![one; encodings[0].vals.len()],
        };

        for (i, (enc, proof)) in encodings.into_iter().zip(proofs).enumerate() {
            // Verify proofs (todo: batch verify)
            let ck = params.client_key_comms[i];
            let relation = Self::create_relation(params.g, params.h, &params.pks, ck, &enc);
            let nizk = NISigmaProtocol::<_, ShakeCodec<G>>::new(b"dl_agg_enc", relation);
            nizk.verify_batchable(&proof).unwrap(); // todo

            // Aggregate
            agg.rand += enc.rand;
            agg.secret += enc.secret;
            agg.vals.iter_mut().zip(enc.vals).for_each(|(a, e)| *a += e);
        }
        Ok(agg)
    }

    fn decode(
        key: &Self::DecryptorKey,
        aggregate: Self::Encoding,
    ) -> Result<Vec<Self::Output>, ()> {
        let g = G::generator();
        let c_lifted_share = aggregate.secret - aggregate.rand * key.0[0];
        if c_lifted_share == g * key.1 {
            Ok(aggregate
                .vals
                .into_iter()
                .enumerate()
                .map(|(i, x)| x - aggregate.rand * key.0[i + 1])
                .collect::<Vec<_>>())
        } else {
            Err(())
        }
    }
}

impl<G: Group + GroupEncoding> ToBytes for Params<G> {
    fn to_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        serialize_element(&mut out, self.g);
        serialize_element(&mut out, self.h);
        serialize_elements(&mut out, &self.pks);
        serialize_elements(&mut out, &self.client_key_comms);
        out
    }
}

impl<G: Group + GroupEncoding> FromBytes for Params<G> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
        let elem_len = element_len::<G>();

        let (buf, rest) = bytes.split_at(elem_len);
        let g: G = deserialize_element(buf)?;

        let (buf, rest) = rest.split_at(elem_len);
        let h: G = deserialize_element(buf)?;

        let (buf, rest) = rest.split_at(4);
        let pks_len = deserialize_len(buf);

        let (buf, rest) = rest.split_at(elem_len * pks_len);
        let pks: Vec<G> = deserialize_elements(buf, pks_len)?;

        let (buf, rest) = rest.split_at(4);
        let cks_len = deserialize_len(buf);

        let client_key_comms: Vec<G> = deserialize_elements(rest, cks_len)?;

        Ok(Params {
            g,
            h,
            pks,
            client_key_comms,
        })
    }
}

impl<G: Group + GroupEncoding> ToBytes for ClientKey<G> {
    fn to_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        serialize_element(&mut out, self.g);
        serialize_element(&mut out, self.h);
        serialize_elements(&mut out, &self.pks);
        serialize_scalar(&mut out, self.secret);
        out
    }
}

impl<G: Group + GroupEncoding> FromBytes for ClientKey<G> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
        let elem_len = element_len::<G>();

        let (buf, rest) = bytes.split_at(elem_len);
        let g: G = deserialize_element(buf)?;

        let (buf, rest) = rest.split_at(elem_len);
        let h: G = deserialize_element(buf)?;

        let (buf, rest) = rest.split_at(4);
        let pks_len = deserialize_len(buf);

        let (buf, rest) = rest.split_at(elem_len * pks_len);
        let pks: Vec<G> = deserialize_elements(buf, pks_len)?;

        let secret: G::Scalar = deserialize_scalar(rest)?;

        Ok(ClientKey { g, h, pks, secret })
    }
}

impl<G: Group + GroupEncoding> ToBytes for Encoding<G> {
    fn to_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        serialize_element(&mut out, self.rand);
        serialize_element(&mut out, self.secret);
        serialize_elements(&mut out, &self.vals);
        out
    }
}

impl<G: Group + GroupEncoding> FromBytes for Encoding<G> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
        let elem_len = element_len::<G>();

        let (buf, rest) = bytes.split_at(elem_len);
        let rand: G = deserialize_element(buf)?;

        let (buf, rest) = rest.split_at(elem_len);
        let secret: G = deserialize_element(buf)?;

        let (buf, rest) = rest.split_at(4);
        let vals_len = deserialize_len(buf);
        let vals: Vec<G> = deserialize_elements(rest, vals_len)?;

        Ok(Encoding { rand, secret, vals })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use curve25519_dalek::RistrettoPoint;
    use group::Group;
    use rand::rngs::OsRng;

    type G = RistrettoPoint;
    type Agg = DiscreteLog<G>;

    #[test]
    fn serialization() {
        let num_clients = 1;
        let length = 1;
        let (params, sk, cks) = Agg::setup(num_clients, length, &mut OsRng);

        let params_bytes = params.clone().to_bytes();
        let new_params = <Agg as Aggregation>::Params::from_bytes(&params_bytes).unwrap();
        assert_eq!(params, new_params);

        let ck_bytes = cks[0].clone().to_bytes();
        let new_ck = <Agg as Aggregation>::ClientKey::from_bytes(&ck_bytes).unwrap();
        assert_eq!(cks[0], new_ck);

        let (encoding, proof) =
            Agg::encode(&cks[0], &[<G as Group>::Scalar::ONE], &mut OsRng).unwrap();

        let enc_bytes = encoding.clone().to_bytes();
        let new_enc = <Agg as Aggregation>::Encoding::from_bytes(&enc_bytes).unwrap();
        assert_eq!(encoding, new_enc);

        let proof_bytes = proof.clone().to_bytes();
        let new_proof = <Agg as Aggregation>::Proof::from_bytes(&proof_bytes).unwrap();
        assert_eq!(proof, new_proof);

        let agg = Agg::aggregate(&params, vec![encoding], vec![proof]).unwrap();
        let results = Agg::decode(&sk, agg).unwrap();
        assert_eq!(results[0], G::generator());
    }
}
