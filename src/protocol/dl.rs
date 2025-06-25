use group::{Group, GroupEncoding};
use ff::Field;
use std::marker::PhantomData;
use rand_core::{CryptoRng, RngCore};
use sigma_rs::{
    codec::ShakeCodec,
    composition::{Protocol, ProtocolWitness},
    LinearRelation, NISigmaProtocol,
};

pub struct DiscreteLog<G: Group + GroupEncoding> {
    _g: PhantomData<G>,
}

pub struct Params<G: Group + GroupEncoding> {
    g: G,
    h: G,
    pks: Vec<G>,
    cks_commits: Option<Vec<G>>,
}

pub struct Encoding<G: Group + GroupEncoding> {
    rand: G,
    secret: G,
    vals: Vec<G>,
}

impl<G: Group + GroupEncoding> DiscreteLog<G> {
    /// Prove that the encoding is well-formed with inputs either 0 or 1.
    fn create_relation(params: &Params<G>, ck: G, encoding: &Encoding<G>) -> Protocol<G> {
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
            
            let g = relation.allocate_element();
            let h = relation.allocate_element();
            let pk1 = relation.allocate_element();
            let pk2 = relation.allocate_element();
            relation.set_element(g, params.g);
            relation.set_element(h, params.h);
            relation.set_element(pk1, params.pks[0]);
            relation.set_element(pk2, params.pks[1]);

            // Relation 0: c_0 = g * r
            let r_0 = relation.allocate_eq(g * r);
            relation.set_element(r_0, encoding.rand);

            // Relation 1: c_1 = pk1 * r + g * s
            let r_1 = relation.allocate_eq(pk1 * r + g * s);
            relation.set_element(r_1, encoding.secret);
            
            // Relation 2: ck = h^s
            let r_2 = relation.allocate_eq(h * s);
            relation.set_element(r_2, ck);

            // Relation 3: c_2 = pk2 * r + g * x for x = 0 or x = 1
            let r_3 = relation.allocate_eq(pk2 * r);
            match i {
                0 => relation.set_element(r_3, encoding.vals[0]),
                1 => relation.set_element(r_3, encoding.vals[0] - params.g),
                _ => unreachable!(),
            };
        }
        
        Protocol::Or(relations.into_iter().map(|r| Protocol::from(r)).collect::<Vec<_>>())
    }
}

impl<G: Group + GroupEncoding> Encoding<G> {
    fn size(&self) -> usize {
        self.rand.to_bytes().as_ref().len() +
        self.secret.to_bytes().as_ref().len() +
        self.vals.iter().map(|v| v.to_bytes().as_ref().len()).sum::<usize>()
    }
}

// todo: Eventually abstract out the encryption scheme
impl<G: Group + GroupEncoding> super::Aggregation for DiscreteLog<G> {
    type Params = Params<G>;
    type DecryptorKey = (Vec<G::Scalar>, G::Scalar);
    type ClientKey = G::Scalar;
    type Input = G::Scalar;
    type Output = G; // protocol outputs `g^X` where X is the aggregated sum. 
    type Encoding = Encoding<G>;
    type Proof = Vec<u8>;
    
    fn setup<R: RngCore + CryptoRng>(
        num_clients: usize,
        length: usize,
        rng: &mut R
    ) -> (Self::Params, Self::DecryptorKey, Vec<Self::ClientKey>) {
        let mut client_keys = Vec::with_capacity(num_clients);
        let mut share = G::Scalar::ZERO;
        for _ in 0..num_clients {
            let c_share = G::Scalar::random(&mut *rng);
            share += c_share;
            client_keys.push(c_share);
        }

        let g = G::generator();
        let h = G::random(&mut *rng); // todo: generate correctly
        let secret_keys: Vec<_> = (0..=length).map(|_| G::Scalar::random(&mut *rng)).collect();

        let params = Params {
            g,
            h,
            pks: secret_keys.iter().map(|ski| g * ski).collect(),
            cks_commits: Some(client_keys.iter().map(|ck| h * ck).collect::<Vec<G>>()),
        };

        (params, (secret_keys, share), client_keys)
    }

    fn encode<R: RngCore + CryptoRng>(
        params: &Self::Params,
        key: &Self::ClientKey,
        val: &[Self::Input],
        rng: &mut R,
    ) -> Result<(Self::Encoding, Self::Proof), ()> {
        assert_eq!(params.pks.len()-1, val.len());
        let g = G::generator();

        // Compute input encoding (ElGamal ciphertext)
        let r = G::Scalar::random(&mut *rng);
        let encoding = Encoding {
            rand: g * r,
            secret: params.pks[0] * r + g * key,
            vals: val
                .iter()
                .enumerate()
                .map(|(i, v)| params.pks[i + 1] * r + g * v)
                .collect::<Vec<_>>(),
        };

        // Prove ciphertext is well-formed
        let relation = Self::create_relation(params, params.h * key, &encoding);
        let witness = match val[0] == G::Scalar::ZERO {
            true => ProtocolWitness::Or(0, vec![ProtocolWitness::Simple(vec![r, *key])]),
            false => ProtocolWitness::Or(1, vec![ProtocolWitness::Simple(vec![r, *key])]),
        };
        let nizk = NISigmaProtocol::<_, ShakeCodec<G>>::new(b"dl_agg_enc", relation);
        let proof = nizk.prove_batchable(&witness, rng).unwrap(); // TODO
        Ok((encoding, proof))
    }
    
    fn aggregate(
        params: &Self::Params,
        encodings: Vec<Self::Encoding>,
        proofs: Vec<Self::Proof>
    ) -> Result<Self::Encoding, ()> {
        let one = G::identity();
        let mut agg = Encoding {
            rand: one,
            secret: one,
            vals: vec![one; encodings[0].vals.len()],
        };

        for (i, (enc, proof)) in encodings.into_iter().zip(proofs).enumerate() {
            // Verify proofs (todo: batch verify)
            let ck = params.cks_commits.as_ref().unwrap()[i];
            let relation = Self::create_relation(params, ck, &enc);
            let nizk = NISigmaProtocol::<_, ShakeCodec<G>>::new(b"dl_agg_enc", relation);
            nizk.verify_batchable(&proof).unwrap(); // todo
            
            // Aggregate
            agg.rand += enc.rand;
            agg.secret += enc.secret;
            agg.vals.iter_mut().zip(enc.vals).for_each(|(a, e)| *a += e);
        }
        Ok(agg)
    }

    fn decode(key: &Self::DecryptorKey, aggregate: Self::Encoding) -> Result<Vec<Self::Output>, ()> {
        let g = G::generator();
        let c_lifted_share = aggregate.secret - aggregate.rand * key.0[0];
        if c_lifted_share ==  g * key.1 {
            Ok(aggregate.vals
                .into_iter()
                .enumerate()
                .map(|(i, x)| x - aggregate.rand * key.0[i+1])
                .collect::<Vec<_>>())
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::*;
    
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::RistrettoPoint;
    use group::Group;
    use rand::{Rng, rngs::OsRng};
    use std::time::{Duration, Instant};

    use ff::PrimeField;

    type G = RistrettoPoint;
    type Agg = DiscreteLog<G>;

    #[test]
    fn basic_sum() {
        let num_clients = 1000;
        let length = 1;
        let (params, sk, cks) = Agg::setup(num_clients, length, &mut OsRng);

        // Generate encodings and proofs
        let mut sums = vec![0; length];
        let mut encodings = Vec::with_capacity(num_clients);
        let mut proofs = Vec::with_capacity(num_clients);
        for i in 0..num_clients {
            let mut inputs = Vec::with_capacity(length);
            for j in 0..length {
                let val = OsRng.gen_bool(0.5);
                sums[j] += val as u32;
                inputs.push(match val {
                    true => Scalar::ONE,
                    false => Scalar::ZERO,
                });
            }
            let (encoding, proof) = Agg::encode(&params, &cks[i], &inputs, &mut OsRng).unwrap();
            encodings.push(encoding);
            proofs.push(proof);
        }
       
        // Aggregate and decode
        let agg = Agg::aggregate(&params, encodings, proofs).unwrap();
        let results = Agg::decode(&sk, agg).unwrap();

        // Solve discrete-log for each result
        let g = G::generator();
        for (i, result) in results.into_iter().enumerate() {
            let mut guess = Scalar::ZERO;
            for _ in 0..num_clients {
                if guess * g == result {
                    break;
                }
                guess += Scalar::ONE;
            }
            assert_eq!(guess, Scalar::from(sums[i]));
        }
    }
}
