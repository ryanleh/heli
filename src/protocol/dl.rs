use ff::Field;
use group::{Group, GroupEncoding};
use std::marker::PhantomData;
use rand_core::RngCore; // todo: Eventually go over RNGs

pub struct DiscreteLog<G: Group> {
    _g: PhantomData<G>,
}

pub struct Encoding<G: Group> {
    rand: G,
    secret: G,
    vals: Vec<G>,
}

impl<G: Group> Encoding<G> {

}

// todo: Eventually abstract out the encryption scheme
impl<G: Group> super::Aggregation for DiscreteLog<G> {
    type Params = Vec<G>;
    type DecryptorKey = (Vec<G::Scalar>, G::Scalar);
    type ClientKey = G::Scalar;
    type Input = G::Scalar;
    type Output = G; // protocol outputs `g^X` where X is the aggregated sum. 
    type Encoding = Encoding<G>; // todo: Proof
    
    fn setup<R: RngCore>(
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
        let secret_keys: Vec<_> = (0..=length).map(|_| G::Scalar::random(&mut *rng)).collect();
        let public_keys = secret_keys.iter().map(|ski| g * ski).collect();
        (public_keys, (secret_keys, share), client_keys)
    }

    fn encode<R: RngCore>(
        params: &Self::Params,
        key: &Self::ClientKey,
        val: &[Self::Input],
        rng: &mut R,
    ) -> Self::Encoding {
        assert_eq!(params.len()-1, val.len());
        
        let g = G::generator();
        let r = G::Scalar::random(rng);
        Encoding {
            rand: g * r,
            secret: params[0] * r + g * key,
            vals: val
                .iter()
                .enumerate()
                .map(|(i, v)| params[i + 1] * r + g * v)
                .collect::<Vec<_>>(),
        }
    }

    fn aggregate(encodings: Vec<Self::Encoding>) -> Self::Encoding {
        let one = G::identity();
        let agg = Encoding {
            rand: one,
            secret: one,
            vals: vec![one; encodings[0].vals.len()],
        };

        encodings
            .into_iter()
            .fold(agg, |mut e1, e2| {
                e1.rand += e2.rand;
                e1.secret += e2.secret;
                e1.vals.iter_mut().enumerate().for_each(|(i, e)| *e += e2.vals[i]);
                e1
            })
    }

    fn decode(key: &Self::DecryptorKey, aggregate: Self::Encoding) -> Result<Vec<Self::Output>, ()> {
        //let (sk1, sk2, share) = key;
        //let (g_r, g_s, g_x) = aggregate;

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

impl<G: Group + GroupEncoding> Encoding<G> {
    fn size(&self) -> usize {
        self.rand.to_bytes().as_ref().len() +
        self.secret.to_bytes().as_ref().len() +
        self.vals.iter().map(|v| v.to_bytes().as_ref().len()).sum::<usize>()
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
        let length = 5;
        let (params, sk, cks) = Agg::setup(num_clients, length, &mut OsRng);

        // Generate encodings
        let mut sums = vec![0; length];
        let mut encodings = Vec::with_capacity(num_clients);
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
            encodings.push(Agg::encode(&params, &cks[i], &inputs, &mut OsRng));
        }
       
        // Aggregate and decode
        let agg = Agg::aggregate(encodings);
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
