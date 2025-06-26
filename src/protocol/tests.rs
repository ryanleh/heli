use crate::protocol::*;

use curve25519_dalek::{RistrettoPoint, scalar::Scalar};
use group::Group;
use rand::{Rng, rngs::OsRng};

type G = RistrettoPoint;
type Agg = DiscreteLog<G>;

#[test]
fn basic_aggregation() {
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
        let (encoding, proof) = Agg::encode(&cks[i], &inputs, &mut OsRng).unwrap();
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
