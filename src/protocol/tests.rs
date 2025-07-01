use crate::protocol::*;

use curve25519_dalek::{RistrettoPoint, scalar::Scalar};
use group::Group;
use rand::{Rng, rngs::OsRng};

type G = RistrettoPoint;
type Agg = DiscreteLog<G>;

#[test]
fn basic_aggregation() {
    //let num_clients = 1000;
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
            inputs.push(val as u32);
        }
        let (encoding, proof) = Agg::encode(&cks[i], &inputs, &mut OsRng).unwrap();
        encodings.push(encoding);
        proofs.push(proof);
    }

    // Check proofs and combine encodings
    Agg::verify_encodings(&params, None, &encodings, &proofs).unwrap();
    let agg = Agg::aggregate(&params, &encodings).unwrap();
    let partial_results = Agg::decode(&sk, agg).unwrap();
    let results = Agg::post_process(&params, partial_results).unwrap();

    for (i, result) in results.into_iter().enumerate() {
        assert_eq!(result, sums[i]);
    }
}
