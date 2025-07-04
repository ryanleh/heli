use super::{Aggregation, dlog::*, messages::*, proofs::*};

use anyhow::{Result, anyhow};
use ff::Field;
use group::{Group, GroupEncoding};
use rand_core::{CryptoRng, RngCore};
use std::marker::PhantomData;

pub struct DiscreteLog<G: Group + GroupEncoding> {
    _g: PhantomData<G>,
}

impl<G: Group + GroupEncoding> Aggregation for DiscreteLog<G> {
    type Params = Params<G>;
    type DecryptorKey = (Vec<G::Scalar>, G::Scalar);
    type ClientKey = ClientKey<G>;
    type Encoding = Encoding<G>;
    type Proof = Proof<G>;
    type PartialOutput = PartialOutput<G>;

    fn setup<R: RngCore + CryptoRng>(
        num_clients: usize,
        length: usize,
        rng: &mut R,
    ) -> (Self::Params, Self::DecryptorKey, Vec<Self::ClientKey>) {
        let g = G::generator();
        let h = G::random(&mut *rng); // TODO: generate correctly
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
        val: &[u32],
        rng: &mut R,
    ) -> Result<(Self::Encoding, Self::Proof)> {
        debug_assert!(
            val.iter().all(|v| *v == 0 || *v == 1),
            "Only binary inputs are currently supported"
        );
        debug_assert_eq!(key.pks.len() - 1, val.len());
        let g = G::generator();

        // Compute input encoding (ElGamal ciphertext)
        let r = G::Scalar::random(&mut *rng);
        let encoding = Encoding {
            rand: g * r,
            secret: key.pks[0] * r + g * key.secret,
            vals: val
                .iter()
                .enumerate()
                .map(|(i, v)| key.pks[i + 1] * r + g * G::Scalar::from(*v as u64))
                .collect::<Vec<_>>(),
        };

        // Prove ciphertext is well-formed and inputs are binary
        let proof = create_proof_binary(key, r, val, &encoding, rng);
        Ok((encoding, proof))
    }

    fn verify_encodings(
        params: &Self::Params,
        _client_indices: Option<&[u32]>,
        encodings: &[Self::Encoding],
        proofs: &[Self::Proof],
    ) -> Result<()> {
        debug_assert_eq!(encodings.len(), proofs.len());
        for (i, (enc, pi)) in encodings.iter().zip(proofs.iter()).enumerate() {
            if !verify_proof_binary(params, i as u32, enc, pi) {
                return Err(anyhow!("Proof verification failed for client {}", i));
            }
        }
        Ok(())
    }

    fn aggregate(_params: &Self::Params, encodings: &[Self::Encoding]) -> Result<Self::Encoding> {
        let one = G::identity();
        let mut agg = Encoding {
            rand: one,
            secret: one,
            vals: vec![one; encodings[0].vals.len()],
        };

        for enc in encodings {
            agg.rand += enc.rand;
            agg.secret += enc.secret;
            agg.vals
                .iter_mut()
                .zip(enc.vals.iter())
                .for_each(|(a, e)| *a += e);
        }
        Ok(agg)
    }

    fn decode(key: &Self::DecryptorKey, aggregate: Self::Encoding) -> Result<Self::PartialOutput> {
        let g = G::generator();
        let c_lifted_share = aggregate.secret - aggregate.rand * key.0[0];
        if c_lifted_share == g * key.1 {
            Ok(PartialOutput {
                vals: aggregate
                    .vals
                    .into_iter()
                    .enumerate()
                    .map(|(i, x)| x - aggregate.rand * key.0[i + 1])
                    .collect::<Vec<_>>(),
            })
        } else {
            Err(anyhow!("Verification failure"))
        }
    }

    fn post_process(
        params: &Self::Params,
        partial_outputs: Self::PartialOutput,
    ) -> Result<Vec<u32>> {
        let g = G::generator();
        let mut results = Vec::with_capacity(partial_outputs.vals.len());

        for (i, output) in partial_outputs.vals.iter().enumerate() {
            // Bruteforce discrete log
            let max_dlog = Self::num_clients(params);
            let found = compute_dlog(&g, output, max_dlog as u32, &mut results[i]);
            
            if !found {
                // Handle error case where discrete log not found
                return Err(anyhow!("Could not find discrete log"));
            }
        }

        Ok(results)
    }

    fn num_clients(params: &Self::Params) -> usize {
        params.client_key_comms.len()
    }

    fn length(params: &Self::Params) -> usize {
        params.pks.len() - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{Rng, rngs::OsRng};

    type G = curve25519_dalek::RistrettoPoint;
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
}
