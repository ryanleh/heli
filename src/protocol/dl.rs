use super::{MSM, dlog::*, messages::*, proofs::*};
use anyhow::{Result, anyhow};
use ff::Field;
use group::{Group, GroupEncoding};
use rand_core::{CryptoRng, RngCore};
use std::marker::PhantomData;

pub struct DiscreteLog<G: Group + GroupEncoding, P: Prover<G>> {
    _g: PhantomData<G>,
    _p: PhantomData<P>,
}

impl<G: Group + GroupEncoding, P: Prover<G>> DiscreteLog<G, P>
where
    G: MSM<Coeff = G::Scalar, Point = G>,
{
    pub fn setup<R: RngCore + CryptoRng>(
        num_clients: usize,
        length: usize,
        rng: &mut R,
    ) -> (AggParams<G>, DecKey<G>, Vec<ClientKey<G>>) {
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

        let params = AggParams {
            g,
            h,
            pks,
            client_key_comms: client_keys
                .iter()
                .map(|ck| h * ck.secret)
                .collect::<Vec<G>>(),
        };

        (params, DecKey { secret_keys, share }, client_keys)
    }

    pub fn encode<R: RngCore + CryptoRng>(
        key: &ClientKey<G>,
        prover_key: &P::ProverKey,
        val: &[u32],
        rng: &mut R,
    ) -> Result<(Encoding<G>, P::Proof)> {
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
        let proof = P::prove(prover_key, key, val, r, &encoding, rng);
        Ok((encoding, proof))
    }

    pub fn verify_encodings(
        params: &AggParams<G>,
        verifier_key: &P::VerifierKey,
        client_indices: Option<&[u32]>,
        encodings: &[Encoding<G>],
        proofs: &[P::Proof],
    ) -> Result<()> {
        debug_assert_eq!(encodings.len(), proofs.len());
        let proof_indices = match client_indices {
            Some(indices) => indices.to_vec(),
            None => (0..encodings.len() as u32).collect::<Vec<_>>(),
        };
        for (i, (enc, pi)) in encodings.iter().zip(proofs.iter()).enumerate() {
            if !P::verify(verifier_key, params, proof_indices[i], enc, pi) {
                return Err(anyhow!("Proof verification failed for client {}", i));
            }
        }
        Ok(())
    }

    pub fn batch_verify_encodings<R: RngCore + CryptoRng>(
        params: &AggParams<G>,
        verifier_key: &P::VerifierKey,
        client_indices: Option<&[u32]>,
        encodings: &[Encoding<G>],
        proofs: &[P::Proof],
        rng: &mut R,
    ) -> Result<()> {
        debug_assert_eq!(encodings.len(), proofs.len());
        let proof_indices = match client_indices {
            Some(indices) => indices.to_vec(),
            None => (0..encodings.len() as u32).collect::<Vec<_>>(),
        };

        if !P::batch_verify(
            verifier_key,
            params,
            proof_indices.as_slice(),
            encodings,
            proofs,
            rng,
        ) {
            return Err(anyhow!("Proof verification failed"));
        }
        Ok(())
    }

    pub fn aggregate(_params: &AggParams<G>, encodings: &[Encoding<G>]) -> Result<Encoding<G>> {
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

    pub fn decode(key: &DecKey<G>, aggregate: Encoding<G>) -> Result<PartialOutput<G>> {
        let g = G::generator();
        let c_lifted_share = aggregate.secret - aggregate.rand * key.secret_keys[0];
        if c_lifted_share == g * key.share {
            Ok(PartialOutput {
                vals: aggregate
                    .vals
                    .into_iter()
                    .enumerate()
                    .map(|(i, x)| x - aggregate.rand * key.secret_keys[i + 1])
                    .collect::<Vec<_>>(),
            })
        } else {
            Err(anyhow!("Verification failure"))
        }
    }

    pub fn post_process(
        params: &AggParams<G>,
        partial_outputs: PartialOutput<G>,
    ) -> Result<Vec<u32>> {
        let g = G::generator();
        let max_dlog = Self::num_clients(params) as u32 + 1;
        let results = partial_outputs
            .vals
            .into_iter()
            .map(|partial| compute_dlog(&g, &partial, max_dlog))
            .collect::<Result<Vec<_>>>()?;
        Ok(results)
    }

    pub fn num_clients(params: &AggParams<G>) -> usize {
        params.client_key_comms.len()
    }

    pub fn length(params: &AggParams<G>) -> usize {
        params.pks.len() - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::protocol::{Ristretto, proofs::BinarySchnorr};
    use rand::{Rng, rngs::OsRng};

    type G = Ristretto;
    type P = BinarySchnorr<G>;
    type Agg = DiscreteLog<G, P>;

    #[test]
    fn basic_aggregation() {
        //let num_clients = 1000;
        let num_clients = 1000;
        let length = 1;
        let (params, sk, cks) = Agg::setup(num_clients, length, &mut OsRng);

        // Setup proof system
        let (prover_key, verifier_key) = P::setup();

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
            let (encoding, proof) = Agg::encode(&cks[i], &prover_key, &inputs, &mut OsRng).unwrap();
            encodings.push(encoding);
            proofs.push(proof);
        }

        // Check proofs and combine encodings
        Agg::verify_encodings(&params, &verifier_key, None, &encodings, &proofs).unwrap();
        let agg = Agg::aggregate(&params, &encodings).unwrap();
        let partial_results = Agg::decode(&sk, agg).unwrap();
        let results = Agg::post_process(&params, partial_results).unwrap();

        for (i, result) in results.into_iter().enumerate() {
            assert_eq!(result, sums[i]);
        }
    }
}
