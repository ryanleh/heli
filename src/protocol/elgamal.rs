use super::{G, Scalar, messages::*, provers::Prover};
use anyhow::{Result, anyhow};
use group::Group;
use rand_core::{CryptoRng, RngCore};
use std::{collections::HashMap, marker::PhantomData};

pub struct ElGamal<P: Prover> {
    _p: PhantomData<P>,
}

impl<P: Prover> ElGamal<P> {
    fn compute_dlog(g: &G, challenge: &G, max_dlog: u64) -> Result<u64> {
        if max_dlog > (u64::MAX >> 4) {
            return Err(anyhow!("max_dlog is too large"));
        }

        let m = ((max_dlog as f64).sqrt().ceil() as u64) + 1;
        let m_scalar = Scalar::from(m);

        // Compute giant steps table: g^(m*i) for i in 0..m
        let mut giant_steps: HashMap<Vec<u8>, u64> = HashMap::with_capacity(m as usize);
        let giant_step = *g * m_scalar;
        let mut curr = G::identity();

        // Compute g^(m*i) for i in 0..m
        for i in 0..m {
            let curr_bytes = curr.compress().to_bytes().as_ref().to_vec();
            giant_steps.insert(curr_bytes, i * m);
            curr += giant_step;
        }

        // Compute challenge * g^j for j in 0..m
        let mut guess = *challenge;
        for j in 0..m {
            let guess_bytes = guess.compress().to_bytes().as_ref().to_vec();
            if let Some(&i) = giant_steps.get(&guess_bytes) {
                let res = i - j;
                if res < max_dlog {
                    return Ok(res);
                }
            }
            guess += *g;
        }
        Err(anyhow!("discrete log not found"))
    }
}

impl<P: Prover> ElGamal<P> {
    pub fn setup<R: RngCore + CryptoRng>(
        num_clients: usize,
        length: usize,
        rng: &mut R,
    ) -> (AggParams, DecKey, Vec<ClientKey>) {
        let g = G::generator();
        let h = G::random(&mut *rng); // TODO: generate correctly
        let secret_keys: Vec<_> = (0..=length).map(|_| Scalar::random(&mut *rng)).collect();
        let pks: Vec<_> = secret_keys.iter().map(|ski| g * ski).collect();

        let mut client_keys = Vec::with_capacity(num_clients);
        let mut share = Scalar::ZERO;
        for _ in 0..num_clients {
            let c_share = Scalar::random(&mut *rng);
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
        key: &ClientKey,
        prover_key: &P::ProverKey,
        val: &[u64],
        rng: &mut R,
    ) -> Result<(Encoding, P::Proof)> {
        debug_assert!(
            val.iter().all(|v| *v == 0 || *v == 1),
            "Only binary inputs are currently supported"
        );
        debug_assert_eq!(key.pks.len() - 1, val.len());
        let g = G::generator();

        // Compute input encoding (ElGamal ciphertext)
        let r = Scalar::random(&mut *rng);
        let encoding = Encoding {
            rand: g * r,
            secret: key.pks[0] * r + g * key.secret,
            vals: val
                .iter()
                .enumerate()
                .map(|(i, v)| key.pks[i + 1] * r + g * Scalar::from(*v))
                .collect::<Vec<_>>(),
        };

        // Prove ciphertext is well-formed and inputs are binary
        let proof = P::prove(prover_key, key, val, r, &encoding, rng);
        Ok((encoding, proof))
    }

    pub fn verify_encodings(
        params: &AggParams,
        verifier_key: &P::VerifierKey,
        client_indices: Option<&[u32]>,
        encodings: &[Encoding],
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
        params: &AggParams,
        verifier_key: &P::VerifierKey,
        client_indices: Option<&[u32]>,
        encodings: &[Encoding],
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

    pub fn aggregate(_params: &AggParams, encodings: &[Encoding]) -> Result<Encoding> {
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

    pub fn decode(key: &DecKey, aggregate: Encoding) -> Result<PartialOutput> {
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

    pub fn post_process(params: &AggParams, partial_outputs: PartialOutput) -> Result<Vec<u64>> {
        let g = G::generator();
        let max_dlog = Self::num_clients(params) + 1;
        let results = partial_outputs
            .vals
            .into_iter()
            .map(|partial| Self::compute_dlog(&g, &partial, max_dlog))
            .collect::<Result<Vec<_>>>()?;
        Ok(results)
    }

    pub fn num_clients(params: &AggParams) -> u64 {
        params.client_key_comms.len() as u64
    }

    pub fn length(params: &AggParams) -> usize {
        params.pks.len() - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{G, provers::Binary};
    use rand::{Rng, rngs::OsRng};

    type P = Binary;
    type Agg = ElGamal<P>;

    #[test]
    fn basic_bool_aggregation() {
        //let num_clients = 1000;
        let num_clients = 1000;
        let length = 1;
        let (params, sk, cks) = Agg::setup(num_clients, length, &mut OsRng);

        // Setup proof system
        let (prover_key, verifier_key) = P::setup(length, 1);

        // Generate encodings and proofs
        let mut sums = vec![0; length];
        let mut encodings = Vec::with_capacity(num_clients);
        let mut proofs = Vec::with_capacity(num_clients);
        for i in 0..num_clients {
            let mut inputs = Vec::with_capacity(length);
            for j in 0..length {
                let val = OsRng.gen_bool(0.5) as u64;
                sums[j] += val;
                inputs.push(val);
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

    #[test]
    fn test_compute_dlog() {
        let g = G::generator();
        let n = 1000;

        // Test finding discrete log for known values
        for x in [0u64, 1u64, 5u64, 42u64, 999u64].iter() {
            let scalar = <G as Group>::Scalar::from(*x);
            let output = g * scalar;

            let result = ElGamal::<P>::compute_dlog(&g, &output, n).unwrap();
            assert_eq!(result, *x);
        }

        // Test value outside range
        let scalar = <G as Group>::Scalar::from(1000u64);
        let output = g * scalar;
        assert!(ElGamal::<P>::compute_dlog(&g, &output, n).is_err());

        // Test large value near u32::MAX
        let n_big = u32::MAX as u64;
        let scalar = <G as Group>::Scalar::from(n_big - 1);
        let output = g * scalar;
        assert_eq!(
            ElGamal::<P>::compute_dlog(&g, &output, n_big).unwrap(),
            n_big - 1,
        );
    }

    #[test]
    fn measure_sizes() {
        use bytesize::ByteSize;

        let lengths = vec![1, 5, 10, 25, 50, 75, 100];
        let bitlength = 1;
        debug_assert_eq!(bitlength, 1, "Only binary inputs are currently supported");

        println!("\n=== Size Measurements (Serde/Bincode) ===");
        println!("Format: (input_length) -> encoding_size + proof_size = comm_per_client\n");

        for length in lengths.iter() {
            let (_params, _sk, cks) = Agg::setup(1, *length, &mut OsRng);
            let (prover_key, _) = P::setup(*length, bitlength);

            // Generate one encoding and proof for size measurement
            let input: Vec<u64> = (0..*length)
                .map(|_| if OsRng.gen_bool(0.5) { 1 } else { 0 })
                .collect();
            let (encoding, proof) = Agg::encode(&cks[0], &prover_key, &input, &mut OsRng).unwrap();

            // Serialize using bincode
            let encoding_size = bincode::serialized_size(&encoding).unwrap() as usize;
            let proof_size = bincode::serialized_size(&proof).unwrap() as usize;
            let total_size = encoding_size + proof_size;

            println!(
                "({:>3}) -> {:>8} + {:>8} = {:>8}",
                length,
                ByteSize::b(encoding_size as u64),
                ByteSize::b(proof_size as u64),
                ByteSize::b(total_size as u64)
            );
        }
        println!("\n========================\n");
    }
}
