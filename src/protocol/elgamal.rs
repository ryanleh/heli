use super::{G, Scalar, messages::*};
use anyhow::{Result, anyhow};
use group::Group;
use rand_core::{CryptoRng, RngCore};
use sha3::{Digest, Sha3_512};
use std::collections::HashMap;

pub struct ElGamal;

impl ElGamal {
    pub fn compute_dlog(g: &G, challenge: &G, max_dlog: u64) -> Result<u64> {
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

    pub fn setup<R: RngCore + CryptoRng>(
        num_clients: usize,
        length: usize,
        rng: &mut R,
    ) -> (AggParams, DecKey, Vec<ClientKey>) {
        // Compute generators
        let g = G::generator();
        let h = G::from_hash(Sha3_512::new().chain_update(b"h"));

        // Compute keys
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
        val: &[u64],
        rng: &mut R,
    ) -> Result<(Encoding, Scalar)> {
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

        Ok((encoding, r))
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

    pub fn post_process(
        params: &AggParams,
        bitlength: usize,
        partial_outputs: PartialOutput,
    ) -> Result<Vec<u64>> {
        let g = G::generator();
        let max_dlog = (1 << bitlength) * (Self::num_clients(params) + 1);
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
    use rand::{Rng, rngs::OsRng};

    #[test]
    fn basic_enc_correctness() {
        let num_clients = 5;
        let length = 8;
        let bitlength = 8;
        let (params, sk, cks) = ElGamal::setup(num_clients, length, &mut OsRng);

        let mut encodings = Vec::with_capacity(num_clients);
        let mut expected_sums = vec![0u64; length];
        for i in 0..num_clients {
            let inputs: Vec<u64> = (0..length)
                .map(|_| OsRng.gen_range(0..1 << bitlength))
                .collect();

            // Track expected sums
            for (j, &val) in inputs.iter().enumerate() {
                expected_sums[j] += val;
            }

            let (encoding, _r) = ElGamal::encode(&cks[i], &inputs, &mut OsRng).unwrap();
            encodings.push(encoding);
        }

        let aggregate = ElGamal::aggregate(&params, &encodings).unwrap();
        let partial_output = ElGamal::decode(&sk, aggregate).unwrap();
        let result = ElGamal::post_process(&params, bitlength, partial_output).unwrap();

        assert_eq!(result, expected_sums);
    }

    #[test]
    fn compute_dlog() {
        let g = G::generator();
        let n = 1000;

        // Test finding discrete log for known values
        for x in [0u64, 1u64, 5u64, 42u64, 999u64].iter() {
            let scalar = <G as Group>::Scalar::from(*x);
            let output = g * scalar;

            let result = ElGamal::compute_dlog(&g, &output, n).unwrap();
            assert_eq!(result, *x);
        }

        // Test value outside range
        let scalar = <G as Group>::Scalar::from(1000u64);
        let output = g * scalar;
        assert!(ElGamal::compute_dlog(&g, &output, n).is_err());

        // Test large value near u32::MAX
        let n_big = u32::MAX as u64;
        let scalar = <G as Group>::Scalar::from(n_big - 1);
        let output = g * scalar;
        assert_eq!(
            ElGamal::compute_dlog(&g, &output, n_big).unwrap(),
            n_big - 1,
        );
    }
}
