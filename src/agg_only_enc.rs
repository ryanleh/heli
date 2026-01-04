use crate::crypto::*;
use anyhow::Result;
use group::Group;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Aggregation-only encryption instantiated with
/// Naor-Pinkas-Reingold key-homomorphic PRF
///
/// This implementation only supports basic sums, not general linear functions.
pub struct AggOnlyEnc;

pub struct SecretKey {
    prf_key: Scalar,
    keygen_prf: ScalarPRF,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct EvalKey(Scalar);

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Ciphertext(Vec<G>);

impl AggOnlyEnc {
    // Given the function arity, output a secret key and set of evaluation keys
    pub fn setup<R: RngCore + CryptoRng>(arity: usize, rng: &mut R) -> (SecretKey, Vec<EvalKey>) {
        // Initialize PRF for generating client keys
        let mut keygen_prf_key = [0u8; 32];
        rng.fill_bytes(&mut keygen_prf_key);
        let keygen_prf = ScalarPRF::new(&keygen_prf_key);

        // Generate evaluation keys
        let mut prf_key = Scalar::ZERO;
        let eval_keys = (0..arity)
            .map(|i| {
                let prf_key_share = keygen_prf.evaluate(i as u64);
                prf_key += prf_key_share;
                EvalKey(prf_key_share)
            })
            .collect();

        (
            SecretKey {
                prf_key,
                keygen_prf,
            },
            eval_keys,
        )
    }

    // Encrypt an input under the provided context and randomness
    pub fn encrypt(ek: &EvalKey, context: u32, input: &[Scalar]) -> Ciphertext {
        // For each slot, the KH-PRF is evaluated on the context concatenated with the slot index.
        let g = G::generator();
        Ciphertext(
            input
                .iter()
                .enumerate()
                .map(|(i, x)| g * x + KHPRF::evaluate_context(&ek, context, i))
                .collect(),
        )
    }

    // Generate the decryption mask for a given context and dropout list
    pub fn decrypt_mask(
        sk: &SecretKey,
        context: u32,
        dropouts: &[usize],
        invert: bool,
        length: usize,
    ) -> Vec<G> {
        let key = match dropouts.len() {
            0 => sk.prf_key,
            _ => match invert {
                false => sk.prf_key - sk.keygen_prf.batch_evaluate(dropouts),
                true => sk.keygen_prf.batch_evaluate(dropouts),
            },
        };
        (0..length)
            .map(|i| KHPRF::evaluate_context(&key, context, i))
            .collect()
    }

    // Decrypt an aggregate ciphertext using the provided decryption mask
    pub fn decrypt(aggregate: &[G], mask: &[G], max_dlog: u64) -> Result<Vec<u64>> {
        let g = G::generator();
        let result = aggregate
            .into_iter()
            .zip(mask.iter())
            .map(|(a, m)| a - m)
            .map(|a| compute_dlog(&g, &a, max_dlog))
            .collect::<Result<Vec<_>>>()?;
        Ok(result)
    }
}

impl std::ops::Deref for EvalKey {
    type Target = Scalar;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::Deref for Ciphertext {
    type Target = [G];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Homomorphically add ciphertexts
impl std::ops::Add for Ciphertext {
    type Output = Ciphertext;

    fn add(mut self, other: Ciphertext) -> Ciphertext {
        self.0
            .iter_mut()
            .zip(other.iter())
            .for_each(|(e1, e2)| *e1 += e2);
        self
    }
}

// Homomorphically multiply ciphertext by scalar
impl std::ops::Mul<Scalar> for Ciphertext {
    type Output = Ciphertext;

    fn mul(mut self, scalar: Scalar) -> Ciphertext {
        self.0.iter_mut().for_each(|slot| *slot *= scalar);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, rngs::OsRng};

    fn random_inputs(length: usize, max_val: u64) -> Vec<Scalar> {
        let mut rng = OsRng;
        (0..length)
            .map(|_| Scalar::from(rng.gen_range(0..max_val)))
            .collect()
    }

    #[test]
    fn agg_only_correctness() {
        let mut rng = OsRng;
        let arity = 5;
        let context = 2357;
        let length = 3;
        let max_val = 1000;

        // Setup the scheme
        let (sk, eval_keys) = AggOnlyEnc::setup(arity, &mut rng);

        // Generate ciphertexts
        let mut inputs = Vec::with_capacity(arity);
        let mut ciphertexts = Vec::with_capacity(arity);
        for i in 0..arity {
            // Generate ciphertext
            let input = random_inputs(length, max_val);
            ciphertexts.push(AggOnlyEnc::encrypt(&eval_keys[i], context, &input));
            inputs.push(input);
        }

        // Test aggregation with different sets of dropouts
        let dropouts: Vec<Vec<usize>> = vec![vec![], vec![1, 2, 3], vec![0, 4]];
        for dropout in dropouts {
            // Only aggregate ciphertexts that are not in the dropout list
            let (to_aggregate_inputs, to_aggregate_cts): (Vec<_>, Vec<_>) = ciphertexts
                .iter()
                .enumerate()
                .filter(|(i, _)| !dropout.contains(i))
                .map(|(i, ct)| (inputs[i].clone(), ct.clone()))
                .unzip();
            let aggregate = to_aggregate_cts.into_iter().reduce(|a, b| a + b).unwrap();
            let mask =
                AggOnlyEnc::decrypt_mask(&sk, context, dropout.as_slice(), false, aggregate.len());
            let results = AggOnlyEnc::decrypt(&aggregate, &mask, max_val * arity as u64).unwrap();

            // Check that doing the inverse dropout list produces the same mask
            if dropout.len() != 0 {
                let online = (0..arity)
                    .filter(|i| !dropout.contains(i))
                    .collect::<Vec<_>>();
                let mask_from_inv = AggOnlyEnc::decrypt_mask(
                    &sk,
                    context,
                    online.as_slice(),
                    true,
                    aggregate.len(),
                );
                assert_eq!(mask, mask_from_inv);
            }

            let expected_results = to_aggregate_inputs
                .into_iter()
                .reduce(|mut a, b| {
                    a.iter_mut().zip(b.iter()).for_each(|(x, y)| *x += y);
                    a
                })
                .unwrap();
            assert_eq!(
                results.into_iter().map(Scalar::from).collect::<Vec<_>>(),
                expected_results
            );
        }
    }

    #[test]
    fn agg_only_dropout_soundness() {
        let mut rng = OsRng;
        let arity = 4;
        let length = 2;
        let context = 2357;
        let max_val = 100;

        // Setup the scheme
        let (sk, eval_keys) = AggOnlyEnc::setup(arity, &mut rng);

        // Generate ciphertexts
        let mut inputs = Vec::with_capacity(arity);
        let mut ciphertexts = Vec::with_capacity(arity);
        for i in 0..arity {
            let input = random_inputs(length, max_val);
            ciphertexts.push(AggOnlyEnc::encrypt(&eval_keys[i], context, &input));
            inputs.push(input);
        }

        // Test case 1: Claim dropouts that didn't happen
        let aggregate1 = ciphertexts
            .clone()
            .into_iter()
            .reduce(|a, b| a + b)
            .unwrap();
        let wrong_dropouts = vec![0, 2]; // Claiming clients 0 and 2 dropped out, but they didn't
        let mask = AggOnlyEnc::decrypt_mask(
            &sk,
            context,
            wrong_dropouts.as_slice(),
            false,
            aggregate1.len(),
        );
        let result1 = AggOnlyEnc::decrypt(&aggregate1, &mask, max_val);
        assert!(result1.is_err());

        // Test case 2: Actually drop some clients but don't report it
        let actual_dropouts = vec![1u64, 3u64]; // Actually drop clients 1 and 3
        let (_remaining_inputs, remaining_cts): (Vec<_>, Vec<_>) = ciphertexts
            .iter()
            .enumerate()
            .filter(|(i, _)| !actual_dropouts.contains(&(*i as u64)))
            .map(|(i, ct)| (inputs[i].clone(), ct.clone()))
            .unzip();
        let aggregate2 = remaining_cts.into_iter().reduce(|a, b| a + b).unwrap();
        let mask = AggOnlyEnc::decrypt_mask(
            &sk,
            context,
            wrong_dropouts.as_slice(),
            false,
            aggregate2.len(),
        );
        let result2 = AggOnlyEnc::decrypt(&aggregate2, &mask, max_val);
        assert!(result2.is_err());
    }

    #[test]
    fn test_soundness_context() {
        let mut rng = OsRng;
        let arity = 3;
        let length = 2;
        let context = 111u32;
        let wrong_context = 222u32;
        let context1 = 333u32;
        let context2 = 444u32;
        let max_val = 100;

        // Setup the scheme
        let (sk, eval_keys) = AggOnlyEnc::setup(arity, &mut rng);

        // Test case 1: Wrong context
        let mut ciphertexts = Vec::with_capacity(arity);
        for i in 0..arity {
            let input = random_inputs(length, max_val);
            ciphertexts.push(AggOnlyEnc::encrypt(&eval_keys[i], context, &input));
        }

        let aggregate1 = ciphertexts.into_iter().reduce(|a, b| a + b).unwrap();
        let mask = AggOnlyEnc::decrypt_mask(&sk, wrong_context, &[], false, aggregate1.len());
        let result1 = AggOnlyEnc::decrypt(&aggregate1, &mask, max_val);
        assert!(result1.is_err());

        // Test case 2: Mixed contexts
        let mut ciphertexts2 = Vec::with_capacity(arity);
        for i in 0..arity {
            let input = random_inputs(length, max_val);
            let ctx = if i % 2 == 0 { context1 } else { context2 };
            ciphertexts2.push(AggOnlyEnc::encrypt(&eval_keys[i], ctx, &input));
        }

        let aggregate2 = ciphertexts2.into_iter().reduce(|a, b| a + b).unwrap();
        let mask2 = AggOnlyEnc::decrypt_mask(&sk, context1, &[], false, aggregate2.len());
        let result2 = AggOnlyEnc::decrypt(&aggregate2, &mask2, max_val);
        assert!(result2.is_err());

        let mask3 = AggOnlyEnc::decrypt_mask(&sk, context2, &[], false, aggregate2.len());
        let result3 = AggOnlyEnc::decrypt(&aggregate2, &mask3, max_val);
        assert!(result3.is_err());
    }
}
