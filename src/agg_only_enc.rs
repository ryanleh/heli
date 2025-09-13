use crate::crypto::*;
use anyhow::{Result, anyhow};
use rand_core::{CryptoRng, RngCore};
use serde::{Serialize, Deserialize};

/// Aggregation-only encryption instantiated with
/// * ElGamal linearly-homomorphic vector encryption
/// * Naor-Pinkas-Reingold key-homomorphic PRF
/// 
/// This implementation only supports basic sums, not general linear functions.
pub struct AggOnlyEnc;

pub struct SecretKey {
    enc_sk: ElGamalSecretKey,
    prf_key: Scalar,
    keygen_prf: ScalarPRF, 
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct EvalKey {
    pub(crate) enc_pk: ElGamalPublicKey,
    pub(crate) prf_key_share: Scalar,
}

impl AggOnlyEnc {
    // Given the function arity, output a secret key and set of evaluation keys
    pub fn setup<R: RngCore + CryptoRng>(arity: usize, length: usize, rng: &mut R) -> (SecretKey, Vec<EvalKey>) {
        // Setup ElGamal encryption (encrypts `length` elements + a checksum)
        let (enc_pk, enc_sk) = ElGamal::setup(length+1, rng);

        // Initialize PRF for generating client keys
        let mut keygen_prf_key = [0u8; 32];
        rng.fill_bytes(&mut keygen_prf_key);
        let keygen_prf = ScalarPRF::new(&keygen_prf_key);

        // Generate evaluation keys
        let mut prf_key = Scalar::ZERO;
        let eval_keys = (0..arity).map(|i| {
            let prf_key_share = keygen_prf.evaluate(i as u64);
            prf_key += prf_key_share;
            EvalKey { enc_pk: enc_pk.clone(), prf_key_share }
        }).collect();

        (SecretKey { enc_sk, prf_key, keygen_prf }, eval_keys)
    }

    // Encrypt an input under the provided context and randomness
    pub fn encrypt(ek: &EvalKey, context: u64, r: Scalar, input: &[Scalar]) -> ElGamalCiphertext {
        let attestation = KHPRF::evaluate(&ek.prf_key_share, context);
        let ciphertext = ElGamal::encrypt(&ek.enc_pk, r, &input, &[attestation]);
        ciphertext
    }
        
    // Decrypt an aggregate ciphertext under the provided context with the
    // specified dropouts. This function performs partial decryption, so
    // inputs need to be post-processed to get the final result.
    pub fn decrypt(sk: &SecretKey, context: u64, dropouts: &[u64], aggregate: ElGamalCiphertext) -> Result<Vec<G>> {
        // Generate the KH-PRF contribution for missing evaluation keys
        let dropout_prf_key = sk.keygen_prf.batch_evaluate(dropouts);
        let mut partial_decryption = ElGamal::decrypt(&sk.enc_sk, aggregate);

        let checksum = partial_decryption.pop().unwrap();
        if KHPRF::evaluate(&(sk.prf_key - dropout_prf_key), context) != checksum {
            return Err(anyhow!("Verification check failed"));
        } 
        Ok(partial_decryption)
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
        let length = 3;
        let max_val = 1000;

        // Setup the scheme
        let (sk, eval_keys) = AggOnlyEnc::setup(arity, length, &mut rng);

        // Generate ciphertexts
        let mut inputs = Vec::with_capacity(arity);
        let mut ciphertexts = Vec::with_capacity(arity);
        for i in 0..arity {
            // Generate ciphertext
            let input = random_inputs(length, max_val);
            ciphertexts.push(AggOnlyEnc::encrypt(&eval_keys[i], 0, Scalar::random(&mut rng), &input));
            inputs.push(input);
        }

        // Test aggregation with different sets of dropouts
        let dropouts = vec![vec![], vec![1, 2, 3], vec![0, 4]];
        for dropout in dropouts {
            // Only aggregate ciphertexts that are not in the dropout list
            let (to_aggregate_inputs, to_aggregate_cts): (Vec<_>, Vec<_>) = ciphertexts
                .iter()
                .enumerate()
                .filter(|(i, _)| !dropout.contains(&(*i as u64)))
                .map(|(i, ct)| (inputs[i].clone(), ct.clone()))
                .unzip();
            let aggregate = to_aggregate_cts.into_iter().reduce(|a, b| a + b).unwrap();
            let lifted_results = AggOnlyEnc::decrypt(&sk, 0, &dropout, aggregate).unwrap();

            let expected_results = to_aggregate_inputs.into_iter().reduce(|mut a, b| {
                a.iter_mut().zip(b.iter()).for_each(|(x, y)| *x += y);
                a
            }).unwrap();
            let results = ElGamal::post_process(arity as u64 * max_val, &lifted_results).unwrap();
            assert_eq!(results.into_iter().map(Scalar::from).collect::<Vec<_>>(), expected_results);
        }
    }

    #[test]
    fn agg_only_dropout_soundness() {
        let mut rng = OsRng;
        let arity = 4;
        let length = 2;
        let context = 456u64;
        let max_val = 100;

        // Setup the scheme
        let (sk, eval_keys) = AggOnlyEnc::setup(arity, length, &mut rng);

        // Generate ciphertexts
        let mut inputs = Vec::with_capacity(arity);
        let mut ciphertexts = Vec::with_capacity(arity);
        for i in 0..arity {
            let input = random_inputs(length, max_val);
            ciphertexts.push(AggOnlyEnc::encrypt(&eval_keys[i], context, Scalar::random(&mut rng), &input));
            inputs.push(input);
        }

        // Test case 1: Claim dropouts that didn't happen
        let aggregate1 = ciphertexts.clone().into_iter().reduce(|a, b| a + b).unwrap();
        let wrong_dropouts = vec![0u64, 2u64]; // Claiming clients 0 and 2 dropped out, but they didn't
        let result1 = AggOnlyEnc::decrypt(&sk, context, &wrong_dropouts, aggregate1);
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
        let result2 = AggOnlyEnc::decrypt(&sk, context, &[], aggregate2); // Don't report dropouts
        assert!(result2.is_err());
    }

    #[test]
    fn test_soundness_context() {
        let mut rng = OsRng;
        let arity = 3;
        let length = 2;
        let context = 111u64;
        let wrong_context = 222u64;
        let context1 = 333u64;
        let context2 = 444u64;
        let max_val = 100;

        // Setup the scheme
        let (sk, eval_keys) = AggOnlyEnc::setup(arity, length, &mut rng);

        // Test case 1: Wrong context
        let mut ciphertexts = Vec::with_capacity(arity);
        for i in 0..arity {
            let input = random_inputs(length, max_val);
            ciphertexts.push(AggOnlyEnc::encrypt(&eval_keys[i], context, Scalar::random(&mut rng), &input));
        }

        let aggregate1 = ciphertexts.into_iter().reduce(|a, b| a + b).unwrap();
        let result1 = AggOnlyEnc::decrypt(&sk, wrong_context, &[], aggregate1);
        assert!(result1.is_err());

        // Test case 2: Mixed contexts
        let mut ciphertexts2 = Vec::with_capacity(arity);
        for i in 0..arity {
            let input = random_inputs(length, max_val);
            let ctx = if i % 2 == 0 { context1 } else { context2 };
            ciphertexts2.push(AggOnlyEnc::encrypt(&eval_keys[i], ctx, Scalar::random(&mut rng), &input));
        }

        let aggregate2 = ciphertexts2.into_iter().reduce(|a, b| a + b).unwrap();
        let result2 = AggOnlyEnc::decrypt(&sk, context1, &[], aggregate2.clone());
        assert!(result2.is_err());

        let result3 = AggOnlyEnc::decrypt(&sk, context2, &[], aggregate2);
        assert!(result3.is_err());
    }
}
