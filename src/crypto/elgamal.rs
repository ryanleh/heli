use super::{G, Scalar};
use anyhow::{Result, anyhow};
use group::Group;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// ElGamal linearly-homomorphic vector encryption scheme
pub struct ElGamal;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ElGamalPublicKey(Vec<G>);

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ElGamalSecretKey(Vec<Scalar>);

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ElGamalCiphertext {
    /// g^r
    pub rand: G,
    /// pk_i^r * x_i
    pub slots: Vec<G>,
}

impl ElGamal {
    /// Compute the discrete log of a group element.
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

    /// Generate public and secret keys.
    pub fn setup<R: RngCore + CryptoRng>(
        length: usize, // Number of plaintext slots
        rng: &mut R,
    ) -> (ElGamalPublicKey, ElGamalSecretKey) {
        // Compute keys
        let g = G::generator();
        let secret_keys: Vec<_> = (0..length).map(|_| Scalar::random(&mut *rng)).collect();
        let pks: Vec<_> = secret_keys.iter().map(|ski| g * ski).collect();
        (ElGamalPublicKey(pks), ElGamalSecretKey(secret_keys))
    }

    /// Encrypt a given vector of group and scalar elements using the provided randomness.
    pub fn encrypt(pk: &ElGamalPublicKey, r: Scalar, z_elems: &[Scalar], g_elems: &[G]) -> ElGamalCiphertext {
        debug_assert_eq!(g_elems.len() + z_elems.len(), pk.len());
        let g = G::generator();

        // We encode Zp elements first, then the group elements (opposite order from paper).
        // Later, this allows us to decrypt without re-allocating a vec :)
        let slots = z_elems
            .iter()
            .enumerate()
            .map(|(i, z)| pk[i] * r + g * z)
            .chain(g_elems
                .iter()
                .enumerate()
                .map(|(i, u)| pk[z_elems.len() + i] * r + u)
            )
            .collect::<Vec<_>>();
        ElGamalCiphertext { rand: g * r, slots }
    }

    /// Decrypts a ciphertext and returns the plaintext as group elements.
    /// Note that scalar plaintexts will need to be post-processed.
    pub fn decrypt(sk: &ElGamalSecretKey, ct: ElGamalCiphertext) -> Vec<G> {
        ct.slots
            .into_iter()
            .enumerate()
            .map(|(i, slot)| slot - ct.rand * sk[i])
            .collect()
    }

    pub fn post_process(
        max_dlog: u64, // Maximum value of the plaintext
        lifted_slots: &[G],
    ) -> Result<Vec<u64>> {
        let g = G::generator();
        let results = lifted_slots
            .iter()
            .map(|l_slot| Self::compute_dlog(&g, &l_slot, max_dlog))
            .collect::<Result<Vec<_>>>()?;
        Ok(results)
    }
}

impl std::ops::Deref for ElGamalPublicKey {
    type Target = Vec<G>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::Deref for ElGamalSecretKey {
    type Target = Vec<Scalar>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Homomorphically add ciphertexts
impl std::ops::Add for ElGamalCiphertext {
    type Output = ElGamalCiphertext;

    fn add(mut self, other: ElGamalCiphertext) -> ElGamalCiphertext {
        self.rand += other.rand;
        self.slots
            .iter_mut()
            .zip(other.slots.iter())
            .for_each(|(e1, e2)| *e1 += e2);
        self
    }
}

// Homomorphically multiply ciphertext by scalar
impl std::ops::Mul<Scalar> for ElGamalCiphertext {
    type Output = ElGamalCiphertext;

    fn mul(mut self, scalar: Scalar) -> ElGamalCiphertext {
        self.rand *= scalar;
        self.slots.iter_mut().for_each(|slot| *slot *= scalar);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, rngs::OsRng};

    #[test]
    fn elgamal_correctness() {
        let length = 4;
        let (pk, sk) = ElGamal::setup(2 * length, &mut OsRng);

        // Sample 8-bit scalar inputs
        let bitlength = 8;
        let max_val = (1u64 << bitlength) - 1;
        let mut scalars = Vec::new();
        let z_elems: Vec<Scalar> = (0..length)
            .map(|_| {
                let val = OsRng.gen_range(0..max_val);
                scalars.push(val);
                Scalar::from(val)
            })
            .collect();
        
        // Sample random group elements
        let g_elems: Vec<G> = (0..length)
            .map(|_| G::generator() * Scalar::random(&mut OsRng))
            .collect();

        let r = Scalar::random(&mut OsRng);
        let ct = ElGamal::encrypt(&pk, r, &z_elems, &g_elems);
        let decrypted = ElGamal::decrypt(&sk, ct);

        // Check scalar elements by post-processing
        let scalar_results = ElGamal::post_process(max_val, &decrypted[..length]).unwrap();
        assert_eq!(scalar_results, scalars);
        
        // Check group elements (first g_length elements)
        assert_eq!(&decrypted[length..], &g_elems[..]);
    }

    #[test]
    fn elgamal_homomorphism_correctness() {
        let num_ct = 8;
        let bitlength = 8;
        let max_val = (1u64 << bitlength) - 1;
        let length = 4;

        // We test a basic sum and linear function
        let coefficients = vec![
            vec![1u64; num_ct],
            (1u64..=num_ct as u64).collect::<Vec<u64>>(),
        ];

        // Create ciphertexts
        let (pk, sk) = ElGamal::setup(2 * length, &mut OsRng);
        let mut expected_scalars = vec![vec![0u64; length]; coefficients.len()];
        let mut expected_g_elems = vec![vec![G::identity(); length]; coefficients.len()];
        let mut cts = Vec::with_capacity(num_ct);
        for ct_idx in 0..num_ct {
            let z_elems: Vec<Scalar> = (0..length)
                .map(|slot_idx| {
                    let val = OsRng.gen_range(0..max_val);
                    coefficients.iter().enumerate().for_each(|(j, coeff)| {
                        expected_scalars[j][slot_idx] += val * coeff[ct_idx];
                    });
                    Scalar::from(val)
                })
                .collect();
            
            let g_elems: Vec<G> = (0..length)
                .map(|slot_idx| {
                    let val = G::generator() * Scalar::random(&mut OsRng);
                    coefficients.iter().enumerate().for_each(|(j, coeff)| {
                        expected_g_elems[j][slot_idx] += val * Scalar::from(coeff[ct_idx]);
                    });
                    val
                })
                .collect();

            let r_i = Scalar::random(&mut OsRng);
            cts.push(ElGamal::encrypt(&pk, r_i, &z_elems, &g_elems));
        }

        // Homomorphically evaluate ciphertexts
        for (j, coeffs) in coefficients.iter().enumerate() {
            let aggregate = cts.clone().into_iter().enumerate().map(|(i, ct)| ct * Scalar::from(coeffs[i])).reduce(|a, b| a + b).unwrap();
            let results = ElGamal::decrypt(&sk, aggregate);
            let max_coeff = *coeffs.iter().max().unwrap();
            let scalar_results = ElGamal::post_process(max_coeff * max_val * num_ct as u64, &results[..length]).unwrap();
            assert_eq!(scalar_results, expected_scalars[j]);
            assert_eq!(&results[length..], &expected_g_elems[j][..]);
        }
    }

    #[test]
    fn elgamal_compute_dlog() {
        let g = G::generator();

        // Test small values
        let max_dlog = 1000;
        for x in [0u64, 1u64, 5u64, 42u64, 999u64].iter() {
            let scalar = Scalar::from(*x);
            let output = g * scalar;

            // Test post_process
            let result = ElGamal::post_process(max_dlog, &[output]).unwrap();
            assert_eq!(result, vec![*x]);
        }

        // Test large values
        let n_big = u32::MAX as u64;
        let scalar = Scalar::from(n_big - 1);
        let result = ElGamal::post_process(n_big, &[g * scalar]).unwrap();
        assert_eq!(result, vec![n_big - 1]);

        // Test value outside range
        let scalar_out = Scalar::from(1000u64);
        assert!(ElGamal::post_process(max_dlog, &[g * scalar_out]).is_err());
    }
}