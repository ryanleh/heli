use super::{G, Scalar};
use aes::cipher::generic_array::GenericArray;
use aes::{
    Aes256,
    cipher::{BlockEncrypt, KeyInit},
};
use sha3::Sha3_512;

/// Naor-Pinkas-Reingold key-homomorphic PRF
pub struct KHPRF;

/// AES-based PRF for generating random scalar elements,
pub struct ScalarPRF {
    cipher: Aes256,
}

impl KHPRF {
    // Evaluates the PRF on the given input. For our purposes, the
    // input just needs to a number, but can be an arbitrary bit-string.
    pub fn evaluate(key: &Scalar, input: u64) -> G {
        let base = G::hash_from_bytes::<Sha3_512>(&input.to_le_bytes().as_ref());
        base * key
    }
}

impl ScalarPRF {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256::new(&GenericArray::from_slice(key)),
        }
    }

    // Evaluates the PRF on the given index
    pub fn evaluate(&self, index: u64) -> Scalar {
        let aes_blocks = self.evaluate_aes(index);

        // Map to scalar element
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&aes_blocks[0]);
        bytes[16..].copy_from_slice(&aes_blocks[1]);
        Scalar::from_bytes_mod_order(bytes)
    }

    // Computes the sum of a batch of PRF evaluations. It uses a 320-bit
    // accumulator, so can support up to 2^64 unique evaluations.
    pub fn batch_evaluate(&self, indices: &[usize]) -> Scalar {
        if indices.is_empty() {
            return Scalar::ZERO;
        }
        let mut accum = [0u64; 5];
        for idx in indices.into_iter() {
            // Compute the PRF eval
            let aes_blocks = self.evaluate_aes(*idx as u64);
            let limbs = [
                u64::from_le_bytes(aes_blocks[0][0..8].try_into().unwrap()),
                u64::from_le_bytes(aes_blocks[0][8..16].try_into().unwrap()),
                u64::from_le_bytes(aes_blocks[1][0..8].try_into().unwrap()),
                u64::from_le_bytes(aes_blocks[1][8..16].try_into().unwrap()),
            ];

            // Add to accumulator
            Self::add_u256(&mut accum, limbs);
        }

        // Reduce accumulator to group element. The API only supports 256-bit
        // and 512-bit inputs, so we map to 512-bits.
        let mut accum_bytes = [0u8; 64];
        for i in 0..5 {
            accum_bytes[i * 8..(i + 1) * 8].copy_from_slice(&accum[i].to_le_bytes());
        }
        Scalar::from_bytes_mod_order_wide(&accum_bytes)
    }

    fn evaluate_aes(&self, index: u64) -> [GenericArray<u8, aes::cipher::consts::U16>; 2] {
        // Set input
        let mut blocks = [GenericArray::default(); 2];
        for (i, block) in blocks.iter_mut().enumerate() {
            block[0..8].copy_from_slice(&index.to_le_bytes()); // index
            block[15] = i as u8; // block domain bit
        }

        // Evaluate AES
        self.cipher.encrypt_blocks(&mut blocks);
        blocks
    }

    /// Add a 256-bit integer (4 limbs) to a 320-bit accumulator.
    fn add_u256(accum: &mut [u64; 5], val: [u64; 4]) {
        let mut carry = 0u128;

        // Add limb by limb with carry
        for i in 0..4 {
            let sum = accum[i] as u128 + val[i] as u128 + carry;
            accum[i] = sum as u64;
            carry = sum >> 64;
        }
        // Add carry to the 5th limb
        let sum = accum[4] as u128 + carry;
        accum[4] = sum as u64;
    }
}
