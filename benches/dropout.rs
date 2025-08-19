use aes::{Aes256, cipher::{BlockEncrypt, KeyInit}};
use aes::cipher::generic_array::GenericArray;
use criterion::{Criterion, criterion_group, criterion_main};
use curve25519_dalek::scalar::Scalar;
use std::hint::black_box;

const KEY: [u8; 32] = [0x42u8; 32];

/// 320-bit accumulator (5 limbs * 64 bits)
#[derive(Clone, Copy, Debug)]
struct Accumulator([u64; 5]);

impl Accumulator {
    fn zero() -> Self {
        Self([0; 5])
    }

    /// Add a 256-bit integer (4 limbs) to the accumulator.
    fn add_u256(&mut self, val: [u64; 4]) {
        let mut carry = 0u128;

        // Add limb by limb with carry
        for i in 0..4 {
            let sum = self.0[i] as u128 + val[i] as u128 + carry;
            self.0[i] = sum as u64;
            carry = sum >> 64;
        }
        // Add carry to the 5th limb
        let sum = self.0[4] as u128 + carry;
        self.0[4] = sum as u64;
        // Note: We won't overflow 320 bits
    }

    fn to_64_bytes_le(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        for i in 0..5 {
            buf[i*8..(i+1)*8].copy_from_slice(&self.0[i].to_le_bytes());
        }
        buf
    }
}

fn make_block(i: u32, domain_bit: u8) -> GenericArray<u8, aes::cipher::consts::U16> {
    let mut block = GenericArray::default();
    block[0..4].copy_from_slice(&i.to_le_bytes());
    block[15] = domain_bit;
    block
}

fn block_to_u64_pair(block: &GenericArray<u8, aes::cipher::consts::U16>) -> [u64; 2] {
    [
        u64::from_le_bytes(block[0..8].try_into().unwrap()),
        u64::from_le_bytes(block[8..16].try_into().unwrap()),
    ]
}

fn bench_dropout(c: &mut Criterion, n: u32) {
    let cipher = Aes256::new(&GenericArray::from_slice(&KEY));
    
    c.bench_function(&format!("decryptor_dropout_{}", n), |b| {
        b.iter(|| {
            let mut acc = Accumulator::zero();
            for i in 1..=n {
                // PRF eval -> two concatenated AES evaluations
                let mut block0 = make_block(i, 0);
                let mut block1 = make_block(i, 1);

                cipher.encrypt_block(&mut block0);
                cipher.encrypt_block(&mut block1);

                let limbs0 = block_to_u64_pair(&block0);
                let limbs1 = block_to_u64_pair(&block1);

                // 256-bit output is limbs0 || limbs1
                let val = [limbs0[0], limbs0[1], limbs1[0], limbs1[1]];

                // Add to accumulator
                acc.add_u256(val);
            }

            // Reduce accumuulator to group element
            let wide_bytes = acc.to_64_bytes_le();
            black_box(Scalar::from_bytes_mod_order_wide(&wide_bytes))
        })
    });
}

// NOTE: This needs to be run with `RUSTFLAGS="-c target-cpu=native"`
//       on a machine with AES-NI intrinsics
fn dropout(c: &mut Criterion) {
    // Parameters (num_clients)
    bench_dropout(c, 1_000_000);
}

criterion_group!(benches, dropout);
criterion_main!(benches);
