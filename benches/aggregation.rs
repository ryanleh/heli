use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use group::Group;
use heli::{
    agg_only_enc::{AggOnlyEnc, Ciphertext},
    crypto::{G, Scalar},
};
use rand::Rng;
use rand_core::OsRng;
use std::hint::black_box;

mod common;
use common::*;

fn bench_setup(c: &mut Criterion, num_clients: usize, length: usize) {
    let mut group = c.benchmark_group("setup");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    group.sample_size(10);

    group.bench_with_input(
        BenchmarkId::from_parameter(format!("{num_clients}_clients_{length}_inputs")),
        &(num_clients, length),
        |b, &(num_clients, _length)| {
            b.iter(|| {
                black_box(AggOnlyEnc::setup(num_clients, &mut OsRng));
            });
        },
    );
    group.finish();
}

fn bench_encode(c: &mut Criterion, length: usize, bitlength: usize) {
    let mut group = c.benchmark_group("encode");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));

    // Setup
    const CONTEXT: u32 = 42;
    let setup_data = get_setup_data(1, length, bitlength);
    let input: Vec<Scalar> = random_inputs(length, bitlength)
        .into_iter()
        .map(|x| Scalar::from(x))
        .collect();

    // Benchmark
    group.bench_with_input(
        BenchmarkId::from_parameter(format!("{length}_inputs_{bitlength}_bits")),
        &(length, bitlength),
        |b, _| {
            b.iter(|| {
                // Encode (encrypt) for client
                black_box(AggOnlyEnc::encrypt(&setup_data.eval_keys[0], CONTEXT, &input));
            });
        },
    );
    group.finish();
}

fn bench_aggregate(c: &mut Criterion, num_clients: usize, length: usize, bitwidth: usize) {
    let mut group = c.benchmark_group("aggregate");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));

    // Setup
    const CONTEXT: u32 = 42;
    let setup_data = get_setup_data(num_clients, length, bitwidth);
    let input: Vec<Scalar> = random_inputs(length, bitwidth)
        .into_iter()
        .map(|x| Scalar::from(x))
        .collect();

    // We can use the same input for all clients since the encryption is randomized
    let ciphertexts: Vec<Ciphertext> = setup_data
        .eval_keys
        .iter()
        .map(|ek| AggOnlyEnc::encrypt(ek, CONTEXT, &input))
        .collect();

    // Benchmark aggregation (homomorphic addition)
    group.bench_with_input(
        BenchmarkId::from_parameter(format!(
            "{num_clients}_clients_{length}_inputs_{bitwidth}_bits"
        )),
        &(num_clients, length),
        |b, _| {
            b.iter(|| {
                let mut aggregate = ciphertexts[0].clone();
                for ct in ciphertexts.iter().skip(1) {
                    aggregate = aggregate.clone() + ct.clone();
                }
                black_box(aggregate);
            });
        },
    );
    group.finish();
}

fn bench_decode(c: &mut Criterion, length: usize, bitwidth: usize) {
    let mut group = c.benchmark_group("decode");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));

    // Setup
    const CONTEXT: u32 = 42;
    let setup_data = get_setup_data(2, length, bitwidth); // num clients doesn't matter
    let input: Vec<Scalar> = random_inputs(length, bitwidth)
        .into_iter()
        .map(|x| Scalar::from(x))
        .collect();
    let ciphertexts: Vec<Ciphertext> = setup_data
        .eval_keys
        .iter()
        .map(|ek| AggOnlyEnc::encrypt(ek, CONTEXT, &input))
        .collect();
    let aggregate: Vec<G> = ciphertexts
        .iter()
        .fold(vec![G::identity(); length], |mut acc, ct| {
            for (i, slot) in ct.iter().enumerate() {
                acc[i] += slot;
            }
            acc
        });
    let mask = AggOnlyEnc::decrypt_mask(&setup_data.sk, CONTEXT, &[], length);
    let max_dlog = 1u64 << (bitwidth + 1); // Account for sum of multiple values

    // Benchmark
    group.bench_with_input(
        BenchmarkId::from_parameter(format!("{length}_inputs_{bitwidth}_bits")),
        &(length, bitwidth),
        |b, _| {
            b.iter(|| {
                black_box(AggOnlyEnc::decrypt(&aggregate, &mask, max_dlog).unwrap());
            });
        },
    );
    group.finish();
}

fn bench_post_process(c: &mut Criterion, num_clients: usize, length: usize, bitwidth: usize) {
    let mut group = c.benchmark_group("post-process");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    group.sample_size(10);

    // Choose a random number from [0, 2^bitlength]
    let input = random_inputs(length, bitwidth);
    let partial_output: Vec<G> = input
        .into_iter()
        .map(|x| G::generator() * Scalar::from(x))
        .collect();

    // Benchmark (post-processing is just the discrete log computation)
    group.bench_with_input(
        BenchmarkId::from_parameter(format!(
            "{num_clients}_clients_{length}_inputs_{bitwidth}_bits"
        )),
        &(num_clients, length),
        |b, _| {
            b.iter(|| {
                // Post-processing would involve computing discrete log
                // This is a placeholder - actual implementation depends on use case
                black_box(partial_output.clone());
            });
        },
    );
    group.finish();
}

fn bench_secret_sharing_vs_elgamal(c: &mut Criterion, length: usize, bitlength: usize) {
    let mut group = c.benchmark_group("secret_sharing_vs_elgamal");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    group.sample_size(10);

    // Setup
    let input = random_inputs(length, bitlength);
    let setup_data = get_setup_data(1, length, bitlength);

    // Use a 128-bit prime field (2^128 - 159 is prime)
    let field_modulus = 2u128.pow(128) - 159;

    // Pre-generate randomness for secret sharing
    let mut rng = OsRng;
    let random_shares: Vec<u128> = (0..length)
        .map(|_| rng.gen_range(0..field_modulus))
        .collect();

    // Pre-generate randomness for ElGamal (just the scalar r)
    let r = Scalar::random(&mut OsRng);

    // Benchmark secret sharing computation (just modular arithmetic)
    group.bench_with_input(
        BenchmarkId::new(
            "secret_sharing",
            format!("{length}_inputs_{bitlength}_bits"),
        ),
        &(length, bitlength),
        |b, _| {
            b.iter(|| {
                // Just compute the other share: (x - random_share) mod field_modulus
                let shares: Vec<_> = input
                    .iter()
                    .zip(random_shares.iter())
                    .map(|(&x, &random_share)| {
                        let other_share = (x as u128 * random_share) % field_modulus;
                        (random_share, other_share)
                    })
                    .collect();
                black_box(shares);
            });
        },
    );

    // Benchmark ElGamal exponentiation (just g^r computation)
    group.bench_with_input(
        BenchmarkId::new(
            "elgamal_exponentiation",
            format!("{length}_inputs_{bitlength}_bits"),
        ),
        &(length, bitlength),
        |b, _| {
            b.iter(|| {
                // Just compute g^r (the main expensive operation in ElGamal)
                let g_r = G::generator() + G::generator();
                black_box(g_r);
            });
        },
    );

    group.finish();
}

fn setup(c: &mut Criterion) {
    // Choice of prover doesn't matter here
    //
    // Parameters (num_clients, length)
    bench_setup(c, 1, 1);
    bench_setup(c, 10, 1);
    bench_setup(c, 100, 1);
    bench_setup(c, 1000, 1);
    //bench_setup(c, 10000, 1);
}

fn client_encoding(c: &mut Criterion) {
    // Parameters (length, bitlength)
    bench_encode(c, 1, 1);
    bench_encode(c, 1, 2);
    bench_encode(c, 1, 4);
    bench_encode(c, 1, 8);
    bench_encode(c, 1, 16);
    bench_encode(c, 1, 32);
    bench_encode(c, 1, 64);
}

fn aggregate(c: &mut Criterion) {
    // Parameters (num_clients, length, bitwidth)
    //bench_aggregate(c, 1, 1, 1);
    //bench_aggregate(c, 1, 8, 1);
    //bench_aggregate(c, 1, 16, 1);
    //bench_aggregate(c, 1, 1, 8);
    //bench_aggregate(c, 1, 8, 8);
    //bench_aggregate(c, 1, 16, 8);
    bench_aggregate(c, 1, 16, 16);
}

fn decode(c: &mut Criterion) {
    // Parameters (length, bitwidth)
    let bitwidths = vec![1];
    let lengths = vec![32, 64];
    for b in bitwidths.iter() {
        for l in lengths.iter() {
            bench_decode(c, *l, *b);
        }
    }
}

fn post_process(_c: &mut Criterion) {
    // Parameters (num_clients, length, bitlength)
    //bench_post_process(c, 100, 1, 1);
    //bench_post_process(c, 1_000_000_000, 1, 1);
    //bench_post_process(c, 1_000_000, 1, 1);
    //bench_post_process(c, 100, 1, 8);
    //bench_post_process(c, 1000, 1, 8);
}

fn secret_sharing_vs_elgamal(c: &mut Criterion) {
    // Parameters (length, bitlength)
    bench_secret_sharing_vs_elgamal(c, 1, 1);
    //bench_secret_sharing_vs_elgamal(c, 1, 8);
}

criterion_group!(
    benches,
    setup,
    client_encoding,
    aggregate,
    decode,
    post_process,
    secret_sharing_vs_elgamal,
);
criterion_main!(benches);
