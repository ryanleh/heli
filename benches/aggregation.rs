use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use group::Group;
use hlagg::protocol::{
    ElGamal, G, Scalar,
    provers::{Binary, Prover, Range},
};
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
        |b, &(num_clients, length)| {
            b.iter(|| {
                black_box(ElGamal::setup(num_clients, length, &mut OsRng));
            });
        },
    );
    group.finish();
}

fn bench_encode<P: Prover>(c: &mut Criterion, length: usize, bitlength: usize) {
    let mut group = c.benchmark_group("encode");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));

    // Setup
    let input = random_inputs(length, bitlength);
    let setup_data = get_setup_data(1, length, bitlength);
    let (prover_key, _) = P::setup(length, bitlength);

    // Benchmark
    group.bench_with_input(
        BenchmarkId::from_parameter(format!("{length}_inputs_{bitlength}_bits")),
        &(length, bitlength),
        |b, _| {
            b.iter(|| {
                // Encode and prove for all clients
                let (encoding, r) =
                    ElGamal::encode(&setup_data.cks[0], &input, &mut OsRng).unwrap();
                black_box(
                    P::prove(
                        &prover_key,
                        &setup_data.cks[0],
                        &input,
                        r,
                        &encoding,
                        &mut OsRng,
                    )
                    .unwrap(),
                );
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
    let input = random_inputs(length, bitwidth);
    let setup_data = get_setup_data(num_clients, length, bitwidth);

    // We can use the same input for all clients since the encryption is randomized
    let encodings: Vec<_> = setup_data
        .cks
        .iter()
        .map(|ck| ElGamal::encode(ck, &input, &mut OsRng).unwrap().0)
        .collect();

    // Benchmark
    group.bench_with_input(
        BenchmarkId::from_parameter(format!(
            "{num_clients}_clients_{length}_inputs_{bitwidth}_bits"
        )),
        &(num_clients, length),
        |b, _| {
            b.iter(|| {
                black_box(ElGamal::aggregate(&setup_data.params, &encodings).unwrap());
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
    let input = random_inputs(length, bitwidth);
    let setup_data = get_setup_data(2, length, bitwidth); // num clients doesn't matter
    let encodings: Vec<_> = setup_data
        .cks
        .iter()
        .map(|ck| ElGamal::encode(ck, &input.clone(), &mut OsRng).unwrap().0)
        .collect();
    let aggregate = ElGamal::aggregate(&setup_data.params, &encodings).unwrap();

    // Benchmark
    group.bench_with_input(
        BenchmarkId::from_parameter(format!("{length}_inputs_{bitwidth}_bits")),
        &(length, bitwidth),
        |b, _| {
            b.iter(|| {
                black_box(ElGamal::decode(&setup_data.sk, aggregate.clone()).unwrap());
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
    let setup_data = get_setup_data(num_clients, length, bitwidth);
    let partial_output = hlagg::protocol::messages::PartialOutput {
        vals: input
            .into_iter()
            .map(|x| G::generator() * Scalar::from(x))
            .collect(),
    };

    // Benchmark
    group.bench_with_input(
        BenchmarkId::from_parameter(format!(
            "{num_clients}_clients_{length}_inputs_{bitwidth}_bits"
        )),
        &(num_clients, length),
        |b, _| {
            b.iter(|| {
                black_box(
                    ElGamal::post_process(&setup_data.params, bitwidth, partial_output.clone())
                        .unwrap(),
                );
            });
        },
    );
    group.finish();
}

//fn bench_secret_sharing_vs_elgamal(c: &mut Criterion, length: usize, bitlength: usize) {
//    let mut group = c.benchmark_group("secret_sharing_vs_elgamal");
//    group.warm_up_time(std::time::Duration::from_millis(100));
//    group.measurement_time(std::time::Duration::from_millis(500));
//    group.sample_size(10);
//
//    // Setup
//    let input = random_inputs(length, bitlength);
//    let setup_data = get_setup_data(1, length, bitlength);
//
//    // Use a 128-bit prime field (2^128 - 159 is prime)
//    let field_modulus = 2u128.pow(128) - 159;
//
//    // Pre-generate randomness for secret sharing
//    let mut rng = OsRng;
//    let random_shares: Vec<u128> = (0..length)
//        .map(|_| rng.gen_range(0..field_modulus))
//        .collect();
//
//    // Pre-generate randomness for ElGamal (just the scalar r)
//    let r = Scalar::random(&mut OsRng);
//
//    // Benchmark secret sharing computation (just modular arithmetic)
//    group.bench_with_input(
//        BenchmarkId::new("secret_sharing", format!("{length}_inputs_{bitlength}_bits")),
//        &(length, bitlength),
//        |b, _| {
//            b.iter(|| {
//                // Just compute the other share: (x - random_share) mod field_modulus
//                let shares: Vec<_> = input
//                    .iter()
//                    .zip(random_shares.iter())
//                    .map(|(&x, &random_share)| {
//                        let other_share = (x as u128 + field_modulus - random_share) % field_modulus;
//                        (random_share, other_share)
//                    })
//                    .collect();
//                black_box(shares);
//            });
//        },
//    );
//
//    // Benchmark ElGamal exponentiation (just g^r computation)
//    group.bench_with_input(
//        BenchmarkId::new("elgamal_exponentiation", format!("{length}_inputs_{bitlength}_bits")),
//        &(length, bitlength),
//        |b, _| {
//            b.iter(|| {
//                // Just compute g^r (the main expensive operation in ElGamal)
//                let g_r = G::generator() * r;
//                black_box(g_r);
//            });
//        },
//    );
//
//    group.finish();
//}

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
    bench_encode::<Range>(c, 1, 1);
    bench_encode::<Range>(c, 1, 2);
    bench_encode::<Range>(c, 1, 4);
    bench_encode::<Range>(c, 1, 8);
    bench_encode::<Range>(c, 1, 16);
    bench_encode::<Range>(c, 1, 32);
    bench_encode::<Range>(c, 1, 64);
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

fn post_process(c: &mut Criterion) {
    // Parameters (num_clients, length, bitlength)
    //bench_post_process(c, 100, 1, 1);
    //bench_post_process(c, 1_000_000_000, 1, 1);
    //bench_post_process(c, 1_000_000, 1, 1);
    //bench_post_process(c, 100, 1, 8);
    //bench_post_process(c, 1000, 1, 8);
}

//fn secret_sharing_vs_elgamal(c: &mut Criterion) {
//    // Parameters (length, bitlength)
//    bench_secret_sharing_vs_elgamal(c, 1, 1);
//    bench_secret_sharing_vs_elgamal(c, 1, 8);
//}

criterion_group!(
    benches,
    setup,
    client_encoding,
    aggregate,
    decode,
    post_process
);
criterion_main!(benches);
