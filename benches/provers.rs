use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use hlagg::protocol::{
    ElGamal,
    provers::{Binary, Prover, Range},
};
use itertools::iproduct;
use rand_core::OsRng;
use std::hint::black_box;

mod common;
use common::*;

fn bench_encode<P: Prover>(c: &mut Criterion, length: usize, bitlength: usize) {
    let mut group = c.benchmark_group("prove");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    group.sample_size(10);

    // Setup
    let input = random_inputs(length, bitlength);
    let setup_data = get_setup_data(1, length, bitlength);
    let (prover_key, _) = P::setup(length, bitlength);
    let (encoding, r) = ElGamal::encode(&setup_data.cks[0], &input, &mut OsRng).unwrap();

    // Benchmark
    group.bench_with_input(
        BenchmarkId::from_parameter(format!("{length}_inputs_{bitlength}_bits")),
        &(length, bitlength),
        |b, _| {
            b.iter(|| {
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

fn bench_encode_untagged<P: Prover>(c: &mut Criterion, length: usize, bitlength: usize) {
    let mut group = c.benchmark_group("prove_untagged");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    group.sample_size(10);

    // Setup
    let input = random_inputs(length, bitlength);
    let setup_data = get_setup_data(1, length, bitlength);
    let (prover_key, _) = P::setup(length, bitlength);
    let (encoding, r) = ElGamal::encode(&setup_data.cks[0], &input, &mut OsRng).unwrap();

    // Benchmark
    group.bench_with_input(
        BenchmarkId::from_parameter(format!("{length}_inputs_{bitlength}_bits")),
        &(length, bitlength),
        |b, _| {
            b.iter(|| {
                black_box(
                    P::prove_untagged(
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

fn bench_verify<P: Prover>(c: &mut Criterion, length: usize, bitlength: usize) {
    let mut group = c.benchmark_group("verify");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    group.sample_size(10);

    // Setup
    let input = random_inputs(length, bitlength);
    let setup_data = get_setup_data(1, length, bitlength);
    let (prover_key, verifier_key) = P::setup(length, bitlength);
    let (encoding, r) = ElGamal::encode(&setup_data.cks[0], &input, &mut OsRng).unwrap();
    let proof = P::prove(
        &prover_key,
        &setup_data.cks[0],
        &input,
        r,
        &encoding,
        &mut OsRng,
    )
    .unwrap();

    // Benchmark
    group.bench_with_input(
        BenchmarkId::from_parameter(format!("{length}_inputs_{bitlength}_bits")),
        &(length, bitlength),
        |b, _| {
            b.iter(|| {
                black_box(
                    P::verify(&verifier_key, &setup_data.params, 0, &encoding, &proof).unwrap(),
                );
            });
        },
    );
    group.finish();
}

fn bench_batch_verify<P: Prover>(
    c: &mut Criterion,
    num_clients: usize,
    length: usize,
    bitlength: usize,
) {
    let mut group = c.benchmark_group("batch_verify");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    group.sample_size(10);

    // Setup
    let input = random_inputs(length, bitlength);
    let setup_data = get_setup_data(num_clients, length, bitlength);
    let (prover_key, verifier_key) = P::setup(length, bitlength);
    let (encodings, proofs): (Vec<_>, Vec<_>) = (0..num_clients)
        .map(|i| {
            let (encoding, r) = ElGamal::encode(&setup_data.cks[i], &input, &mut OsRng).unwrap();
            let proof = P::prove(
                &prover_key,
                &setup_data.cks[i],
                &input,
                r,
                &encoding,
                &mut OsRng,
            )
            .unwrap();
            (encoding, proof)
        })
        .unzip();
    let indices = (0..num_clients).collect::<Vec<_>>();

    // Benchmark
    group.bench_with_input(
        BenchmarkId::from_parameter(format!(
            "{num_clients}_clients_{length}_inputs_{bitlength}_bits"
        )),
        &(length, bitlength),
        |b, _| {
            b.iter(|| {
                black_box(
                    P::batch_verify(
                        &verifier_key,
                        &setup_data.params,
                        &indices,
                        &encodings,
                        &proofs,
                        &mut OsRng,
                    )
                    .unwrap(),
                );
            });
        },
    );
    group.finish();
}

fn bench_batch_verify_untagged<P: Prover>(
    c: &mut Criterion,
    num_clients: usize,
    length: usize,
    bitlength: usize,
) {
    let mut group = c.benchmark_group("batch_verify_untagged");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    group.sample_size(10);

    // Setup
    let input = random_inputs(length, bitlength);
    let setup_data = get_setup_data(num_clients, length, bitlength);
    let (prover_key, verifier_key) = P::setup(length, bitlength);
    let (encodings, proofs): (Vec<_>, Vec<_>) = (0..num_clients)
        .map(|i| {
            let (encoding, r) = ElGamal::encode(&setup_data.cks[i], &input, &mut OsRng).unwrap();
            let proof = P::prove_untagged(
                &prover_key,
                &setup_data.cks[i],
                &input,
                r,
                &encoding,
                &mut OsRng,
            )
            .unwrap();
            (encoding, proof)
        })
        .unzip();
    let indices = (0..num_clients).collect::<Vec<_>>();

    // Benchmark
    group.bench_with_input(
        BenchmarkId::from_parameter(format!(
            "{num_clients}_clients_{length}_inputs_{bitlength}_bits"
        )),
        &(length, bitlength),
        |b, _| {
            b.iter(|| {
                black_box(
                    P::batch_verify_untagged(
                        &verifier_key,
                        &setup_data.params,
                        &indices,
                        &encodings,
                        &proofs,
                        &mut OsRng,
                    )
                    .unwrap(),
                );
            });
        },
    );
    group.finish();
}

fn encode(c: &mut Criterion) {
    // (length, bitlength)
    bench_encode::<Binary>(c, 1, 1);
    bench_encode::<Binary>(c, 8, 1);
    bench_encode::<Range>(c, 1, 8);
    bench_encode::<Range>(c, 8, 8);
}

fn encode_untagged(c: &mut Criterion) {
    // (length, bitlength)
    bench_encode_untagged::<Binary>(c, 1, 1);
    bench_encode_untagged::<Binary>(c, 8, 1);
    bench_encode_untagged::<Range>(c, 1, 8);
    bench_encode_untagged::<Range>(c, 8, 8);
}

fn verify(c: &mut Criterion) {
    // (length, bitlength)
    bench_verify::<Binary>(c, 1, 1);
    bench_verify::<Binary>(c, 8, 1);
    bench_verify::<Range>(c, 1, 8);
    bench_verify::<Range>(c, 8, 8);
}

fn batch_verify(c: &mut Criterion) {
    // (num_clients, length, bitlength)
    let num_clients = vec![100];
    let lengths = vec![1, 8];
    let bitlengths = vec![1, 8];

    for (n, l, b) in iproduct!(&num_clients, &lengths, &bitlengths) {
        if *b == 1 {
            bench_batch_verify::<Binary>(c, *n, *l, *b);
        } else {
            bench_batch_verify::<Range>(c, *n, *l, *b);
        }
    }
}

fn batch_verify_untagged(c: &mut Criterion) {
    // (num_clients, length, bitlength)
    let num_clients = vec![100];
    let lengths = vec![1, 8];
    let bitlengths = vec![1, 8];

    for (n, l, b) in iproduct!(&num_clients, &lengths, &bitlengths) {
        if *b == 1 {
            bench_batch_verify_untagged::<Binary>(c, *n, *l, *b);
        } else {
            bench_batch_verify_untagged::<Range>(c, *n, *l, *b);
        }
    }
}

//criterion_group!(benches, encode, verify, batch_verify,);
criterion_group!(benches, encode, encode_untagged, batch_verify, batch_verify_untagged);
criterion_main!(benches);
