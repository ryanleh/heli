use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use heli::{
    agg_only_enc::AggOnlyEnc,
    crypto::Scalar,
    proofs::Proof,
};
use itertools::iproduct;
use rand_core::OsRng;
use std::hint::black_box;

mod common;
use common::*;

fn bench_encode(c: &mut Criterion, length: usize, bitlength: usize) {
    let mut group = c.benchmark_group("prove");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    group.sample_size(10);

    // Setup
    let mut rng = OsRng;
    let (_, eval_keys) = AggOnlyEnc::setup(1, &mut rng);
    let (prover_keys, _) = Proof::setup(&eval_keys, bitlength, length);
    let input: Vec<Scalar> = random_inputs(length, bitlength)
        .into_iter()
        .map(|x| Scalar::from(x))
        .collect();
    const CONTEXT: u32 = 42;
    let ciphertext = AggOnlyEnc::encrypt(&eval_keys[0], CONTEXT, &input);

    // Benchmark
    group.bench_with_input(
        BenchmarkId::from_parameter(format!("{length}_inputs_{bitlength}_bits")),
        &(length, bitlength),
        |b, _| {
            b.iter(|| {
                black_box(
                    Proof::prove(
                        &prover_keys[0],
                        &eval_keys[0],
                        CONTEXT,
                        &input,
                        &ciphertext,
                        &mut OsRng,
                    )
                    .unwrap(),
                );
            });
        },
    );
    group.finish();
}

fn bench_verify(c: &mut Criterion, length: usize, bitlength: usize) {
    let mut group = c.benchmark_group("verify");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    group.sample_size(10);

    // Setup
    let mut rng = OsRng;
    const CONTEXT: u32 = 42;
    let (_, eval_keys) = AggOnlyEnc::setup(1, &mut rng);
    let (prover_keys, verifier_key) = Proof::setup(&eval_keys, bitlength, length);
    let input: Vec<Scalar> = random_inputs(length, bitlength)
        .into_iter()
        .map(|x| Scalar::from(x))
        .collect();
    let ciphertext = AggOnlyEnc::encrypt(&eval_keys[0], CONTEXT, &input);
    let proof = Proof::prove(
        &prover_keys[0],
        &eval_keys[0],
        CONTEXT,
        &input,
        &ciphertext,
        &mut OsRng,
    )
    .unwrap();

    // Benchmark
    group.bench_with_input(
        BenchmarkId::from_parameter(format!("{length}_inputs_{bitlength}_bits")),
        &(length, bitlength),
        |b, _| {
            b.iter(|| {
                black_box(proof.verify(&verifier_key, &ciphertext, CONTEXT, 0).unwrap());
            });
        },
    );
    group.finish();
}

fn bench_batch_verify(
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
    let mut rng = OsRng;
    const CONTEXT: u32 = 42;
    let (_, eval_keys) = AggOnlyEnc::setup(num_clients, &mut rng);
    let (prover_keys, verifier_key) = Proof::setup(&eval_keys, bitlength, length);
    let input: Vec<Scalar> = random_inputs(length, bitlength)
        .into_iter()
        .map(|x| Scalar::from(x))
        .collect();
    let (ciphertexts, proofs): (Vec<_>, Vec<_>) = (0..num_clients)
        .map(|i| {
            let ciphertext = AggOnlyEnc::encrypt(&eval_keys[i], CONTEXT, &input);
            let proof = Proof::prove(
                &prover_keys[i],
                &eval_keys[i],
                CONTEXT,
                &input,
                &ciphertext,
                &mut OsRng,
            )
            .unwrap();
            (ciphertext, proof)
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
                    Proof::batch_verify(
                        &verifier_key,
                        &ciphertexts,
                        CONTEXT,
                        &proofs,
                        &indices,
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
    // Note: Binary proofs are not yet implemented, so we only benchmark Range
    bench_encode(c, 1, 8);
    bench_encode(c, 8, 8);
}

fn verify(c: &mut Criterion) {
    // (length, bitlength)
    // Note: Binary proofs are not yet implemented, so we only benchmark Range
    bench_verify(c, 1, 8);
    bench_verify(c, 8, 8);
}

fn batch_verify(c: &mut Criterion) {
    // (num_clients, length, bitlength)
    let num_clients = vec![100];
    let lengths = vec![1, 8];
    let bitlengths = vec![8]; // Only Range proofs are implemented

    for (n, l, b) in iproduct!(&num_clients, &lengths, &bitlengths) {
        bench_batch_verify(c, *n, *l, *b);
    }
}

//criterion_group!(benches, encode, verify, batch_verify,);
criterion_group!(benches, encode, batch_verify);
criterion_main!(benches);
