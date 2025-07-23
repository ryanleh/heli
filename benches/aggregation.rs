use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use hlagg::protocol::{
    ElGamal,
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

fn bench_aggregate(c: &mut Criterion, num_clients: usize, length: usize) {
    let mut group = c.benchmark_group("aggregate");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    group.sample_size(10);

    // Setup
    let input = random_inputs(length, 1);
    let setup_data = get_setup_data(num_clients, length, 1);

    // We can use the same input for all clients since the encryption is randomized
    let encodings: Vec<_> = setup_data
        .cks
        .iter()
        .map(|ck| ElGamal::encode(ck, &input, &mut OsRng).unwrap().0)
        .collect();

    // Benchmark
    group.bench_with_input(
        BenchmarkId::from_parameter(format!("{num_clients}_clients_{length}_inputs")),
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

fn bench_post_process(c: &mut Criterion, num_clients: usize, length: usize, bitlength: usize) {
    let mut group = c.benchmark_group("post-process");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    group.sample_size(10);

    // Setup
    let input = random_inputs(length, bitlength);
    let setup_data = get_setup_data(num_clients, length, bitlength);
    let encodings: Vec<_> = setup_data
        .cks
        .iter()
        .map(|ck| ElGamal::encode(ck, &input.clone(), &mut OsRng).unwrap().0)
        .collect();
    let aggregate = ElGamal::aggregate(&setup_data.params, &encodings).unwrap();
    let partial_output = ElGamal::decode(&setup_data.sk, aggregate.clone()).unwrap();

    // Benchmark
    group.bench_with_input(
        BenchmarkId::from_parameter(format!(
            "{num_clients}_clients_{length}_inputs_{bitlength}_bits"
        )),
        &(num_clients, length),
        |b, _| {
            b.iter(|| {
                black_box(
                    ElGamal::post_process(&setup_data.params, bitlength, partial_output.clone())
                        .unwrap(),
                );
            });
        },
    );
    group.finish();
}

fn setup(c: &mut Criterion) {
    // Choice of prover doesn't matter here
    //
    // Parameters (num_clients, length)
    bench_setup(c, 1000, 1);
    bench_setup(c, 10000, 1);
}

fn aggregate(c: &mut Criterion) {
    // Parameters (num_clients, length)
    bench_aggregate(c, 100, 1);
    bench_aggregate(c, 1000, 1);
    bench_aggregate(c, 100, 8);
    bench_aggregate(c, 1000, 8);
}

fn decode(c: &mut Criterion) {
    // Parameters (length, bitwidth)
    bench_decode(c, 1, 1);
    bench_decode(c, 1, 8);
    bench_decode(c, 8, 1);
    bench_decode(c, 8, 8);
}

fn post_process(c: &mut Criterion) {
    // Parameters (num_clients, length, bitlength)
    bench_post_process(c, 100, 1, 1);
    bench_post_process(c, 1000, 1, 1);
    bench_post_process(c, 100, 1, 8);
    bench_post_process(c, 1000, 1, 8);
}

criterion_group!(benches, setup, aggregate, decode, post_process,);
criterion_main!(benches);
