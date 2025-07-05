use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use hlagg::protocol::{
    DiscreteLog, Ristretto,
    proofs::{BinarySchnorr, Prover},
};
use rand_core::OsRng;
use std::hint::black_box;

mod common;
use common::*;

type G = Ristretto;
type Agg = DiscreteLog<G, BinarySchnorr<G>>;

// TODO: Tweak
const NUM_CLIENTS: [usize; 1] = [1000];
const LENGTHS: [usize; 3] = [1, 5, 10];

fn bench_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("setup");
    for num_clients in NUM_CLIENTS {
        for length in LENGTHS {
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{num_clients}_clients_{length}_inputs")),
                &(num_clients, length),
                |b, &(num_clients, length)| {
                    b.iter(|| {
                        black_box(Agg::setup(num_clients, length, &mut OsRng));
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode");
    for num_clients in NUM_CLIENTS {
        for length in LENGTHS {
            let (_params, _sk, cks) = Agg::setup(num_clients, length, &mut OsRng);
            let input = random_binary_vec(length);
            let (prover_key, _) = BinarySchnorr::<G>::setup();
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{num_clients}_clients_{length}_inputs")),
                &(num_clients, length),
                |b, _| {
                    b.iter(|| {
                        black_box(Agg::encode(&cks[0], &prover_key, &input, &mut OsRng).unwrap());
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_encodings");
    group.sample_size(10);
    for num_clients in NUM_CLIENTS {
        for length in LENGTHS {
            let (params, _sk, cks) = Agg::setup(num_clients, length, &mut OsRng);
            let inputs = random_inputs(num_clients, length);
            let (prover_key, verifier_key) = BinarySchnorr::<G>::setup();
            let encodings_and_proofs: Vec<_> = cks
                .iter()
                .zip(inputs.iter())
                .map(|(ck, input)| Agg::encode(ck, &prover_key, input, &mut OsRng).unwrap())
                .collect();
            let (encodings, proofs): (Vec<_>, Vec<_>) = encodings_and_proofs.into_iter().unzip();
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{num_clients}_clients_{length}_inputs")),
                &(num_clients, length),
                |b, _| {
                    b.iter(|| {
                        black_box(
                            Agg::verify_encodings(
                                &params,
                                &verifier_key,
                                None,
                                &encodings,
                                &proofs,
                            )
                            .unwrap(),
                        );
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_batch_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_verify_encodings");
    group.sample_size(10);
    for num_clients in NUM_CLIENTS {
        for length in LENGTHS {
            let (params, _sk, cks) = Agg::setup(num_clients, length, &mut OsRng);
            let inputs = random_inputs(num_clients, length);
            let (prover_key, verifier_key) = BinarySchnorr::<G>::setup();
            let encodings_and_proofs: Vec<_> = cks
                .iter()
                .zip(inputs.iter())
                .map(|(ck, input)| Agg::encode(ck, &prover_key, input, &mut OsRng).unwrap())
                .collect();
            let (encodings, proofs): (Vec<_>, Vec<_>) = encodings_and_proofs.into_iter().unzip();
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{num_clients}_clients_{length}_inputs")),
                &(num_clients, length),
                |b, _| {
                    b.iter(|| {
                        black_box(
                            Agg::batch_verify_encodings(
                                &params,
                                &verifier_key,
                                None,
                                &encodings,
                                &proofs,
                                &mut OsRng,
                            )
                            .unwrap(),
                        );
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_aggregate(c: &mut Criterion) {
    let mut group = c.benchmark_group("aggregate");
    for num_clients in NUM_CLIENTS {
        for length in LENGTHS {
            let (params, _sk, cks) = Agg::setup(num_clients, length, &mut OsRng);
            let inputs = random_inputs(num_clients, length);
            let (prover_key, _) = BinarySchnorr::<G>::setup();
            let encodings: Vec<_> = cks
                .iter()
                .zip(inputs.iter())
                .map(|(ck, input)| Agg::encode(ck, &prover_key, input, &mut OsRng).unwrap().0)
                .collect();
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{num_clients}_clients_{length}_inputs")),
                &(num_clients, length),
                |b, _| {
                    b.iter(|| {
                        black_box(Agg::aggregate(&params, &encodings).unwrap());
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode");
    for num_clients in NUM_CLIENTS {
        for length in LENGTHS {
            let (params, sk, cks) = Agg::setup(num_clients, length, &mut OsRng);
            let inputs = random_inputs(num_clients, length);
            let (prover_key, _) = BinarySchnorr::<G>::setup();
            let encodings: Vec<_> = cks
                .iter()
                .zip(inputs.iter())
                .map(|(ck, input)| Agg::encode(ck, &prover_key, input, &mut OsRng).unwrap().0)
                .collect();
            let agg = Agg::aggregate(&params, &encodings).unwrap();
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{num_clients}_clients_{length}_inputs")),
                &(num_clients, length),
                |b, _| {
                    b.iter(|| {
                        black_box(Agg::decode(&sk, agg.clone()).unwrap());
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_post_process(c: &mut Criterion) {
    let mut group = c.benchmark_group("post_process");
    for num_clients in NUM_CLIENTS {
        for length in LENGTHS {
            let (params, sk, cks) = Agg::setup(num_clients, length, &mut OsRng);
            let inputs = random_inputs(num_clients, length);
            let (prover_key, _) = BinarySchnorr::<G>::setup();
            let encodings: Vec<_> = cks
                .iter()
                .zip(inputs.iter())
                .map(|(ck, input)| Agg::encode(ck, &prover_key, input, &mut OsRng).unwrap().0)
                .collect();
            let agg = Agg::aggregate(&params, &encodings).unwrap();
            let partial = Agg::decode(&sk, agg).unwrap();
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{num_clients}_clients_{length}_inputs")),
                &(num_clients, length),
                |b, _| {
                    b.iter(|| {
                        black_box(Agg::post_process(&params, partial.clone()).unwrap());
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_setup,
    bench_encode,
    bench_verify,
    bench_batch_verify,
    bench_aggregate,
    bench_decode,
    bench_post_process
);
criterion_main!(benches);
