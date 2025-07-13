use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use hlagg::protocol::{
    DiscreteLog, Ristretto,
    proofs::{BinarySchnorr, Prover},
};
use rand_core::OsRng;
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::OnceLock;

mod common;
use common::*;

type G = Ristretto;
type Agg = DiscreteLog<G, BinarySchnorr<G>>;

const NUM_CLIENTS: [usize; 5] = [1, 10, 100, 1000, 10000];
const LENGTHS: [usize; 1] = [1];

// Setup data structure to avoid repeated setup calls
struct SetupData {
    params: hlagg::protocol::messages::AggParams<G>,
    sk: hlagg::protocol::messages::DecKey<G>,
    cks: Vec<hlagg::protocol::messages::ClientKey<G>>,
    prover_key: <BinarySchnorr<G> as Prover<G>>::ProverKey,
    verifier_key: <BinarySchnorr<G> as Prover<G>>::VerifierKey,
}

// Global setup data cache
static SETUP_DATA: OnceLock<HashMap<(usize, usize), SetupData>> = OnceLock::new();

// Pre-compute all setup data once
fn get_setup_data() -> &'static HashMap<(usize, usize), SetupData> {
    SETUP_DATA.get_or_init(|| {
        let mut setup_data = HashMap::new();
        let (prover_key, verifier_key) = BinarySchnorr::<G>::setup();

        println!("Pre-computing setup data for all configurations...");
        for &num_clients in &NUM_CLIENTS {
            for &length in &LENGTHS {
                println!(
                    "  Setting up for {} clients, {} inputs",
                    num_clients, length
                );
                let (params, sk, cks) = Agg::setup(num_clients, length, &mut OsRng);
                setup_data.insert(
                    (num_clients, length),
                    SetupData {
                        params,
                        sk,
                        cks,
                        prover_key: prover_key.clone(),
                        verifier_key: verifier_key.clone(),
                    },
                );
            }
        }
        println!("Setup data pre-computation complete!");
        setup_data
    })
}

fn bench_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("setup");
    group.sample_size(10); // Reduce sample size for expensive setup
    group.warm_up_time(std::time::Duration::from_millis(100)); // Reduce warmup
    group.measurement_time(std::time::Duration::from_millis(500)); // Reduce measurement time
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
    let setup_data = get_setup_data();
    let mut group = c.benchmark_group("encode");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    for num_clients in NUM_CLIENTS {
        for length in LENGTHS {
            let setup = &setup_data[&(num_clients, length)];
            let input = random_binary_vec(length);
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{num_clients}_clients_{length}_inputs")),
                &(num_clients, length),
                |b, _| {
                    b.iter(|| {
                        black_box(
                            Agg::encode(&setup.cks[0], &setup.prover_key, &input, &mut OsRng)
                                .unwrap(),
                        );
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let setup_data = get_setup_data();
    let mut group = c.benchmark_group("verify_encodings");
    group.sample_size(10);
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    for num_clients in NUM_CLIENTS {
        for length in LENGTHS {
            let setup = &setup_data[&(num_clients, length)];
            let inputs = random_inputs(num_clients, length);
            let encodings_and_proofs: Vec<_> = setup
                .cks
                .iter()
                .zip(inputs.iter())
                .map(|(ck, input)| Agg::encode(ck, &setup.prover_key, input, &mut OsRng).unwrap())
                .collect();
            let (encodings, proofs): (Vec<_>, Vec<_>) = encodings_and_proofs.into_iter().unzip();
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{num_clients}_clients_{length}_inputs")),
                &(num_clients, length),
                |b, _| {
                    b.iter(|| {
                        black_box(
                            Agg::verify_encodings(
                                &setup.params,
                                &setup.verifier_key,
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
    let setup_data = get_setup_data();
    let mut group = c.benchmark_group("batch_verify_encodings");
    group.sample_size(10);
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    for num_clients in NUM_CLIENTS {
        for length in LENGTHS {
            let setup = &setup_data[&(num_clients, length)];
            let inputs = random_inputs(num_clients, length);
            let encodings_and_proofs: Vec<_> = setup
                .cks
                .iter()
                .zip(inputs.iter())
                .map(|(ck, input)| Agg::encode(ck, &setup.prover_key, input, &mut OsRng).unwrap())
                .collect();
            let (encodings, proofs): (Vec<_>, Vec<_>) = encodings_and_proofs.into_iter().unzip();
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{num_clients}_clients_{length}_inputs")),
                &(num_clients, length),
                |b, _| {
                    b.iter(|| {
                        black_box(
                            Agg::batch_verify_encodings(
                                &setup.params,
                                &setup.verifier_key,
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
    let setup_data = get_setup_data();
    let mut group = c.benchmark_group("aggregate");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    for num_clients in NUM_CLIENTS {
        for length in LENGTHS {
            let setup = &setup_data[&(num_clients, length)];
            let inputs = random_inputs(num_clients, length);
            let encodings: Vec<_> = setup
                .cks
                .iter()
                .zip(inputs.iter())
                .map(|(ck, input)| {
                    Agg::encode(ck, &setup.prover_key, input, &mut OsRng)
                        .unwrap()
                        .0
                })
                .collect();
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{num_clients}_clients_{length}_inputs")),
                &(num_clients, length),
                |b, _| {
                    b.iter(|| {
                        black_box(Agg::aggregate(&setup.params, &encodings).unwrap());
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    let setup_data = get_setup_data();
    let mut group = c.benchmark_group("decode");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    for num_clients in NUM_CLIENTS {
        for length in LENGTHS {
            let setup = &setup_data[&(num_clients, length)];
            let inputs = random_inputs(num_clients, length);
            let encodings: Vec<_> = setup
                .cks
                .iter()
                .zip(inputs.iter())
                .map(|(ck, input)| {
                    Agg::encode(ck, &setup.prover_key, input, &mut OsRng)
                        .unwrap()
                        .0
                })
                .collect();
            let agg = Agg::aggregate(&setup.params, &encodings).unwrap();
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{num_clients}_clients_{length}_inputs")),
                &(num_clients, length),
                |b, _| {
                    b.iter(|| {
                        black_box(Agg::decode(&setup.sk, agg.clone()).unwrap());
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_post_process(c: &mut Criterion) {
    let setup_data = get_setup_data();
    let mut group = c.benchmark_group("post_process");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    for num_clients in NUM_CLIENTS {
        for length in LENGTHS {
            let setup = &setup_data[&(num_clients, length)];
            let inputs = random_inputs(num_clients, length);
            let encodings: Vec<_> = setup
                .cks
                .iter()
                .zip(inputs.iter())
                .map(|(ck, input)| {
                    Agg::encode(ck, &setup.prover_key, input, &mut OsRng)
                        .unwrap()
                        .0
                })
                .collect();
            let agg = Agg::aggregate(&setup.params, &encodings).unwrap();
            let partial = Agg::decode(&setup.sk, agg).unwrap();
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{num_clients}_clients_{length}_inputs")),
                &(num_clients, length),
                |b, _| {
                    b.iter(|| {
                        black_box(Agg::post_process(&setup.params, partial.clone()).unwrap());
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
