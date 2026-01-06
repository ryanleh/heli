use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use group::Group;
use heli::{
    agg_only_enc::{AggOnlyEnc, Ciphertext},
    crypto::{G, Scalar},
    proofs::Proof,
};
use rand::{Rng, seq::IteratorRandom};
use rand_core::OsRng;
use std::hint::black_box;

pub fn random_inputs(len: usize, bitlength: usize) -> Vec<u64> {
    let mut rng = OsRng;
    (0..len)
        .map(|_| rng.gen_range(0..(1 << bitlength)))
        .collect()
}

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
    let (_, eval_keys) = AggOnlyEnc::setup(1, &mut OsRng);
    let (prover_keys, _) = Proof::setup(&eval_keys, bitlength, length);
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
                // Encode = encrypt + prove
                let mut rng = OsRng;
                let ciphertext = AggOnlyEnc::encrypt(&eval_keys[0], CONTEXT, &input);
                let proof = Proof::prove(
                    &prover_keys[0],
                    &eval_keys[0],
                    CONTEXT,
                    &input,
                    &ciphertext,
                    &mut rng,
                )
                .unwrap();
                black_box((ciphertext, proof));
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
    let (_sk, eval_keys) = AggOnlyEnc::setup(num_clients, &mut OsRng);
    let input: Vec<Scalar> = random_inputs(length, bitwidth)
        .into_iter()
        .map(|x| Scalar::from(x))
        .collect();

    // We can use the same input for all clients since the encryption is randomized
    let ciphertexts: Vec<Ciphertext> = eval_keys
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

fn bench_decode(
    c: &mut Criterion,
    num_clients: usize,
    num_dropouts: usize,
    length: usize,
    bitwidth: usize,
) {
    let mut group = c.benchmark_group("decode");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    group.sample_size(10);

    // Setup
    const CONTEXT: u32 = 42;
    let (sk, _eval_keys) = AggOnlyEnc::setup(num_clients, &mut OsRng);

    // Randomly choose dropout indices
    let mut rng = OsRng;
    let (invert, dropouts) = match 2 * num_dropouts > num_clients {
        true => (
            true,
            (0..num_clients).choose_multiple(&mut rng, num_clients - num_dropouts),
        ),
        false => (
            false,
            (0..num_clients).choose_multiple(&mut rng, num_dropouts),
        ),
    };

    // Benchmark decrypt_mask computation
    group.bench_with_input(
        BenchmarkId::from_parameter(format!(
            "{num_clients}_clients_{num_dropouts}_dropouts_{length}_inputs_{bitwidth}_bits"
        )),
        &(num_clients, num_dropouts, length, bitwidth),
        |b, _| {
            b.iter(|| {
                black_box(AggOnlyEnc::decrypt_mask(
                    &sk, CONTEXT, &dropouts, invert, length,
                ));
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

    // Setup
    const CONTEXT: u32 = 42;
    let (sk, eval_keys) = AggOnlyEnc::setup(num_clients, &mut OsRng);
    let input: Vec<Scalar> = random_inputs(length, bitwidth)
        .into_iter()
        .map(|x| Scalar::from(x))
        .collect();

    // Create aggregated ciphertext
    let ciphertexts: Vec<Ciphertext> = eval_keys
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

    // Pre-compute mask
    let mask = AggOnlyEnc::decrypt_mask(&sk, CONTEXT, &[], false, length);
    let max_dlog = (1u64 << bitwidth) * num_clients as u64; // Account for sum of multiple values

    // Benchmark decrypt (post-processing)
    group.bench_with_input(
        BenchmarkId::from_parameter(format!(
            "{num_clients}_clients_{length}_inputs_{bitwidth}_bits"
        )),
        &(num_clients, length, bitwidth),
        |b, _| {
            b.iter(|| {
                black_box(AggOnlyEnc::decrypt(&aggregate, &mask, max_dlog).unwrap());
            });
        },
    );
    group.finish();
}

fn setup(c: &mut Criterion) {
    bench_setup(c, 1, 1);
    bench_setup(c, 10, 1);
    bench_setup(c, 100, 1);
    bench_setup(c, 1000, 1);
}

fn encode(c: &mut Criterion) {
    // Parameters (length, bitwidth)
    let lengths = [1, 2, 4, 8, 16, 32, 64];
    for l in lengths {
        bench_encode(c, l, 1);
    }

    let bitwidths = [2, 4, 8, 16, 32, 64];
    for b in bitwidths {
        bench_encode(c, 1, b);
    }
}

fn aggregate(c: &mut Criterion) {
    // Parameters (num_clients, length, bitwidth)
    bench_aggregate(c, 1, 16, 16);
}

// Needs to be run with: RUSTFLAGS='-C target-cpu=native'
fn decode(c: &mut Criterion) {
    let mut num_clients = Vec::new();
    let mut dropouts = Vec::new();

    // First, baseline experiment with no dropout and varying clients
    num_clients.extend([1, 100, 1000, 10000, 100000, 1000000, 10000000]);
    dropouts.extend([0, 0, 0, 0, 0, 0, 0]);

    // Then 10% dropout
    num_clients.extend([100, 1000, 10000, 100000, 1000000, 10000000]);
    dropouts.extend([10, 100, 1000, 10000, 100000, 1000000]);

    // Then add in the experiments for growing dropout percentage with fixed
    // number of clients
    let mut dropout_percs = (0..=9).map(|i| i as f64 * 0.1).collect::<Vec<_>>();
    dropout_percs.extend([0.99, 0.99995]);
    num_clients.extend(std::iter::repeat(10_000_000).take(dropout_percs.len()));
    dropouts.extend(
        dropout_percs
            .into_iter()
            .map(|p| (p * 10_000_000 as f64).floor() as usize),
    );

    for (n, d) in num_clients.iter().zip(dropouts.iter()) {
        bench_decode(c, *n, *d, 1, 1);
    }

    // Finally do experiments with varying bitwidth and length
    let lengths = [8, 16, 32, 64];
    for l in lengths {
        bench_decode(c, 10_000_000, 0, l, 1);
        bench_decode(c, 10_000_000, 1_000_000, l, 1);
    }

    let bitwidths = [8, 16, 32, 64];
    for b in bitwidths {
        bench_decode(c, 10_000_000, 0, 1, b);
        bench_decode(c, 10_000_000, 1_000_000, 1, b);
    }
}

fn post_process(c: &mut Criterion) {
    // Parameters (num_clients, length, bitlength)
    bench_post_process(c, 100, 1, 1);
    bench_post_process(c, 100, 1, 8);
    bench_post_process(c, 1000, 1, 1);
    bench_post_process(c, 1000, 1, 8);
}

criterion_group!(
    benches,
    //setup,
    encode,
    aggregate,
    decode,
    post_process,
);
criterion_main!(benches);
