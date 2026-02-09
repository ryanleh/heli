<h1 align="center">Heli</h1>

__Heli__ is a Rust library for **private aggregation**.

This library was developed as part of the paper [*"Heli: Heavy-Light Private Aggregation"*](https://eprint.iacr.org/2026/059) and is released under the MIT License and the Apache v2 License (see [License](#license)).

**WARNING:** This is an academic proof-of-concept prototype, and has not received careful code review. It should NOT be used for production use.

## Directory structure

This repository contains several modules that implement the different building blocks of Heli. The high-level structure of the repository is as follows.

* [`src/crypto`](src/crypto): Low-level cryptographic components.

* [`src/agg_only_enc.rs`](src/agg_only_enc.rs): Aggregation-only encryption scheme.

* [`src/proofs.rs`](src/proofs.rs): Zero-knowledge proofs for protecting against malicious clients.

* [`src/system`](src/system): Network protocol implementation.

* [`benches`](benches): Benchmarks.

* [`experiments`](src/experiments): End-to-end experiments.

* [`artifact-eval`](src/artifact-eval): Scripts to recreate Figures 4, 5 from the Heli paper.

## Build guide

Ensure that you have a C++ compiler and Rust installed. 

On Ubuntu, you can install a C++ compiler via:
```bash
sudo apt install g++
```

You can install Rust by following the directions [here](https://www.rust-lang.org/tools/install).

Next, ensure the following environment variable is set either in your current session (e.g., via `export`) or in your config file (e.g., in your `~/.bashrc` file):
```bash
RUSTFLAGS="-C target-cpu=native"
```
Then, clone this repository and build the project:

```bash
cargo build --release
```
To run the test suite:
```bash
cargo test
```

## Experiments

### Micro-benchmarks

To reproduce Figures 4 and 5 of the Heli paper, install `cargo-criterion` via:
```bash
cargo install cargo-criterion
```
download the necessary Python dependencies:
```bash
cd artifact-eval/
pip -r requirements.txt
```
and run the following script:
```bash
python3 run_and_plot.py
```
Plots will appear in the `artifact-eval/plots` directory

### End-to-end experiments

To run end-to-end experiments, create a new config file in `experiments/config`
that specifies your aggregation parameters and networking information to connect
to the aggregator and decryptor. (There are a few examples of this already)

To start the aggregator:
```bash
RUST_LOG=info cargo run --release --bin exp_aggregator -- {YOUR CONFIG}
```

To start the decryptor:
```bash
RUST_LOG=info cargo run --release --bin exp_decryptor -- {YOUR CONFIG}
```

Aggregation is initialized by the client and follows four steps. 

First, run the one-time setup:
```bash
RUST_LOG=info cargo run --release --bin exp_client -- {YOUR CONFIG} --mode setup
```
After running this, you should be able to run the following steps as many
times as you want (even with different configurations) without restarting the
aggregator/decryptor or re-running setup.

To locally generate client reports, run:
```bash
RUST_LOG=info cargo run --release --bin exp_client -- {YOUR CONFIG} --mode generate
```

To submit the reports to the aggregator, run:
```bash
RUST_LOG=info cargo run --release --bin exp_client -- {YOUR CONFIG} --mode submit
```

Finally, to request the aggregator to aggregate, run:
```bash
RUST_LOG=info cargo run --release --bin exp_client -- {YOUR CONFIG} --mode aggregate
```

> **NOTE:** All of the binaries have a `clear-db` flag that clear local state. This
> is useful to recover from a buggy run.

> **TIP:** The `exp_client` binary simulates many clients from a single machine. If 
> you experience the following error "(errno 24) too many open files", try
> raising the operating system's limit on file descriptors via:
> ```bash
> set ulimit -Sn 100000
> ```

## License

Heli is licensed under either of the following licenses, at your discretion.

 * Apache License Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution submitted for inclusion in Heli by you shall be dual licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.
