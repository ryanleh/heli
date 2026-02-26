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

* [`experiments`](experiments): End-to-end experiments to recreate Table 2
from the Heli paper.

* [`artifact-eval`](artifact-eval): Scripts to recreate Figures 4, 5 from the Heli paper.

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
pip install -r requirements.txt
```
and run the following script:
```bash
python3 run_and_plot.py
```
Plots will appear in the `artifact-eval/plots` directory.


### End-to-end experiments

The scripts in `experiments/bin/` run the aggregator, decryptor, and client with predefined configs. For these to work, ensure that the aggregator and decryptor accept TCP traffic on ports 9000 and 9001. 

* `run_{aggregator,decryptor,client}.sh` runs aggregation over 10,000,000 million clients (with 10% offline) with bit vectors of length 1, 32, and 128. The experiments are specified in `experiments/configs/full-{1,32,128}.json`.

* `run_{aggregator,decryptor,client}_sim.sh` runs aggregation over 100,000 clients (with 10% offline) with bit vectors of length 1, 32, and 128. The experiments are specified in `experiments/configs/simplified-{1,32,128}.json`.

> **Note:** For faster benchmarking, these scripts simulate the one-time setup
> and run aggregation over a small set of duplicated client reports; this does
> not effect the servers' aggregation runtimes. To run the system without 
> the simulated steps, replace the `sim-setup` and `sim-generate` modes
> specified in the client scripts to `setup` and `generate`. (Note that this
> requires the client machine to have 250 GB of disk space for writing reports)

> **Tip:** If your aggregator machine runs out of memory during aggregation, lower 
> the `max_pending_batches` config option.


#### Config file reference

Experiment configs are JSON files. See the predefined configs in `experiments/configs/` as examples of the correct format. The configuration options are specified below:

| Field | Type | Description |
|-------|------|-------------|
| `num_clients` | number | Total number of clients to simulate. |
| `threshold` | number | Minimum number of clients that must participate for aggregation to succeed. |
| `dropouts` | number | Number of clients that drop out. |
| `length` | number | Number of data slots per client (vector length). |
| `prover` | object | Proof type: `{"type": "binary"}` or `{"type": "range", "bitlength": N}`. |
| `aggregator_addr` | string | Host:port the aggregator listens on (e.g. `"0.0.0.0:9000"`). |
| `decryptor_addr` | string | Host:port the decryptor listens on (e.g. `"0.0.0.0:9001"`). |
| `db_path` | string | Directory path for a local sled DB. |
| `max_pending_batches` | number (optional) | Max pending client report chunks on the aggregator. Default: `100`. |
| `reports_per_chunk` | number (optional) | Number of reports the aggregator combines into one processing chunk. Default: `10000`. |

## License

Heli is licensed under either of the following licenses, at your discretion.

 * Apache License Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution submitted for inclusion in Heli by you shall be dual licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.
