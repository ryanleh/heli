#!/usr/bin/env python3
"""
Run all benches, update artifact-eval data CSVs with results, then generate PDF plots.
Run from repo root: python code/artifact-eval/run.py
Or from code/:    python artifact-eval/run.py
"""
import os

import pandas as pd

_SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
_DATA_DIR = os.path.join(_SCRIPT_DIR, "data")

from run_benches import (
    run_heavy_cpu,
    run_server_comm,
    run_light_cpu,
    run_client_cpu,
    run_client_comm,
    unwrap_time_ms,
)


def _update_server_df(server_df, heavy_results, server_comm_list, decode_results):
    """Update server_df in place with us_* and related columns from bench results."""
    # (length, bitlength) -> mean_ms for 128 clients (from verify-bench)
    heavy_lookup = {}
    for r in heavy_results:
        key = (r.config["length"], r.config["bitlength"])
        heavy_lookup[key] = r.mean_ms

    # (length, bitlength) -> us_c KB
    comm_lookup = {(row["length"], row["bitlength"]): row["us_c"] for row in server_comm_list}

    # (clients, length, bitlength) -> decode mean_ms (dropouts=0)
    decode_lookup = {}
    for r in decode_results:
        if r.dropouts == 0:
            decode_lookup[(r.clients, r.length, r.bitlength)] = r.mean_ms

    for idx, row in server_df.iterrows():
        b, l, c = int(row["bitwidth"]), int(row["length"]), int(row["clients"])
        # unwrap
        server_df.at[idx, "unwrap"] = round(unwrap_time_ms * c, 2)
        # us_v + us_a from heavy (scale by c/128)
        key = (l, b)
        if key in heavy_lookup:
            server_df.at[idx, "us_v"] = round(heavy_lookup[key] * (c / 128.0), 2)
            server_df.at[idx, "us_a"] = 0.0
        if key in comm_lookup:
            server_df.at[idx, "us_c"] = comm_lookup[key]
        dkey = (c, l, b)
        if dkey in decode_lookup:
            server_df.at[idx, "decode"] = decode_lookup[dkey]


def _update_dropout_10_df(df, decode_results):
    """Update dropout_10.csv cpu column from decode results (10% dropout, length=1, bitwidth=1)."""
    # (clients, dropouts, length, bitlength) -> mean_ms
    lookup = {}
    for r in decode_results:
        if r.length == 1 and r.bitlength == 1 and r.dropouts == round(0.1 * r.clients):
            lookup[r.clients] = r.mean_ms
    for idx, row in df.iterrows():
        c = int(row["clients"])
        if c in lookup:
            df.at[idx, "cpu"] = round(lookup[c], 2)
    # comm: no bench output, leave as-is


def _update_dropout_df(df, decode_results):
    """Update dropout.csv light column from decode results (10^7 clients, varying dropout %)."""
    clients_10m = 10_000_000
    # (dropouts, length, bitlength) for clients=10^7 -> mean_ms
    lookup = {}
    for r in decode_results:
        if r.clients == clients_10m and r.length == 1 and r.bitlength == 1:
            lookup[r.dropouts] = r.mean_ms
    for idx, row in df.iterrows():
        pct = float(row["dropout_perc"])
        dropouts = round(pct / 100.0 * clients_10m)
        if dropouts in lookup:
            df.at[idx, "light"] = round(lookup[dropouts], 2)
    # light_c, prio, etc.: no bench output, leave as-is


def _update_client_df(client_df, encode_results, size_results):
    """Update client_df in place with us_s, us_e from bench results."""
    # (length, bitlength) -> mean_ms encode
    encode_lookup = {(r.length, r.bitlength): r.mean_ms for r in encode_results}
    # (length, bitlength) -> total_kb
    size_lookup = {(r.length, r.bitlength): r.total_kb for r in size_results}

    for idx, row in client_df.iterrows():
        b, l = int(row["bitwidth"]), int(row["length"])
        key = (l, b)
        if key in encode_lookup:
            client_df.at[idx, "us_c"] = encode_lookup[key]
        if key in size_lookup:
            client_df.at[idx, "us_s"] = size_lookup[key]


def main():
    # Run cargo from code/ (parent of artifact-eval)
    code_dir = os.path.join(_SCRIPT_DIR, "..")
    os.chdir(os.path.abspath(code_dir))

    print("Running benches...")
    heavy_results = run_heavy_cpu()
    server_comm_list = run_server_comm()
    decode_results = run_light_cpu()
    encode_results = run_client_cpu()
    size_results = run_client_comm()

    print("\nLoading saved CSVs (baseline) from", _DATA_DIR)
    server_df = pd.read_csv(os.path.join(_DATA_DIR, "server.csv"), sep=r"\s+")
    client_df = pd.read_csv(os.path.join(_DATA_DIR, "client.csv"), sep=r"\s+")
    dropout_10_df = pd.read_csv(os.path.join(_DATA_DIR, "dropout_10.csv"), sep=r"\s+")
    dropout_df = pd.read_csv(os.path.join(_DATA_DIR, "dropout.csv"), sep=r"\s+")

    _update_server_df(server_df, heavy_results, server_comm_list, decode_results)
    _update_client_df(client_df, encode_results, size_results)
    _update_dropout_10_df(dropout_10_df, decode_results)
    _update_dropout_df(dropout_df, decode_results)

    # Write bench results to *_new.csv so you can compare with saved baseline
    new_files = (
        ("server_new.csv", server_df),
        ("client_new.csv", client_df),
        ("dropout_10_new.csv", dropout_10_df),
        ("dropout_new.csv", dropout_df),
    )
    for name, df in new_files:
        path = os.path.join(_DATA_DIR, name)
        df.to_csv(path, sep="\t", index=False)
        print("Wrote", path)
    print("(Compare *_new.csv with server.csv, client.csv, etc. for baseline vs this run.)")

    plots_dir = os.path.join(_SCRIPT_DIR, "plots")
    os.makedirs(plots_dir, exist_ok=True)
    print("\nGenerating plots from this run's bench results...")
    import plot_paper
    plot_paper.run_all(out_dir=plots_dir, data_dir=_DATA_DIR, use_bench_results=True)


if __name__ == "__main__":
    main()
