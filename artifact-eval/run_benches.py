import argparse
import json
import subprocess
import re
from typing import List, Dict, Any
from dataclasses import dataclass
import os

# This is the benchmarked time it took to encode/unwrap a single 
# client submission (b=1, l=1) using github.com/divviup/janus. The
# main overhead is the HPKE group exponentiation, so the report
# size doesn't meaningfully affect this
unwrap_time_ms = 0.078264
encode_time_ms = 0.104

# Size of a single group element
group_elem_bytes = 32

@dataclass
class BenchmarkResult:
    """Stores results for a single benchmark run."""
    clients: int
    mean_ms: float
    per_user_ms: float
    relative: str
    median_ms: float
    min_ms: float
    max_ms: float
    std_dev_ms: float
    config: Dict[str, Any]


def _env():
    e = os.environ.copy()
    e["RAYON_NUM_THREADS"] = "1"
    e["RUSTFLAGS"] = "-C target-cpu=native"
    return e


def _configs() -> List[Dict[str, Any]]:
    configs = [{"length": 1, "bitlength": 1, "clients": [128], "iterations": 20, "warmup": 1}]
    for bitlength in [8, 16, 32, 64]:
        configs.append({"length": 1, "bitlength": bitlength, "clients": [128], "iterations": 20, "warmup": 1})
    for length in [8, 16, 32, 64]:
        configs.append({"length": length, "bitlength": 1, "clients": [128], "iterations": 20, "warmup": 1})
    return configs


def parse_verify_bench_output(output: str, config: Dict[str, Any]) -> List[BenchmarkResult]:
    """Parse verify_bench table output."""
    results = []
    row_pattern = re.compile(
        r"\s+(\d+)\s+\|\s+([\d.]+)ms\s+\|\s+([\d.]+)ms\s+\|\s+([\d.]+x)\s+\|\s+([\d.]+)ms\s+\|\s+([\d.]+)ms\s+\|\s+([\d.]+)ms\s+\|\s+([\d.]+)ms"
    )
    for line in output.split("\n"):
        match = row_pattern.match(line)
        if match:
            clients, mean, per_user, relative, median, min_val, max_val, std_dev = match.groups()
            results.append(
                BenchmarkResult(
                    clients=int(clients),
                    mean_ms=float(mean),
                    per_user_ms=float(per_user),
                    relative=relative,
                    median_ms=float(median),
                    min_ms=float(min_val),
                    max_ms=float(max_val),
                    std_dev_ms=float(std_dev),
                    config=config.copy(),
                )
            )
    return results


# size_bench prints: "  (length, bitlength) [Binary|Range] -> encoding + proof = total"
_SIZE_LINE_RE = re.compile(
    r"\(\s*(\d+)\s*,\s*(\d+)\s*\)\s*\[\w+\]\s*->\s*(\d+)\s*B\s*\+\s*(\d+)\s*B\s*=\s*([\d.]+)KB"
)


@dataclass
class SizeResult:
    length: int
    bitlength: int
    encoding_bytes: int
    proof_bytes: int
    total_kb: float


def parse_size_bench_output(output: str) -> List[SizeResult]:
    results = []
    for line in output.split("\n"):
        m = _SIZE_LINE_RE.search(line)
        if m:
            length, bitlength, enc_b, proof_b, total_kb = m.groups()
            results.append(
                SizeResult(
                    length=int(length),
                    bitlength=int(bitlength),
                    encoding_bytes=int(enc_b),
                    proof_bytes=int(proof_b),
                    total_kb=float(total_kb),
                )
            )
    return results


def run_server_bin(
    kind: str,
    configs: List[Dict[str, Any]],
    release: bool = True,
) -> List[Any]:
    if kind == "verify":
        out_results: List[BenchmarkResult] = []
        for i, cfg in enumerate(configs):
            cmd = [
                "cargo", "run", "--release" if release else "",
                "--bin", "verify-bench", "--",
                "-c", *[str(c) for c in cfg["clients"]],
                "-l", str(cfg["length"]),
                "-b", str(cfg["bitlength"]),
                "-i", str(cfg["iterations"]),
                "-w", str(cfg["warmup"]),
            ]
            cmd = [x for x in cmd if x]
            print(f"Running: {' '.join(cmd)}")
            r = subprocess.run(cmd, env=_env(), capture_output=True, text=True)
            if r.returncode != 0:
                print(f"Error: {r.stderr}")
                continue
            out_results.extend(parse_verify_bench_output(r.stdout, cfg))
        return out_results

    if kind == "size":
        results = []
        # First run with different lengths
        lengths = sorted({c["length"] for c in configs})
        cmd = [
            "cargo", "run", "--release" if release else "",
            "--bin", "size-bench", "--",
            "-l", *[str(x) for x in lengths],
        ]
        print(f"Running: {' '.join(cmd)}")
        r = subprocess.run(cmd, env=_env(), capture_output=True, text=True)
        if r.returncode != 0:
            print(f"Error: {r.stderr}")
            return []
        results += parse_size_bench_output(r.stdout)
      
        #.. then different bitlengths
        bitlengths = sorted({c["bitlength"] for c in configs})
        cmd = [
            "cargo", "run", "--release" if release else "",
            "--bin", "size-bench", "--",
            "-b", *[str(x) for x in bitlengths],
        ]
        print(f"Running: {' '.join(cmd)}")
        r = subprocess.run(cmd, env=_env(), capture_output=True, text=True)
        if r.returncode != 0:
            print(f"Error: {r.stderr}")
            return []
        results += parse_size_bench_output(r.stdout)
        return results

    raise ValueError("kind must be 'verify' or 'size'")


def run_heavy_cpu() -> List[BenchmarkResult]:
    return run_server_bin("verify", _configs())


def run_server_comm() -> List[Dict[str, Any]]:
    configs = _configs()
    return [
        {
            "length": c["length"],
            "bitlength": c["bitlength"],
            "us_c": round((group_elem_bytes * c["length"]) / 1024.0, 2),
        }
        for c in configs
    ]


# ---------------------------------------------------------------------------
# light + cpu: cargo bench decode, parse criterion JSON
# ---------------------------------------------------------------------------

@dataclass
class DecodeResult:
    clients: int
    dropouts: int
    length: int
    bitlength: int
    mean_ms: float


def parse_criterion_decode(output: str) -> List[DecodeResult]:
    results = []
    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            if entry.get("reason") != "benchmark-complete":
                continue
            m = re.search(
                r"(\d+)_clients_(\d+)_dropouts_(\d+)_inputs_(\d+)_bits",
                entry["id"]
            )
            clients, dropouts, length, bitlength = (int(x) for x in m.groups())
            mean_ms = round(entry["mean"]["estimate"] / 1_000_000, 2)
            results.append(
                DecodeResult(
                    clients=clients,
                    dropouts=dropouts,
                    length=length,
                    bitlength=bitlength,
                    mean_ms=mean_ms,
                )
            )
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
    return results


def run_light_cpu() -> List[DecodeResult]:
    cmd = ["cargo", "criterion", "decode", "--message-format=json"]
    print(f"Running: {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True, env=_env())
    if r.returncode != 0:
        print(f"Error running cargo bench decode:\n{r.stderr}\n{r.stdout}")
        return []
    return parse_criterion_decode(r.stdout)

# ---------------------------------------------------------------------------
# client + cpu: cargo bench encode (client_encoding)
# ---------------------------------------------------------------------------



@dataclass
class EncodeResult:
    length: int
    bitlength: int
    mean_ms: float


def parse_criterion_encode(output: str) -> List[EncodeResult]:
    results = []
    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            if entry.get("reason") != "benchmark-complete":
                continue
            m = re.search(
                r"(\d+)_inputs_(\d+)_bits",
                entry["id"]
            )
            length, bitlength = m.group(1, 2)
            mean_ms = round(entry["mean"]["estimate"] / 1_000_000, 2)
            results.append(EncodeResult(
                length=int(length),
                bitlength=int(bitlength),
                mean_ms=mean_ms))
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
    return results

def run_client_cpu() -> List[EncodeResult]:
    cmd = [
        "cargo", "criterion",
        "encode",
        "--message-format=json",
    ]
    print(f"Running: {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True, env=_env())
    if r.returncode != 0:
        print(f"Error: {r.stderr}\n{r.stdout}")
        return []
    return parse_criterion_encode(r.stdout)


# ---------------------------------------------------------------------------
# client + comm: size-bench (same configs)
# ---------------------------------------------------------------------------

def run_client_comm() -> List[SizeResult]:
    return run_server_bin("size", _configs())



RUNNERS = {
    ("heavy", "cpu"): run_heavy_cpu,
    ("heavy", "comm"): run_server_comm,
    ("light", "cpu"): run_light_cpu,
    ("light", "comm"): run_server_comm,
    ("client", "cpu"): run_client_cpu,
    ("client", "comm"): run_client_comm,
}


if __name__ == "__main__":
    parties = ["heavy", "light", "client"]
    metrics = ["cpu", "comm"]

    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--party", type=str, choices=parties, default=None)
    parser.add_argument("-m", "--metric", type=str, choices=metrics, default=None)
    args = parser.parse_args()

    party_list = [args.party] if args.party else parties
    metric_list = [args.metric] if args.metric else metrics

    for p in party_list:
        for m in metric_list:
            result = RUNNERS[(p, m)]()
            if (p, m) == ("heavy", "cpu") and result:
                print("\n\nHeavy CPU (core-ms):")
                print("--------------------")
                results = result
                assert results[0].config["bitlength"] == 1 and results[0].config["length"] == 1
                for num_clients in [128, 1000, 10000, 1000000, 10000000]:
                    time = unwrap_time_ms * num_clients + round(
                        results[0].mean_ms * (num_clients / 128.0), 2
                    )
                    print(f"Clients={num_clients:<8}, b=1 , l=1: {time}ms")
                for r in results[1:]:
                    b, l = r.config["bitlength"], r.config["length"]
                    time = unwrap_time_ms * 10_000_000 + round(
                        r.mean_ms * (10_000_000 / 128.0), 2
                    )
                    print(f"Clients=10000000, b={b:<2}, l={l:<2}: {time}ms")
            elif (p, m) == ("heavy", "comm") and result:
                print("\n\nServer-to-Server comm. (KB):")
                print("--------------------")
                for num_clients in [128, 1000, 10000, 1000000, 10000000]:
                    comm = result[0]["us_c"]
                    print(f"Clients={num_clients:<8}, b=1 , l=1: {comm}KB")
                for row in result:
                    print(f"Clients=10000000, b={row['bitlength']:<2}, l={row['length']:<2}: {row['us_c']}KB")
            elif (p, m) == ("light", "cpu") and result:
                print("\n\nLight CPU (core-ms):")
                print("--------------------")
                for x in result:
                    print(f"Clients={x.clients:<8}, dropouts={x.dropouts:<8}, b={x.bitlength}, l={x.length}: {x.mean_ms} ms")
            elif (p, m) == ("client", "cpu") and result:
                print("\n\nClient Encoding CPU (ms):")
                print("--------------------")
                for x in result:
                    print(f"b={x.bitlength:<2}, l={x.length:<2}: {x.mean_ms} ms")
            elif (p, m) == ("client", "comm") and result:
                print("\n\nClient Encoding Size (KB):")
                print("--------------------")
                for r in result[1:]:
                    print(f"b={r.bitlength:<2}, l={r.length:<2}: {r.total_kb}KB")
