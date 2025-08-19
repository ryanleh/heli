import json
import pandas as pd
import re
import sys

def parse_json_stream(input_file):
    records = []

    with open(input_file, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line)
                if entry.get("reason") == "benchmark-complete":
                    pattern = re.search(r'(\d+)_clients_(\d+)_inputs_(\d+)_bits', entry["id"])
                    clients, length, bitlength = pattern.group(1, 2, 3)
                    mean_ms = entry["mean"]["estimate"] / 1_000_000  # ns → ms
                    records.append({
                        "bitlength": int(bitlength),
                        "length": int(length),
                        "clients": int(clients),
                        "time_ms": mean_ms
                    })
            except json.JSONDecodeError:
                continue  # skip malformed lines

    df = pd.DataFrame(records)

    # Example sort: by time descending
    df = df.sort_values(by=["bitlength", "length", "clients"], ascending=[True, True, True])

    # Write to TSV (stdout or file)
    df.to_csv(sys.stdout, sep='\t', index=False)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python parse_criterion_json_stream.py input.json")
    else:
        parse_json_stream(sys.argv[1])
