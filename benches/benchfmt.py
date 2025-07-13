import csv
import json
import re
import sys

def parse_json_stream(input_file):
    with open(input_file, 'r') as f:
        writer = csv.writer(sys.stdout)
        writer.writerow(["batch", "time_ms"])
        
        for line in f:
            try:
                entry = json.loads(line)
                if entry.get("reason") == "benchmark-complete":
                    batch = re.search(r'(\d+)_clients*', entry["id"]).group(1)
                    # Criterion gives all numbers in ns by default
                    mean_ms = entry["mean"]["estimate"] / 1000.0 / 1000.0
                    writer.writerow([batch, mean_ms])
            except json.JSONDecodeError:
                continue  # skip malformed lines

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python parse_criterion_json_stream.py input.jsonl output.csv")
    else:
        parse_json_stream(sys.argv[1], sys.argv[2])

