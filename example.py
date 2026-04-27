"""
Minimal usage example for pcapflower.

Install:
    pip install pcapflower

Run this file:
    python example.py capture.pcap [output.csv]
"""

import sys
import time
from pcapflower import convert_pcap_to_csv

if len(sys.argv) < 2:
    print("Usage: python example.py <input.pcap> [output.csv]")
    sys.exit(1)

input_path = sys.argv[1]
output_path = sys.argv[2] if len(sys.argv) > 2 else "flows.csv"

t0 = time.perf_counter()
n_flows = convert_pcap_to_csv(input_path, output_path)
elapsed = time.perf_counter() - t0

print(f"Wrote {n_flows} flows to {output_path!r} in {elapsed:.2f}s")
