<p align="center">
  <img src="assets/icon.png" alt="pcapflower" width="128" />
</p>

<h1 align="center">pcapflower</h1>

<p align="center">High-performance PCAP-to-CSV network flow extractor for edge devices.</p>

Converts `.pcap` / `.pcapng` captures into bidirectional flow features compatible with the [CICFlowMeter](https://www.unb.ca/cic/research/applications.html) feature set — using a fraction of the memory and CPU.

## Why pcapflower?

| | CICFlowMeter | pcapflower |
|---|---|---|
| Packet parser | Scapy | dpkt |
| Memory per flow | O(n packets) | O(1) — Welford's online algorithm |
| Output buffering | ? | Batched (1 syscall/500 rows) |
| Parallelism | ✗ | ✓ — `n_jobs` parameter |
| pcapng support | ✗ | ✓ |

## Installation

```bash
pip install pcapflower
```

## Quick start

```python
from pcapflower import convert_pcap_to_csv

n = convert_pcap_to_csv("capture.pcap", "flows.csv")
print(f"Extracted {n} flows")

# Use all available CPUs
n = convert_pcap_to_csv("capture.pcap", "flows.csv", n_jobs=-1)
```

## API

### `convert_pcap_to_csv(input_path, output_path, **kwargs) → int`

| Parameter | Default | Description |
|-----------|---------|-------------|
| `input_path` | — | Path to `.pcap` or `.pcapng` file |
| `output_path` | — | Path for the output `.csv` (created or overwritten) |
| `flow_timeout` | `120.0` | Seconds of inactivity before a flow is evicted |
| `gc_interval` | `1000` | Run idle-flow GC every N packets |
| `buffer_rows` | `500` | Rows buffered in memory before flushing to disk |
| `n_jobs` | `1` | Worker processes. `-1` uses all available CPUs |

Returns the number of flow rows written.

## Output features

Each row contains **82 features** covering:

- Flow identity: source/destination IP, port, protocol, timestamp
- Duration, bytes/s, and packets/s (forward, backward, combined)
- Packet length statistics (mean, std, min, max, variance)
- Inter-arrival time statistics (flow, forward, backward)
- TCP flag counts (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR)
- Active/idle period statistics
- Bulk transfer metrics (forward and backward)
- Subflow metrics
- Initial TCP window sizes

## Supported input formats

- **pcap** — standard libpcap format
- **pcapng** — next-generation capture format

Only **IPv4 TCP and UDP** flows are extracted; other protocols are silently skipped.

## License

MIT — see [LICENSE](LICENSE).
