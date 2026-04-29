"""
pcapflower — high-performance PCAP-to-CSV flow feature extractor.

Designed for edge devices (Raspberry Pi and similar) where memory and CPU
are constrained.  Key design choices versus CICFlowMeter:

  * dpkt for packet parsing (~10-25× faster than Scapy on ARM)
  * Welford's online algorithm for statistics — no packet objects stored
  * O(1) memory per flow regardless of how many packets it contains
  * Batch-buffered CSV output — one syscall per N rows instead of one per row

Public API
----------
    convert_pcap_to_csv(input_path, output_path, **kwargs) -> int
"""

from ._convert import convert_pcap_to_csv

__all__ = ["convert_pcap_to_csv"]
__version__ = "1.1.0"
