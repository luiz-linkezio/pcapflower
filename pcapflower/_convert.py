"""
Main conversion pipeline: PCAP → FlowSession → CSV.

Supports both pcap and pcapng formats.
Packets are streamed one by one; no packet objects are retained after processing.
"""

import socket
import struct
from typing import Iterator

import dpkt
import dpkt.pcapng

from ._session import FlowSession
from ._writer import CsvWriter
from ._constants import FLOW_TIMEOUT, CSV_BUFFER_ROWS


def _open_pcap(path: str):
    """Return an iterable of (timestamp, raw_bytes) from a pcap or pcapng file."""
    with open(path, "rb") as fh:
        magic = fh.read(4)

    # pcapng uses a Section Header Block with magic 0x0A0D0D0A
    if magic == b"\x0a\x0d\x0d\x0a":
        return _iter_pcapng(path)
    return _iter_pcap(path)


def _iter_pcap(path: str) -> Iterator[tuple[float, bytes]]:
    with open(path, "rb") as fh:
        reader = dpkt.pcap.Reader(fh)
        yield from reader


def _iter_pcapng(path: str) -> Iterator[tuple[float, bytes]]:
    with open(path, "rb") as fh:
        reader = dpkt.pcapng.Reader(fh)
        yield from reader


def _parse_packet(buf: bytes):
    """
    Parse an Ethernet frame and return the fields needed by FlowSession.

    Returns None if the packet is not IPv4 TCP/UDP.

    Return tuple:
        (src_ip, dst_ip, src_port, dst_port, protocol,
         pkt_len, header_len, payload_len, flags, window)
    """
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except Exception:
        return None

    ip = eth.data
    if not isinstance(ip, dpkt.ip.IP):
        return None

    src_ip = socket.inet_ntoa(ip.src)
    dst_ip = socket.inet_ntoa(ip.dst)
    pkt_len = len(ip)  # IP header + payload (mirrors CICFlowMeter's len(packet))

    transport = ip.data
    if isinstance(transport, dpkt.tcp.TCP):
        src_port = transport.sport
        dst_port = transport.dport
        protocol = 6
        flags = transport.flags
        window = transport.win
        header_len = (transport.off & 0xF0) >> 2  # data offset × 4
        payload_len = len(transport.data)
    elif isinstance(transport, dpkt.udp.UDP):
        src_port = transport.sport
        dst_port = transport.dport
        protocol = 17
        flags = 0
        window = -1
        header_len = 8  # UDP header is always 8 bytes
        payload_len = len(transport.data)
    else:
        return None

    return (
        src_ip, dst_ip, src_port, dst_port, protocol,
        pkt_len, header_len, payload_len, flags, window,
    )


def convert_pcap_to_csv(
    input_path: str,
    output_path: str,
    flow_timeout: float = FLOW_TIMEOUT,
    gc_interval: int = 1000,
    buffer_rows: int = CSV_BUFFER_ROWS,
) -> int:
    """
    Convert a PCAP (or pcapng) file into a flow-based CSV file.

    Each row in the output CSV represents one bidirectional network flow and
    contains 81 features compatible with the CICFlowMeter feature set.

    Parameters
    ----------
    input_path:   Path to the input .pcap or .pcapng file.
    output_path:  Path for the output .csv file (created or overwritten).
    flow_timeout: Seconds of inactivity before a flow is flushed (default 120).
    gc_interval:  Run idle-flow garbage collection every N packets (default 1000).
    buffer_rows:  Rows buffered in memory before a disk write (default 500).

    Returns
    -------
    Number of flow rows written to the CSV.

    Example
    -------
    >>> from pcapflower import convert_pcap_to_csv
    >>> n = convert_pcap_to_csv("capture.pcap", "flows.csv")
    >>> print(f"Extracted {n} flows")
    """
    with CsvWriter(output_path, buffer_rows) as writer:
        session = FlowSession(writer, flow_timeout)
        pkt_counter = 0
        last_ts = 0.0

        for ts, buf in _open_pcap(input_path):
            parsed = _parse_packet(buf)
            if parsed is None:
                continue

            src_ip, dst_ip, src_port, dst_port, proto, pkt_len, hdr_len, pay_len, flags, win = parsed
            session.process(ts, src_ip, dst_ip, src_port, dst_port, proto,
                            pkt_len, hdr_len, pay_len, flags, win)

            pkt_counter += 1
            last_ts = ts

            if pkt_counter % gc_interval == 0:
                session.gc(last_ts)

        session.flush_all()

    return writer.row_count
