#!/usr/bin/env python3
"""Capture or inspect network packets and export recruiter-friendly reports."""

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Iterable

from scapy.all import IP, TCP, UDP, get_if_list, rdpcap, sniff, wrpcap


def packet_to_row(packet) -> dict[str, object]:
    """Convert a Scapy packet into a flat row suitable for CSV output."""
    row: dict[str, object] = {
        "timestamp": float(packet.time),
        "length_bytes": len(packet),
        "protocol": "NON_IP",
        "source_ip": "",
        "destination_ip": "",
        "source_port": "",
        "destination_port": "",
    }

    if IP not in packet:
        return row

    row["source_ip"] = packet[IP].src
    row["destination_ip"] = packet[IP].dst
    row["protocol"] = "OTHER_IP"

    if TCP in packet:
        row["protocol"] = "TCP"
        row["source_port"] = int(packet[TCP].sport)
        row["destination_port"] = int(packet[TCP].dport)
    elif UDP in packet:
        row["protocol"] = "UDP"
        row["source_port"] = int(packet[UDP].sport)
        row["destination_port"] = int(packet[UDP].dport)

    return row


def summarize(packets: Iterable) -> dict[str, object]:
    """Return aggregate traffic counts without storing packet payloads."""
    rows = [packet_to_row(packet) for packet in packets]
    protocol_counts = Counter(row["protocol"] for row in rows)
    top_sources = Counter(row["source_ip"] for row in rows if row["source_ip"])
    top_destinations = Counter(
        row["destination_ip"] for row in rows if row["destination_ip"]
    )
    top_destination_ports = Counter(
        row["destination_port"]
        for row in rows
        if row["destination_port"] != ""
    )

    return {
        "total_packets": len(rows),
        "total_bytes": sum(int(row["length_bytes"]) for row in rows),
        "protocol_counts": dict(protocol_counts),
        "top_sources": top_sources.most_common(10),
        "top_destinations": top_destinations.most_common(10),
        "top_destination_ports": top_destination_ports.most_common(10),
    }


def write_json(summary: dict[str, object], path: Path) -> None:
    path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


def write_csv(packets: Iterable, path: Path) -> None:
    rows = [packet_to_row(packet) for packet in packets]
    fieldnames = [
        "timestamp",
        "length_bytes",
        "protocol",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture live traffic or analyze an existing PCAP with Scapy."
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--read-pcap",
        type=Path,
        help="Analyze an existing PCAP instead of capturing live traffic.",
    )
    source.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Print available capture interfaces and exit.",
    )
    parser.add_argument("--count", type=int, default=50, help="Packets to capture.")
    parser.add_argument("--iface", help="Capture interface; Scapy chooses by default.")
    parser.add_argument("--filter", help="Optional BPF capture filter, such as 'tcp port 443'.")
    parser.add_argument(
        "--pcap",
        type=Path,
        default=Path("capture.pcap"),
        help="PCAP path for a live capture.",
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=Path("summary.json"),
        help="Aggregate JSON report path.",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        default=Path("packets.csv"),
        help="Per-packet CSV report path.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.list_interfaces:
        print("\n".join(get_if_list()))
        return

    if args.read_pcap:
        packets = list(rdpcap(str(args.read_pcap)))
        source = args.read_pcap
    else:
        if args.count < 1:
            raise SystemExit("--count must be at least 1")
        print(
            f"Capturing {args.count} packet(s) on {args.iface or 'the default interface'}..."
        )
        packets = list(
            sniff(count=args.count, iface=args.iface, filter=args.filter, store=True)
        )
        wrpcap(str(args.pcap), packets)
        source = args.pcap

    write_json(summarize(packets), args.json)
    write_csv(packets, args.csv)
    print(
        f"Analyzed {len(packets)} packet(s) from {source}. "
        f"Wrote {args.json} and {args.csv}."
    )


if __name__ == "__main__":
    main()
