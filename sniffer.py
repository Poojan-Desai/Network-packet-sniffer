#!/usr/bin/env python3
import json
import argparse
from collections import Counter
from scapy.all import sniff, wrpcap, IP, TCP, UDP, get_if_list

def summarize(packets):
    proto_counts = Counter()
    top_src = Counter()
    top_dst = Counter()
    ports = Counter()
    for pkt in packets:
        if IP in pkt:
            top_src[pkt[IP].src] += 1
            top_dst[pkt[IP].dst] += 1
            if TCP in pkt:
                proto_counts['TCP'] += 1
                ports[pkt[TCP].dport] += 1
            elif UDP in pkt:
                proto_counts['UDP'] += 1
                ports[pkt[UDP].dport] += 1
            else:
                proto_counts['Other_IP'] += 1
        else:
            proto_counts['Non_IP'] += 1
    return {
        "total_packets": len(packets),
        "protocol_counts": dict(proto_counts),
        "top_src": top_src.most_common(10),
        "top_dst": top_dst.most_common(10),
        "top_dst_ports": ports.most_common(10),
    }

def main():
    p = argparse.ArgumentParser(description="Minimal Scapy packet sniffer")
    p.add_argument("--count", type=int, default=50, help="Number of packets to capture")
    p.add_argument("--iface", type=str, default=None, help="Interface to sniff on")
    p.add_argument("--pcap", type=str, default="capture.pcap", help="Output pcap filename")
    p.add_argument("--out", type=str, default="summary.json", help="Output JSON summary")
    args = p.parse_args()

    print("Available interfaces:", get_if_list())
    print(f"Sniffing {args.count} packets on iface={args.iface} ... (Ctrl+C to stop)")
    packets = sniff(count=args.count, iface=args.iface)
    print("Done. Writing PCAP and summary...")
    wrpcap(args.pcap, packets)
    summary = summarize(packets)
    with open(args.out, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Wrote {args.pcap} and {args.out}")

if __name__ == "__main__":
    main()
