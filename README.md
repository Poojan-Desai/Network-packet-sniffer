# Network Traffic Analyzer

A Python and Scapy command-line tool for capturing live traffic or inspecting an existing PCAP. It produces an aggregate JSON summary and a per-packet CSV report without exporting packet payloads.

## Why I built it

I built this project to practice packet capture, protocol inspection, and turning raw network data into reports that are easier to investigate. The current scope is intentionally small: IPv4 TCP/UDP metadata, traffic counts, top endpoints, and destination ports.

## Features

- Capture a fixed number of live packets from a selected interface
- Apply an optional BPF capture filter
- Analyze an existing PCAP without root access
- Summarize protocol counts, byte volume, endpoints, and destination ports
- Export aggregate JSON and flat per-packet CSV
- Unit-test the analysis path with synthetic packets—no live capture required

## Architecture

```text
live interface ──> Scapy capture ──┐
                                   ├──> packet normalization ──> JSON summary
existing PCAP ──> Scapy reader ────┘                         └──> CSV rows
```

`packet_to_row()` normalizes packet metadata. `summarize()` calculates aggregates from the same normalized representation, keeping the reporting logic testable and separate from privileged packet capture.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

List interfaces:

```bash
python sniffer.py --list-interfaces
```

Capture 100 HTTPS packets (live capture may require administrator privileges):

```bash
sudo .venv/bin/python sniffer.py \
  --count 100 \
  --iface en0 \
  --filter "tcp port 443"
```

Analyze a saved capture safely without live capture privileges:

```bash
python sniffer.py --read-pcap capture.pcap \
  --json summary.json \
  --csv packets.csv
```

The JSON report includes `total_packets`, `total_bytes`, protocol counts, top source and destination IPs, and top destination ports. The CSV contains one row per packet with timestamp, size, protocol, endpoint, and port metadata.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

The tests build synthetic TCP, UDP, and non-IP packets, then verify normalization, aggregation, and both export formats.

## Limitations and responsible use

- IPv6-specific aggregation and deep packet inspection are not implemented.
- Encrypted application payloads are not decrypted or interpreted.
- Capture only networks and systems you own or have explicit permission to test.
- PCAPs may contain sensitive traffic metadata; generated captures and reports are ignored by Git.
