import csv
import json

from scapy.all import ARP, Ether, IP, TCP, UDP

from sniffer import packet_to_row, summarize, write_csv, write_json


def sample_packets():
    return [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=51515, dport=443),
        Ether() / IP(src="10.0.0.1", dst="10.0.0.3") / UDP(sport=5353, dport=53),
        Ether() / ARP(psrc="10.0.0.4", pdst="10.0.0.1"),
    ]


def test_packet_to_row_extracts_transport_metadata():
    row = packet_to_row(sample_packets()[0])

    assert row["protocol"] == "TCP"
    assert row["source_ip"] == "10.0.0.1"
    assert row["destination_ip"] == "10.0.0.2"
    assert row["source_port"] == 51515
    assert row["destination_port"] == 443


def test_summarize_counts_protocols_endpoints_and_bytes():
    packets = sample_packets()
    summary = summarize(packets)

    assert summary["total_packets"] == 3
    assert summary["total_bytes"] == sum(len(packet) for packet in packets)
    assert summary["protocol_counts"] == {"TCP": 1, "UDP": 1, "NON_IP": 1}
    assert summary["top_sources"][0] == ("10.0.0.1", 2)
    assert summary["top_destination_ports"] == [(443, 1), (53, 1)]


def test_writers_create_machine_readable_reports(tmp_path):
    packets = sample_packets()
    json_path = tmp_path / "summary.json"
    csv_path = tmp_path / "packets.csv"

    write_json(summarize(packets), json_path)
    write_csv(packets, csv_path)

    assert json.loads(json_path.read_text())["total_packets"] == 3
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 3
    assert rows[1]["protocol"] == "UDP"
