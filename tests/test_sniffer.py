import csv
import json

from scapy.all import ARP, Ether, IP, IPv6, TCP, UDP

from sniffer import packet_to_row, summarize, write_csv, write_json


def sample_packets():
    return [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=51515, dport=443),
        Ether() / IP(src="10.0.0.1", dst="10.0.0.3") / UDP(sport=5353, dport=53),
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / UDP(sport=5353, dport=53),
        Ether() / ARP(psrc="10.0.0.4", pdst="10.0.0.1"),
    ]


def test_packet_to_row_extracts_transport_metadata():
    row = packet_to_row(sample_packets()[0])

    assert row["protocol"] == "TCP"
    assert row["ip_version"] == 4
    assert row["source_ip"] == "10.0.0.1"
    assert row["destination_ip"] == "10.0.0.2"
    assert row["source_port"] == 51515
    assert row["destination_port"] == 443
    assert row["tcp_flags"] == "S"


def test_packet_to_row_supports_ipv6_without_payload_inspection():
    row = packet_to_row(sample_packets()[2])

    assert row["ip_version"] == 6
    assert row["source_ip"] == "2001:db8::1"
    assert row["destination_ip"] == "2001:db8::2"
    assert row["protocol"] == "UDP"


def test_summarize_counts_protocols_endpoints_and_bytes():
    packets = sample_packets()
    summary = summarize(packets)

    assert summary["total_packets"] == 4
    assert summary["total_bytes"] == sum(len(packet) for packet in packets)
    assert summary["protocol_counts"] == {"TCP": 1, "UDP": 2, "NON_IP": 1}
    assert summary["ip_version_counts"] == {"4": 2, "6": 1}
    assert summary["top_sources"][0] == ("10.0.0.1", 2)
    assert summary["top_destination_ports"] == [(53, 2), (443, 1)]
    assert summary["top_conversations"][0][1] == 1
    assert summary["tcp_flag_counts"] == {"S": 1}


def test_writers_create_machine_readable_reports(tmp_path):
    packets = sample_packets()
    json_path = tmp_path / "summary.json"
    csv_path = tmp_path / "packets.csv"

    write_json(summarize(packets), json_path)
    write_csv(packets, csv_path)

    assert json.loads(json_path.read_text())["total_packets"] == 4
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 4
    assert rows[1]["protocol"] == "UDP"
    assert rows[2]["ip_version"] == "6"
