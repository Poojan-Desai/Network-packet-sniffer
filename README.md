# Network Packet Sniffer

I wrote a small Python tool using Scapy to capture ~50 packets and get a quick feel for TCP/UDP traffic, top talkers, and ports. It helps me practice basic network analysis.

## How I run it
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# You may need sudo/admin to sniff:
sudo python sniffer.py --count 50  # add --iface if needed
```

## What I learned
How to spot patterns quickly (protocol mix, noisy hosts/ports) and save raw pcaps for deeper dives in Wireshark.

## Notes
- I keep things simple and readable.
- If something feels off, I open an issue and fix it quickly.
