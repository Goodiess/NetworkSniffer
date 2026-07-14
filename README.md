# Basic Network Sniffer —Cybersecurity Internship (Task 1)

**Author:** Raphael Goodness Ngene (Goodies)  
**Internship:** CodeAlpha Cybersecurity Internship  
**Task:** Task 1 — Basic Network Sniffer  

---

## Overview

A Python-based network packet sniffer built with Scapy that captures live network traffic, displays packet details in real time, and saves results to both a `.pcap` file (for Wireshark analysis) and a `.csv` summary file (for documentation and reporting).

---

## Features

- Live packet capture on any specified network interface
- Displays source/destination IP addresses and ports
- Identifies protocols: TCP, UDP, ICMP, ARP, and others
- Shows payload preview for packets containing raw data
- Saves captured packets to a `.pcap` file (Wireshark-compatible)
- Exports a structured `.csv` summary for documentation
- Supports BPF filter strings (e.g. `tcp port 80`, `udp`, `icmp`)
- Configurable packet count (capture N packets or run indefinitely)

---

## Requirements

- Kali Linux (or any Debian-based Linux)
- Python 3
- Scapy

### Install Scapy

```bash
pip install scapy --break-system-packages
```

> Scapy comes pre-installed on Kali Linux 2024+

---

## Usage

> **Must be run as root (sudo) for raw packet capture**

### Basic capture (auto-detect interface, unlimited packets):
```bash
sudo python3 network_sniffer.py
```

### Capture on a specific interface:
```bash
sudo python3 network_sniffer.py -i eth0
```

### Capture exactly 30 packets then stop:
```bash
sudo python3 network_sniffer.py -i eth0 -c 30
```

### Filter by protocol or port:
```bash
sudo python3 network_sniffer.py -i eth0 -f "tcp port 80"
sudo python3 network_sniffer.py -i eth0 -f "udp"
sudo python3 network_sniffer.py -i eth0 -f "icmp"
```

### Set custom output filename:
```bash
sudo python3 network_sniffer.py -i eth0 -c 50 -o my_capture
```

Press **Ctrl+C** at any time to stop capture early — files are saved automatically.

---

## Output

Each run generates two timestamped files:

| File | Description |
|------|-------------|
| `capture_YYYYMMDD_HHMMSS.pcap` | Full packet capture, open with Wireshark |
| `capture_YYYYMMDD_HHMMSS.csv` | Packet summary (No., Timestamp, Protocol, IPs, Ports, Length, Payload Preview) |

Sample CSV columns:
```
No. | Timestamp | Protocol | Source IP | Source Port | Destination IP | Destination Port | Length (bytes) | Payload Preview
```

---

## Sample Output (Terminal)

```
======================================================================
 CodeAlpha Cybersecurity Internship - Task 1: Network Sniffer
======================================================================
 Interface : eth0
 Filter    : none (all traffic)
 Count     : 30
 Output    : capture_20260630_175311.pcap, capture_20260630_175311.csv
======================================================================
 Starting capture... press Ctrl+C to stop early.

[1] 2026-06-30 17:54:11 | ARP   | 192.168.203.1:N/A -> 192.168.203.2:N/A | Len: 60B
[2] 2026-06-30 17:54:12 | UDP   | 192.168.203.129:39617 -> 102.205.44.55:123 | Len: 90B
[3] 2026-06-30 17:54:30 | TCP   | 192.168.203.129:443 -> 104.18.32.10:52341 | Len: 120B
...
[30] 2026-06-30 17:55:12 | OTHER | 192.168.203.1:N/A -> 224.0.0.22:N/A | Len: 60B

[+] Saved 30 packets to capture_20260630_175311.pcap
[+] Saved packet summary to capture_20260630_175311.csv
[+] Total packets captured: 30
[+] Done. Open the .pcap file in Wireshark for deeper analysis.
```

---

## Tools & Technologies

- **Python 3** — core scripting language
- **Scapy 2.7.1** — packet capture and dissection library
- **Wireshark** — pcap file analysis
- **Kali Linux 2026.2** — testing environment (VMware Workstation)

---

## What I Learned

- How network packets flow across different protocols (TCP, UDP, ICMP, ARP)
- How to use Scapy for raw packet capture and inspection
- How to extract and parse packet layers (IP, transport, payload)
- How to export network captures in pcap format for Wireshark analysis
- The importance of root privileges for low-level network access

---

## License

This project was built as part of the CodeAlpha Cybersecurity Internship program for educational purposes.
