#!/usr/bin/env python3
"""
CodeAlpha Cybersecurity Internship - Task 1: Basic Network Sniffer
Author: Raphael Goodness Ngene (Goodies)

A Python-based network packet sniffer built with Scapy. Captures live
network traffic, displays key packet details in the terminal, and saves
captures to both a .pcap file (for Wireshark analysis) and a .csv summary
file (for documentation/reporting).

Usage (run as root/sudo on Kali Linux):
    sudo python3 network_sniffer.py
    sudo python3 network_sniffer.py -i eth0 -c 100
    sudo python3 network_sniffer.py -i eth0 -f "tcp port 80"

Requires: scapy (pip install scapy --break-system-packages)
"""

import argparse
import csv
import os
import sys
from datetime import datetime

try:
    from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, ARP, Raw
except ImportError:
    print("[!] Scapy is not installed. Install it with:")
    print("    pip install scapy --break-system-packages")
    sys.exit(1)


# ----------------------------------------------------------------------
# Global state
# ----------------------------------------------------------------------
captured_packets = []   # holds raw packets for pcap export
csv_rows = []            # holds parsed summaries for csv export
packet_count = 0


def get_protocol_name(packet):
    """Return a human-readable protocol name for a packet."""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    elif packet.haslayer(ARP):
        return "ARP"
    else:
        return "OTHER"


def get_payload_preview(packet, max_len=60):
    """Return a short, safe preview of the payload (if any)."""
    if packet.haslayer(Raw):
        try:
            payload = bytes(packet[Raw].load)
            # Try to decode as text; fall back to hex preview
            try:
                text = payload.decode("utf-8", errors="replace")
            except Exception:
                text = payload.hex()
            text = text.replace("\n", " ").replace("\r", " ")
            return text[:max_len] + ("..." if len(text) > max_len else "")
        except Exception:
            return ""
    return ""


def process_packet(packet):
    """Callback executed for every captured packet."""
    global packet_count
    packet_count += 1

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    protocol = get_protocol_name(packet)

    src_ip = dst_ip = "N/A"
    src_port = dst_port = "N/A"

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif packet.haslayer(IPv6):
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
    elif packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    length = len(packet)
    payload_preview = get_payload_preview(packet)

    # --- Live terminal display ---
    print(f"[{packet_count}] {timestamp} | {protocol:5} | "
          f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
          f"Len: {length}B"
          + (f" | Payload: {payload_preview}" if payload_preview else ""))

    # --- Store for export ---
    captured_packets.append(packet)
    csv_rows.append({
        "No.": packet_count,
        "Timestamp": timestamp,
        "Protocol": protocol,
        "Source IP": src_ip,
        "Source Port": src_port,
        "Destination IP": dst_ip,
        "Destination Port": dst_port,
        "Length (bytes)": length,
        "Payload Preview": payload_preview
    })


def save_outputs(pcap_path, csv_path):
    """Save captured packets to .pcap and .csv files."""
    if captured_packets:
        wrpcap(pcap_path, captured_packets)
        print(f"\n[+] Saved {len(captured_packets)} packets to {pcap_path}")
    else:
        print("\n[!] No packets captured, nothing to save.")
        return

    with open(csv_path, "w", newline="") as f:
        fieldnames = ["No.", "Timestamp", "Protocol", "Source IP", "Source Port",
                      "Destination IP", "Destination Port", "Length (bytes)",
                      "Payload Preview"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)
    print(f"[+] Saved packet summary to {csv_path}")


def main():
    parser = argparse.ArgumentParser(
        description="CodeAlpha Task 1 - Basic Network Sniffer (Scapy-based)"
    )
    parser.add_argument("-i", "--interface", default=None,
                         help="Network interface to sniff on (e.g. eth0). "
                              "Defaults to Scapy's auto-detected interface.")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Number of packets to capture (0 = infinite, stop with Ctrl+C)")
    parser.add_argument("-f", "--filter", default="",
                         help="BPF filter string (e.g. 'tcp port 80', 'udp', 'icmp')")
    parser.add_argument("-o", "--output", default="capture",
                         help="Base name for output files (default: 'capture')")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] This script requires root privileges for packet capture.")
        print("    Try: sudo python3 network_sniffer.py")
        sys.exit(1)

    timestamp_tag = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_path = f"{args.output}_{timestamp_tag}.pcap"
    csv_path = f"{args.output}_{timestamp_tag}.csv"

    print("=" * 70)
    print(" CodeAlpha Cybersecurity Internship - Task 1: Network Sniffer")
    print("=" * 70)
    print(f" Interface : {args.interface or 'auto-detect'}")
    print(f" Filter    : {args.filter or 'none (all traffic)'}")
    print(f" Count     : {'unlimited (Ctrl+C to stop)' if args.count == 0 else args.count}")
    print(f" Output    : {pcap_path}, {csv_path}")
    print("=" * 70)
    print(" Starting capture... press Ctrl+C to stop early.\n")

    try:
        sniff(
            iface=args.interface,
            filter=args.filter if args.filter else None,
            prn=process_packet,
            count=args.count if args.count > 0 else 0,
            store=False
        )
    except KeyboardInterrupt:
        print("\n[!] Capture stopped by user.")
    except PermissionError:
        print("[!] Permission denied. Run this script with sudo.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error during capture: {e}")
    finally:
        save_outputs(pcap_path, csv_path)
        print(f"\n[+] Total packets captured: {packet_count}")
        print("[+] Done. Open the .pcap file in Wireshark for deeper analysis.")


if __name__ == "__main__":
    main()
