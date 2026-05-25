#!/usr/bin/env python3
"""
=============================================================
  Network Intrusion Detection System (IDS)
  Author  : [MOULI DUTTA]
  Tools   : Python 3, Scapy
  Purpose : Detect port scans, ARP spoofing, brute-force,DNS tunneling, ICMP flood, SYN flood/DoS
  Usage   : sudo python3 ids_monitor2.py 
=============================================================
"""

import argparse
import csv
import json
import os
from collections import defaultdict
from datetime import datetime

from scapy.all import ARP, IP, TCP,ICMP,UDP,DNS,DNSQR, sniff
# ─────────────────────────────────────────────
#  CONFIGURATION  (tune thresholds here)
# ─────────────────────────────────────────────

IFACE              =  ["eth0", "eth1"]          # Network interface to sniff on
LOG_FILE_CSV       = "ids_alerts.csv"
LOG_FILE_JSON      = "ids_alerts.json"

# Port-scan detection
PORT_SCAN_THRESHOLD   = 50           # SYN packets from same IP within window
PORT_SCAN_WINDOW_SEC  = 5            # Time window in seconds

# Brute-force detection
BRUTE_FORCE_THRESHOLD = 10           # Failed connection attempts
BRUTE_FORCE_WINDOW_SEC= 60           # Time window in seconds
BRUTE_FORCE_PORTS     = {22, 21, 23, 3389, 5900}  # SSH, FTP, Telnet, RDP, VNC

# ARP spoof detection
ARP_TABLE             = {}           # Stores known IP → MAC mappings

# Rule 4 — DNS Tunneling
DNS_QUERY_THRESHOLD     = 10       # DNS queries from same IP in window
DNS_WINDOW_SEC          = 30       # Time window in seconds
DNS_LENGTH_THRESHOLD    = 50       # Suspicious query name length (chars)
 
# Rule 5 — ICMP Flood
ICMP_THRESHOLD          = 100      # ICMP packets from same IP in window
ICMP_WINDOW_SEC         = 5        # Time window in seconds
ICMP_SIZE_THRESHOLD     = 1024     # Suspicious ICMP packet size (bytes)
 
# Rule 6 — SYN Flood / DoS
SYN_FLOOD_THRESHOLD     = 500      # SYN packets to SAME port in window
SYN_FLOOD_WINDOW_SEC    = 3        # Time window in seconds


# ─────────────────────────────────────────────
#  INTERNAL STATE
# ─────────────────────────────────────────────

# { src_ip: [(timestamp, dst_port), ...] }
syn_tracker      = defaultdict(list)

# { src_ip: [(timestamp, dst_port), ...] }
brute_tracker    = defaultdict(list)

# DNS tracking: { src_ip: [(timestamp, query_name), ...] }
dns_tracker         = defaultdict(list)
dns_alerted = set()
 
#ICMP tracking: { src_ip: [timestamp, ...] }
icmp_tracker        = defaultdict(list)
 
#SYN flood tracking: { (src_ip, dst_port): [timestamp, ...] }
syn_flood_tracker   = defaultdict(list)

# Running list of all alerts (written to JSON at end)
all_alerts       = []


# ─────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────

def init_csv():
    """Create CSV log file with headers if it doesn't exist."""
    if not os.path.exists(LOG_FILE_CSV):
        with open(LOG_FILE_CSV, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "src_ip", "dst_ip",
                "threat_type", "severity", "detail"
            ])

def log_alert(src_ip, dst_ip, threat_type, severity, detail):
    """Print alert to console and append to CSV + in-memory list."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Console output
    colour = {"CRITICAL": "\033[91m","HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[96m"}
    reset  = "\033[0m"
    c = colour.get(severity, "")
    print(f"{c}[{ts}] [{severity}] {threat_type}{reset}")
    print(f"       SRC: {src_ip}  →  DST: {dst_ip}")
    print(f"       {detail}\n")

    # CSV
    with open(LOG_FILE_CSV, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([ts, src_ip, dst_ip, threat_type, severity, detail])

    # In-memory (saved to JSON on exit)
    all_alerts.append({
        "timestamp":   ts,
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "threat_type": threat_type,
        "severity":    severity,
        "detail":      detail
    })

def save_json():
    """Dump all alerts to a JSON file."""
    with open(LOG_FILE_JSON, "w") as f:
        json.dump(all_alerts, f, indent=2)
    print(f"\n[*] Alerts saved → {LOG_FILE_CSV}  and  {LOG_FILE_JSON}")


# ─────────────────────────────────────────────
#  DETECTION RULE 1 — Port Scan (SYN Flood)
# ─────────────────────────────────────────────
#
#  How it works:
#    A port scanner (e.g. nmap -sS) sends many TCP SYN packets
#    to different destination ports from the same source IP.
#    We track SYN counts per source IP inside a sliding time window.
#    If count exceeds threshold → ALERT.
#
#  CVSS v3.1 Base Score: 7.5 (High)
#  CVE reference: technique used in recon phase of many attacks.

def detect_port_scan(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    if pkt[TCP].flags != 0x02:          # SYN flag only (not SYN-ACK)
        return

    src_ip  = pkt[IP].src
    dst_ip  = pkt[IP].dst
    dst_port= pkt[TCP].dport
    now     = datetime.now().timestamp()

    # Add this SYN to tracker
    syn_tracker[src_ip].append((now, dst_port))

    # Remove entries outside the time window
    syn_tracker[src_ip] = [
        (t, p) for (t, p) in syn_tracker[src_ip]
        if now - t <= PORT_SCAN_WINDOW_SEC
    ]

    count = len(syn_tracker[src_ip])
    unique_ports = len(set(p for _, p in syn_tracker[src_ip]))


    if count == PORT_SCAN_THRESHOLD and unique_ports > 1:    # Fire alert exactly at threshold

        log_alert(
            src_ip     = src_ip,
            dst_ip     = dst_ip,
            threat_type= "PORT SCAN DETECTED",
            severity   = "HIGH",
            detail     = (
                f"{count} SYN packets in {PORT_SCAN_WINDOW_SEC}s — "
                f"{unique_ports} unique destination ports targeted."
            )
        )


# ─────────────────────────────────────────────
#  DETECTION RULE 2 — ARP Spoofing / MITM
# ─────────────────────────────────────────────
#
#  How it works:
#    An attacker sends fake ARP replies to poison the ARP cache
#    of victims, mapping their IP to the attacker's MAC address.
#    We build a trusted IP→MAC table from the first ARP reply
#    we see per IP. Any subsequent reply with a DIFFERENT MAC
#    for the same IP is flagged as spoofing.
#
#  CVSS v3.1 Base Score: 8.1 (High) — enables MITM
#  CVE reference: ARP spoofing is the basis for many MITM attacks.

def detect_arp_spoof(pkt):
    if not pkt.haslayer(ARP):
        return
    if pkt[ARP].op != 2:                # ARP reply (op=2) only
        return

    src_ip  = pkt[ARP].psrc             # Claimed IP
    src_mac = pkt[ARP].hwsrc            # Sender's MAC

    if src_ip not in ARP_TABLE:
        # First time we see this IP — trust it
        ARP_TABLE[src_ip] = src_mac
        return

    if ARP_TABLE[src_ip] != src_mac:
        log_alert(
            src_ip     = src_mac,       # Use MAC as "source" for ARP
            dst_ip     = src_ip,
            threat_type= "ARP SPOOFING DETECTED",
            severity   = "HIGH",
            detail     = (
                f"IP {src_ip} previously mapped to MAC {ARP_TABLE[src_ip]}, "
                f"now claiming MAC {src_mac}. Possible MITM attack."
            )
        )
        # Update table to new MAC (attacker may now own traffic)
        ARP_TABLE[src_ip] = src_mac


# ─────────────────────────────────────────────
#  DETECTION RULE 3 — Brute Force Login
# ─────────────────────────────────────────────
#
#  How it works:
#    Brute-force tools (e.g. Hydra) attempt many logins rapidly,
#    each generating a new TCP SYN to the target service port.
#    We watch for high SYN counts from one IP to a SINGLE
#    well-known service port (SSH/FTP/RDP etc.) within a window.
#
#  CVSS v3.1 Base Score: 9.8 (Critical) — if credentials found
#  CVE reference: CWE-307 — Improper Restriction of Excessive Auth Attempts

def detect_brute_force(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    if pkt[TCP].flags != 0x02:          # SYN only
        return

    src_ip  = pkt[IP].src
    dst_ip  = pkt[IP].dst
    dst_port= pkt[TCP].dport

    if dst_port not in BRUTE_FORCE_PORTS:
        return

    now = datetime.now().timestamp()
    brute_tracker[src_ip].append((now, dst_port))

    # Sliding window cleanup
    brute_tracker[src_ip] = [
        (t, p) for (t, p) in brute_tracker[src_ip]
        if now - t <= BRUTE_FORCE_WINDOW_SEC
    ]

    # Count attempts to this specific port only
    port_attempts = [p for _, p in brute_tracker[src_ip] if p == dst_port]

    if len(port_attempts) == BRUTE_FORCE_THRESHOLD:
        service_map = {
            22: "SSH", 21: "FTP", 23: "Telnet",
            3389: "RDP", 5900: "VNC"
        }
        service = service_map.get(dst_port, f"port {dst_port}")
        log_alert(
            src_ip     = src_ip,
            dst_ip     = dst_ip,
            threat_type= f"BRUTE FORCE DETECTED — {service}",
            severity   = "CRITICAL",
            detail     = (
                f"{len(port_attempts)} connection attempts to {service} "
                f"(port {dst_port}) in {BRUTE_FORCE_WINDOW_SEC}s."
            )
        )
# ─────────────────────────────────────────────
# RULE 4 — DNS Tunneling Detection
#
#  How it works:
#    Normal DNS queries are short (google.com = 10 chars)
#    DNS tunneling encodes data IN the query name:
#    e.g. "aGVsbG8gd29ybGQ.evil.com" (base64 encoded data)
#    We flag:
#      1. Queries longer than DNS_LENGTH_THRESHOLD chars
#      2. Too many DNS queries from same IP in short time
#
#  CVSS: 7.5 HIGH
#  CWE-284: Improper Access Control
# ─────────────────────────────────────────────
 
def detect_dns_tunneling(pkt):
   # if pkt.haslayer(DNS):
   #    print(f"[DNS] packet seen")
    if not (pkt.haslayer(IP) and pkt.haslayer(DNS)):
        return
    if not pkt.haslayer(DNSQR):
#        print(f" DNS but no DNSQR")
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    if pkt[DNS].qr != 0:    # ignore DNS responses
        return
    if src_ip == dst_ip:
        return
    now    = datetime.now().timestamp()

    try:
        query_name = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
    #    print(f"Query: {query_name} from {src_ip}")  # ← add this
    except Exception as e:
 #       print(f"Exception: {e}")  # ← and this
        return
 
    # Check 1 — Unusually long DNS query name
    if len(query_name) > DNS_LENGTH_THRESHOLD:
        log_alert(
            src_ip     = src_ip,
            dst_ip     = dst_ip,
            threat_type= "DNS TUNNELING DETECTED — LONG QUERY",
            severity   = "HIGH",
            detail     = (
                f"Suspicious DNS query length: {len(query_name)} chars "
                f"(threshold: {DNS_LENGTH_THRESHOLD}). "
                f"Query: {query_name[:80]}..."
            )
        )
        return
 
    # Check 2 — High volume of DNS queries from same IP
    dns_tracker[src_ip].append((now, query_name))
    dns_tracker[src_ip] = [
        (t, q) for (t, q) in dns_tracker[src_ip]
        if now - t <= DNS_WINDOW_SEC
    ]
 
    count = len(dns_tracker[src_ip])
   # print(f"{src_ip} — {count} DNS queries so far")
    if count >= DNS_QUERY_THRESHOLD and src_ip not in dns_alerted: #change is made from '==' to '>=' due to the count is going up but alert not firing.
        dns_alerted.add(src_ip)
        unique_domains = len(set(q for _, q in dns_tracker[src_ip]))
        log_alert(
            src_ip     = src_ip,
            dst_ip     = dst_ip,
            threat_type= "DNS TUNNELING DETECTED — HIGH QUERY VOLUME",
            severity   = "HIGH",
            detail     = (
                f"{count} DNS queries in {DNS_WINDOW_SEC}s from same IP. "
                f"{unique_domains} unique domains queried."
                f"Possible data exfiltration via DNS."
            )
        )
 
# ─────────────────────────────────────────────
# RULE 5 — ICMP Flood / Ping of Death
#
#  How it works:
#    Normal ping sends 1-2 ICMP packets occasionally.
#    An ICMP flood sends thousands per second to DoS victim.
#    Ping of Death sends oversized packets to crash systems.
#    We detect:
#      1. High volume ICMP from same IP (flood)
#      2. Oversized ICMP packets (ping of death)
#
#  CVSS: 7.5 HIGH
#  CWE-400: Uncontrolled Resource Consumption
# ─────────────────────────────────────────────
 
def detect_icmp_flood(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(ICMP)):
        return
    if pkt[ICMP].type != 8:  #  only echo REQUESTS
        return
 
    src_ip  = pkt[IP].src
    dst_ip  = pkt[IP].dst
    pkt_size= len(pkt)
    now     = datetime.now().timestamp()
 
    # Check 1 — Oversized ICMP packet (Ping of Death)
    if pkt_size > ICMP_SIZE_THRESHOLD:
        log_alert(
            src_ip     = src_ip,
            dst_ip     = dst_ip,
            threat_type= "PING OF DEATH DETECTED",
            severity   = "HIGH",
            detail     = (
                f"Oversized ICMP packet detected: {pkt_size} bytes "
                f"(threshold: {ICMP_SIZE_THRESHOLD} bytes). "
                f"Possible Ping of Death attack."
            )
        )
        return
 
    # Check 2 — ICMP flood (high volume)
    icmp_tracker[src_ip].append(now)
    icmp_tracker[src_ip] = [
        t for t in icmp_tracker[src_ip]
        if now - t <= ICMP_WINDOW_SEC
    ]
 
    count = len(icmp_tracker[src_ip])
    if count == ICMP_THRESHOLD:
        log_alert(
            src_ip     = src_ip,
            dst_ip     = dst_ip,
            threat_type= "ICMP FLOOD DETECTED",
            severity   = "HIGH",
            detail     = (
                f"{count} ICMP packets in {ICMP_WINDOW_SEC}s from same IP. "
                f"Possible DoS/DDoS attack via ICMP flood."
            )
        )
 
 
# ─────────────────────────────────────────────
#  NEW RULE 6 — SYN Flood / DoS Detection
#
#  How it works:
#    Different from port scan — attacker hammers ONE port
#    with massive SYN packets, never completing handshake.
#    Server runs out of half-open connections and crashes.
#    We detect: >200 SYNs to SAME port in 5 seconds.
#
#  CVSS: 8.6 HIGH
#  CWE-400: Uncontrolled Resource Consumption
# ─────────────────────────────────────────────
 
def detect_syn_flood(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    if pkt[TCP].flags != 0x02:    # SYN only
        return
 
    src_ip   = pkt[IP].src
    dst_ip   = pkt[IP].dst
    dst_port = pkt[TCP].dport
    now      = datetime.now().timestamp()
 
    # Track SYNs per (src_ip, dst_port) combination
    key = (src_ip, dst_port)
    syn_flood_tracker[key].append(now)
    syn_flood_tracker[key] = [
        t for t in syn_flood_tracker[key]
        if now - t <= SYN_FLOOD_WINDOW_SEC
    ]
 
    count = len(syn_flood_tracker[key])
 
    if count == SYN_FLOOD_THRESHOLD:
        log_alert(
            src_ip     = src_ip,
            dst_ip     = dst_ip,
            threat_type= "SYN FLOOD / DoS DETECTED",
            severity   = "HIGH",
            detail     = (
                f"{count} SYN packets to port {dst_port} in "
                f"{SYN_FLOOD_WINDOW_SEC}s from same source IP. "
                f"Possible SYN flood DoS attack."
            )
        )


# ─────────────────────────────────────────────
#  PACKET DISPATCHER
# ─────────────────────────────────────────────

def process_packet(pkt):
    """Route each captured packet through all detection rules."""
    detect_port_scan(pkt)
    detect_arp_spoof(pkt)
    detect_brute_force(pkt)
 # advanced rules
    detect_dns_tunneling(pkt)
    detect_icmp_flood(pkt)
    detect_syn_flood(pkt)


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Python/Scapy Network IDS — detects port scans, ARP spoofing, brute force"
    )
    parser.add_argument(
        "-i", "--interface",
        default=IFACE,
        help=f"Network interface to monitor (default: {IFACE})"
    )
    args = parser.parse_args()

    init_csv()

    print("=" * 60)
    print("  Network IDS — Python/Scapy")
    print("=" * 60)
    print(f"  Interface : {args.interface}")
    print(f"  Log (CSV) : {LOG_FILE_CSV}")
    print(f"  Log (JSON): {LOG_FILE_JSON}")
    print(f"  Thresholds:")
    print(f"    Port scan   → {PORT_SCAN_THRESHOLD} SYNs in {PORT_SCAN_WINDOW_SEC}s")
    print(f"    Brute force → {BRUTE_FORCE_THRESHOLD} SYNs to service port in {BRUTE_FORCE_WINDOW_SEC}s")
    print(f"    ARP spoof   → any MAC change for known IP")
    print(f"    DNS Tunneling Detection     (CVSS 7.5 HIGH)  ")
    print(f"  	ICMP Flood / Ping of Death  (CVSS 7.5 HIGH)  ")
    print(f"  	SYN Flood / DoS Detection   (CVSS 8.6 HIGH)  ")
    print("=" * 60)
    print("  [*] Sniffing... Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface  = args.interface,
            prn    = process_packet,
            store  = False           # Don't keep packets in memory
        )
    except KeyboardInterrupt:
        print("\n[*] Stopping IDS...")
    finally:
        save_json()
        print(f"[*] Total alerts generated: {len(all_alerts)}")
        print("[*] Done.")


if __name__ == "__main__":
    main()
