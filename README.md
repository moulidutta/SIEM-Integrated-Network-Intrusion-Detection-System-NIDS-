<div align="center">

# 🛡️ SIEM-Integrated Network Intrusion Detection System
### SOC Platform — Real-Time Threat Detection + Splunk SIEM

![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=flat-square&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-Packet%20Analysis-009688?style=flat-square)
![Splunk](https://img.shields.io/badge/Splunk-SIEM-FF5733?style=flat-square&logo=splunk&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=flat-square&logo=kalilinux&logoColor=white)
![Rules](https://img.shields.io/badge/Detection%20Rules-6-brightgreen?style=flat-square)
![Status](https://img.shields.io/badge/Status-Complete-success?style=flat-square)

> A production-representative SOC platform built from scratch — combining a custom Python/Scapy Network IDS with Splunk Enterprise SIEM to simulate real-world Security Operations Centre workflows. Six detection rules cover network reconnaissance, credential attacks, volumetric DoS, covert exfiltration, and MITM — all visualised on a live SOC dashboard.

[Overview](#-overview) • [Architecture](#-architecture) • [Detection Rules](#-detection-rules) • [Installation](#-installation) • [Usage](#-usage) • [SIEM Integration](#-siem-integration) • [Results](#-results) • [Engineering Decisions](#-engineering-decisions)

</div>

---

## 🎯 Overview

Most IDS projects stop at detection. This one goes further — every alert is automatically forwarded to **Splunk Enterprise** for real-time log ingestion, correlation, and SOC dashboard visualisation. The result is a complete attack-to-dashboard pipeline that mirrors enterprise security operations.

### What makes this different

| Feature | Basic IDS | This Project |
|---|---|---|
| Detection rules | 1–3 | **6 across 4 protocols** |
| Alert output | Print to terminal | **CSV + JSON + Splunk SIEM** |
| Visualisation | None | **Live SOC dashboard** |
| False positive handling | None | **Protocol-aware filtering** |
| Architecture | Single script | **NIDS + SIEM integrated** |
| Evidence | None | **Wireshark pcap + Splunk logs** |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  VirtualBox Host-Only Network                   │
│                       192.168.56.0/24                           │
│                                                                 │
│   ┌──────────────────┐          ┌──────────────────┐           │
│   │   Kali Linux     │  attack  │  Metasploitable3 │           │
│   │   (Attacker)     │─────────▶│    (Victim)      │           │
│   │  192.168.56.101  │          │  192.168.56.102  │           │
│   └──────────────────┘          └──────────────────┘           │
│            │                            │                       │
│            └────────────┬───────────────┘                       │
│                         │ all traffic                           │
│                         ▼                                       │
│            ┌────────────────────────┐                           │
│            │    Kali Linux          │                           │
│            │    IDS Monitor         │◀── promiscuous mode       │
│            │    192.168.56.103      │    eth0 + eth1            │
│            │                        │                           │
│            │  ┌──────────────────┐  │                           │
│            │  │  Python/Scapy    │  │                           │
│            │  │  IDS Engine      │──┼──▶ ids_alerts.csv         │
│            │  │  6 detection     │  │                           │
│            │  │  rules           │  │                           │
│            │  └──────────────────┘  │                           │
│            │           │            │                           │
│            │           ▼            │                           │
│            │  ┌──────────────────┐  │                           │
│            │  │  Splunk          │  │                           │
│            │  │  Enterprise SIEM │  │                           │
│            │  │  SOC Dashboard   │  │                           │
│            │  └──────────────────┘  │                           │
│            └────────────────────────┘                           │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔍 Detection Rules

Six rules covering four network protocols — each with CVSS v3.1 scoring and CWE reference:

| # | Rule | Protocol | CVSS | Severity | Detection Logic |
|---|---|---|---|---|---|
| 1 | Port Scan | TCP | 7.5 | HIGH | 50+ SYN packets to multiple ports within 5s |
| 2 | ARP Spoofing / MITM | ARP | 8.1 | HIGH | MAC address change for known IP |
| 3 | SSH Brute Force | TCP | 9.8 | CRITICAL | 10+ SYN packets to service ports within 60s |
| 4 | DNS Tunneling | UDP/DNS | 7.5 | HIGH | 10+ DNS queries from same IP within 30s |
| 5 | ICMP Flood | ICMP | 7.5 | HIGH | 100+ echo requests from same IP within 5s |
| 6 | SYN Flood / DoS | TCP | 8.6 | HIGH | 500+ SYN packets to single port within 3s |

### Protocol coverage

```
TCP  ──▶  Port Scan, Brute Force, SYN Flood
ARP  ──▶  ARP Spoofing / MITM
ICMP ──▶  ICMP Flood / Ping of Death
DNS  ──▶  DNS Tunneling / Data Exfiltration
```

---

## 🛠️ Tech Stack

| Layer | Tool | Purpose |
|---|---|---|
| Detection engine | Python 3 + Scapy | Packet capture and rule execution |
| SIEM | Splunk Enterprise 8.2.6 | Log ingestion, correlation, dashboard |
| Attack simulation | Nmap, Hydra, hping3, arpspoof | Controlled attack generation |
| Forensics | Wireshark / tshark | Packet capture and evidence |
| Virtualisation | VirtualBox | Isolated lab environment |
| OS | Kali Linux x2, Metasploitable3 | Attacker, monitor, victim VMs |

---

## ⚙️ Installation

### Prerequisites
- VirtualBox with 3 VMs (Kali Attacker, Kali Monitor, Metasploitable3)
- All VMs on host-only network (192.168.56.0/24)
- Splunk Enterprise 8.2.6 installed on Monitor VM

### Clone the repository
```bash
git clone https://github.com/yourusername/siem-nids-soc-platform.git
cd siem-nids-soc-platform
```

### Install dependencies on Monitor VM
```bash
pip install scapy --break-system-packages
sudo apt install tshark wireshark -y
```

### Enable promiscuous mode
```bash
sudo ip link set eth0 promisc on
sudo ip link set eth1 promisc on
```

### Verify Scapy
```bash
python3 -c "from scapy.all import *; print('Scapy ready ✓')"
```

---

## 🚀 Usage

### Start the IDS
```bash
sudo python3 ids_advanced.py
```

### Capture packets simultaneously
```bash
sudo tshark -i eth0 -i eth1 -w /tmp/ids_capture.pcap
```

### Simulate all 6 attacks from attacker VM
```bash
# 1. Port scan
nmap -sS -T4 192.168.56.102

# 2. SSH brute force
hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 ssh://192.168.56.102

# 3. ARP spoofing
sudo arpspoof -i eth1 -t 192.168.56.102 192.168.56.101

# 4. ICMP flood
sudo hping3 -1 --flood 192.168.56.102

# 5. SYN flood
sudo hping3 -S --flood -p 80 192.168.56.102

# 6. DNS tunneling
for i in {1..15}; do dig @192.168.56.103 test.local; done
```

### Open Splunk dashboard
```
Firefox → http://localhost:8000
→ Search & Reporting → Dashboards
→ SOC Network IDS Dashboard
```

---

## 📊 SIEM Integration

### How it works
```
IDS script detects attack
       │
       ▼
Alert written to ids_alerts.csv (real time)
       │
       ▼
Splunk file input monitors ids_alerts.csv
       │
       ▼
Alert ingested into ids_alerts index
       │
       ▼
SOC dashboard updates automatically
```

### SOC Dashboard Panels

| Panel | SPL Query | Visualisation |
|---|---|---|
| Total Alerts | `index=ids_alerts \| stats count` | Radial gauge |
| Critical Alerts | `index=ids_alerts severity=CRITICAL \| stats count` | Single value |
| High Alerts | `index=ids_alerts severity=HIGH \| stats count` | Single value |
| Alert Timeline | `index=ids_alerts \| timechart count by threat_type` | Line chart |
| Alert Severity | `index=ids_alerts \| stats count by severity` | Pie chart |
| Alert Log | `index=ids_alerts \| table timestamp src_ip dst_ip threat_type severity` | Table |
| Threats Detected | `index=ids_alerts \| stats count by threat_type` | Bar chart |

---

## 📈 Results

Assessment results from controlled lab simulation:

```
Total alerts generated : 21
Critical alerts        : 2   (SSH Brute Force)
High alerts            : 19  (all other threats)
Detection rate         : 6/6 threat types detected
SIEM ingestion         : 100% of alerts ingested
Highest volume attack  : SYN Flood / DoS
```

| Threat | CVSS | Alerts | Splunk |
|---|---|---|---|
| SSH Brute Force | 9.8 CRITICAL | ✅ | ✅ |
| SYN Flood / DoS | 8.6 HIGH | ✅ | ✅ |
| ARP Spoofing | 8.1 HIGH | ✅ | ✅ |
| Port Scan | 7.5 HIGH | ✅ | ✅ |
| DNS Tunneling | 7.5 HIGH | ✅ | ✅ |
| ICMP Flood | 7.5 HIGH | ✅ | ✅ |

---

## 🧠 Engineering Decisions

Several design iterations were made during development — each solving a real technical challenge:

**Multi-interface sniffing** — VirtualBox's virtual adapter assignment caused traffic to flow across both eth0 and eth1. Single-interface capture missed packets. Resolved by configuring Scapy to sniff on both interfaces simultaneously.

**Port scan vs SYN flood separation** — Both attacks use SYN packets, causing duplicate alerts. Separated by unique destination port count — port scan targets many ports, SYN flood targets one port at high volume.

**ICMP false positive elimination** — Promiscuous mode captured both attacker echo requests and victim echo replies, generating duplicate alerts. Resolved by filtering on ICMP type 8 (echo request) only — protocol-aware, no IP hardcoding.

**DNS alert deduplication** — Changed threshold comparison from `==` to `>=` to handle high packet rates where the counter could skip the exact threshold value. Added per-source IP cooldown set to prevent repeated alerts from same attacker.

**Capture strategy** — Live Wireshark GUI caused OOM kills on 3GB VM when running alongside IDS and Splunk. Adapted to tshark CLI for live capture, Wireshark for post-capture forensic analysis — mirroring real SOC sensor/analyst separation.

---

## 📁 Project Structure

```
siem-nids-soc-platform/
├── ids_advanced.py              # Main IDS script — 6 detection rules
├── ids_monitor_ml.py            # ML edition — Isolation Forest anomaly detection
├── ids_alerts.csv               # Auto-generated alert log
├── ids_alerts.json              # Auto-generated alert log (JSON)
├── ids_capture.pcap             # Wireshark packet capture evidence
├── SIEM_NIDS_Report.docx        # Formal vulnerability assessment report
└── README.md                    # This file
```

---

## 📄 Log Output Format

```
[2026-05-24 02:42:22] [HIGH] PORT SCAN DETECTED
       SRC: 192.168.56.101  →  DST: 192.168.56.102
       50 SYN packets in 5s — 36 unique destination ports targeted.

[2026-05-24 02:43:19] [CRITICAL] BRUTE FORCE DETECTED — SSH
       SRC: 192.168.56.101  →  DST: 192.168.56.102
       10 connection attempts to SSH (port 22) in 60s.

[2026-05-24 02:45:34] [HIGH] ARP SPOOFING DETECTED
       SRC: 08:00:27:c5:06:86  →  DST: 192.168.56.103
       IP 192.168.56.103 previously mapped to MAC 08:00:27:44:dd:84,
       now claiming MAC 08:00:27:c5:06:86. Possible MITM attack.
```

---

## ⚠️ Disclaimer

> This project was built strictly for educational purposes in an isolated virtual lab environment. All attacks were simulated against intentionally vulnerable machines (Metasploitable3) that I own and control. **Never use these techniques against systems you do not own or have explicit written permission to test.** Unauthorised network scanning and attacks are illegal under the Computer Misuse Act and equivalent legislation worldwide.

---

## 🙌 References

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Splunk Enterprise Documentation](https://docs.splunk.com/)
- [NIST CVSS v3.1 Calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)
- [VulnHub — Metasploitable3](https://www.vulnhub.com/)
- [Wireshark Display Filters](https://wiki.wireshark.org/DisplayFilters)

---

<div align="center">

⭐ If this project helped you — give it a star!

</div>
