# Day 06 — Network Traffic Analyzer

## What I Built

A live network traffic analyzer that captures packets from any network interface, breaks them down by protocol, identifies top communicators, extracts DNS queries, and saves captures to PCAP files. Built with Python and Scapy.

---

## How It Works

```
python analyser.py  (run as Administrator)
```

Pick a network interface, set a capture filter if you want, and watch your network traffic analyzed in real-time.

Example output:
```
Available interfaces:
  1. Ethernet
  2. Wi-Fi
  3. Loopback

Capturing 100 packets...
Captured 100 packets

--- Protocol Breakdown ---
  TCP:   60
  UDP:   31
  ICMP:  0
  Other: 9

--- Top Source IPs ---
  192.168.1.2: 41 packets
  162.159.130.234: 24 packets

--- Top Destination Ports ---
  Port 443 [HTTPS]: 39 packets
  Port 53 [DNS]: 5 packets

--- DNS Queries (domains being resolved) ---
  www.linkedin.com.
  optimizationguide-pa.googleapis.com.
```

---

## Features

### Live Packet Capture
Captures real-time traffic from your network using Scapy's `sniff()` function. Requires administrator privileges because reading raw packets needs kernel-level access.

### Interface Selection
Lists all network interfaces (WiFi, Ethernet, Loopback) and lets you choose which one to sniff on — or capture from all.

### BPF Filtering
Supports Berkeley Packet Filter syntax to capture only specific traffic at the kernel level:
- `tcp` — only TCP
- `udp port 53` — only DNS
- `host 192.168.1.1` — only traffic to/from this IP
- `tcp port 443` — only HTTPS

### Protocol Breakdown
Categorizes every captured packet into TCP, UDP, ICMP, or Other. Shows you the composition of your network traffic.

### Top Talkers
Identifies the most active source and destination IPs — who's sending and receiving the most data on your network.

### Top Ports with Service Names
Shows which ports see the most traffic, mapped to service names (443=HTTPS, 53=DNS, 22=SSH, etc.).

### Bandwidth Statistics
Calculates total bytes captured and average packet size.

### DNS Query Extraction
Pulls out every domain name being resolved. Even though web traffic is encrypted (HTTPS), DNS queries are usually plaintext — revealing what sites are being visited. This is how security teams detect malware phoning home.

### Save to PCAP
Exports captured packets to a `.pcap` file you can open in Wireshark or analyze later.

---

## What I Learned

- **Packet structure:** Network data is layered (Ethernet → IP → TCP/UDP → Application). Each layer has headers with different info.
- **OSI model:** Understanding how protocols nest inside each other.
- **Scapy:** Python's packet manipulation library — can capture, craft, and analyze packets.
- **BPF filters:** Kernel-level filtering for efficient packet capture.
- **DNS monitoring:** Even encrypted traffic leaks domain names through DNS queries.
- **Network interfaces:** Your computer has multiple network adapters, each captures different traffic.
- **PCAP format:** The standard format for storing captured network traffic.
- **Counter from collections:** Efficient way to count and rank occurrences.
- **Why admin is needed:** Raw packet capture normally requires kernel privileges because it bypasses normal network stack restrictions. On Windows, Npcap can optionally allow non-admin users to capture.

---

## Connections to Previous Days

- **Day 02 (Port Scanner):** Same `common_ports` mapping. Could auto-scan IPs found in traffic.
- **Day 03 (DNS Lookup):** DNS extraction here shows what the machine is resolving. Could do reverse lookups on captured IPs.
- **Day 05 (Metadata):** Saved PCAP files could be hashed for integrity verification.

---

## Requirements

```
pip install scapy
```

Windows also requires [Npcap](https://npcap.com/#download) installed with "WinPcap API-compatible mode" checked.

Must run as **Administrator** for live packet capture (unless Npcap was installed with "Allow non-administrators to capture packets" enabled).

---

## BPF Filter Examples

| Filter | Captures |
|--------|----------|
| `tcp` | All TCP traffic |
| `udp` | All UDP traffic |
| `port 80` | HTTP traffic |
| `port 443` | HTTPS traffic |
| `udp port 53` | DNS queries only |
| `host 8.8.8.8` | Traffic to/from Google DNS |
| `src 192.168.1.2` | Traffic from your machine |

---

## Project Structure

```
network_traffic_annalyser/
├── analyser.py    # The traffic analyzer
└── README.md      # This file
```

---

**#30DaysOfCyber**
