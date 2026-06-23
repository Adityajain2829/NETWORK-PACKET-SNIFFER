# Task 2 — Network Packet Sniffer

**Intern:** Aditya Jain
**Intern ID:** CITS2742
**Company:** CodTech IT Solutions
**Domain:** Cyber Security & Ethical Hacking

## Overview

This project is a live network packet sniffer built with `scapy`. It captures
packets on the local machine's network interface(s), identifies the protocol
(TCP, UDP, ICMP, DNS, HTTP), extracts key fields (source/destination IP,
ports, TCP flags, DNS queries, HTTP requests), and prints a structured
breakdown of each packet in real time. It also keeps running protocol
statistics and can save the full capture to a log file.

## How It Works

1. **ProtocolDecoder** — inspects each captured packet layer by layer
   (IP -> TCP/UDP/ICMP -> DNS/HTTP) and extracts a clean dict of relevant
   fields for that packet.
2. **CaptureSession** — receives decoded packet info, prints a formatted
   block to the console, and tracks running protocol counts.
3. **Privilege check** — on Windows, checks if the script is running with
   Administrator rights (required for raw socket access) and warns if not.
4. **Summary & log file** — after capture stops (by count or Ctrl+C), prints
   a protocol breakdown and optionally saves the full log to a `.txt` file.

## Requirements

- Python 3.8+
- [scapy](https://scapy.net/): `pip install scapy`
- **Windows only:** [Npcap](https://npcap.com/#download) must be installed
  (tick "Install Npcap in WinPcap API-compatible Mode" during setup)
- **Administrator privileges** — raw packet capture requires running your
  terminal / VS Code as Administrator on Windows

## Usage

```bash
python packet_sniffer.py
```

You'll be asked how many packets to capture (or `0` for continuous capture
until you press `Ctrl+C`). Each captured packet is printed with its protocol,
addresses, ports, and any relevant detail (e.g. DNS query name, HTTP request
path, TCP flags).

### Sample Output

```
--- Packet #1 | 18:42:11 ---
  IP        192.168.1.10     -> 142.250.182.106
  Protocol  TCP
  Ports     54213 -> 443  | Flags: S
  Detail

--- Packet #2 | 18:42:11 ---
  IP        192.168.1.10     -> 8.8.8.8
  Protocol  DNS
  Ports     54871 -> 53
  Detail    query for example.com.
```

At the end of a session:

```
============================================================
        PACKET CAPTURE SUMMARY
============================================================
Total packets captured : 20
  TCP     : 12
  UDP     : 5
  ICMP    : 1
  DNS     : 4
  HTTP    : 2
  OTHER   : 2
============================================================
```

## Disclaimer

This tool captures **real live traffic** from the network interface it runs
on. Only use it on networks and devices you own or have explicit permission
to monitor. It is built strictly for educational purposes as part of a cyber
security internship task — unauthorized packet capture may be illegal in
your jurisdiction.

## Troubleshooting

- **"Permission denied" / no packets captured** — re-run your terminal as
  Administrator.
- **Import error for scapy** — run `pip install scapy`.
- **Still nothing captured on Windows** — confirm Npcap is installed and was
  set up in WinPcap-compatible mode.
