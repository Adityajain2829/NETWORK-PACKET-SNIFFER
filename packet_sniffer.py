"""
========================================================
    CODTECH IT SOLUTIONS - INTERNSHIP PROJECT
========================================================
Name      : Aditya Jain
Intern ID : CITS2742
Company   : CodTech IT Solutions
Domain    : Cyber Security & Ethical Hacking
Task      : Task 2 - Network Packet Sniffer
========================================================

DISCLAIMER:
    This tool captures live network traffic on the machine it
    is run on, for EDUCATIONAL purposes as part of a cyber
    security internship task. Only run it on networks and
    devices you own or have explicit permission to monitor.
    Capturing traffic on networks without authorization may
    be illegal in your jurisdiction.

REQUIREMENTS (Windows):
    - Npcap installed (https://npcap.com/#download)
      -> during install, tick "Install Npcap in WinPcap API-
         compatible Mode"
    - scapy installed:  pip install scapy
    - Run your terminal / VS Code as Administrator, otherwise
      Windows will not allow raw packet capture.
========================================================
"""

import sys
import os
import ctypes
import datetime
from collections import Counter

try:
    from scapy.all import sniff
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ============================================================
#  PRIVILEGE CHECK (Windows-specific)
# ============================================================
def has_admin_rights() -> bool:
    if os.name != "nt":
        return True  # not Windows, skip this check
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ============================================================
#  PROTOCOL DECODER — turns a raw scapy packet into a
#  structured dict describing what was seen
# ============================================================
class ProtocolDecoder:
    ICMP_TYPES = {
        0: "Echo Reply", 3: "Destination Unreachable",
        8: "Echo Request", 11: "Time Exceeded"
    }

    def decode(self, packet) -> dict:
        info = {
            "protocol": "OTHER",
            "src": None,
            "dst": None,
            "detail": "",
        }

        if not packet.haslayer(IP):
            info["detail"] = "Non-IP packet (e.g. ARP) — skipped detail decoding"
            return info

        ip_layer = packet[IP]
        info["src"] = ip_layer.src
        info["dst"] = ip_layer.dst

        if packet.haslayer(TCP):
            info["protocol"] = "TCP"
            tcp = packet[TCP]
            info["sport"], info["dport"] = tcp.sport, tcp.dport
            info["flags"] = self._tcp_flags(tcp)

            if packet.haslayer(HTTPRequest):
                info["protocol"] = "HTTP"
                http = packet[HTTPRequest]
                method = http.Method.decode(errors="replace") if http.Method else "?"
                host = http.Host.decode(errors="replace") if http.Host else "?"
                path = http.Path.decode(errors="replace") if http.Path else "/"
                info["detail"] = f"{method} http://{host}{path}"
            elif packet.haslayer(HTTPResponse):
                info["protocol"] = "HTTP"
                info["detail"] = "HTTP response"

        elif packet.haslayer(UDP):
            info["protocol"] = "UDP"
            udp = packet[UDP]
            info["sport"], info["dport"] = udp.sport, udp.dport

            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                info["protocol"] = "DNS"
                qname = packet[DNSQR].qname
                info["detail"] = f"query for {qname.decode(errors='replace') if qname else '?'}"

        elif packet.haslayer(ICMP):
            info["protocol"] = "ICMP"
            icmp_type = packet[ICMP].type
            info["detail"] = self.ICMP_TYPES.get(icmp_type, f"type {icmp_type}")

        else:
            info["protocol"] = "OTHER"
            info["detail"] = f"IP protocol number {ip_layer.proto}"

        return info

    @staticmethod
    def _tcp_flags(tcp) -> str:
        mapping = [("S", tcp.flags.S), ("A", tcp.flags.A), ("F", tcp.flags.F),
                   ("R", tcp.flags.R), ("P", tcp.flags.P)]
        active = [name for name, present in mapping if present]
        return "+".join(active) if active else "-"


# ============================================================
#  CAPTURE SESSION — owns state for one sniffing run
# ============================================================
class CaptureSession:
    def __init__(self):
        self.decoder = ProtocolDecoder()
        self.protocol_counts = Counter()
        self.captured_lines = []
        self.packet_no = 0

    def on_packet(self, packet):
        self.packet_no += 1
        info = self.decoder.decode(packet)
        self.protocol_counts[info["protocol"]] += 1

        ts = datetime.datetime.now().strftime("%H:%M:%S")
        line = self._format_line(ts, info)
        print(line)
        self.captured_lines.append(line)

    def _format_line(self, ts, info: dict) -> str:
        rows = [f"\n--- Packet #{self.packet_no} | {ts} ---"]
        if info["src"]:
            rows.append(f"  IP        {info['src']:<16} -> {info['dst']}")
        proto = info["protocol"]
        rows.append(f"  Protocol  {proto}")

        if proto in ("TCP", "HTTP") and "sport" in info:
            rows.append(f"  Ports     {info['sport']} -> {info['dport']}  | Flags: {info.get('flags','-')}")
        elif proto in ("UDP", "DNS") and "sport" in info:
            rows.append(f"  Ports     {info['sport']} -> {info['dport']}")

        if info["detail"]:
            rows.append(f"  Detail    {info['detail']}")

        return "\n".join(rows)

    def summary(self) -> str:
        lines = []
        lines.append("=" * 60)
        lines.append("        PACKET CAPTURE SUMMARY")
        lines.append("=" * 60)
        lines.append(f"Total packets captured : {self.packet_no}")
        for proto in ("TCP", "UDP", "ICMP", "DNS", "HTTP", "OTHER"):
            lines.append(f"  {proto:<8}: {self.protocol_counts.get(proto, 0)}")
        lines.append("=" * 60)
        return "\n".join(lines)

    def save_log(self, path: str = None) -> str:
        if path is None:
            path = f"capture_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(path, "w", encoding="utf-8") as f:
            f.write("=" * 60 + "\n")
            f.write("  CODTECH IT SOLUTIONS - PACKET CAPTURE LOG\n")
            f.write("  Intern: Aditya Jain | ID: CITS2742\n")
            f.write(f"  Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n")
            for line in self.captured_lines:
                f.write(line + "\n")
            f.write("\n" + self.summary() + "\n")
        return path


# ============================================================
#  CLI ENTRY POINT
# ============================================================
BANNER = """
============================================================
   NETWORK PACKET SNIFFER
   CodTech IT Solutions - Cyber Security Internship
   Intern: Aditya Jain | ID: CITS2742
============================================================

DISCLAIMER: Only capture traffic on networks/devices you own
or are authorized to monitor. Educational use only.
"""


def prompt_packet_count() -> int:
    print("\nHow many packets do you want to capture?")
    print("(Enter 0 to capture continuously until Ctrl+C)\n")
    raw = input("Enter number: ").strip()
    try:
        return int(raw)
    except ValueError:
        print("Invalid input - defaulting to 20 packets.")
        return 20


def main():
    print(BANNER)

    if not SCAPY_AVAILABLE:
        print("ERROR: 'scapy' is not installed.")
        print("Install it with:  pip install scapy")
        print("On Windows you also need Npcap: https://npcap.com/#download")
        sys.exit(1)

    if os.name == "nt" and not has_admin_rights():
        print("WARNING: This terminal is not running as Administrator.")
        print("Raw packet capture on Windows requires admin rights.")
        print("Right-click your terminal / VS Code and choose")
        print("'Run as Administrator', then run this script again.\n")
        proceed = input("Try anyway? (y/n): ").strip().lower()
        if proceed != "y":
            sys.exit(0)

    count = prompt_packet_count()
    session = CaptureSession()

    print("\nStarting capture... Press Ctrl+C to stop early.\n")
    try:
        if count == 0:
            sniff(prn=session.on_packet, store=False)
        else:
            sniff(prn=session.on_packet, count=count, store=False)
    except KeyboardInterrupt:
        print("\n\nCapture stopped by user.")
    except PermissionError:
        print("\nERROR: Permission denied opening a raw socket.")
        print("Re-run this terminal as Administrator and try again.")
    except Exception as e:
        print(f"\nERROR: {e}")
        print("If this is a Windows Npcap/permission issue, make sure:")
        print("  1. Npcap is installed")
        print("  2. You're running as Administrator")
    finally:
        print("\n" + session.summary())
        choice = input("\nSave this capture log to a file? (y/n): ").strip().lower()
        if choice == "y":
            path = session.save_log()
            print(f"Saved -> {path}")
        print("\nExiting. Stay secure!\n")


if __name__ == "__main__":
    main()
