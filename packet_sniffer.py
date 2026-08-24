from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest


def analyze_packet(packet):
    info = {
        "protocol": "OTHER",
        "src": "?",
        "dst": "?",
        "sport": "-",
        "dport": "-",
        "flags": "-",
        "detail": ""
    }

    # Check for IP layer.
    if packet.haslayer(IP):
        ip = packet[IP]
        info["src"] = ip.src
        info["dst"] = ip.dst

    # Check if the packet uses TCP.
    if packet.haslayer(TCP):
        info["protocol"] = "TCP"

        tcp = packet[TCP]

        # Get source and destination ports.
        info["sport"] = tcp.sport
        info["dport"] = tcp.dport

        # Get TCP flags.
        flags = []

        if tcp.flags & 0x02:       # SYN
            flags.append("S")

        if tcp.flags & 0x10:       # ACK
            flags.append("A")

        if tcp.flags & 0x01:       # FIN
            flags.append("F")

        if tcp.flags & 0x04:       # RST
            flags.append("R")

        if tcp.flags & 0x08:       # PSH
            flags.append("P")

        info["flags"] = "+".join(flags) if flags else "-"

        # Check for HTTP request.
        if packet.haslayer(HTTPRequest):
            info["protocol"] = "HTTP"

            http = packet[HTTPRequest]

            # HTTP method.
            method = getattr(http, "Method", None)
            if method:
                method = method.decode("utf-8", errors="replace")
            else:
                method = "?"

            # Website host.
            host = getattr(http, "Host", None)
            if host:
                host = host.decode("utf-8", errors="replace")
            else:
                host = "?"

            # Requested path.
            path = getattr(http, "Path", None)
            if path:
                path = path.decode("utf-8", errors="replace")
            else:
                path = "/"

            info["detail"] = f"{method} http://{host}{path}"

    # Check UDP packets.
    elif packet.haslayer(UDP):
        info["protocol"] = "UDP"

        udp = packet[UDP]
        info["sport"] = udp.sport
        info["dport"] = udp.dport

    # Check ICMP packets.
    elif packet.haslayer(ICMP):
        info["protocol"] = "ICMP"

    return info


def packet_callback(packet):
    info = analyze_packet(packet)

    print(
        f"{info['src']:>15} -> "
        f"{info['dst']:<15} | "
        f"{info['protocol']:<5} | "
        f"{str(info['sport']):>5} -> "
        f"{str(info['dport']):<5} | "
        f"Flags: {info['flags']:<7} | "
        f"{info['detail']}"
    )


def main():
    print("=" * 100)
    print("NETWORK PACKET SNIFFER")
    print("=" * 100)
    print("Capturing packets...")
    print("Press Ctrl+C to stop.")
    print("-" * 100)

    try:
        sniff(
            prn=packet_callback,
            store=False
        )

    except KeyboardInterrupt:
        print("\n")
        print("=" * 100)
        print("Packet capture stopped.")
        print("=" * 100)

    except Exception as e:
        print(f"\nError while capturing packets: {e}")


if __name__ == "__main__":
    main()
