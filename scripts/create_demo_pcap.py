from pathlib import Path

from scapy.all import ICMP, IP, TCP, UDP, Raw, wrpcap


def main() -> None:
    output_path = Path("captures/demo-traffic.pcap")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    packets = [
        IP(src="192.168.1.25", dst="10.0.0.10")
        / TCP(sport=51500, dport=443)
        / Raw(load=b"GET / HTTP/1.1\r\nHost: example.local\r\n\r\n"),

        IP(src="172.16.0.50", dst="10.0.0.10")
        / TCP(sport=52000, dport=23)
        / Raw(load=b"telnet-test"),

        IP(src="192.168.1.40", dst="10.0.0.53")
        / UDP(sport=53000, dport=53)
        / Raw(load=b"dns-test"),

        IP(src="172.16.0.75", dst="10.0.0.10")
        / TCP(sport=54000, dport=445)
        / Raw(load=b"smb-test"),

        IP(src="10.1.0.15", dst="10.0.0.10")
        / ICMP(),
    ]

    wrpcap(str(output_path), packets)

    print(f"Created {output_path}")
    print(f"Packets written: {len(packets)}")


if __name__ == "__main__":
    main()
