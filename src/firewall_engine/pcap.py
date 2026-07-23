from __future__ import annotations

from pathlib import Path
from typing import Iterable

from scapy.all import ICMP, IP, TCP, UDP, Raw, rdpcap
from scapy.packet import Packet as ScapyPacket

from firewall_engine.models import Packet


def convert_scapy_packet(
    captured_packet: ScapyPacket,
) -> Packet | None:
    """Convert a supported Scapy packet into the firewall Packet model."""

    if not captured_packet.haslayer(IP):
        return None

    ip_layer = captured_packet[IP]

    protocol: str
    src_port = 0
    dst_port = 0

    if captured_packet.haslayer(TCP):
        transport_layer = captured_packet[TCP]
        protocol = "TCP"
        src_port = int(transport_layer.sport)
        dst_port = int(transport_layer.dport)

    elif captured_packet.haslayer(UDP):
        transport_layer = captured_packet[UDP]
        protocol = "UDP"
        src_port = int(transport_layer.sport)
        dst_port = int(transport_layer.dport)

    elif captured_packet.haslayer(ICMP):
        protocol = "ICMP"

    else:
        return None

    payload = b""

    if captured_packet.haslayer(Raw):
        payload = bytes(captured_packet[Raw].load)

    return Packet(
        src_ip=str(ip_layer.src),
        dst_ip=str(ip_layer.dst),
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        payload=payload,
    )


def load_pcap(
    pcap_path: str | Path,
) -> list[Packet]:
    """Load supported IPv4 packets from a PCAP file."""

    input_path = Path(pcap_path)

    if not input_path.exists():
        raise FileNotFoundError(
            f"PCAP file not found: {input_path}"
        )

    captured_packets: Iterable[ScapyPacket] = rdpcap(
        str(input_path)
    )

    converted_packets: list[Packet] = []

    for captured_packet in captured_packets:
        packet = convert_scapy_packet(
            captured_packet
        )

        if packet is not None:
            converted_packets.append(packet)

    return converted_packets
