from scapy.all import ARP, Ether, ICMP, IP, Raw, TCP, UDP, wrpcap

from firewall_engine.pcap import convert_scapy_packet, load_pcap


def test_convert_tcp_packet() -> None:
    captured_packet = (
        IP(src="192.168.1.25", dst="10.0.0.10")
        / TCP(sport=51500, dport=443)
        / Raw(load=b"test-http")
    )

    packet = convert_scapy_packet(captured_packet)

    assert packet is not None
    assert packet.src_ip == "192.168.1.25"
    assert packet.dst_ip == "10.0.0.10"
    assert packet.src_port == 51500
    assert packet.dst_port == 443
    assert packet.protocol == "TCP"
    assert packet.payload == b"test-http"


def test_convert_udp_packet() -> None:
    captured_packet = (
        IP(src="192.168.1.40", dst="10.0.0.53")
        / UDP(sport=53000, dport=53)
        / Raw(load=b"dns-test")
    )

    packet = convert_scapy_packet(captured_packet)

    assert packet is not None
    assert packet.protocol == "UDP"
    assert packet.src_port == 53000
    assert packet.dst_port == 53


def test_convert_icmp_packet_uses_zero_ports() -> None:
    captured_packet = (
        IP(src="10.1.0.15", dst="10.0.0.10")
        / ICMP()
    )

    packet = convert_scapy_packet(captured_packet)

    assert packet is not None
    assert packet.protocol == "ICMP"
    assert packet.src_port == 0
    assert packet.dst_port == 0


def test_unsupported_packet_returns_none() -> None:
    captured_packet = (
        Ether()
        / ARP(
            psrc="192.168.1.25",
            pdst="192.168.1.1",
        )
    )

    assert convert_scapy_packet(captured_packet) is None


def test_load_pcap_returns_supported_packets(tmp_path) -> None:
    pcap_path = tmp_path / "test-traffic.pcap"

    captured_packets = [
        IP(src="192.168.1.25", dst="10.0.0.10")
        / TCP(sport=51500, dport=443),

        IP(src="192.168.1.40", dst="10.0.0.53")
        / UDP(sport=53000, dport=53),

        IP(src="10.1.0.15", dst="10.0.0.10")
        / ICMP(),

        Ether()
        / ARP(
            psrc="192.168.1.25",
            pdst="192.168.1.1",
        ),
    ]

    wrpcap(str(pcap_path), captured_packets)

    packets = load_pcap(pcap_path)

    assert len(packets) == 3
    assert packets[0].protocol == "TCP"
    assert packets[1].protocol == "UDP"
    assert packets[2].protocol == "ICMP"


def test_load_pcap_rejects_missing_file(tmp_path) -> None:
    missing_path = tmp_path / "missing.pcap"

    try:
        load_pcap(missing_path)
        assert False, "Expected FileNotFoundError"
    except FileNotFoundError:
        assert True
