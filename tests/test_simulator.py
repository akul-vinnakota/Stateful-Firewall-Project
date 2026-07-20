import pytest

from firewall_engine.simulator import TrafficSimulator


def test_generate_packet_returns_valid_packet() -> None:
    simulator = TrafficSimulator(seed=42)

    packet = simulator.generate_packet()

    assert packet.protocol in {"TCP", "UDP", "ICMP"}
    assert packet.src_ip
    assert packet.dst_ip
    assert 0 <= packet.src_port <= 65535
    assert 0 <= packet.dst_port <= 65535


def test_generate_packets_returns_requested_count() -> None:
    simulator = TrafficSimulator(seed=42)

    packets = simulator.generate_packets(10)

    assert len(packets) == 10


def test_seed_produces_repeatable_traffic() -> None:
    first_simulator = TrafficSimulator(seed=42)
    second_simulator = TrafficSimulator(seed=42)

    first_packets = first_simulator.generate_packets(5)
    second_packets = second_simulator.generate_packets(5)

    first_five_tuples = [
        packet.five_tuple
        for packet in first_packets
    ]

    second_five_tuples = [
        packet.five_tuple
        for packet in second_packets
    ]

    assert first_five_tuples == second_five_tuples


def test_different_seeds_produce_different_traffic() -> None:
    first_simulator = TrafficSimulator(seed=42)
    second_simulator = TrafficSimulator(seed=100)

    first_packets = first_simulator.generate_packets(5)
    second_packets = second_simulator.generate_packets(5)

    first_five_tuples = [
        packet.five_tuple
        for packet in first_packets
    ]

    second_five_tuples = [
        packet.five_tuple
        for packet in second_packets
    ]

    assert first_five_tuples != second_five_tuples


def test_generate_packets_rejects_zero_count() -> None:
    simulator = TrafficSimulator(seed=42)

    with pytest.raises(ValueError):
        simulator.generate_packets(0)


def test_generate_packets_rejects_non_integer_count() -> None:
    simulator = TrafficSimulator(seed=42)

    with pytest.raises(TypeError):
        simulator.generate_packets("10")  # type: ignore[arg-type]


def test_icmp_packets_use_zero_ports() -> None:
    simulator = TrafficSimulator(seed=42)

    packets = simulator.generate_packets(100)

    icmp_packets = [
        packet
        for packet in packets
        if packet.protocol == "ICMP"
    ]

    assert icmp_packets

    for packet in icmp_packets:
        assert packet.src_port == 0
        assert packet.dst_port == 0
