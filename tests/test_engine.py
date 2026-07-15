from datetime import datetime

import pytest

from firewall_engine.models import Packet


def test_creates_valid_packet() -> None:
    packet = Packet(
        src_ip="192.168.1.25",
        dst_ip="10.0.0.10",
        src_port=51500,
        dst_port=443,
        protocol="TCP",
        payload=b"example-data",
    )

    assert packet.src_ip == "192.168.1.25"
    assert packet.dst_ip == "10.0.0.10"
    assert packet.protocol == "TCP"
    assert packet.dst_port == 443


def test_normalizes_protocol_to_uppercase() -> None:
    packet = Packet(
        src_ip="192.168.1.25",
        dst_ip="10.0.0.10",
        src_port=51500,
        dst_port=53,
        protocol="udp",
    )

    assert packet.protocol == "UDP"


def test_returns_five_tuple() -> None:
    packet = Packet(
        src_ip="192.168.1.25",
        dst_ip="10.0.0.10",
        src_port=51500,
        dst_port=443,
        protocol="TCP",
    )

    assert packet.five_tuple == (
        "192.168.1.25",
        "10.0.0.10",
        51500,
        443,
        "TCP",
    )


def test_rejects_invalid_ip_address() -> None:
    with pytest.raises(ValueError):
        Packet(
            src_ip="999.999.999.999",
            dst_ip="10.0.0.10",
            src_port=51500,
            dst_port=443,
            protocol="TCP",
        )


def test_rejects_invalid_port() -> None:
    with pytest.raises(ValueError):
        Packet(
            src_ip="192.168.1.25",
            dst_ip="10.0.0.10",
            src_port=70000,
            dst_port=443,
            protocol="TCP",
        )


def test_rejects_unsupported_protocol() -> None:
    with pytest.raises(ValueError):
        Packet(
            src_ip="192.168.1.25",
            dst_ip="10.0.0.10",
            src_port=51500,
            dst_port=443,
            protocol="FTP",
        )


def test_rejects_string_payload() -> None:
    with pytest.raises(TypeError):
        Packet(
            src_ip="192.168.1.25",
            dst_ip="10.0.0.10",
            src_port=51500,
            dst_port=443,
            protocol="TCP",
            payload="not-bytes",
        )


def test_rejects_timestamp_without_timezone() -> None:
    with pytest.raises(ValueError):
        Packet(
            src_ip="192.168.1.25",
            dst_ip="10.0.0.10",
            src_port=51500,
            dst_port=443,
            protocol="TCP",
            timestamp=datetime.now(),
        )
